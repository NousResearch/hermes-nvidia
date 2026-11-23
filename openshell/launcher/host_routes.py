"""Routes the launcher answers on the host, never forwarded into the sandbox.

* ``/api/plugins/openshell/*``: the plugin's own status, policy, restart and stop, and the settings
  page's routes: the saved spec (``config``), folder and network edits (validated and saved here;
  network edits apply live where the driver can, the rest on the next start) and the profile's key
  names. Where the driver's enforcer has them (``capabilities``), also: blocked network requests
  (``proposals``, approve / reject with a reason), the enforcer's policy history
  (``policy/revisions``, ``policy/rollback``) and recent audit events (``events``).
* Credential writes. The sandbox cannot read or write ``.env`` (its grant denies every credential
  store), so the Keys page's routes run here, in the launcher's host process, through the same Hermes
  handlers ``hermes serve`` uses. The sandbox picks the change up on its next restart. These writes are
  the user's (the sandbox holds no outer token), so each one refreshes the launcher's pins (pins.py);
  ``endpoints/allow`` lets a key be used at an endpoint the sandbox's model entry names now.
  What these routes show of the keys (the list, a revealed value) is the pinned ``.env``, never the home's:
  the sandbox may have replaced that file, and a Hermes that reads no env file from a home that runs
  elsewhere answers nothing for it. A write still lands in the home's ``.env`` (put back from the pin first)
  and the pin then follows it.
* The Sandbox switch's off half (``switch/ticket``, ``switch/off``; order and reasons in switch.py).
  ``switch/off`` is the one route that takes a one-time ticket instead of the outer token.
* The hand-back (handback.py): ``handback`` lists what the sandbox changed among the files that run on this
  computer since it was switched on, ``handback/answer`` records the user's keep, and ``switch/off`` takes the
  answer (``"handback": "revert"`` or ``"keep"``). A key or endpoint the user writes through the routes above
  joins the baseline, so it is never listed as the sandbox's.
* Signing in or out of a provider answers 409 while the sandbox is on: the sign-ins a sandbox uses are kept
  current on this computer from the launcher's copy (signins.py), and a new one is taken at the next switch-on.
  An MCP server's sign-in is not carried into the sandbox at all, and its route says so.
* The provider rows of the status (``providers``) reach the page through ``settings_view.page_rows``: the fields
  the page reads and nothing else a row carries. Moving a key out of ``config.yaml`` is refused here in plain
  words: the route that does it belongs to the backend of a profile that is off.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Callable, Optional

from . import handback, pins
from .driver import NotSupported, ProposalChanged
from .layout import LayoutError
from .proxy import HostHandler, Request
from .settings_view import MOVE_WHILE_ON, config_payload, key_rows, status_providers
from .spec import allow_entry, folder_from_entry, folders_from_body, network_from_body, network_policy, update_spec
from .switch import (Tickets, clear_marker, hand_back, host_serve, needs_an_answer, needs_answer, review,
                     switch_view, unregister)

log = logging.getLogger("openshell.host_routes")

PLUGIN_PREFIX = "/api/plugins/openshell"
_RESTART_HEADER = {"X-Hermes-Sandbox-Restart-Required": "1"}
_SIGN_IN_REFUSED = ("Sign in or out with the sandbox off: turn the sandbox off for this profile, then turn it "
                    "back on afterwards. The Sandbox page shows which sign-ins the sandbox can use.")
_MCP_SIGN_IN_REFUSED = ("An MCP server's sign-in stays on this computer: the sandbox can't use it yet. Turn the "
                        "sandbox off for this profile to sign in.")
_REFUSED = (
    (("POST", "DELETE"), re.compile(r"/api/providers/oauth/.+"), _SIGN_IN_REFUSED),
    (("POST",), re.compile(r"/api/mcp/servers/[^/]+/auth"), _MCP_SIGN_IN_REFUSED),
)
_CUSTOM_ENDPOINT_RE = re.compile(r"/api/providers/custom-endpoints/([^/]+)")
_PROPOSAL_RE = re.compile(r"proposals/([A-Za-z0-9._:-]{1,128})/(approve|reject)")
_REVISION_RE = re.compile(r"policy/revisions/(\d{1,9})")
_PROPOSAL_STATUSES = ("pending", "approved", "rejected", "all")
_EVENT_CLASSES = ("NET", "HTTP", "SSH", "PROC", "FINDING", "CONFIG", "LIFECYCLE", "EVENT")
_MAX_REASON = 500
SWITCH_OFF_LINGER = 5.0  # seconds the launcher stays up after switch/off answered (status probes only)
_REVEAL_MAX, _REVEAL_WINDOW = 5, 30.0
HANDBACK_VIEW_TTL = 5.0  # seconds ``GET handback`` answers from its last list (the page opens, then the click)
HANDBACK_TEXT_ROWS = 200  # the most changed skill and memory files one answer lists; the rest is a count
# The config.yaml entries a custom-endpoint write of the user's may change (Hermes's handler writes the provider
# and, saved as the default, the model). Nothing else such a write is seen to change joins the baseline.
_ENDPOINT_KEYS = ("providers", "custom_providers", "model")


class HostRoutes:
    def __init__(self, supervisor, request_stop: Callable[[], None], extra_routes: Optional[dict] = None):
        self._sup = supervisor
        self._request_stop = request_stop
        self._reveals: list[float] = []
        self._spec_lock = asyncio.Lock()
        # The hand-back module does no locking: every call into it from here runs under this lock.
        self._handback_lock = asyncio.Lock()
        self._handback_view: Optional[tuple] = None  # (monotonic time, full, payload, stamp) of the last list
        self._plugin = {
            ("GET", "status"): self._status, ("GET", "policy"): self._policy,
            ("POST", "restart"): self._restart, ("POST", "stop"): self._stop,
            ("GET", "config"): self._config, ("PUT", "folders"): self._put_folders,
            ("POST", "folders/check"): self._check_folder, ("PUT", "network"): self._put_network,
            ("POST", "network/check"): self._check_destination,
            ("GET", "keys"): self._keys, ("PUT", "keys"): self._key_set, ("DELETE", "keys"): self._key_delete,
            ("GET", "providers"): self._providers, ("POST", "providers/move"): _refuse(MOVE_WHILE_ON),
            ("GET", "proposals"): self._proposals, ("GET", "policy/revisions"): self._revisions,
            ("POST", "policy/rollback"): self._rollback, ("GET", "events"): self._events,
            ("POST", "endpoints/allow"): self._endpoint_allow,
            ("GET", "handback"): self._handback, ("POST", "handback/answer"): self._handback_answer,
            ("POST", "switch/ticket"): self._switch_ticket, ("DELETE", "switch/ticket"): self._switch_revoke,
            ("POST", "switch/off"): _ticket_auth(self._switch_off), ("OPTIONS", "switch/off"): _ticket_auth(_preflight),
        }
        self._tickets = Tickets()
        # Routes owned by other launcher parts: the cards' status (cards.py) and the Activity tab's
        # timeline and OCSF export (activity.py).
        self._plugin.update(extra_routes or {})
        self._credential = {
            ("GET", "/api/env"): self._env_list, ("PUT", "/api/env"): self._env_set,
            ("DELETE", "/api/env"): self._env_delete, ("POST", "/api/env/reveal"): self._env_reveal,
            ("POST", "/api/providers/custom-endpoints"): self._endpoint_upsert,
        }

    def match(self, method: str, path: str) -> Optional[HostHandler]:
        if path == PLUGIN_PREFIX or path.startswith(PLUGIN_PREFIX + "/"):
            sub = path[len(PLUGIN_PREFIX):].strip("/")
            handler = self._plugin.get((method, sub))
            if handler is not None:
                return handler
            m = _PROPOSAL_RE.fullmatch(sub)
            if m and method == "POST":
                return lambda req, body: self._decide(m.group(1), m.group(2), body)
            m = _REVISION_RE.fullmatch(sub)
            if m and method == "GET":
                return lambda req, body: self._revision(int(m.group(1)))
            return _not_found
        handler = self._credential.get((method, path))
        if handler is not None:
            return handler
        m = _CUSTOM_ENDPOINT_RE.fullmatch(path)
        if method == "DELETE" and m:
            return lambda req, body: self._endpoint_delete(m.group(1))
        for methods, pattern, reason in _REFUSED:
            if method in methods and pattern.fullmatch(path):
                return _refuse(reason)
        return None

    # -- plugin routes -------------------------------------------------------------------------
    async def _status(self, req: Request, body: bytes):
        view = await asyncio.to_thread(switch_view, self._sup.layout, sandboxed=True)
        return 200, {**_page_status(self._sup.status()), "switch": view}, {}

    async def _providers(self, req: Request, body: bytes):
        """The provider rows alone, as the status carries them for the page: the same path answers with the
        rows of a profile that is off on that profile's own backend. Nothing keeps a switch that is on from
        turning on, so ``providers_block`` is null here."""
        return 200, {"providers": _page_status(self._sup.status()).get("providers") or [], "providers_block": None}, {}

    async def _policy(self, req: Request, body: bytes):
        return 200, await asyncio.to_thread(self._sup.policy), {}

    async def _restart(self, req: Request, body: bytes):
        await self._sup.restart()
        return 200, _page_status(self._sup.status()), {}

    async def _stop(self, req: Request, body: bytes):
        asyncio.get_running_loop().call_later(0.2, self._request_stop)
        return 200, {"ok": True, "stopping": True}, {}

    # -- the Sandbox switch (see switch.py for the order and why) --------------------------------
    async def _switch_ticket(self, req: Request, body: bytes):
        """A one-time ticket for ``switch/off``: the page takes one before it asks the desktop to stop
        routing the profile here, because afterwards ``ctx.rest`` no longer reaches this launcher."""
        return 200, {"ticket": self._tickets.mint(), "url": f"http://127.0.0.1:{self._sup.outer_port}",
                     "expires_in": int(self._tickets._ttl)}, {}

    async def _switch_revoke(self, req: Request, body: bytes):
        self._tickets.revoke_all()
        return 200, {"ok": True}, {}

    async def _switch_off(self, req: Request, body: bytes):
        """Stop the sandbox, hand the home back, remove the login service, clear core's marker (last), then
        exit. Takes the outer token or a ticket; the sandbox has neither. Any failure keeps the marker: fail
        closed. ``{"handback": "revert" | "keep"}`` is the user's answer to the list of what the sandbox changed
        (order and reasons in switch.py); without one, changes that need an answer stop nothing (409)."""
        data, error = _json_body(body)
        if error:
            return error
        ticket = data.get("ticket") if isinstance(data, dict) else None
        if not (getattr(req, "authenticated", False) or self._tickets.redeem(ticket)):
            return 403, {"detail": "Not allowed."}, {}
        self._tickets.revoke_all()
        answer = data.get("handback") if isinstance(data, dict) else None
        if answer not in (None, "revert", "keep"):
            return 422, {"detail": 'handback is "revert" or "keep".'}, {}
        sup = self._sup
        # Before anything stops: is there something the user has not answered? A list nobody answered never
        # stops the sandbox. The answer carries no rows: this route answers cross-origin, the list comes from
        # ``GET handback`` (outer token).
        self._handback_view = None
        async with self._handback_lock:
            view = await asyncio.to_thread(review, sup.layout)
        if needs_an_answer(view, answer):
            return 409, {"detail": needs_answer(view["unanswered"]), "code": "handback_needs_answer",
                         "unanswered": view["unanswered"]}, {}
        sup.switching_off = True  # status probes keep their last answer until the desktop has moved on
        try:
            await sup.stop()
            # The sandbox is gone and the profile still marked: an env file it created or replaced is put back
            # (the pin) and what it changed among the files that run here is reverted or kept as answered,
            # before any host process may read the home again.
            async with self._handback_lock:
                # A driver whose sandbox could not be removed says so: its credential files stay out of reach.
                gone = getattr(getattr(sup, "driver", None), "sandbox_gone", None)
                done = await asyncio.to_thread(hand_back, sup.layout, view, answer,
                                               sandbox_gone=bool(gone()) if callable(gone) else True)
            if done["blocked"]:
                # Fail closed, as a failed unregister does: stopped, still registered, still marked. Trying
                # again is safe, and "keep" always goes through.
                sup.switching_off = False
                return 409, {"detail": done["blocked"], "code": "handback_incomplete", "left": done["left"]}, {}
            await asyncio.to_thread(unregister, sup.layout, sup.runtime)
            cleared = await asyncio.to_thread(clear_marker, sup.layout)
        except Exception as exc:
            sup.switching_off = False
            return 500, {"detail": f"The sandbox didn't turn off: {exc}"}, {}
        if cleared:  # best effort: a running host gateway serves the profile now, not at its next rescan
            await asyncio.to_thread(host_serve, sup.layout)
        # Exit a moment later, not at once: the desktop drops its route to this launcher right after this
        # answer, and status probes it sends meanwhile should not find the port closed.
        asyncio.get_running_loop().call_later(SWITCH_OFF_LINGER, self._request_stop)
        return 200, {"ok": True, "state": "off", "marker_cleared": cleared, "handback": done["result"]}, {}

    # -- the hand-back: what the sandbox changed among the files that run on this computer --------
    async def _handback(self, req: Request, body: bytes):
        """The list, while the sandbox is still on (the page's card, ``hermes sandbox handback``). ``?full=1``
        reads every file again; without it size and time are trusted for the text the agent reads. The last
        answer is kept for a few seconds, while the watched files are as they were then (``handback.stamp``:
        the page asks again when the status's stamp changes, and must get the new list); an answer, a
        switch-off and a write of the user's drop it. ``kept``: what the user kept at an earlier hand-back and
        is still in the profile."""
        query = getattr(req, "query_values", None)
        full = bool(query and (query("full") or [""])[0] == "1")
        layout = self._sup.layout
        stamp = await asyncio.to_thread(handback.stamp, layout.home, layout.state_dir)
        last = self._handback_view
        if (last is not None and last[1] == full and last[3] == stamp
                and time.monotonic() - last[0] < HANDBACK_VIEW_TTL):
            return 200, last[2], {}
        async with self._handback_lock:
            view = await asyncio.to_thread(review, layout, quick=not full)
            kept = await asyncio.to_thread(_kept, layout)
        payload = {**_text_rows_cut(view), "kept": kept}
        self._handback_view = (time.monotonic(), full, payload, stamp)
        return 200, payload, {}

    async def _handback_answer(self, req: Request, body: bytes):
        """Record the user's keep: ``{"answer": "keep", "rows": "all" | [ids], "seen": {id: state}}``. With
        ``seen`` (the rows as the page showed them) a row that changed since is not kept. A revert is not an
        answer to record: it happens when the sandbox turns off. Only the user can call this (the sandbox holds
        no outer token)."""
        data, error = _json_body(body)
        if error:
            return error
        data = data if isinstance(data, dict) else {}
        answer, rows, seen = data.get("answer"), data.get("rows", "all"), data.get("seen")
        if answer == "revert":
            return 409, {"detail": "Changes are reverted when the sandbox turns off."}, {}
        rows_ok = rows == "all" or (isinstance(rows, list) and all(isinstance(row, str) for row in rows))
        if answer != "keep" or not rows_ok or not (seen is None or isinstance(seen, dict)):
            return 422, {"detail": 'Expected {"answer": "keep", "rows": "all" or a list of row ids}.'}, {}
        layout = self._sup.layout
        self._handback_view = None
        async with self._handback_lock:
            done = await asyncio.to_thread(handback.keep, layout.home, layout.state_dir, rows, seen=seen)
            view = await asyncio.to_thread(review, layout, quick=True)
        return 200, {"kept": done["kept"], "skipped": done["skipped"], "unanswered": view["unanswered"]}, {}

    # -- settings page -------------------------------------------------------------------------
    async def _config(self, req: Request, body: bytes):
        sup = self._sup
        payload = await asyncio.to_thread(config_payload, sup.layout, sup.spec, sup.driver.capabilities(),
                                          sandboxed=True, restart_required=sup.restart_required,
                                          opened=sup.opened_hosts())
        return 200, payload, {}

    async def _put_folders(self, req: Request, body: bytes):
        return await self._edit_spec(body, lambda data: {"folders": folders_from_body(data, self._sup.layout)})

    async def _put_network(self, req: Request, body: bytes):
        """Saved on the host first; where the driver applies network rules live and a sandbox runs,
        applied now too (nothing pends). A live apply that fails leaves the edit saved and pending."""
        caps = self._sup.driver.capabilities()
        approved = network_policy(self._sup.spec).get("approved")
        status, payload, extra = await self._edit_spec(body, lambda data: {"network": network_from_body(
            data, host_loopback=caps["host_loopback"], rules=tuple(caps.get("network_rules", ("cidr",))),
            allow_all=caps.get("egress_allow_all", True), approved=approved)})
        if status != 200 or not (caps.get("network_live") and self._sup.running()):
            return status, payload, extra
        try:
            result = await self._sup.apply_network(network_policy(self._sup.spec))
        except Exception as exc:
            return 200, {**payload, "live_error": f"Saved; not applied to the running sandbox: {exc}"}, extra
        status, payload, extra = await self._config(None, b"")
        if isinstance(result, dict) and result.get("loaded") is False and not result.get("skipped"):
            payload = {**payload, "live_note": "Saved; the sandbox has not confirmed the new rules yet."}
        return status, payload, extra

    async def _check_folder(self, req: Request, body: bytes):
        return await _check(body, lambda data: folder_from_entry(data, self._sup.layout))

    async def _check_destination(self, req: Request, body: bytes):
        caps = self._sup.driver.capabilities()
        return await _check(body, lambda data: allow_entry(data, host_loopback=caps["host_loopback"],
                                                           rules=tuple(caps.get("network_rules", ("cidr",)))))

    # -- enforcer features: blocked requests, policy history, audit events ----------------------
    async def _enforcer(self, feature: str, call, *args, needs_running: bool = True):
        sup = self._sup
        if not sup.driver.can(feature):
            label = sup.driver.capabilities().get("label") or sup.driver.name
            return 409, {"detail": f"The {label} driver does not support this.", "supported": False}, {}
        if needs_running and not sup.running():
            return 409, {"detail": "The sandbox is not running.", "state": sup.state}, {}
        try:
            return 200, await asyncio.to_thread(call, *args), {}
        except ProposalChanged as exc:
            return 409, {"detail": str(exc), "changed": True, "proposal": exc.proposal}, {}
        except NotSupported as exc:
            return 409, {"detail": str(exc)}, {}
        except KeyError as exc:
            return 404, {"detail": f"Not found: {exc.args[0] if exc.args else ''}"}, {}

    async def _proposals(self, req: Request, body: bytes):
        status = (req.query_values("status") or ["pending"])[0] if req is not None else "pending"
        if status not in _PROPOSAL_STATUSES:
            return 422, {"detail": f"status must be one of {', '.join(_PROPOSAL_STATUSES)}"}, {}
        code, payload, extra = await self._enforcer("requests_supported", self._sup.driver.proposals, status)
        return (code, {"status": status, "proposals": payload}, extra) if code == 200 else (code, payload, extra)

    async def _decide(self, proposal_id: str, action: str, body: bytes):
        data, error = _json_body(body)
        if error:
            return error
        if action == "reject":
            reason = data.get("reason") if isinstance(data, dict) else None
            if not isinstance(reason, str) or not reason.strip():
                return 422, {"detail": "A rejection needs a reason; the agent sees it and can ask for less."}, {}
            if len(reason) > _MAX_REASON:
                return 422, {"detail": f"Keep the reason under {_MAX_REASON} characters."}, {}
            return await self._enforcer("requests_supported", self._sup.driver.reject, proposal_id, reason.strip())
        code, payload, extra = await self._enforcer("requests_supported", self._sup.driver.approve, proposal_id)
        if code == 200:
            payload = {**payload, "network": await self._adopt_live_network()}
        return code, payload, extra

    async def _revisions(self, req: Request, body: bytes):
        return await self._enforcer("policy_revisions", self._sup.driver.revisions)

    async def _revision(self, version: int):
        return await self._enforcer("policy_revisions", self._sup.driver.revision, version)

    async def _rollback(self, req: Request, body: bytes):
        data, error = _json_body(body)
        if error:
            return error
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            return 422, {"detail": "Expected {\"version\": N} naming an earlier revision."}, {}
        code, payload, extra = await self._enforcer("policy_revisions", self._sup.driver.rollback, version)
        if code == 200:
            payload = {**payload, "network": await self._adopt_live_network()}
        return code, payload, extra

    async def _events(self, req: Request, body: bytes):
        try:
            since = _float_query(req, "since")
            until = _float_query(req, "until")
            limit = int((req.query_values("limit") or ["200"])[0]) if req is not None else 200
        except ValueError:
            return 422, {"detail": "since and until are Unix seconds; limit is a number."}, {}
        classes = tuple(c.strip().upper() for c in ",".join(req.query_values("class") if req else []).split(",") if c.strip())
        if any(c not in _EVENT_CLASSES for c in classes) or not 1 <= limit <= 1000:
            return 422, {"detail": f"class is any of {', '.join(_EVENT_CLASSES)}; limit is 1 to 1000."}, {}
        # A stopped sandbox's audit trail stays readable: the driver serves its saved log (the host
        # archive) and says NotSupported (409) where it kept none.
        code, payload, extra = await self._enforcer(
            "audit_events", lambda: self._sup.driver.events(since=since, until=until, limit=limit, classes=classes),
            needs_running=False)
        return (code, {"events": payload, "format": "ocsf-shorthand"}, extra) if code == 200 else (code, payload, extra)

    async def _adopt_live_network(self) -> Optional[dict]:
        """An approval or rollback changed the running sandbox's network: the saved spec follows it,
        so a restart recreates the same rules and nothing shows as pending."""
        try:
            live = await asyncio.to_thread(self._sup.driver.current_network)
        except Exception:
            return None
        if live is None:
            return None
        async with self._spec_lock:
            try:
                spec = await asyncio.to_thread(update_spec, self._sup.layout, network=live)
            except LayoutError:
                return None
            self._sup.adopt_network(spec)
        return network_policy(spec)

    async def _edit_spec(self, body: bytes, changes_for):
        """Validate on the host, save the spec atomically, answer with the spec read back."""
        data, error = _json_body(body)
        if error:
            return error
        async with self._spec_lock:
            try:
                changes = await asyncio.to_thread(changes_for, data)
                spec = await asyncio.to_thread(update_spec, self._sup.layout, **changes)
            except LayoutError as exc:
                return 422, {"detail": str(exc)}, {}
            self._sup.set_spec(spec)
        return await self._config(None, b"")

    async def _keys(self, req: Request, body: bytes):
        status, payload, extra = await self._env_list(req, body)
        if status != 200:
            return status, payload, extra
        return 200, {"keys": key_rows(payload), "credentials": self._sup.driver.capabilities()["credentials"]}, {}

    async def _key_set(self, req: Request, body: bytes):
        """Save a key. The answer says what that means for the sandbox (``sandbox``: ``in_use``, ``after_restart``
        or ``not_used``), so the page can say it in one line."""
        status, payload, extra = _key_result(await self._env_set(req, body))
        try:
            name = json.loads(body or b"{}").get("key")
        except (ValueError, AttributeError):
            name = None
        if status < 300 and isinstance(name, str) and name:
            use = self._sup.key_use(name, bool(payload["sandbox_restart_required"]))
            payload = {**payload, "sandbox": use}
        return status, payload, extra

    async def _key_delete(self, req: Request, body: bytes):
        return _key_result(await self._env_delete(req, body))

    # -- credential routes (host-side Hermes handlers, scoped to this profile's home) -----------
    async def _env_list(self, req: Request, body: bytes):
        """Hermes's own rows (names, descriptions, grouping), with which keys are set taken from the pin."""
        from hermes_cli.web_routers import config_env

        layout = self._sup.layout
        # Put back an env file the sandbox created or replaced first, as a write does: Hermes's handler reads
        # the home's file where this Hermes still reads it.
        await asyncio.to_thread(pins.restore_env, layout)
        status, payload, extra = await _call(config_env.get_env_vars(None))
        if status == 200:
            payload = _pinned_rows(payload, await asyncio.to_thread(pins.env_values, layout))
        return status, payload, extra

    async def _env_set(self, req: Request, body: bytes):
        from hermes_cli.web_models import EnvVarUpdate
        from hermes_cli.web_routers import config_env

        return await self._key_live(await self._write(body, EnvVarUpdate, lambda m: config_env.set_env_var(m, None)))

    async def _key_live(self, result):
        """After a key was saved: when the running sandbox already uses the new value (the driver replaced the
        value behind the key's placeholder), the answer no longer asks for a restart."""
        status, payload, extra = result
        if status >= 300 or not await asyncio.to_thread(self._sup.keys_saved):
            return result
        if isinstance(payload, dict):
            payload = {**payload, "sandbox_restart_required": False}
        return status, payload, {k: v for k, v in extra.items() if k not in _RESTART_HEADER}

    async def _env_delete(self, req: Request, body: bytes):
        from hermes_cli.web_models import EnvVarDelete
        from hermes_cli.web_routers import config_env

        return await self._write(body, EnvVarDelete, lambda m: config_env.remove_env_var(m, None))

    async def _endpoint_upsert(self, req: Request, body: bytes):
        from hermes_cli.web_models import CustomEndpointUpdate
        from hermes_cli.web_routers import config_env

        return await self._write(body, CustomEndpointUpdate,
                                 lambda m: asyncio.to_thread(config_env.upsert_custom_endpoint, m, None))

    async def _endpoint_delete(self, endpoint_id: str):
        from hermes_cli.web_routers import config_env

        async with self._handback_lock:
            before = await asyncio.to_thread(_before_write, self._sup.layout)
            seen = await asyncio.to_thread(_handback_before, self._sup.layout)
            status, payload, extra = await _call(asyncio.to_thread(config_env.delete_custom_endpoint, endpoint_id, None))
            if status < 300:
                files = await asyncio.to_thread(_after_write, self._sup.layout, before, None)
                await asyncio.to_thread(_handback_written, self._sup.layout, seen, True, files)
                self._handback_view = None
        return self._mark_written(status, payload, extra)

    async def _endpoint_allow(self, req: Request, body: bytes):
        """Let a key be used at the endpoint the sandbox's model entry names now: one of the status's
        ``endpoint_changed`` rows, named by ``{env, host, port}``. The pair joins the pin and the key is bound
        at the next sandbox start. Only the user can call this (the sandbox holds no outer token)."""
        data, error = _json_body(body)
        if error:
            return error
        data = data if isinstance(data, dict) else {}
        row = next((c for c in self._sup.endpoint_changed()
                    if all(c.get(k) == data.get(k) for k in ("env", "host", "port"))), None)
        if row is None:
            return 404, {"detail": "No withheld key for this endpoint."}, {}
        from .openshell_driver import route_host

        pair = {"env": row["env"], "host": route_host(row["host"]), "port": row["port"]}
        if not await asyncio.to_thread(pins.allow, self._sup.layout, pair):
            return 409, {"detail": "Turn the sandbox off and on first."}, {}
        self._sup.endpoint_allowed(row)
        return 200, {"ok": True, "sandbox_restart_required": True,
                     "endpoint_changed": self._sup.endpoint_changed()}, dict(_RESTART_HEADER)

    async def _env_reveal(self, req: Request, body: bytes):
        from hermes_cli.config import load_env
        from hermes_cli.web_models import EnvVarReveal

        model, error = self._model(body, EnvVarReveal)
        if error:
            return error
        now = time.monotonic()
        self._reveals = [t for t in self._reveals if now - t < _REVEAL_WINDOW]
        if len(self._reveals) >= _REVEAL_MAX:
            return 429, {"detail": "Too many reveal requests. Try again shortly."}, {}
        self._reveals.append(now)
        # Never a value the sandbox planted: the pinned file answers. Without a pin (a sandbox switched on by
        # an older version) Hermes's own reader does, as before.
        pinned = await asyncio.to_thread(_pinned_env, self._sup.layout)
        value = (pinned if pinned is not None else await asyncio.to_thread(load_env)).get(model.key)
        if value is None:
            return 404, {"detail": f"{model.key} not found in .env"}, {}
        return 200, {"key": model.key, "value": value}, {}

    async def _write(self, body: bytes, model_cls, call):
        model, error = self._model(body, model_cls)
        if error:
            return error
        base_url = getattr(model, "base_url", None)  # only an endpoint write has one
        async with self._handback_lock:
            before = await asyncio.to_thread(_before_write, self._sup.layout)
            seen = await asyncio.to_thread(_handback_before, self._sup.layout)
            status, payload, extra = await _call(call(model))
            if status < 300:
                files = await asyncio.to_thread(_after_write, self._sup.layout, before, base_url)
                await asyncio.to_thread(_handback_written, self._sup.layout, seen, base_url is not None, files)
                self._handback_view = None
        return self._mark_written(status, payload, extra)

    def _model(self, body: bytes, model_cls):
        from pydantic import ValidationError

        try:
            data = json.loads(body or b"{}")
            model = model_cls(**data)
        except (ValueError, TypeError, ValidationError) as exc:
            return None, (422, {"detail": str(exc)}, {})
        requested = getattr(model, "profile", None)
        if requested and not self._sup.owns_profile(requested):
            return None, (403, {"detail": f"This sandboxed backend serves one profile; {requested!r} is not it."}, {})
        return model, None

    def _mark_written(self, status: int, payload, extra: dict):
        if status < 300:
            self._sup.keys_changed = True
            if isinstance(payload, dict):
                payload = {**payload, "sandbox_restart_required": True}
            extra = {**extra, **_RESTART_HEADER}
        return status, payload, extra


def _page_status(status: dict) -> dict:
    """The supervisor's status as the page gets it: its provider rows reduced to what the page reads, each with
    the page's sentence (settings_view.py). A status without such rows is passed on as it is."""
    return {**status, **status_providers(status)}


def _before_write(layout) -> list[dict]:
    """Before a key or endpoint write: an env file or a sign-in store the sandbox created or replaced is put
    back first, so the write lands in the user's own file and the refresh after it never pins the sandbox's.
    Returns the home's model entries as they are now."""
    pins.restore_env(layout)
    pins.restore_stores(layout)
    return pins.current_models(layout)


def _after_write(layout, before: list[dict], base_url) -> list[str]:
    """After a key or endpoint write went through: the env file as written is the pinned one, so is the sign-in
    store when that write changed it, and a model entry the write added (an endpoint saved as the default
    model) joins the pinned entries. Returns the files whose pinned copy now follows the write."""
    pins.update_env(layout)
    stores = pins.update_stores(layout)
    if base_url:
        pins.add_models(layout, before, str(base_url))
    return [".env", *stores]


def _pinned_env(layout) -> Optional[dict]:
    """The pinned ``.env`` (name -> value) after an env file the sandbox created or replaced was put back; None
    without a pin."""
    pins.restore_env(layout)
    return pins.env_values(layout)


def _pinned_rows(rows, pinned: Optional[dict]):
    """Hermes's ``/api/env`` rows with ``is_set`` and the preview taken from the pinned ``.env`` (*pinned*; None
    without a pin: the rows as they came). A row Hermes listed only because the home's file names it is dropped
    when the pin does not; a pinned name Hermes did not list (it read nothing from the home) is added the way
    Hermes lists a key it has no entry for."""
    if pinned is None or not isinstance(rows, dict):
        return rows
    try:
        from hermes_cli.web_routers._common import redacted_credential_preview as preview
    except ImportError:
        def preview(value):
            return None
    try:
        from hermes_cli.web_routers.config_env import _channel_managed_env_keys

        elsewhere = set(_channel_managed_env_keys())  # Hermes leaves these to its Channels page
    except Exception:
        elsewhere = set()
    out = {}
    for name, row in rows.items():
        if not isinstance(row, dict):
            out[name] = row
        elif not (row.get("custom") and not pinned.get(name)):
            out[name] = {**row, "is_set": bool(pinned.get(name)), "redacted_value": preview(pinned.get(name))}
    for name, value in pinned.items():
        if value and name not in out and name not in elsewhere:
            out[name] = {"is_set": True, "redacted_value": preview(value), "description": "", "url": None,
                         "category": "custom", "is_password": True, "tools": [], "advanced": False,
                         "channel_managed": False, "provider": "", "provider_label": "", "provider_profiles": [],
                         "provider_primary": False, "custom": True}
    return out


def _handback_before(layout) -> Optional[dict]:
    """Before a key or endpoint write of the user's: the settings that run on this computer as they are now
    (None when no baseline is open, or when they cannot be read: the write goes on either way)."""
    try:
        return handback.tier1_paths(layout.home) if handback.is_open(layout.state_dir) else None
    except Exception as exc:
        log.warning("hand-back: could not read the settings before a write: %s", exc)
        return None


def _handback_written(layout, before: Optional[dict], endpoint: bool, files=(".env",)) -> None:
    """The user's own write through a host route becomes part of the baseline, so it is not listed later as the
    sandbox's: the env file as written (``_before_write`` put the pinned one back first, so it is the user's),
    the sign-in store when that write changed it (*files*: what the pin followed), and for an endpoint write
    the provider and model entries that write changed. A key write takes no setting: whatever else changed in
    config.yaml meanwhile stays the sandbox's. Never fails the write."""
    if before is None:
        return
    try:
        wrote = []
        if endpoint:
            after = handback.tier1_paths(layout.home)
            wrote = [path for path in set(before) | set(after)
                     if before.get(path) != after.get(path) and path[0] in _ENDPOINT_KEYS]
        handback.update_baseline_for_host_write(layout.home, layout.state_dir, files=list(files), config_keys=wrote)
    except Exception as exc:
        log.warning("hand-back: a write of the user's could not join the baseline: %s", exc)


def _kept(layout) -> list:
    """What the user kept from a sandbox and is still in the profile (``handback.kept``); [] when it cannot be
    read. Never fails the list."""
    try:
        return handback.kept(layout.home, layout.state_dir)
    except Exception as exc:
        log.warning("hand-back: what was kept for profile %s could not be read: %s", layout.name, exc)
        return []


def _text_rows_cut(view: dict) -> dict:
    """*view* with the list of changed text files cut to HANDBACK_TEXT_ROWS and ``more`` counting the rest."""
    text = view.get("tier2")
    if not isinstance(text, dict):
        return view
    items = text.get("items") or []
    return {**view, "tier2": {**text, "items": items[:HANDBACK_TEXT_ROWS],
                              "more": max(0, len(items) - HANDBACK_TEXT_ROWS)}}


async def _call(awaitable):
    from fastapi import HTTPException

    try:
        return 200, await awaitable, {}
    except HTTPException as exc:
        return exc.status_code, {"detail": exc.detail}, {}


def _json_body(body: bytes):
    try:
        return json.loads(body or b"{}"), None
    except ValueError as exc:
        return None, (422, {"detail": f"Body is not JSON: {exc}"}, {})


def _float_query(req: Optional[Request], key: str) -> Optional[float]:
    values = req.query_values(key) if req is not None else []
    return float(values[0]) if values and values[0] else None


async def _check(body: bytes, validate):
    """Validate one entry the way the matching PUT would, without saving (the page asks before it
    widens access, and wants the refusal first)."""
    data, error = _json_body(body)
    if error:
        return error
    try:
        return 200, await asyncio.to_thread(validate, data), {}
    except LayoutError as exc:
        return 422, {"detail": str(exc)}, {}


def _key_result(result):
    """A key write's answer without whatever the credential handler echoed back."""
    status, payload, extra = result
    if status >= 300:
        return status, payload, extra
    restart = payload.get("sandbox_restart_required", True) if isinstance(payload, dict) else True
    return status, {"ok": True, "sandbox_restart_required": bool(restart)}, extra


async def _not_found(req: Request, body: bytes):
    return 404, {"detail": "Not found"}, {}


def _ticket_auth(handler: HostHandler) -> HostHandler:
    """Mark a host route the proxy lets through without the outer token: it checks a one-time ticket
    itself, and its answer is readable cross-origin (the page calls it directly over loopback)."""
    async def wrapped(req: Request, body: bytes):
        return await handler(req, body)

    wrapped.ticket_auth = True  # type: ignore[attr-defined]
    return wrapped


async def _preflight(req: Request, body: bytes):
    return 204, None, {"Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "content-type",
                       "Access-Control-Max-Age": "60"}


def _refuse(reason: str) -> HostHandler:
    async def handler(req: Request, body: bytes):
        return 409, {"detail": reason, "sandboxed": True}, {}

    return handler
