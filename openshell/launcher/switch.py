"""The Sandbox switch: turn a profile's sandbox on and off.

Three things change together, and the order is what keeps a half-finished switch fail-closed:

* the **login service** that runs the profile's launcher (``login_service``),
* core's **run-elsewhere marker** (``<hermes root>/profiles_run_elsewhere/<profile>.json``): while it
  names the profile, nothing on the host runs it (host gateway, cron, Kanban, desktop),
* the desktop's **per-profile backend override**, which the page sets and clears through
  ``host.setProfileBackend`` / ``host.clearProfileBackend`` (Electron main confirms each natively).

Turning on (``turn_on``, from the unsandboxed page's host route or ``hermes sandbox on``). On a desktop
with ``host.profileBackendFeatures.prepare`` the page asks the user FIRST and calls this route from
``setProfileBackend``'s ``prepare``, so nothing starts before the user said yes. Before any of that, the
host compatibility check (``compat.py``) must pass: the page shows its reason with the switch disabled,
and ``turn_on`` re-runs it and refuses with the same reason.

1. Preflight the driver, then review the last sandbox session if it ended without one
   (``previous_session``, below: nothing is pinned or recorded from a home whose changes nobody answered),
   save the spec (a refused driver never reaches ``spec.yaml``), pin the profile's keys and model endpoints
   on the host (``pins.take``: the launcher never reads them from the home again, which the sandbox
   writes), rotate the outer token, record the home as it is (``handback.take_baseline``: what the
   switch-off compares it with), write the service definition and start the service.
2. Wait until the launcher answers and its sandbox runs, and take a one-time undo ticket from it. Any
   failure here undoes 1; nothing was marked.
3. Mark the profile LAST, right before answering, then ask a running host gateway to drop it at once
   (else its 30 s rescan does). From now on the host refuses to run it, so the desktop can never route
   the profile to a host backend while the sandbox owns it; and since the desktop applies its override
   the moment ``prepare`` resolves, the host refuses the profile only for that apply (~1 s).
4. Return the launcher URL, its token and the undo ticket. The desktop routes the profile to the
   launcher; if it then refuses the URL or the set fails (or, on an older desktop without ``prepare``,
   the user cancels the confirm that follows), the page spends the ticket on the launcher's
   ``switch/off`` route (the host route can't be used: the marker already refuses the profile there).

``turn_on`` does all four in one call and returns when the sandbox runs (``hermes sandbox on``, and a page that
sends no ``wait``). The page's route cannot hold one request that long: Hermes cuts a request to a profile's plugin
host after 60 seconds, and a sandbox can take longer to start. So the page asks in short requests
(``turn_on_within``, ``Starts``): steps 1 and 2 run in a thread of their own, one per profile, and each request
waits for them a few seconds and answers ``pending``; steps 3 and 4 run inside the request that returns the final
answer, so the profile is still marked right before the answer the desktop routes by. A start whose answer nobody
asks for any more is undone like one that failed, and so is one whose process ended in the middle (``lost_start``).

Turning off (from the sandboxed page, served by the launcher). The desktop must never see the
profile marked while it no longer routes it to the launcher (it fails closed with a full-screen
"Hermes couldn't start"), so the launcher tears down BEFORE the desktop override goes:

1. The page takes a one-time ticket from the launcher (while ``ctx.rest`` still reaches it).
2. ``host.clearProfileBackend({..., beforeApply})``: the desktop asks the user natively first.
   Cancel changes nothing (the page revokes the ticket).
3. ``beforeApply`` spends the ticket on the launcher's ``switch/off`` (a direct loopback call). The
   launcher stops the sandbox, puts back an env file the sandbox created or replaced and deletes the
   pins (``pins.release``), hands the home back (below), removes the service definition and
   registration, clears the marker (the last step that can fail), then asks a running host gateway to
   serve the profile again. The sandbox is gone before the marker is, so the host never runs the
   profile while a sandbox might. A failure before the clear leaves the marker in place and the
   override untouched (fail closed; ``hermes -p <profile> sandbox off`` finishes the job from a
   terminal).
4. Only then does the desktop drop its override, without asking again (the confirm's one-time
   grant): the profile is unmarked by then, so the host serves it at once.

A desktop without ``beforeApply`` ignores it and clears the override straight after the confirm; the
page then spends the ticket afterwards (the profile shows as unavailable until the launcher has
cleared the marker).

Either way the marker is cleared only once the sandbox is known to be gone. The launcher's ``switch/off``
answers 409 ``sandbox_not_stopped`` when its driver could not delete the sandbox, and ``turn_off_here``,
with no launcher to hand the work to, asks the gateway itself to delete this profile's sandbox and raises
while the gateway still has it (``_leftover_gone``). The profile then stays marked. The terminal hands the
work to a launcher only when the launcher's state file names a process that is alive, and sends the launcher's
token nowhere else.

The hand-back (``handback.py``). Once the sandbox is off, Hermes on this computer reads the profile's
home as its own, and the sandbox wrote most of it. So before the marker is cleared, in the launcher's
``switch/off`` and in ``turn_off_here`` alike, the home is compared with the baseline taken at
switch-on:

* no change among the files and settings that run on this computer: the switch turns off as before;
* such changes (rows) and no answer: nothing stops and nothing changes. ``switch/off`` answers 409
  ``handback_needs_answer`` and ``turn_off_here`` raises ``HandbackNeeded``; the page shows the list
  with two buttons, the terminal prints it and asks for ``--revert`` or ``--keep``;
* ``revert``: after the sandbox stopped, every row is put back from the baseline and the sandbox's
  versions are kept in ``<state dir>/handback/held/``; ``keep``: the rows the user was shown stay, and
  what the user was not shown is still put back.

A hand-back step that fails or does not come back never holds the switch: the sandbox turns off and
the answer says the review could not run (``handback.error``). A row that could not be put back keeps
the marker for ``revert`` (409 ``handback_incomplete``); ``keep`` is never refused for it, so there is
always a way to turn off.

A session that ended without that review leaves its baseline open: a switch-off whose review could not
run, a launcher that was killed and whose marker was cleared by hand, a foreground ``sandbox serve``
that was killed, a switch-on that failed and could not put a row back. (A crash, a kill or a reboot
with the login service in place leaves the switch on and the profile marked: ``turn_on`` refuses, and
the switch-off reviews as always.) The next switch-on, and the next foreground serve, would otherwise
pin that home's ``secrets:`` block and model entries as the user's own and record the whole home as
the new baseline. So both first stop a sandbox that launcher left running (``drop_leftover``: it would
go on writing the home), then run the same review (``previous_session``): rows and no answer stop
the switch-on with the list (409 ``handback_needs_answer``, ``HandbackNeeded``) and change nothing;
``revert`` and ``keep`` answer as at a switch-off; no rows goes on. Here a review that cannot run
stops the switch-on (the profile runs unsandboxed meanwhile, as it did), except with ``keep``.

With no baseline at all there is nothing to compare: the first switch-on of a profile, or a profile
whose earlier sandbox sessions ran before the baseline existed. The home is pinned and recorded as it
is. For the first case that is the user's own home. For the second it may hold what an earlier
sandbox wrote, which Hermes on this computer has been reading as the profile's own since that session
ended; nothing here can tell it from the user's, and no list is shown.
"""
from __future__ import annotations

import contextvars
import hmac
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import handback, pins
from .login_service import (LoginService, ServiceError, define, launcher_log, launcher_state_alive, manager_for,
                            process_start_ticks, remove_definition, switched_on, write_definition)

log = logging.getLogger("openshell.switch")

PLUGIN_ID = "openshell"
READY_TIMEOUT = 240.0
# How long a switch-on waits for a launcher that is ending after a switch-off (its linger plus its own exit).
ENDING_WAIT = 30.0
# One hand-back step (making the list, the revert) may take this long; past it the switch goes on without the
# step and says so. A profile folder that cannot be read through must not hold the switch.
HANDBACK_TIMEOUT = 120.0
SWITCH_OFF_TIMEOUT = 2 * HANDBACK_TIMEOUT + 120.0  # how long `hermes sandbox off` waits for a running launcher
TICKET_TTL = 900.0  # the native confirm may sit open for a while
# The longest one request of the page's switch-on is held, whatever it asks for: Hermes cuts a request to a
# profile's plugin host after 60 seconds.
REQUEST_WAIT_MAX = 25.0
# A start no request has asked about for this long is undone: the window was closed, or the page stopped asking.
# A page that waits asks again as soon as it is answered, so its requests are never this far apart.
UNCOLLECTED_AFTER = 45.0
# Which process is starting the sandbox, kept beside the launcher's state while a start is neither marked nor undone.
START_RECORD = "switch-on.json"
NOT_FINISHED = "The sandbox didn't finish starting. Turn it on again."
SWITCH_ROUTE = "/api/plugins/openshell/switch"


def refuse_unready(layout) -> Optional[str]:
    """Before a switch-on changes anything: the switch does not turn on while a key is written in the profile's
    ``config.yaml`` (the sandbox reads that file), nor into a main model that cannot work in the sandbox, nor
    while one of the files that says so cannot be read (provider_rows.py). Raises ``SwitchError`` (422) with what
    to do; ``code`` is ``unreadable``, ``key_in_config``, ``model_unavailable`` or ``model_needs_sign_in`` and
    ``keys`` lists the keys. A Hermes that cannot be asked refuses nothing.

    Returns what to know about a switch-on that goes ahead (one line: the profile's model has no key), or None.
    What an earlier move of keys left on disk is removed here too (config_keys.py)."""
    from . import config_keys, provider_rows, settings_view

    try:
        config_keys.sweep(layout.home)
    except Exception as exc:
        log.warning("what an earlier move of keys left could not be removed: %s", _why(exc))
    seen: list = []
    try:
        refusal = provider_rows.refusal(layout, seen=seen)
    except Exception as exc:
        log.warning("the providers of profile %s could not be checked before the switch: %s", layout.name, _why(exc))
        return None
    if refusal is not None:
        error = SwitchError(refusal["detail"], 422)
        error.code, error.keys = refusal["code"], refusal["keys"]
        raise error
    note = settings_view.switch_note(seen)
    return note["reason"] if note else None


class SwitchError(RuntimeError):
    code: Optional[str] = None  # set where the caller can act on the kind of refusal
    keys: list = []

    def __init__(self, detail: str, status: int = 409):
        super().__init__(detail)
        self.status = status


# -- core's marker ---------------------------------------------------------------------------------

def marker_api():
    try:
        from hermes_cli import profiles_run_elsewhere
    except ImportError:
        return None
    return profiles_run_elsewhere


def state_folder_api():
    """Core's reader of the install-state folder a launcher names for its process
    (``pm.environments.named_install_state_dir``), or None on a Hermes without it."""
    try:
        from pm import environments
    except ImportError:
        return None
    return getattr(environments, "named_install_state_dir", None)


def _hermes_too_old() -> bool:
    """On Windows the host's own interpreter runs in the sandbox, and the supervisor names Hermes inside an
    install-state folder of its own. A Hermes that does not read the name ends at start there."""
    from . import compat

    return marker_api() is None or (compat._platform_key() == "windows" and state_folder_api() is None)


def availability(layout, *, check_host: bool = True, refresh: bool = False) -> dict:
    """Whether this host can flip the switch for *layout*, and if not, why (page copy). With
    ``check_host`` it includes the host compatibility check (compat.py, cached; ``refresh`` re-runs
    it): an incompatible computer answers its one reason and action, and ``host`` carries the verdict."""
    if _hermes_too_old():
        return {"available": False, "reason": "Needs a newer version of Hermes."}
    if layout.name == "default":
        return {"available": False, "reason": "Not available for the default profile yet."}
    from .openshell_install import RUNTIME_DIRNAME

    if layout.name == RUNTIME_DIRNAME:
        # Its state folder would be the one that holds the installed OpenShell runtime and its gateway.
        return {"available": False, "reason": f"Not available for a profile named {layout.name}."}
    if not check_host:
        return {"available": True, "reason": None}
    host = host_check(layout, refresh=refresh)
    if not host["ok"]:
        return {"available": False, "reason": host["reason"], "action": host["action"], "host": host}
    return {"available": True, "reason": None, "host": host}


def host_check(layout, *, refresh: bool = False) -> dict:
    """compat.check with the wxc-exec this profile's launcher would use (its spec, then the environment, then
    the plugin's own install under the profile's Hermes root)."""
    from . import compat
    from .layout import LayoutError
    from .spec import load_spec

    try:
        spec = load_spec(layout)
    except (LayoutError, OSError, ValueError):
        spec = {}
    return compat.check(compat.wxc_exec_for(spec, layout.root), refresh=refresh)


def is_marked(layout) -> bool:
    api = marker_api()
    return api is not None and api.run_elsewhere(layout.name, root=layout.root) is not None


def mark(layout) -> None:
    marker_api().mark_profile_run_elsewhere(layout.name, PLUGIN_ID, root=layout.root)


def clear_marker(layout) -> bool:
    api = marker_api()
    return bool(api and api.clear_profile_run_elsewhere(layout.name, PLUGIN_ID, root=layout.root))


def _host_gateway(verb: str, layout) -> Optional[dict]:
    """Best effort: tell a running host gateway to drop (``unserve``) or serve (``serve``) the
    profile now instead of at its next rescan. None when no gateway answers or core lacks the verb."""
    try:
        from gateway import control_socket
    except ImportError:
        return None
    call = {"unserve": getattr(control_socket, "request_unserve_profile", None),
            "serve": getattr(control_socket, "request_serve_profile_hot", None)}[verb]
    if call is None:
        return None
    try:
        return call(layout.root, layout.name)
    except Exception:
        return None


def host_drop(layout) -> Optional[dict]:
    """After marking: the host gateway stops serving the profile at once."""
    return _host_gateway("unserve", layout)


def host_serve(layout) -> Optional[dict]:
    """After clearing the marker: the host gateway serves the profile again at once."""
    return _host_gateway("serve", layout)


def switch_view(layout, *, sandboxed: bool, refresh: bool = False) -> dict:
    # A running sandbox is never held back by the host check: turning it off must always work.
    return {**availability(layout, check_host=not sandboxed, refresh=refresh), "on": sandboxed,
            "marked": is_marked(layout), "service": switched_on(layout)}


# -- one-time tickets (held by the launcher, in memory only) ---------------------------------------

class Tickets:
    """Single-use tokens that authorize ``switch/off`` without the outer token. Minted only through the
    authenticated host route, so the sandbox (which never holds the outer token) cannot get one."""

    def __init__(self, ttl: float = TICKET_TTL, clock: Callable[[], float] = time.monotonic):
        self._ttl, self._clock = ttl, clock
        self._items: dict[str, float] = {}

    def mint(self) -> str:
        self._expire()
        ticket = secrets.token_urlsafe(32)
        self._items[ticket] = self._clock() + self._ttl
        return ticket

    def redeem(self, presented) -> bool:
        self._expire()
        if not isinstance(presented, str) or not presented:
            return False
        for ticket in list(self._items):
            if hmac.compare_digest(ticket.encode(), presented.encode()):
                del self._items[ticket]
                return True
        return False

    def revoke_all(self) -> None:
        self._items.clear()

    def _expire(self) -> None:
        now = self._clock()
        self._items = {t: exp for t, exp in self._items.items() if exp > now}


# -- talking to a running launcher -----------------------------------------------------------------

def launcher_call(port: int, token: Optional[str], method: str, route: str, body=None, timeout: float = 5.0):
    """(status, payload) from the launcher on *port*; status 0 when nothing answered."""
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if token:
        headers["X-Hermes-Session-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/plugins/openshell/{route}", method=method,
                                 headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"null")
        except ValueError:
            return exc.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def running_launcher(layout) -> Optional[dict]:
    """The launcher state file, when its process is still alive (the same process, not a reused PID)."""
    from .login_service import launcher_state_alive

    try:
        state = json.loads(layout.state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return state if launcher_state_alive(state) else None


def _log_line(layout) -> str:
    try:
        lines = [l for l in launcher_log(layout).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except OSError:
        return ""
    return lines[-1][-300:] if lines else ""


def wait_ready(layout, port: int, token: str, service: LoginService, timeout: float = READY_TIMEOUT,
               sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> dict:
    """Block until the launcher reports its sandbox running; raise with the launcher's reason if it
    fails or its service stops first."""
    start = clock()
    while clock() - start < timeout:
        status, payload = launcher_call(port, token, "GET", "status", timeout=3.0)
        if status == 200 and isinstance(payload, dict):
            state = payload.get("state")
            if state == "running":
                return payload
            if state in ("failed", "exited", "stopped"):
                reason = str(payload.get("error") or state).split("\n")[0]
                raise SwitchError(f"The sandbox didn't start: {reason}", 502)
        elif status == 401:
            raise SwitchError(f"Port {port} answers with another token; is another sandbox using it?", 502)
        elif clock() - start > 10.0 and service.state() != "running":
            line = _log_line(layout)
            raise SwitchError("The sandbox launcher stopped." + (f" {line}" if line else ""), 502)
        sleep(1.0)
    raise SwitchError(f"The sandbox didn't start within {timeout:.0f} seconds.", 504)


# -- the switch ------------------------------------------------------------------------------------

def already_marked(layout) -> str:
    """Why a switch-on is refused for a profile that is marked, with what to do next. The marker is this
    plugin's own in all but one case: its sandbox is on (a launcher answers), or its last session ended
    without a switch-off (the launcher was killed, the computer restarted without the login service): then the
    switch is still on, nothing runs, and ``sandbox off`` is what reviews that session and frees the profile."""
    api = marker_api()
    entry = api.run_elsewhere(layout.name, root=layout.root) if api is not None else None
    owner = getattr(entry, "plugin", None)
    if owner not in (None, PLUGIN_ID):
        return f"This profile already runs elsewhere (the {owner} plugin). Turn that off first."
    if running_launcher(layout) is not None:
        return "The sandbox is already on for this profile."
    profile = "" if layout.name == "default" else f" -p {layout.name}"
    return ("The sandbox is still switched on for this profile, but it isn't running. "
            f"Run `hermes{profile} sandbox off`, then turn it on again.")


def _wait_for_ending_launcher(layout, sleep: Callable[[float], None] = time.sleep) -> Optional[dict]:
    """The launcher that still runs for *layout*, or None. A launcher that has just turned off stays up for a few
    seconds (the launcher's linger after ``switch/off``, so that a desktop's last status probes find it) and then
    ends by itself; a switch-on in that time waits for it, ``ENDING_WAIT`` seconds at most, instead of refusing.
    Waited for: a launcher that says it is switching off, and one whose port no longer answers. A launcher that
    answers and is not switching off is running: returned at once."""
    state = running_launcher(layout)
    if state is None:
        return None
    try:
        token = layout.token_path.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    code, payload = launcher_call(int(state.get("port") or 0), token, "GET", "status")
    if code == 200 and not (isinstance(payload, dict) and payload.get("switching_off")):
        return state
    for _ in range(int(ENDING_WAIT / 0.5)):
        if state is None:
            break
        sleep(0.5)
        state = running_launcher(layout)
    return state


def _stop_service(layout, service: LoginService, port: Optional[int], token: Optional[str],
                  sleep: Callable[[float], None] = time.sleep) -> None:
    """Ask the launcher to stop (it stops the sandbox first), then end the service if it lingers."""
    if port and token and launcher_call(port, token, "POST", "stop")[0] == 200:
        for _ in range(60):
            if service.state() != "running":
                return
            sleep(0.5)
    service.stop()


def turn_on(layout, *, handback_answer: Optional[str] = None, handback_seen: Optional[dict] = None, runtime=None,
            manager: Callable = manager_for, environ: Optional[dict] = None,
            timeout: float = READY_TIMEOUT, make_driver: Optional[Callable] = None,
            sleep: Callable[[float], None] = time.sleep) -> dict:
    """Start *layout*'s launcher as a login service, wait for its sandbox, mark the profile. Returns
    what the page hands to ``host.setProfileBackend`` plus a one-time undo ticket. *handback_answer*
    (``"revert"``, ``"keep"`` or None) answers the list of a last session that ended without a review
    (``previous_session``); with such changes and no answer ``HandbackNeeded`` is raised and nothing was
    changed. *handback_seen* is ``{row id: state}`` of the rows the user was shown, for a ``keep``."""
    return _finish(_start(layout, handback_answer=handback_answer, handback_seen=handback_seen, runtime=runtime,
                          manager=manager, environ=environ, timeout=timeout, make_driver=make_driver, sleep=sleep))


@dataclass
class _Started:
    """A switch-on between its two parts: the launcher's service is registered and its sandbox runs; nothing is
    marked yet."""
    layout: object
    service: LoginService
    port: int
    token: str
    status: dict
    handed_back: Optional[dict]
    note: Optional[str]
    taken: bool  # this switch-on recorded the baseline
    sleep: Callable[[float], None]


def _start(layout, *, handback_answer: Optional[str] = None, handback_seen: Optional[dict] = None, runtime=None,
           manager: Callable = manager_for, environ: Optional[dict] = None,
           timeout: float = READY_TIMEOUT, make_driver: Optional[Callable] = None,
           sleep: Callable[[float], None] = time.sleep) -> _Started:
    """The first part of a switch-on, everything up to a sandbox that runs (steps 1 and 2 of the module
    docstring). It refuses before anything starts, or undoes what it started and raises; the profile is not
    marked here."""
    from .driver import DriverUnavailable
    from .layout import LayoutError, remove_legacy_secret_copies
    from .spec import ensure_token, free_loopback_port, load_spec, network_policy, save_spec

    avail = availability(layout, refresh=True)  # the page's answer may be a minute old: check the host again
    if not avail["available"]:
        raise SwitchError(avail["reason"])
    if is_marked(layout):
        raise SwitchError(already_marked(layout))
    if _wait_for_ending_launcher(layout, sleep) is not None:
        raise SwitchError("A sandbox is already running for this profile. Stop it first.")
    note = refuse_unready(layout)
    if runtime is None:
        from .layout import current_runtime

        runtime = current_runtime()
    if make_driver is None:
        from ..launcher_cli import make_driver
    try:
        spec = load_spec(layout)
        spec["port"] = spec.get("port") or free_loopback_port()
        network_policy(spec)
        driver = make_driver(spec)
        driver.preflight()
    except (DriverUnavailable, LayoutError) as exc:
        raise SwitchError(str(exc), 422) from None
    drop_leftover(layout, driver)
    # Before anything is saved, pinned or recorded: what the last sandbox session left without an answer.
    handed_back = previous_session(layout, handback_answer, seen=handback_seen)
    save_spec(layout, spec)  # only once the driver passed preflight
    try:
        # Now, on the host, before anything starts: the one moment the home is the user's alone. A restart
        # (``serve --service``) never pins.
        pins.take(layout)
    except OSError as exc:
        raise SwitchError(f"Couldn't keep a copy of this profile's keys: {exc}", 500) from None
    port = int(spec["port"])
    token = ensure_token(layout, rotate=True)
    defn = define(layout, runtime, environ)
    service = manager(defn)
    layout.state_path.unlink(missing_ok=True)  # stale: no live launcher owns it (checked above)
    try:
        # The home as the user left it, recorded on the host before anything starts (the service is written,
        # installed and started below); the switch-off compares the home with it. A restart never records one.
        # A baseline that was still open (the last session ended without a review) has been answered above
        # (``previous_session``), so this one replaces whatever is left of it.
        # First what the launcher itself removes from the home before every launch (layout.profile_grants): done
        # here too, so that its own cleanup is never listed as the sandbox's.
        remove_legacy_secret_copies(layout.home)
        baseline = handback.take_baseline(layout.home, layout.state_dir, replace=True)
    except Exception as exc:
        pins.release(layout)
        raise SwitchError(f"Couldn't save a copy of this profile's settings: {exc}", 500) from None
    _note_start(layout)
    try:
        write_definition(defn)
        service.install()
        service.start()
        status = wait_ready(layout, port, token, service, timeout, sleep=sleep)
    except BaseException as exc:
        _undo(layout, service, port, token, False, sleep, baseline["taken"])
        if isinstance(exc, ServiceError):
            raise SwitchError(f"Couldn't register the sandbox to start at login: {exc}", 502) from None
        raise
    return _Started(layout, service, port, token, status, handed_back, note, baseline["taken"], sleep)


def _finish(started: _Started) -> dict:
    """The second part of a switch-on (steps 3 and 4): take the undo ticket, mark the profile, tell the host
    gateway, and return the answer. Short, so the page's route runs it inside the request it answers. A failure
    undoes the whole switch-on."""
    layout, service, port, token = started.layout, started.service, started.port, started.token
    marked = False
    try:
        code, minted = launcher_call(port, token, "POST", "switch/ticket", {})
        if code != 200 or not isinstance(minted, dict) or not minted.get("ticket"):
            raise SwitchError("The sandbox started but didn't hand out an undo ticket.", 502)
        # Marked LAST, right before the answer: the desktop asks the user first (setProfileBackend's prepare)
        # and applies its override the moment this returns, so the host refuses the profile only for that
        # apply, never while a dialog is open.
        mark(layout)
        marked = True
        host_drop(layout)
    except BaseException:
        _undo(layout, service, port, token, marked, started.sleep, started.taken)
        raise
    _forget_start(layout)
    return {"profile": layout.name, "plugin": PLUGIN_ID, "url": f"http://127.0.0.1:{port}", "token": token,
            "undo_ticket": minted["ticket"], "service": service.kind, "status": started.status,
            "handback": started.handed_back, **({"note": started.note} if started.note else {})}


def _undo(layout, service: LoginService, port: int, token: str, marked: bool, sleep, taken: bool = False) -> None:
    """*taken*: this switch-on recorded the baseline (an older one that was still open is not its to end)."""
    for step in (lambda: _stop_service(layout, service, port, token, sleep), lambda: pins.release(layout),
                 *([lambda: _hand_back_undone(layout)] if taken else []),
                 lambda: remove_definition(layout), lambda: _forget_start(layout), service.uninstall,
                 *([lambda: clear_marker(layout), lambda: host_serve(layout)] if marked else [])):
        try:
            step()
        except Exception:
            pass


def _hand_back_undone(layout) -> None:
    """A switch-on that failed may have run the sandbox for a moment.

    Beta decision: what it wrote among the files that run on this computer is put back without asking (seconds
    of runtime, nobody has seen a list, the sandbox's versions are kept in the held folder), then the baseline
    ends. Rows that could not be put back keep it open, and the next switch-off lists them. To leave what that
    sandbox wrote in place instead, drop the revert here and only close."""
    if not handback.revert(layout.home, layout.state_dir, "all")["left"]:
        handback.close(layout.state_dir)


# -- a switch-on asked for in short requests (the page's route) ------------------------------------

def _note_start(layout) -> None:
    """Record which process is about to write the service definition and start the launcher. The record goes
    when the switch-on has marked the profile or undone itself (``_finish``, ``_undo``); one that outlives its
    process says the switch-on was cut off in between (``lost_start``). Never holds the switch-on."""
    pid = os.getpid()
    record = {"pid": pid, "since": time.time(), "start_ticks": process_start_ticks(pid)}
    try:
        layout.state_dir.mkdir(parents=True, exist_ok=True)
        (layout.state_dir / START_RECORD).write_text(json.dumps(record), encoding="utf-8")
    except OSError as exc:
        log.warning("the start of profile %s's sandbox could not be recorded: %s", layout.name, _why(exc))


def _forget_start(layout) -> None:
    try:
        (layout.state_dir / START_RECORD).unlink(missing_ok=True)
    except OSError as exc:
        log.warning("the record of profile %s's start could not be removed: %s", layout.name, _why(exc))


def lost_start(layout, alive: Callable[[Optional[dict]], bool] = launcher_state_alive) -> bool:
    """Whether a switch-on of this profile was cut off: its record is still there and the process that wrote it
    no longer runs. The process that serves the page's route does not outlive Hermes, and Hermes replaces it
    when it dies; a start in flight then leaves the launcher's service registered and running with the profile
    unmarked, and nothing in memory that knows of it."""
    try:
        record = json.loads((layout.state_dir / START_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return not alive(record)


def undo_lost_start(layout, *, runtime=None, manager: Callable = manager_for, environ: Optional[dict] = None,
                    sleep: Callable[[float], None] = time.sleep) -> bool:
    """Undo what a switch-on that was cut off left behind, as a failed one undoes itself (``_undo``): the service
    stopped and removed, the pins released, the home put back as it was recorded. Returns whether there was
    anything to undo. A profile that is marked got its answer, and one without a service definition has been
    switched off since: for both only the record goes."""
    if is_marked(layout) or not switched_on(layout):
        _forget_start(layout)
        return False
    from .layout import LayoutError
    from .spec import load_spec

    if runtime is None:
        from .layout import current_runtime

        runtime = current_runtime()
    try:
        port = int(load_spec(layout).get("port") or 0)
    except (LayoutError, OSError, ValueError):
        port = 0
    try:
        token = layout.token_path.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    # The definition is written after the baseline is recorded, so the open baseline is that switch-on's own.
    _undo(layout, manager(define(layout, runtime, environ)), port, token, False, sleep, True)
    return True


class _Job:
    """One start of one profile's sandbox, shared by every request that asks for it."""

    def __init__(self, layout, how: dict, now: float):
        self.layout, self.how = layout, how
        self.state = "starting"  # then "ready" and "finishing", or "ending"; at last "over"
        self.asked = now  # when a request last asked for it
        self.left = False  # no request asked in time: it ends without an answer to give
        self.started: Optional[_Started] = None
        self.answer: Optional[dict] = None
        self.error: Optional[BaseException] = None


class Starts:
    """The switch-ons in flight in this process, one per profile, for requests that each wait a few seconds.

    ``ask`` begins a profile's start in a thread of its own, or joins the one in flight, and waits for it as
    long as the request allows. While the sandbox is still starting it answers ``{"pending": True}`` and the
    caller asks again. Once the sandbox runs, the request that is asking finishes the switch-on itself
    (``_finish``: the mark comes last, in the request whose answer the desktop routes by); requests waiting
    beside it get the same answer. What refuses or fails the start is raised in the request that asks next,
    as ``turn_on`` raises it.

    A start no request has asked about for ``UNCOLLECTED_AFTER`` seconds ends without an answer: it is undone
    like one that failed and the profile is never marked for it. A request that comes after that begins
    another. *clock* tells how long ago a request asked; *tick* is how often a waiting thread looks again.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic, tick: float = 0.5,
                 alive: Callable[[Optional[dict]], bool] = launcher_state_alive):
        self._clock, self._tick, self._alive = clock, tick, alive
        self._changed = threading.Condition()
        self._jobs: dict = {}

    def ask(self, layout, wait: float, **how) -> dict:
        """*how* is what ``turn_on`` takes; it is used by the request that begins the start."""
        key = (str(layout.root), layout.name)
        until = time.monotonic() + min(max(float(wait), 0.0), REQUEST_WAIT_MAX)
        with self._changed:
            while True:
                job = self._jobs.get(key)
                if job is None:
                    job = self._jobs[key] = _Job(layout, how, self._clock())
                    # The start runs as the request that began it does: for the same profile.
                    context = contextvars.copy_context()
                    threading.Thread(target=context.run, args=(self._run, key, job), daemon=True,
                                     name=f"openshell-switch-on-{layout.name}").start()
                while job.state in ("starting", "finishing", "ending"):
                    job.asked = self._clock()
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        return {"pending": True, "profile": layout.name}
                    self._changed.wait(min(remaining, self._tick))
                job.asked = self._clock()
                if not (job.state == "over" and job.left):
                    break
                # It ended because nobody asked: this request begins another.
                if self._jobs.get(key) is job:
                    del self._jobs[key]
            if job.state == "over":
                if self._jobs.get(key) is job:
                    del self._jobs[key]  # told once
                    self._changed.notify_all()
                if job.error is not None:
                    raise job.error
                return job.answer
            job.state = "finishing"  # the sandbox runs, and this request is the one that takes the answer
        try:
            answer = _finish(job.started)
        except BaseException as exc:
            self._over(key, job, error=exc if isinstance(exc, Exception) else SwitchError(NOT_FINISHED, 409))
            raise
        self._over(key, job, answer=answer)
        return answer

    def _over(self, key, job: _Job, *, answer: Optional[dict] = None, error: Optional[BaseException] = None) -> None:
        with self._changed:
            job.answer, job.error, job.state = answer, error, "over"
            if self._jobs.get(key) is job:
                del self._jobs[key]
            self._changed.notify_all()

    def _unasked(self, job: _Job) -> bool:
        return self._clock() - job.asked > UNCOLLECTED_AFTER

    def _run(self, key, job: _Job) -> None:
        """The thread of one start: the first part of the switch-on, then the wait for a request to take it."""
        layout, how = job.layout, job.how
        nap = how.get("sleep") or time.sleep

        def sleep(seconds: float) -> None:
            # Each wait of the start first asks whether anyone still waits for it. Said once: the undo that
            # follows waits with the same call.
            if not job.left and self._unasked(job):
                job.left = True
                raise SwitchError(NOT_FINISHED, 409)
            nap(seconds)

        started, error = None, None
        try:
            if lost_start(layout, self._alive) and undo_lost_start(
                    layout, runtime=how.get("runtime"), manager=how.get("manager") or manager_for,
                    environ=how.get("environ"), sleep=nap):
                raise SwitchError(NOT_FINISHED, 409)
            started = _start(layout, **{**how, "sleep": sleep})
            started.sleep = nap
        except BaseException as exc:
            error = exc if isinstance(exc, Exception) else SwitchError(NOT_FINISHED, 409)
        if started is not None:
            with self._changed:
                job.started, job.state = started, "ready"
                self._changed.notify_all()
                while job.state == "ready" and not self._unasked(job):
                    self._changed.wait(self._tick)
                if job.state != "ready":
                    return  # a request took it: the profile is marked there, or the switch-on undone there
                job.state, job.left = "ending", True
            _undo(layout, started.service, started.port, started.token, False, nap, started.taken)
            error = SwitchError(NOT_FINISHED, 409)
        with self._changed:
            job.error, job.state = error, "over"
            self._changed.notify_all()
            # What failed is told to the request that asks next, for as long as one may still come.
            while self._jobs.get(key) is job and not job.left and not self._unasked(job):
                self._changed.wait(self._tick)
            if self._jobs.get(key) is job:
                del self._jobs[key]


_STARTS = Starts()


def turn_on_within(layout, wait: float, *, starts: Optional[Starts] = None, **how) -> dict:
    """``turn_on`` for a caller whose requests must each end within seconds (the page's route): the answer of
    ``turn_on``, or ``{"pending": True, "profile": ...}`` when the sandbox is still starting after *wait* seconds
    (``REQUEST_WAIT_MAX`` at most); the caller then asks again. A second caller for the same profile joins the
    start in flight. Raises what ``turn_on`` raises, in the request that asks when it happens. *how* is what
    ``turn_on`` takes."""
    return (starts or _STARTS).ask(layout, wait, **how)


def unregister(layout, runtime=None, manager: Callable = manager_for) -> LoginService:
    """Remove the service definition (the switch is off on disk) and its registration."""
    if runtime is None:
        from .layout import current_runtime

        runtime = current_runtime()
    service = manager(define(layout, runtime))
    remove_definition(layout)
    service.uninstall()
    return service


def turn_off_here(layout, *, handback_answer: Optional[str] = None, runtime=None, manager: Callable = manager_for,
                  sleep: Callable[[float], None] = time.sleep) -> dict:
    """``hermes sandbox off`` from a host terminal: hand the work to a running launcher (it tears down in
    order). The launcher is the one whose state file names a process that is alive: its token is sent to that
    launcher's port and to no other. With no such launcher the same order is kept here: the service is stopped,
    the gateway is asked to delete this profile's sandbox, and only once that sandbox is gone from it is the
    service removed, the home handed back and the marker cleared. A sandbox that cannot be confirmed gone
    raises ``SwitchError``: the profile is still marked, and its home is as it was. *handback_answer* is
    ``"revert"``, ``"keep"`` or None; with changes that need an answer and none given, ``HandbackNeeded`` is
    raised and nothing was changed."""
    state = running_launcher(layout)
    if state is not None:
        try:
            token = layout.token_path.read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
        port = int(state["port"])
        # A launcher that does not answer its status within a few seconds is not handed the switch-off (that
        # call waits minutes for a teardown): its service is ended below and the review is made from the files.
        code, payload = (_launcher_off(port, token, handback_answer)
                         if launcher_call(port, token, "GET", "status")[0] else (0, None))
        if code == 200:
            return {"stopped": "launcher", **(payload if isinstance(payload, dict) else {})}
        detail = payload if isinstance(payload, dict) else {}
        if code == 409 and detail.get("code") == "handback_needs_answer":
            _, view = launcher_call(port, token, "GET", "handback?full=1", timeout=HANDBACK_TIMEOUT + 30.0)
            raise HandbackNeeded(view if isinstance(view, dict) and isinstance(view.get("rows"), list)
                                 else {"open": True, "rows": [], "unanswered": detail.get("unanswered", 0)})
        if code == 409 and detail.get("code") == "handback_incomplete" and detail.get("detail"):
            raise SwitchError(str(detail["detail"]), 409)  # the launcher's own words: what to close, then again
        if code == 409 and detail.get("code") == "sandbox_not_stopped":
            raise SwitchError(not_stopped(layout), 502)  # the launcher still runs: the same command asks it again
        if code != 0:
            raise SwitchError(f"The launcher refused: {code} {payload}", 502)
    view = review(layout)
    if needs_an_answer(view, handback_answer):
        raise HandbackNeeded(view)  # nothing was changed
    if runtime is None:
        from .layout import current_runtime

        runtime = current_runtime()
    service = manager(define(layout, runtime))
    # The service stops first: a launcher that still runs cannot start the sandbox again. Its definition stays
    # until the sandbox is gone, so a profile whose sandbox is not known to be gone reads as switched on.
    service.stop()
    _leftover_gone(layout)  # raises while the gateway still has the sandbox: the marker and the home stay
    remove_definition(layout)
    # A service manager can start the launcher again after a stop. One that started while the definition was
    # still there found the profile switched on and started its sandbox again. A launcher that starts from here
    # on finds no definition and starts nothing. So the service is stopped once more when it runs, and the
    # gateway is asked once more, before the home is handed back.
    if service.state() == "running":
        service.stop()
    _leftover_gone(layout)
    service.uninstall()
    # Before the marker goes: the host never reads an env file the sandbox left, nor runs what it changed.
    done = hand_back(layout, view, handback_answer, record_keep=True)
    if done["blocked"]:
        raise SwitchError(done["blocked"], 409)  # the marker stays
    cleared = clear_marker(layout)
    if cleared:
        host_serve(layout)
    return {"stopped": "service", "marker_cleared": cleared, "state": "off", "handback": done["result"]}


def not_stopped(layout=None, why: str = "") -> str:
    """What a switch-off says when the gateway still has the profile's sandbox, or cannot say: the profile stays
    marked and switched on. With *layout*, the terminal's sentence: it names the command that tries again."""
    said = f"The sandbox couldn't be stopped{f' ({why})' if why else ''}. It stays switched on."
    if layout is None:
        return said
    profile = "" if layout.name == "default" else f" -p {layout.name}"
    return f"{said} Run `hermes{profile} sandbox off` again."


def _leftover_gone(layout) -> bool:
    """A switch-off without its launcher: end the sandbox this profile still has on its gateway. Returns once the
    sandbox is gone from it (True when there was one to delete); a gateway the driver knows to have ended has
    none. The driver asks for the sandbox by this profile's own name, so another profile's sandbox on the same
    gateway is never touched. Raises ``SwitchError`` when the sandbox cannot be deleted or the driver cannot
    tell. The caller then leaves the profile marked: the host never runs a profile while its sandbox can still
    write its home."""
    try:
        from ..launcher_cli import make_driver
        from .spec import load_spec

        drop = getattr(make_driver(load_spec(layout)), "drop_leftover", None)
        return bool(drop(layout.name)) if drop is not None else False
    except Exception as exc:
        why = " ".join(_why(exc).split())[:300]
        log.warning("the sandbox of profile %s could not be stopped: %s", layout.name, why)
        raise SwitchError(not_stopped(layout, why), 502) from None


def _launcher_off(port: int, token: str, answer: Optional[str]):
    """``switch/off`` on a running launcher with the terminal's answer. A ``keep`` is recorded first; when the
    launcher did not record it, nothing is turned off (a keep that was not recorded would revert)."""
    if answer == "keep":
        code, payload = launcher_call(port, token, "POST", "handback/answer", {"answer": "keep", "rows": "all"},
                                      timeout=2 * HANDBACK_TIMEOUT + 30.0)
        if code != 200:
            return code, payload
    return launcher_call(port, token, "POST", "switch/off", {"handback": answer} if answer else {},
                         timeout=SWITCH_OFF_TIMEOUT)


# -- the hand-back (handback.py): what the sandbox changed among the files this computer trusts ------

class HandbackNeeded(SwitchError):
    """Changes need an answer before the sandbox turns off. Nothing was changed; ``view`` is the list."""

    def __init__(self, view: dict):
        super().__init__(needs_answer(int(view.get("unanswered") or 0)), 409)
        self.view = view


def needs_answer(count: int) -> str:
    return "1 change needs an answer." if count == 1 else f"{count} changes need an answer."


def not_reverted(view: dict, left: list) -> str:
    """Names the rows in *left* as *view* lists them (the id for a row it does not have), three at most."""
    names = {row["id"]: row.get("name") for row in view.get("rows") or []}
    shown = [str(names.get(row_id) or row_id) for row_id in left]
    listed = ", ".join(shown[:3]) + (f" and {len(shown) - 3} more" if len(shown) > 3 else "")
    return f"Couldn't revert {'1 change' if len(shown) == 1 else f'{len(shown)} changes'}: {listed}."


def left_unreverted(view: dict, row_ids: list) -> str:
    """What a revert says about the rows it left on purpose (``handback.NO_COPY_REVERT``)."""
    names = {row["id"]: row.get("name") for row in view.get("rows") or []}
    shown = [str(names.get(row_id) or row_id) for row_id in row_ids]
    listed = ", ".join(shown[:3]) + (f" and {len(shown) - 3} more" if len(shown) > 3 else "")
    return f"Left as the sandbox changed {'it' if len(shown) == 1 else 'them'} (no earlier copy was kept): {listed}."


def incomplete(view: dict, outcome: dict, turning: str = "off") -> str:
    stopped = "The sandbox is stopped. " if turning == "off" else ""
    return (f"{not_reverted(view, outcome['left'])} {stopped}Close any app using this profile's "
            f"files, then turn {turning} again.")


def not_reviewed(error: str) -> str:
    return f"Couldn't review the last sandbox session's changes ({error})."


def _why(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _bounded(call, *args, **kwargs):
    """*call*'s result, waited for HANDBACK_TIMEOUT at most (TimeoutError past it). The call runs in a thread of
    its own, which ends by itself when the call does."""
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = call(*args, **kwargs)
        except BaseException as exc:  # handed to the caller below
            box["error"] = exc

    worker = threading.Thread(target=run, name="openshell-handback", daemon=True)
    worker.start()
    worker.join(HANDBACK_TIMEOUT)
    if worker.is_alive():
        raise TimeoutError(f"took longer than {HANDBACK_TIMEOUT:g} seconds")
    if "error" in box:
        raise box["error"]
    return box["value"]


def review(layout, *, quick: bool = False) -> dict:
    """The hand-back's list for *layout* (``handback.diff``; *quick* for a preview). Never raises and never waits
    longer than HANDBACK_TIMEOUT: when the list cannot be made, ``error`` says why and no row is listed, so
    nothing is asked and nothing holds the switch.

    A sign-in store a host process wrote while the sandbox was on is not a change of the sandbox's. Where that
    can be told, the pin and the record follow it first (``pins.restore_stores``, *follow_only*), as the next
    sandbox start and the switch-off do, so the list has no row for it."""
    try:
        pins.restore_stores(layout, follow_only=True)
    except Exception as exc:
        log.warning("hand-back: the pinned sign-in store of profile %s could not follow the host's: %s",
                    layout.name, _why(exc))
    try:
        view = _bounded(handback.diff, layout.home, layout.state_dir, quick=quick)
        if view["open"] or not handback.is_open(layout.state_dir):
            return view
        return {**view, "error": "the copy saved when the sandbox was turned on cannot be read", "unreadable": True}
    except Exception as exc:
        log.warning("hand-back: the list for profile %s could not be made: %s", layout.name, _why(exc))
        return {"open": False, "rows": [], "unanswered": 0, "error": _why(exc)}


def needs_an_answer(view: dict, answer: Optional[str]) -> bool:
    """The gate of a switch-off: rows the user has not answered, and no answer given with it."""
    return bool(view.get("open") and view.get("unanswered")) and answer is None


def drop_leftover(layout, driver) -> bool:
    """Before a switch-on looks at the home: a sandbox the last launcher left running (the launcher was killed;
    no launcher runs now, the caller checked) is stopped first. It could otherwise go on writing the home while
    it is reviewed, pinned and recorded. A sandbox that cannot be stopped refuses the switch-on."""
    drop = getattr(driver, "drop_leftover", None)
    if drop is None:
        return False
    try:
        return bool(drop(layout.name))
    except Exception as exc:
        raise SwitchError(f"A sandbox from the last session is still running and couldn't be stopped: {_why(exc)}",
                          502) from None


def previous_session(layout, answer: Optional[str] = None, *, seen: Optional[dict] = None) -> Optional[dict]:
    """Before a switch-on (``turn_on``, a foreground ``sandbox serve``): the review of a last sandbox session
    that ended without one. Nothing may be pinned or recorded from that home before it.

    The sign of such a session is its baseline, still open (the module docstring lists what leaves one). The
    home is compared with it as at a switch-off, and the answer means the same: rows that need one and no
    *answer* raise ``HandbackNeeded`` with the list, and nothing was changed; ``"revert"`` puts every row back;
    ``"keep"`` keeps the rows as listed (*seen*: as the user was shown them; a row that changed since is put
    back); with no rows it goes on. Either way the env files and the sign-in store that session's pin still
    holds are put back first (``hand_back``), and the baseline ends, so the switch-on pins and records a home
    that was answered for.

    Unlike a switch-off, a review that cannot run stops here (``SwitchError``): going on would pin a home
    nobody looked at, and stopping costs nothing, the profile keeps running unsandboxed. ``"keep"`` is the way
    past it. A baseline that cannot be read at all compares with nothing: it is dropped and the switch-on goes
    on as a first one.

    Returns what the hand-back did (``{"reverted", "kept", "held", ...}``), or None when no baseline was open.
    """
    if not handback.is_open(layout.state_dir):
        return None
    view = review(layout)
    unreadable = bool(view.get("unreadable"))
    if view.get("error") and not unreadable and answer is None:
        raise SwitchError(not_reviewed(view["error"]), 409)  # nothing was changed
    if needs_an_answer(view, answer):
        raise HandbackNeeded(view)  # nothing was changed
    shown = answer == "keep" and seen is not None and view.get("open") and not view.get("error")
    if shown:
        # The page's keep holds for the rows as it showed them; what changed since is put back with the rest.
        try:
            _bounded(handback.keep, layout.home, layout.state_dir, "all", seen=seen)
        except Exception as exc:
            raise SwitchError(not_reviewed(_why(exc)), 409) from None
        view = review(layout)
    done = hand_back(layout, view, answer, record_keep=not shown, turning="on")
    if done["blocked"]:
        raise SwitchError(done["blocked"], 409)
    result = done["result"]
    if result and result.get("error") and not unreadable and answer != "keep":
        raise SwitchError(not_reviewed(result["error"]), 409)
    # With "keep" the home is taken as it is although nobody could list it: the caller's new record replaces
    # the open one (``take_baseline(replace=True)``).
    return result


def hand_back(layout, view: dict, answer: Optional[str], *, record_keep: bool = False, turning: str = "off",
              sandbox_gone: bool = True) -> dict:
    """The hand-back steps of a switch-off, once the sandbox has stopped and while the profile is still marked.
    *view* is the list made before the stop (``review``), *answer* the user's (``"revert"``, ``"keep"`` or None:
    nothing needed one). Returns ``{"result", "blocked"}``: ``result`` goes into the switch-off's answer (None
    when no baseline was open); ``blocked`` is why the switch-off stops here with the marker kept, or None.

    Beta decision (the order against the pins): ``pins.release`` runs first. The pin is the one owner of the env
    files: it moves a ``.env`` or ``.op.env`` the sandbox created or replaced to its quarantine folder and
    writes the pinned one back, so those are no longer rows when the revert looks. The revert runs second, as
    the net (an env file the pin could not put back is still a row then). To let the revert take the env files
    first, move the release below it; a revert that stops the switch-off would then also keep the pin.

    *sandbox_gone* False: the sandbox could not be confirmed gone, so the credential files its driver keeps out
    of its reach stay where they are (``pins.release``, *unhold*).
    """
    pins.release(layout, unhold=sandbox_gone)
    error = view.get("error")
    outcome = None
    kept = [row["id"] for row in view.get("rows") or [] if row.get("answer") == "keep"]
    if error is None or answer == "revert":  # a list that could not be made reverts nothing, unless asked to
        try:
            if record_keep and answer == "keep" and view.get("open"):
                # No launcher recorded the terminal's keep: it holds for the rows as they were listed.
                kept = _bounded(handback.keep, layout.home, layout.state_dir, "all",
                                seen={row["id"]: row["state"] for row in view["rows"]})["kept"]
            # "revert" means every row, whatever was kept before. Otherwise the rows without a keep: what the
            # user was not shown, what changed after it was shown, and the rows that are always reverted.
            outcome = _bounded(handback.revert, layout.home, layout.state_dir,
                               "all" if answer == "revert" else "unanswered")
            error = None
        except Exception as exc:
            error, outcome = _why(exc), None
    if error is not None:
        # Never held by a hand-back step that cannot run: the switch turns off and the answer says so. The
        # baseline stays open (the next switch-off, or `hermes sandbox handback`, can still list the changes),
        # unless it is the baseline itself that cannot be read.
        log.warning("hand-back: profile %s is handed back without a review: %s", layout.name, error)
        if view.get("unreadable"):
            _close_quietly(layout)
        return {"result": {"reverted": [], "kept": [], "held": None, "error": error}, "blocked": None}
    if not outcome["open"]:
        return {"result": None, "blocked": None}
    reverted = outcome["reverted"]
    result = {"reverted": reverted, "kept": [row_id for row_id in kept if row_id not in reverted],
              "held": Path(outcome["held"]).name if outcome["held"] else None}
    unreverted = list(outcome.get("unreverted") or [])
    if unreverted:
        # The profile's own files, changed in the sandbox, with no copy to put back: left in place and named.
        result.update(unreverted=unreverted, problem=left_unreverted(view, unreverted))
    if outcome["left"]:
        if answer != "keep":
            return {"result": result, "blocked": incomplete(view, outcome, turning), "left": outcome["left"]}
        # "keep" is the way out that always works: what could not be put back stays, and is named.
        problem = not_reverted(view, outcome["left"])
        result.update(left=outcome["left"], problem=" ".join(filter(None, [problem, result.get("problem")])))
    _remember_kept(layout, result["kept"])
    _close_quietly(layout)  # before the service and the marker go: no baseline stays open behind a cleared marker
    return {"result": result, "blocked": None}


def _remember_kept(layout, row_ids: list) -> None:
    """What the user kept runs on this computer from now on like the profile's own, and the next switch-on pins
    it: the launcher keeps a record so the status and the page can go on naming it (``handback.kept``). While
    the baseline is still open: the record is made from the rows as they are. Never holds the switch."""
    try:
        _bounded(handback.remember_kept, layout.home, layout.state_dir, row_ids)
    except Exception as exc:
        log.warning("hand-back: what was kept for profile %s could not be recorded: %s", layout.name, _why(exc))


def _close_quietly(layout) -> None:
    try:
        handback.close(layout.state_dir)
    except OSError as exc:  # kept open: the next switch-on keeps it too, and the next switch-off lists again
        log.warning("hand-back: the baseline of profile %s could not be closed: %s", layout.name, exc)
