"""Sandbox settings routes for a profile the host ``hermes serve`` runs unsandboxed.

Mounted at ``/api/plugins/openshell/`` by the host backend; each request is already scoped to the
``?profile=`` it names. A sandboxed profile never reaches these: its launcher answers the same paths
on the host before anything is forwarded, so the copy of this file inside a sandbox is unreachable.
Both read and write the same host-only spec (``<hermes root>/openshell/<profile>/spec.yaml``), so a
profile's folders and network are already set when its sandbox is turned on. ``switch/on`` turns it
on; turning it off happens on the launcher, which owns the sandbox by then.
``handback`` lists what the last sandbox session changed among the settings and files that run on this
computer when that session ended without a review; ``switch/on`` then needs the answer first
(``{"handback": "revert" | "keep"}``, launcher/switch.py ``previous_session``).
"""
from __future__ import annotations

import importlib
import os
import sys
import types
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse

_PKG = "hermes_openshell_settings"


def _plugin_module(name: str):
    """A module of this plugin's package, imported from beside this file (the dashboard loader
    imports this file on its own, outside the plugin package)."""
    if _PKG not in sys.modules:
        pkg = types.ModuleType(_PKG)
        pkg.__path__ = [str(Path(__file__).resolve().parent.parent)]
        pkg.__package__ = _PKG
        sys.modules[_PKG] = pkg
    return importlib.import_module(f"{_PKG}.{name}")


_layout = _plugin_module("launcher.layout")
_spec = _plugin_module("launcher.spec")
_view = _plugin_module("launcher.settings_view")
_switch = _plugin_module("launcher.switch")
_activity = _plugin_module("launcher.activity")
_handback = _plugin_module("launcher.handback")

router = APIRouter()


def _capabilities(spec: dict | None = None) -> dict:
    """What a sandbox for this profile would enforce on this host: the capabilities of the driver
    ``make_driver`` picks, OpenShell on every OS (on Windows the OpenShell Windows driver: MXC through
    the gateway)."""
    if os.name == "nt":
        return _plugin_module("launcher.openshell_windows").OpenShellWindowsDriver.capabilities()
    return _plugin_module("launcher.openshell_driver").OpenShellDriver.capabilities()


def _profile():
    try:
        return _layout.current_profile()
    except _layout.LayoutError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


def _config(layout) -> dict:
    spec = _spec.load_spec(layout)
    return _view.config_payload(layout, spec, _capabilities(spec), sandboxed=False, restart_required=False)


@router.get("/status")
def status() -> dict:
    layout = _profile()
    return _status(layout, _switch.switch_view(layout, sandboxed=False))


def _status(layout, switch: dict) -> dict:
    spec = _spec.load_spec(layout)
    caps = _capabilities(spec)
    return {
        "profile": layout.name, "sandboxed": False, "state": "off", "driver": caps["driver"],
        "capabilities": caps, "restart_required": False,
        "pending": {"folders": False, "network": False, "keys": False}, "error": None,
        "applied": None, "saved": _view.saved_policy(spec), "switch": switch,
        "handback": _handback_state(layout),
    }


def _handback_state(layout) -> dict:
    """Whether a baseline is still open for this profile (its sandbox ended without a switch-off), a token that
    changes when its list may have (the page then reads the list again), how many changes the user kept from a
    sandbox are still in the profile, and how many reverts keep the sandbox's versions in the launcher's state
    folder (handback.py). Never fails the status."""
    try:
        return {**_handback.status_view(layout.home, layout.state_dir), "held": len(_handback.held(layout.state_dir))}
    except Exception:
        return {"open": False, "stamp": "", "kept": 0, "held": 0}


@router.post("/switch/check")
def switch_check() -> dict:
    """Run the host compatibility check again now (the page's "Check again", and each time the page
    opens); answers the same status as ``/status`` with the fresh verdict in ``switch.host``."""
    layout = _profile()
    return _status(layout, _switch.switch_view(layout, sandboxed=False, refresh=True))


@router.get("/handback")
def handback(full: str = ""):
    """What the last sandbox session changed among the settings and files that run on this computer, when it
    ended without a review (its baseline is still open): the same list the launcher gives while a sandbox is
    on. ``open`` is False, with no rows, when there is nothing to review. ``kept``: what the user kept at an
    earlier hand-back and is still in the profile."""
    layout = _profile()
    view = _switch.review(layout, quick=full != "1")
    routes = _plugin_module("launcher.host_routes")
    return {**routes._text_rows_cut(view), "kept": routes._kept(layout)}


@router.post("/switch/on")
def switch_on(body: Any = Body(None)):
    """Turn this profile's sandbox on: start its launcher as a login service, wait until the sandbox
    runs, mark the profile as run elsewhere. Answers the launcher URL, its token and a one-time undo
    ticket; the page then asks the desktop to route the profile there (see launcher/switch.py).

    When the last sandbox session ended without a review, its changes need an answer first: without
    ``{"handback": "revert" | "keep"}`` nothing starts and nothing changes (409 ``handback_needs_answer``; the
    list is ``GET handback``). ``seen`` is ``{row id: state}`` of the rows the page showed, for a keep."""
    layout = _profile()
    data = body if isinstance(body, dict) else {}
    answer, seen = data.get("handback"), data.get("seen")
    if answer not in (None, "revert", "keep") or not (seen is None or isinstance(seen, dict)):
        raise HTTPException(status_code=422, detail='handback is "revert" or "keep".')
    try:
        return _switch.turn_on(layout, handback_answer=answer, handback_seen=seen)
    except _switch.HandbackNeeded as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc), "code": "handback_needs_answer",
                                                      "unanswered": int(exc.view.get("unanswered") or 0)})
    except _switch.SwitchError as exc:
        if getattr(exc, "code", None):
            # A refusal the page can act on: keys written in config.yaml (``keys``: where each is and the
            # variable it would move to, never its value), or a main model that cannot run in the sandbox.
            # ``detail`` begins with the sentence the page shows for the same thing (provider_rows.py).
            _view.forget_providers(layout)
            return JSONResponse(status_code=exc.status, content={
                "detail": str(exc), "code": exc.code,
                "keys": [{"path": key["path"], "env": key["env"]} for key in exc.keys]})
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


@router.get("/providers")
def providers() -> dict:
    """The profile's providers with the sandbox off, read now: ``providers`` (one row each, with what each will
    do in the sandbox) and ``providers_block`` (what keeps the switch from turning on, or null), as the config
    answer carries them for the page (launcher/settings_view.py). Nothing is renewed and nothing is written.
    While the sandbox is on, the launcher answers this path with its own rows."""
    layout = _profile()
    _view.forget_providers(layout)
    return _view.provider_view(layout)


@router.get("/config")
def config() -> dict:
    return _config(_profile())


@router.post("/providers/move")
def move_provider_keys(body: Any = Body(None)):
    """Move keys written in this profile's config.yaml to its ``.env`` (the Sandbox page's "Move to .env"):
    ``{"keys": [path, ...]}``, each the ``path`` of a provider row the config route listed. Answers what was
    moved and the provider rows read again, or a refusal in plain words with its own status
    (launcher/settings_view.py ``move_keys``). A profile whose sandbox is on is answered by its launcher, which
    refuses: the keys of such a profile are not this home's to edit."""
    code, payload = _view.move_keys(_profile(), body)
    return payload if code == 200 else JSONResponse(status_code=code, content=payload)


@router.put("/folders")
def put_folders(body: Any = Body(None)) -> dict:
    layout = _profile()
    _edit(layout, lambda: {"folders": _spec.folders_from_body(body, layout)})
    return _config(layout)


@router.post("/folders/check")
def check_folder(body: Any = Body(None)) -> dict:
    layout = _profile()
    try:
        return _spec.folder_from_entry(body, layout)
    except _layout.LayoutError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.post("/network/check")
def check_destination(body: Any = Body(None)) -> dict:
    caps = _capabilities(_spec.load_spec(_profile()))
    try:
        return _spec.allow_entry(body, host_loopback=caps["host_loopback"],
                                 rules=tuple(caps.get("network_rules", ("cidr",))))
    except _layout.LayoutError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.put("/network")
def put_network(body: Any = Body(None)) -> dict:
    layout = _profile()
    spec = _spec.load_spec(layout)
    caps = _capabilities(spec)
    approved = _spec.network_policy(spec).get("approved")
    _edit(layout, lambda: {"network": _spec.network_from_body(
        body, host_loopback=caps["host_loopback"], rules=tuple(caps.get("network_rules", ("cidr",))),
        allow_all=caps.get("egress_allow_all", True), approved=approved)})
    return _config(layout)


def _edit(layout, changes_for) -> None:
    try:
        _spec.update_spec(layout, **changes_for())
    except _layout.LayoutError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _saved_grants(layout) -> list[dict]:
    """What a card's Always allow saved: hosts (any program, http and https) and tool categories. They apply
    when the sandbox is on, so the page lists them while it is off. While the profile runs unsandboxed there
    are no Allow grants: they last until the sandbox is switched off."""
    return _view.saved_grants(layout)


@router.get("/grants")
def grants() -> dict:
    return {"grants": _saved_grants(_profile()), "network_apply": None, "restarting": None}


@router.delete("/grants")
def remove_grant(body: Any = Body(None)) -> dict:
    layout = _profile()
    cards = _plugin_module("launcher.cards")
    gid = body.get("id") if isinstance(body, dict) else None
    kind, scope, target = ((gid or "").split(":", 2) + ["", "", ""])[:3]
    if (kind, scope) != ("network", "always"):
        raise HTTPException(status_code=404, detail="No such grant.")
    net = _spec.network_policy(_spec.load_spec(layout))
    approved = dict(net.get("approved") or {})
    # A host's rule, or a tool category's (``tool:<id>``). Nothing runs: the saved policy changes and that is all.
    tool = target[len(cards.TOOL_TARGET_PREFIX):] if target.startswith(cards.TOOL_TARGET_PREFIX) else None
    names = [n for n, r in approved.items()
             if (tool is None and n.startswith(cards.HOST_RULE_PREFIX) and target in cards._rule_hosts(r))
             or (tool is not None and n == cards.TOOL_RULE_PREFIX + tool)]
    if not names:
        raise HTTPException(status_code=404, detail="No such grant.")
    for n in names:
        approved.pop(n)
    new = {**net, "approved": approved} if approved else {k: v for k, v in net.items() if k != "approved"}
    _edit(layout, lambda: {"network": new})
    _view.forget_providers(layout)  # a sign-in's row says where it is used: one address fewer now
    return grants()


def _activity_params(request: Request) -> dict:
    try:
        return _activity.parse_params(request.query_params.getlist)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.get("/activity")
def activity(request: Request) -> dict:
    """The Activity timeline from what the launcher kept on the host (its audit archive, card log and
    run record) and this profile's tool results, while the profile runs unsandboxed."""
    return {**_activity.query(_profile(), **_activity_params(request)), "collector": None}


@router.get("/activity/export")
def activity_export(request: Request) -> dict:
    return _activity.export(_profile(), **_activity_params(request))


@router.get("/keys")
async def keys() -> dict:
    from hermes_cli.web_routers import config_env

    return {"keys": _view.key_rows(await config_env.get_env_vars(None)), "credentials": "host"}


@router.put("/keys")
async def put_key(body: Any = Body(None)) -> dict:
    from hermes_cli.web_models import EnvVarUpdate
    from hermes_cli.web_routers import config_env

    await config_env.set_env_var(_model(EnvVarUpdate, body), None)
    return {"ok": True}


@router.delete("/keys")
async def delete_key(body: Any = Body(None)) -> dict:
    from hermes_cli.web_models import EnvVarDelete
    from hermes_cli.web_routers import config_env

    await config_env.remove_env_var(_model(EnvVarDelete, body), None)
    return {"ok": True}


def _model(model_cls, body):
    from pydantic import ValidationError

    try:
        model = model_cls(**(body if isinstance(body, dict) else {}))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if getattr(model, "profile", None):
        raise HTTPException(status_code=422, detail="Name the profile with ?profile=, not in the body.")
    return model
