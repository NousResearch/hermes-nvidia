"""What the sandbox settings page shows, built from host-only state.

Shared by the launcher's host routes (a sandboxed profile) and the dashboard router the host
``hermes serve`` mounts (a profile that runs unsandboxed), so both answer the page in one shape.
Key values never leave this module: key rows carry a name and whether it is set.

Providers. The page lists the profile's providers, one row each, with what each does in the sandbox:
``{"id", "label", "kind": "key" | "sign_in", "state", "detail"}``. While the sandbox is on the rows are the
launcher's (its status, passed through ``page_rows``). For a profile that is off they are built here from the
profile's own home (``host_rows``; ``provider_view`` keeps them for the page's poll): the sign-in report, the key
discovery of the sandbox driver and the keys written in ``config.yaml``, together with what keeps the switch from
turning on (``providers_block``). The switch and the terminal commands read the same rows (provider_rows.py), and
every sentence a row carries, on either side of the switch, is one of this module's.
``move_keys`` moves such keys to ``.env``. A row never carries a key, a token or a grant.

A file that cannot be read is not an empty file. The rows are read from the profile's ``config.yaml``, its env
files and its sign-in files; while one of them is there and cannot be read (another program holds it open, or the
config is not valid YAML), ``host_rows`` raises ``Unreadable``. The page then keeps the rows it last read and
holds the switch with that reason, the switch refuses with the same sentence, and a move changes nothing.
"""
from __future__ import annotations

import importlib
import ipaddress
import logging
import re
import socket
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Callable, Iterable, Optional

from . import usage_data
from .layout import ProfileLayout
from .spec import network_policy

log = logging.getLogger("openshell.settings_view")

Resolver = Callable[[str], list]
_RESOLVE_TTL = 60.0
_resolved: dict[str, tuple[float, list]] = {}


def saved_policy(spec: dict) -> dict:
    return {"folders": [{"path": str(f["path"]), "access": str(f.get("access", "rw")).lower()}
                        for f in spec.get("folders") or []],
            "network": network_policy(spec)}


def config_payload(layout: ProfileLayout, spec: dict, capabilities: dict, *, sandboxed: bool,
                   restart_required: bool, resolve: Optional[Resolver] = None, opened=()) -> dict:
    """*opened*: every address a sign-in or a key keeps open in the sandbox that runs (the launcher's
    ``Supervisor.opened_hosts``); the page lists and counts them with the destinations the launcher keeps open by
    itself (``builtin``)."""
    policy = saved_policy(spec)
    payload = {
        "profile": layout.name,
        "sandboxed": sandboxed,
        "profile_folder": str(layout.home),
        "folders": [{**f, "missing": not Path(f["path"]).is_dir()} for f in policy["folders"]],
        "network": policy["network"],
        # Destinations the launcher keeps open by itself, each with its reason: never part of "network", so the
        # page's edits neither send nor remove them.
        "builtin": usage_data.destinations(layout.home),
        "opened": [dict(row) for row in opened if isinstance(row, dict)],
        "endpoints": model_endpoints(layout, policy["network"], capabilities, resolve or cached_resolve),
        "capabilities": capabilities,
        "restart_required": restart_required,
    }
    if not sandboxed:
        # Before the switch: the profile's providers and what keeps the switch from turning on, read from the
        # profile's own home. While the sandbox is on the launcher's status carries the rows instead.
        payload.update(provider_view(layout))
    return payload


def key_rows(env_rows: dict) -> list[dict]:
    """``/api/env`` rows -> the keys stored for the profile, by name only."""
    return [{"name": name, "is_set": True}
            for name, row in sorted(env_rows.items()) if isinstance(row, dict) and row.get("is_set")]


# -- model provider endpoints ---------------------------------------------------------------------

def model_endpoints(layout: ProfileLayout, network: dict, capabilities: dict, resolve: Resolver) -> list[dict]:
    out = []
    for label, entry in _model_entries(_read_config(layout)):
        url = str(entry.get("base_url") or "").strip() or _provider_default_url(str(entry.get("provider") or ""))
        if not url:
            continue
        reach, via = endpoint_reach(url, network, capabilities, resolve)
        row = {"label": label, "provider": str(entry.get("provider") or ""), "url": url, "reach": reach, "via": via}
        if row not in out:
            out.append(row)
    return out


def endpoint_reach(url: str, network: dict, capabilities: dict, resolve: Resolver) -> tuple[str, Optional[str]]:
    """Whether the sandbox can open *url* under *network*: ``("allowed", how)`` or ``("blocked", None)``."""
    if capabilities.get("model_endpoints") == "provider":
        # The driver binds each configured model's key and endpoint as a provider at start.
        return "allowed", "provider"
    if network["egress"] == "allow":
        return "allowed", "internet"
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return "blocked", None
    for rule in network["allow"]:
        if rule.get("host") and rule["port"] == port and _host_matches(rule["host"], host):
            return "allowed", "rule"
    addresses = _addresses(host, resolve)
    for rule in network["allow"]:
        if not rule.get("cidr"):
            continue
        block = ipaddress.ip_network(rule["cidr"], strict=False)
        if rule["port"] == port and any(a in block for a in addresses):
            return "allowed", "rule"
    if capabilities.get("host_loopback") == "open" and any(a.is_loopback for a in addresses):
        return "allowed", "loopback"
    return "blocked", None


def _host_matches(pattern: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    if pattern.startswith("**."):
        return host.endswith(pattern[2:])
    if pattern.startswith("*."):
        head, _, tail = host.partition(".")
        return bool(head) and tail == pattern[2:]
    return host == pattern


def cached_resolve(host: str) -> list:
    now = time.monotonic()
    hit = _resolved.get(host)
    if hit and now - hit[0] < _RESOLVE_TTL:
        return hit[1]
    try:
        found = sorted({info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except OSError:
        found = []
    _resolved[host] = (now, found)
    return found


def _addresses(host: str, resolve: Resolver) -> list:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    out = []
    for raw in resolve(host) if host else []:
        try:
            out.append(ipaddress.ip_address(str(raw).split("%", 1)[0]))
        except ValueError:
            continue
    return out


class Unreadable(Exception):
    """A file the provider rows are read from is there and cannot be read. ``name`` is the file's name in the
    profile, ``why`` is ``open`` (it cannot be opened or read) or ``broken`` (it is not valid YAML). The message
    is the sentence for the page and the terminal; ``short`` is the same for the end of another sentence."""

    def __init__(self, name: str, why: str = "open"):
        self.name, self.why = name, why if why in _UNREADABLE else "open"
        self.short = _UNREADABLE_SHORT[self.why].format(name=name)
        super().__init__(_UNREADABLE[self.why].format(name=name))


_UNREADABLE = {"open": "Can't read this profile's {name}. Another program may have it open.",
               "broken": "Can't read this profile's {name}. It isn't valid YAML."}
_UNREADABLE_SHORT = {"open": "{name} can't be read. Another program may have it open.",
                     "broken": "{name} isn't valid YAML."}
_READ_TRIES = 2  # a file another program is just replacing is read at the second look
_READ_PAUSE = 0.1


def read_config(layout: ProfileLayout) -> dict:
    """The profile's own config.yaml, read through Hermes's config backend; {} when there is none. Raises
    ``Unreadable`` when the file is there and cannot be read: that is never the same as an empty config."""
    from hermes_cli.config_backend import config_exists, read_config_doc

    path = layout.home / "config.yaml"
    for attempt in range(_READ_TRIES):
        try:
            data = read_config_doc(path) if config_exists(path) else {}
        except OSError:
            if attempt + 1 < _READ_TRIES:
                time.sleep(_READ_PAUSE)
                continue
            raise Unreadable("config.yaml", "open") from None
        except Exception:  # Hermes's YAML reader refused the text
            raise Unreadable("config.yaml", "broken") from None
        return data if isinstance(data, dict) else {}
    return {}


def _read_config(layout: ProfileLayout) -> dict:
    """The config for what is only shown beside other things (the model endpoints of the Network list): {}
    while it cannot be read. What decides something reads it with ``read_config``."""
    try:
        return read_config(layout)
    except Unreadable:
        return {}


def must_read(layout: ProfileLayout) -> None:
    """Raise ``Unreadable`` for the first env file or sign-in file of the profile that is there and cannot be
    read. A file that is absent is fine: the profile has no such file."""
    from . import held, pins

    for name in (*pins.ENV_FILES, *pins.STORE_FILES):
        path = held.source(layout.home / name)
        for attempt in range(_READ_TRIES):
            try:
                with open(path, "rb") as fh:
                    fh.read(1)
            except FileNotFoundError:
                break
            except OSError:
                if attempt + 1 < _READ_TRIES:
                    time.sleep(_READ_PAUSE)
                    continue
                raise Unreadable(name, "open") from None
            break


def _model_entries(config: dict) -> Iterable[tuple[str, dict]]:
    """Every model route a turn can take, as the config names it: ``(label, entry)`` for the model, the fallback
    models (``fallback_providers``, then ``fallback_model``), each auxiliary task that names a provider or an
    address, and the saved endpoints."""
    model = config.get("model")
    if isinstance(model, dict):
        yield "Model", model
    for key in ("fallback_providers", "fallback_model"):
        fallback = config.get(key)
        for entry in fallback if isinstance(fallback, list) else [fallback]:
            if isinstance(entry, dict):
                yield "Fallback model", entry
    auxiliary = config.get("auxiliary")
    for task, entry in auxiliary.items() if isinstance(auxiliary, dict) else ():
        if isinstance(entry, dict) and (entry.get("provider") or entry.get("base_url")):
            yield f"Auxiliary model ({task})", entry
    for entry in _saved_endpoints(config):
        yield f"Saved endpoint {entry['name']}", entry


def _saved_endpoints(config: dict) -> list[dict]:
    """The endpoints saved under ``providers`` / ``custom_providers``, as Hermes itself reads them, each reduced
    to what decides a key's route: its name, address, key variable and request shape."""
    try:
        from hermes_cli.config_providers import get_compatible_custom_providers

        rows = get_compatible_custom_providers(config)
    except Exception:  # a Hermes without this reader, or a config it cannot read: no saved endpoints
        return []
    out = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("name") and row.get("base_url"):
            out.append({"provider": "custom", "name": str(row["name"]), "base_url": str(row["base_url"]),
                        "key_env": str(row.get("key_env") or ""), "api_mode": str(row.get("api_mode") or "")})
    return out


def _provider_default_url(provider: str) -> str:
    if not provider:
        return ""
    try:
        from hermes_cli.auth import PROVIDER_REGISTRY
    except ImportError:
        return ""
    config = PROVIDER_REGISTRY.get(provider)
    if config is not None and config.inference_base_url:
        return config.inference_base_url
    if provider == "openrouter":
        try:
            from hermes_constants import OPENROUTER_BASE_URL
        except ImportError:
            return ""
        return OPENROUTER_BASE_URL
    return ""


# -- providers: what each one does in the sandbox -------------------------------------------------

# The states of a row. The launcher's status uses the first six while the sandbox is on; ``no_key`` is said
# only here, before the switch, for a provider a model names whose key is not in the profile's ``.env``.
READY = "ready"
NEEDS_SIGN_IN = "needs_sign_in"
EXPIRED = "expired"
UNAVAILABLE = "unavailable"
WITHHELD = "withheld"
KEY_IN_CONFIG = "key_in_config"
NO_KEY = "no_key"

# The sentence of a row, by reason: what the page shows, in one wording on both sides of the switch. The
# reasons of a sign-in are the sign-in report's own (signins.py).
_SENTENCES = {
    "key": "Works in the sandbox. The key stays on this computer and is used only at {where}.",
    "key_plain": "Works in the sandbox. The key stays on this computer.",
    "signed_in": "Works in the sandbox. Stays signed in on this computer.",
    "signed_in_shared": ("Works in the sandbox with the default profile's sign-in. Stays signed in on this "
                         "computer."),
    "signed_in_at": "Works in the sandbox. Stays signed in on this computer and is used only at {where}.",
    "signed_in_shared_at": ("Works in the sandbox with the default profile's sign-in. Stays signed in on this "
                            "computer and is used only at {where}."),
    "key_on_approval": "Used in the sandbox once {uses} is allowed in a chat. The key stays on this computer.",
    "not_signed_in": "Not signed in. Sign in to {label} first.",
    "expired": "Sign-in expired. Sign in to {label} again first.",
    "shared_not_carried": "Signed in for the default profile only. Sign in to {label} for this profile first.",
    "own_program": "Not available in the sandbox: {label} signs in through its own program.",
    "outside_profile": "Not available in the sandbox: {label} keeps its sign-in outside this profile.",
    "claude_code": "Not available in the sandbox: {label} is signed in through Claude Code, outside this profile.",
    "cloud_sdk": "Not available in the sandbox: {label} signs in through a cloud SDK on this computer.",
    "not_carried": "Not available in the sandbox yet: the {label} sign-in stays on this computer.",
    "unknown": "Not available in the sandbox: Hermes doesn't know the provider \"{label}\".",
    "unavailable": "Not available in the sandbox.",
    "key_in_config": "Written in config.yaml, where the sandbox could read it.",
    "no_key": "No key found: {env} is not set in this profile's .env.",
    "no_key_main": ("No key found: {env} is not set in this profile's .env. The model won't answer in the sandbox "
                    "without it."),
    "withheld": "Model endpoint changed in the sandbox. Key withheld.",
    "retrying": "Couldn't reach {label} to renew the sign-in. Trying again.",
    "lapsed": "The {label} sign-in wasn't renewed in time. The model answers again once it is.",
}
# What differs while the sandbox is on: signing in, and moving a key, need the sandbox off.
_SENTENCES_ON = {
    "not_signed_in": "Not signed in. Turn the sandbox off, sign in to {label}, then turn it on.",
    "expired": "Sign-in expired. Turn the sandbox off, sign in to {label}, then turn it on.",
    "shared_not_carried": ("Signed in for the default profile only. Turn the sandbox off, sign in to {label} for "
                           "this profile, then turn it on."),
    "key_in_config": ("Written in config.yaml, where the sandbox can read it. Turn the sandbox off, then move it to "
                      ".env."),
}
_WHY_UNAVAILABLE = ("own_program", "outside_profile", "claude_code", "cloud_sdk", "not_carried", "unknown")
# Why the switch does not turn on (``providers_block``): the switch's tip and the bar above the tabs.
_BLOCKS = {
    "key_in_config": "A key is written in config.yaml, where the sandbox could read it. Move it to .env first.",
    "keys_in_config": "Keys are written in config.yaml, where the sandbox could read them. Move them to .env first.",
    "model_unavailable": "This profile's model uses {label}, which isn't available in the sandbox.",
    "model_needs_sign_in": "This profile's model uses {label}, which needs a sign-in first.",
}
# What to know before the switch is turned on, when nothing holds it (``providers_note``): the desktop's confirm
# and the terminal say it in this one line.
_NOTES = {
    "model_no_key": "This profile's model has no key in .env ({env}). It won't answer in the sandbox until one is set.",
}
MOVE_UNAVAILABLE = "This version can't move keys. Take the key out of config.yaml and save it in .env yourself."
MOVE_WHILE_ON = "Turn the sandbox off for this profile first."
_INLINE_LABEL = "Key in config.yaml"
_OWN_ENDPOINT = "Custom endpoint"  # a key on an address the user configured: its badge says which model uses it
_ROUTE_USES = (("Model", "model"), ("Fallback model", "fallback"), ("Auxiliary model", "auxiliary"))
_LEAD = re.compile(r"Not available in the sandbox(?: yet)?(?:: (.+)|\.)")
_THIS_COMPUTER = ("127.0.0.1", "localhost", "::1", "host.openshell.internal")
_STATE_RE = re.compile(r"[a-z][a-z_]{0,31}")
_PROVIDERS_TTL = 10.0  # seconds a profile's rows are reused while its files have not changed
_WATCHED = ("config.yaml", ".env", "auth.json", ".anthropic_oauth.json")
_provider_views: dict[str, tuple] = {}
_last_views: dict[str, dict] = {}  # per profile home: the last view that was read whole
_last_inline: dict[str, list] = {}  # per profile home: the keys last found written in its config.yaml
_unread_said: dict[str, str] = {}  # per profile home: the file that cannot be read, as it was last logged
_views_lock = threading.Lock()


def provider_view(layout: ProfileLayout) -> dict:
    """``{"providers": rows, "providers_block": block}`` for a profile that runs on this computer: what each of
    its providers will do once the sandbox is on, and what keeps the switch from turning on now (None when
    nothing does). With nothing holding it, ``providers_note`` is what to know before turning it on (a model
    without a key); the field is absent when there is nothing to say. Read from the profile's own home each time
    one of its files changed, and again after a few seconds for what lives outside it (a sign-in shared with the
    default profile). Never fails the page.

    While a file the rows are read from cannot be read, the rows are the ones last read (none when nothing was
    read yet) and the block is that file's (``unreadable``): a key in a config that cannot be read cannot be
    ruled out. Any other failure keeps the last view as it was, block included."""
    key = str(layout.home)
    stamp, now = _stamp(layout), time.monotonic()
    hit = _provider_views.get(key)
    if hit is not None and hit[0] == stamp and now - hit[1] < _PROVIDERS_TTL:
        return hit[2]
    try:
        rows = _host_rows(layout)
    except Unreadable as exc:
        # Not kept: the file's times do not say when it comes free, so the next look reads again.
        if _unread_said.get(key) != str(exc):  # the page looks every few seconds: said once per file
            _unread_said[key] = str(exc)
            log.warning("the providers of profile %s were not read: %s", layout.name, exc)
        last = _last_views.get(key) or {}
        return {"providers": list(last.get("providers") or []), "providers_block": unreadable_block(exc)}
    except Exception as exc:  # a Hermes this plugin cannot ask
        log.warning("the providers of profile %s could not be listed: %s", layout.name, _plain(exc))
        view = dict(_last_views.get(key) or {"providers": [], "providers_block": None})
        _provider_views[key] = (stamp, now, view)  # asked again when a file changes, or in a few seconds
        return view
    block = switch_block(rows)
    note = None if block else switch_note(rows)
    view = {"providers": rows, "providers_block": block, **({"providers_note": note} if note else {})}
    with _views_lock:
        _provider_views[key] = (stamp, now, view)
        _last_views[key] = view
        _unread_said.pop(key, None)
    return view


def forget_providers(layout: Optional[ProfileLayout] = None) -> None:
    """Drop the answer kept for *layout*: the next ``provider_view`` reads again. What was last read stays, for
    the time a file cannot be read. Without a layout everything kept for every profile is dropped."""
    with _views_lock:
        if layout is None:
            _provider_views.clear()
            _last_views.clear()
            _last_inline.clear()
            _unread_said.clear()
        else:
            _provider_views.pop(str(layout.home), None)


def unreadable_block(exc: Unreadable) -> dict:
    """What keeps the switch from turning on while a file cannot be read: ``{"code", "file", "reason", "rows"}``."""
    return {"code": "unreadable", "file": exc.name, "reason": str(exc), "rows": []}


def switch_block(rows: list) -> Optional[dict]:
    """What keeps the switch from turning on, from the rows: a key written in config.yaml, or the main model on
    a provider that is not available in the sandbox or needs a sign-in first. ``{"code", "reason", "rows"}``
    with the ids of the rows it is about; None when the switch may turn on. For a provider that is not available
    ``detail`` is why, as its own sentence (the row's, without the words the reason already says)."""
    inline = [row for row in rows if row.get("state") == KEY_IN_CONFIG]
    if inline:
        return {"code": "key_in_config", "reason": _BLOCKS["key_in_config" if len(inline) == 1 else "keys_in_config"],
                "rows": [row["id"] for row in inline]}
    for row in rows:
        if (row.get("main") or _main(row)) and row.get("state") in (UNAVAILABLE, NEEDS_SIGN_IN):
            code = "model_unavailable" if row["state"] == UNAVAILABLE else "model_needs_sign_in"
            block = {"code": code, "reason": _BLOCKS[code].format(label=row["label"]), "rows": [row["id"]]}
            return {**block, "detail": _why_only(row.get("detail"))} if code == "model_unavailable" else block
    return None


def switch_note(rows: list) -> Optional[dict]:
    """What to know before the switch is turned on, when nothing holds it: the profile's model has no key. The
    switch is not what breaks such a model, so it is not held; the first message would fail, so it is said.
    ``{"code", "reason", "rows"}`` or None."""
    for row in rows:
        if (row.get("main") or _main(row)) and row.get("state") == NO_KEY and row.get("env"):
            return {"code": "model_no_key", "reason": _NOTES["model_no_key"].format(env=row["env"]), "rows": [row["id"]]}
    return None


def _why_only(detail) -> str:
    """A row's "Not available in the sandbox: <why>." as "<Why>." alone; a sentence of another shape as it is."""
    text = _text(detail, 400)
    said = _LEAD.fullmatch(text)
    if said is None:
        return text
    why = said.group(1) or ""
    return why[:1].upper() + why[1:]


def page_rows(rows, *, endpoint_changed=()) -> list[dict]:
    """The launcher's provider rows as the page gets them while the sandbox is on. Only the fields the page
    reads are kept, so nothing else a row carries reaches the page. The sentence is this module's wherever the
    row says enough: its ``state`` and ``kind`` and, when present, its ``reason`` (the sign-in report's), ``hosts``
    and ``path``. A sign-in row without a ``reason`` is recognised by the sign-in engine's own sentence in its
    ``detail``. A row's own ``detail`` is shown as it is where nothing says more: a provider that is not
    available for a reason this module does not know, a sign-in whose detail it does not recognise, a state it
    does not know. ``main`` is the row's own, or ``used_by`` naming the model. A key withheld because its endpoint
    changed inside (*endpoint_changed*, the status's list) gets a row when the launcher sent none."""
    out = []
    for position, item in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(item, dict):
            continue
        state = str(item.get("state") or "").lower()
        if not _STATE_RE.fullmatch(state):
            continue
        kind = "key" if item.get("kind") == "key" else "sign_in"
        label = _text(item.get("label") or item.get("id"), 80)
        hosts = item.get("hosts")
        where = _join([_host_item(host) for host in hosts]) if isinstance(hosts, list) else ""
        path, env = _text(item.get("path"), 160), _text(item.get("env"), 80)
        if state == KEY_IN_CONFIG and not path and str(item.get("id") or "").startswith("config:"):
            path = _text(str(item["id"])[len("config:"):], 160)
        if state == KEY_IN_CONFIG and path and label in ("", path):
            label = _INLINE_LABEL
        own = _text(item.get("detail"), 400)
        given = str(item.get("reason") or "") or (_reason_in(own, label) if kind == "sign_in" else "")
        reason = _reason_while_on(state, kind, given, bool(where))
        if kind == "sign_in" and own and not given and state in (READY, NEEDS_SIGN_IN, EXPIRED):
            reason = ""  # words this module does not recognise say more than the state's sentence would
        if kind == "sign_in" and where and reason in ("signed_in", "signed_in_shared"):
            reason += "_at"  # the row says every address the sign-in is used at, as a key's row does
        detail = _sentence(reason, on=True, label=label, where=where, env=env, uses=_uses_text(item.get("uses"))) or own
        if not detail and state == UNAVAILABLE:
            detail = _SENTENCES["unavailable"]
        out.append(_row(item.get("id") or f"row:{position}", label, kind, state, detail,
                        main=item.get("main") is True or _main(item),
                        fallback=item.get("fallback") is True or _fallback(item), env=env, path=path))
    if not any(row["state"] == WITHHELD for row in out):
        for item in endpoint_changed if isinstance(endpoint_changed, (list, tuple)) else ():
            if isinstance(item, dict) and item.get("env"):
                env = _text(item["env"], 80)
                out.append(_row(f"withheld:{env}:{item.get('host')}:{item.get('port')}", env, "key", WITHHELD,
                                _sentence("withheld", on=True), env=env))
    return _ordered(out)


def status_providers(status) -> dict:
    """The provider rows of a launcher status, as the page gets them: ``{"providers": rows}``, or {} for a
    launcher whose status carries none (the page then lists no providers while the sandbox is on)."""
    if not isinstance(status, dict) or not isinstance(status.get("providers"), list):
        return {}
    return {"providers": page_rows(status["providers"], endpoint_changed=status.get("endpoint_changed") or ())}


def move_keys(layout: ProfileLayout, body) -> tuple[int, dict]:
    """Move keys written in the profile's config.yaml to its ``.env``: ``{"keys": [path, ...]}``, each one a
    ``path`` of a ``key_in_config`` row. Answers ``(200, {"moved": [{"path", "env"}], "left": [path],
    "providers": rows, "providers_block": block})`` with the rows read again, or a refusal in plain words.
    Which variable a key moves to is never the caller's choice. Only for a profile that runs on this computer:
    while its sandbox is on, the home's files are not the ones to edit."""
    from . import pins

    wanted = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(wanted, list) or not wanted or not all(isinstance(path, str) and path for path in wanted):
        return 422, {"detail": 'Expected {"keys": [the path of each key to move]}.'}
    keys = _config_keys()
    if keys is None:
        return 409, {"detail": MOVE_UNAVAILABLE}
    if pins.present(layout):
        return 409, {"detail": MOVE_WHILE_ON}
    try:
        # Both files are looked at before anything is written: a move changes nothing while one cannot be read.
        listed = {item["path"]: item for item in _inline_keys(read_config(layout))}
        must_read(layout)
    except Unreadable as exc:
        forget_providers(layout)
        asked = _join([_text(path, 160) for path in dict.fromkeys(wanted)])
        return 409, {"detail": f"Couldn't move {asked} to .env: {exc.short}", **provider_view(layout)}
    gone = [path for path in dict.fromkeys(wanted) if path not in listed]
    if gone:
        forget_providers(layout)
        return 409, {"detail": f"config.yaml no longer has a key at {_join(gone)}.", **provider_view(layout)}
    items = [listed[path] for path in dict.fromkeys(wanted)]
    names = _join([item["path"] for item in items])
    try:
        moved = set(keys.move_to_env(layout.home, [dict(item) for item in items]) or ())
    except Exception as exc:
        log.warning("keys of profile %s could not be moved to .env: %s", layout.name, _plain(exc))
        forget_providers(layout)
        # The move's own refusals are sentences. The system's are said in the system's few words, without the
        # path and the number that come with them.
        said = (exc.strerror or type(exc).__name__) if isinstance(exc, OSError) else _plain(exc)
        return 500, {"detail": f"Couldn't move {names} to .env: {said}", **provider_view(layout)}
    forget_providers(layout)
    done = [item for item in items if item["path"] in moved]
    if not done:
        return 500, {"detail": f"Couldn't move {names} to .env. config.yaml is unchanged.", **provider_view(layout)}
    return 200, {"moved": done, "left": [item["path"] for item in items if item["path"] not in moved],
                 **provider_view(layout)}


def host_rows(layout: ProfileLayout) -> list[dict]:
    """The rows of a profile that is off, read now from its own home. The one source of these rows: the page
    (through ``provider_view``), the switch and the terminal commands (provider_rows.py) all read them here.
    Nothing is renewed and nothing is written to the home."""
    return _host_rows(layout)


def _host_rows(layout: ProfileLayout) -> list[dict]:
    """Keys written in config.yaml, the sign-in report's providers, and one row per key the sandbox driver
    would hand in. Raises ``Unreadable`` when one of the files they are read from cannot be read."""
    from . import pins

    _sweep(layout)
    _tool_uses.pop(str(layout.home), None)
    config = read_config(layout)
    rows = [_row(f"config:{item['path']}", _INLINE_LABEL, "key", KEY_IN_CONFIG, _sentence("key_in_config"),
                 env=item["env"], path=item["path"]) for item in _inline_keys(config)]
    if pins.present(layout):
        # A sandbox session holds this home (or ended without a switch-off): its keys and sign-ins are the
        # launcher's copy, and the files here may be the sandbox's.
        return rows
    must_read(layout)
    key_rows, routed = _key_rows(layout, config)
    waiting = {row["env"] for row in rows}  # where the keys written in the config will be once they are moved
    reported = _reported(layout)
    _tool_uses[str(layout.home)] = _uses_by_tool(reported)
    for item in reported:
        if item.get("state") != "key":
            row = _sign_in_row(item)
        elif (_main(item) or _fallback(item)) and routed & set(_registered_envs(str(item.get("provider") or ""))):
            # A model's provider uses a key that is handed in: that key's row is the model's or the fallback
            # model's (the first of the provider's variables that is set, as Hermes itself takes it).
            env = next(env for env in _registered_envs(str(item["provider"])) if env in routed)
            for key_row in key_rows:
                if key_row.get("env") == env:
                    key_row["main"] = key_row["main"] or _main(item)
                    if _fallback(item):
                        key_row["fallback"] = True
            continue
        else:
            # A key that is in the config and moves to the provider's own variable is not a missing key.
            row = _missing_key(item, config, routed | waiting)
        if row is not None:
            rows.append(row)
    return _ordered([*rows, *key_rows])


_CHECK_PREFIX = "provider-check-"
_CHECK_STALE = 600.0  # seconds after which a copy a killed process left is swept


def _reported(layout: ProfileLayout) -> list[dict]:
    """The sign-in report of the profile (signins.py), [] when this Hermes cannot be asked.

    Asked over a throwaway copy of the profile's sign-in files and env file in the launcher's own folder, the
    way the launcher asks while the sandbox is on, and never over the home itself: Hermes makes its usual
    folders in whatever folder it is asked about, and the home's own config is not what decides here. The copy
    is owner-only, is one call's own, and is deleted before this returns."""
    import shutil
    import tempfile

    from . import pins

    try:
        signins = importlib.import_module(f"{__package__}.signins")
        layout.state_dir.mkdir(parents=True, exist_ok=True)
        for left in layout.state_dir.glob(_CHECK_PREFIX + "*"):  # what a process that was killed left behind
            try:
                if time.time() - left.stat().st_mtime > _CHECK_STALE:
                    shutil.rmtree(left, ignore_errors=True)
            except OSError:
                continue
        copy = Path(tempfile.mkdtemp(prefix=_CHECK_PREFIX, dir=layout.state_dir))
        try:
            pins._owner_only(copy, 0o700)
            for name in (*pins.ENV_FILES, *pins.STORE_FILES):
                pins._copy_in(layout.home / name, copy / name)
            signins.write_copy_config(layout.home, copy)
            tools = saved_tools(layout)
            report = signins.report(copy, tools) if tools else signins.report(copy)
            return [item for item in report if isinstance(item, dict)]
        finally:
            shutil.rmtree(copy, ignore_errors=True)
    except Exception as exc:
        log.warning("the sign-ins of profile %s could not be read: %s", layout.name, _plain(exc))
        return []


def _sign_in_row(item: dict) -> Optional[dict]:
    state = {"works": READY, "needs_sign_in": NEEDS_SIGN_IN, "not_available": UNAVAILABLE}.get(item.get("state"))
    if state is None:
        return None
    label = str(item.get("label") or item.get("provider") or "")
    fallback = {READY: "signed_in", NEEDS_SIGN_IN: "not_signed_in", UNAVAILABLE: "unavailable"}[state]
    reason = str(item.get("reason") or "")
    hosts = item.get("hosts")
    where = _join([_host_item(host) for host in hosts]) if isinstance(hosts, list) else ""
    if state == READY and where and reason in ("signed_in", "signed_in_shared"):
        reason += "_at"
    detail = _sentence(reason, label=label, where=where) or _sentence(fallback, label=label)
    return _row(f"sign_in:{item.get('provider')}", label, "sign_in", state, detail, main=_main(item),
                fallback=_fallback(item))


def _key_rows(layout: ProfileLayout, config: dict) -> tuple[list[dict], set]:
    """One row per key the sandbox driver would hand in if the sandbox were switched on now, with the addresses
    it could be used at, and the variables those keys are in. Asked of the driver's own discovery with the
    model entries as the switch would pin them; a key's value is never read into a row."""
    from . import pins
    from .openshell_driver import discover_routes

    secrets = pins.secrets(layout)
    found = discover_routes(layout.home, secrets, {"models": pins.model_entries(config), "allowed": [],
                                                   "tools": sorted(saved_tools(layout))})
    return key_rows_of(found.routes, secrets, on_approval=found.on_approval)


_tool_uses: dict[str, dict] = {}  # profile home -> {category id: [address]}, as the last provider read found it


def _uses_by_tool(reported) -> dict:
    """Of a sign-in report: the addresses a sign-in would be used at for each approved tool category."""
    from . import categories

    out: dict = {}
    for item in reported or ():
        for host in (item.get("hosts") or ()) if isinstance(item, dict) else ():
            if isinstance(host, dict) and categories.by_id(host.get("use")) is not None:
                text = categories.host_text(host.get("host"), host.get("port"))
                if text not in out.setdefault(host["use"], []):
                    out[host["use"]].append(text)
    return out


def tool_uses(layout: ProfileLayout) -> dict:
    """For each tool category saved for the profile, the addresses a sign-in of the profile is used at for it
    once the sandbox is on. Taken from the provider rows the page reads anyway (``provider_view``, which reads
    again when a file of the profile changed): Hermes is not asked a second time."""
    provider_view(layout)
    return {cid: list(hosts) for cid, hosts in (_tool_uses.get(str(layout.home)) or {}).items()}


def saved_grants(layout: ProfileLayout) -> list[dict]:
    """What "Allowed from chat" lists for a profile whose sandbox is off: what was saved with a card's Always
    allow, since that applies when the sandbox is on. A host (any program, http and https) and a tool category
    (its services, with the address a sign-in is used at for it first). Allow grants are not here: they end
    when the sandbox is switched off."""
    from . import cards
    from .spec import load_spec

    rows: list[dict] = []
    uses: Optional[dict] = None
    for name, rule in (network_policy(load_spec(layout)).get("approved") or {}).items():
        if name.startswith(cards.TOOL_RULE_PREFIX):
            if uses is None:
                uses = tool_uses(layout)
            rows.append(cards.saved_tool_row(name, rule, uses.get(name[len(cards.TOOL_RULE_PREFIX):]) or ()))
        elif name.startswith(cards.HOST_RULE_PREFIX):
            for host, ports in cards._rule_hosts(rule).items():
                rows.append({"id": f"network:always:{host}", "kind": "network", "target": host,
                             "label": None, "ports": sorted(p for p in ports if p), "scope": "always",
                             "status": "active", "rule_name": name})
    return rows


def saved_tools(layout: ProfileLayout) -> set:
    """The ids of the tool categories whose approval is saved for the profile (categories.py): what the next
    switch-on binds a sign-in or a web service's key for."""
    from . import categories
    from .spec import load_spec

    try:
        return categories.granted(network_policy(load_spec(layout)).get("approved"))
    except Exception as exc:
        log.warning("the saved approvals of profile %s could not be read: %s", layout.name, _plain(exc))
        return set()


def _uses_text(uses) -> str:
    """Tool categories as a row names them: "Web search or Web extract"."""
    return " or ".join(_text(use, 40) for use in uses if use) if isinstance(uses, (list, tuple)) else ""


def key_rows_of(routes: list, secrets: dict, *, facts: bool = False, on_approval=()) -> tuple[list[dict], set]:
    """The key rows for *routes* (the driver's discovery) and the variables they are in: one row per variable,
    named after its provider, with every address it is bound to. A key on an address of the user's own that no
    provider names is a "Custom endpoint"; a saved endpoint keeps its name. *facts*: each row also carries
    ``hosts`` (``[{"host", "port"}]``) and ``used_by`` (the model routes configured with it), for a launcher's
    status. *on_approval*: keys of web services that are bound once a tool category is approved (the
    discovery's list); each gets a row that says so, and its variable is not among the ones returned."""
    from . import categories
    from .openshell_driver import registered_keys

    registered = {env: label for label, env, _url, _entry in registered_keys(secrets)}
    by_env: dict[str, list] = {}
    for route in routes:
        by_env.setdefault(str(route["env"]), []).append(route)
    rows = []
    for env, bound in by_env.items():
        configured = [route for route in bound if route.get("source") == "configured"]
        label = registered.get(env) or next((r["label"] for r in bound if r.get("source") == "web"), None) \
            or (configured or bound)[0]["label"]
        used = list(dict.fromkeys(use for route in configured for use in [_route_use(route.get("label"))] if use))
        if _route_use(label):
            label = _OWN_ENDPOINT  # the route's own name ("Model") is what the row's badge says
        hosts = [{"host": urllib.parse.urlsplit(str(route.get("url") or "")).hostname or route.get("host"),
                  "port": route.get("port")} for route in bound]
        where = _join([_host_text(host["host"], host["port"]) for host in hosts])
        row = _row(f"key:{env}", label, "key", READY, _sentence("key" if where else "key_plain", where=where),
                   env=env, main="model" in used, fallback="fallback" in used)
        rows.append({**row, "hosts": hosts, "used_by": used} if facts else row)
    for item in on_approval or ():
        env = str(item.get("env") or "")
        if not env or env in by_env:
            continue
        uses = categories.labels(item.get("categories") or ())
        row = _row(f"key:{env}", item.get("label") or env, "key", READY,
                   _sentence("key_on_approval", uses=_uses_text(uses)), env=env)
        rows.append({**row, "hosts": [], "used_by": [], "reason": "key_on_approval", "uses": uses} if facts else row)
    return rows, set(by_env)


def _route_use(label) -> str:
    """What a model route's name says uses it (``model``, ``fallback``, ``auxiliary``); "" for a saved endpoint
    and for any other name."""
    text = str(label or "")
    return next((use for name, use in _ROUTE_USES if text == name or text.startswith(name + " (")), "")


def _missing_key(item: dict, config: dict, routed: set) -> Optional[dict]:
    """The row of a provider a model route names that uses a key, when no key of it would be handed in: said
    only where it is certain, for a registered provider whose own variables are all unset. None when a key is
    handed in, when the route names its own variable or address, and when a secret source may supply the key
    at the sandbox's start."""
    provider = str(item.get("provider") or "")
    if not item.get("used_by"):
        return None
    sources = config.get("secrets")
    if isinstance(sources, dict) and any(isinstance(v, dict) and v.get("enabled") is True for v in sources.values()):
        return None
    envs = _registered_envs(provider)
    if not envs or routed & set(envs):
        return None
    for _label, entry in _model_entries(config):
        if str(entry.get("provider") or "").strip().lower() == provider and \
                (entry.get("key_env") or entry.get("api_key_env") or entry.get("base_url")):
            return None
    label = "OpenRouter" if provider == "openrouter" else str(item.get("label") or provider)
    return _row(f"key:{provider}", label, "key", NO_KEY,
                _sentence("no_key_main" if _main(item) else "no_key", env=envs[0]), env=envs[0], main=_main(item),
                fallback=_fallback(item))


def _registered_envs(provider: str) -> tuple:
    """The variables Hermes registers for an API-key provider's key; () for any other provider."""
    if provider == "openrouter":
        return ("OPENROUTER_API_KEY",)
    try:
        from hermes_cli.auth import PROVIDER_REGISTRY
    except ImportError:
        return ()
    row = PROVIDER_REGISTRY.get(provider)
    if row is None or getattr(row, "auth_type", "") != "api_key":
        return ()
    return tuple(str(env) for env in getattr(row, "api_key_env_vars", ()) or ())


def _config_keys():
    """The module that finds and moves keys written in config.yaml (``inline_keys``, ``move_to_env``); None in
    a plugin that has none."""
    try:
        module = importlib.import_module(f"{__package__}.config_keys")
    except ImportError:
        return None
    usable = all(callable(getattr(module, name, None)) for name in ("inline_keys", "move_to_env"))
    return module if usable else None


def _sweep(layout: ProfileLayout) -> None:
    """Remove what an earlier move of keys left behind (config_keys.py ``sweep``). Never fails a read."""
    keys = _config_keys()
    sweep = getattr(keys, "sweep", None)
    if callable(sweep):
        try:
            sweep(layout.home)
        except Exception as exc:
            log.warning("what an earlier move of keys left could not be removed: %s", _plain(exc))


def inline_keys_now(layout: ProfileLayout) -> list[dict]:
    """The keys written in the profile's config.yaml as they are now, for a launcher's rows while the sandbox
    is on; while the file cannot be read, the ones last found (the row stays until the file says otherwise)."""
    key = str(layout.home)
    try:
        found = _inline_keys(read_config(layout))
    except Unreadable:
        return list(_last_inline.get(key) or [])
    _last_inline[key] = found
    return list(found)


def _inline_keys(config: dict) -> list[dict]:
    """``[{"path", "env"}]`` for every key written in *config*; [] when they cannot be listed."""
    keys = _config_keys()
    if keys is None:
        return []
    try:
        items = keys.inline_keys(config)
    except Exception as exc:
        log.warning("the keys written in config.yaml could not be listed: %s", _plain(exc))
        return []
    return [{"path": item["path"], "env": item["env"]} for item in (items if isinstance(items, list) else [])
            if isinstance(item, dict) and all(isinstance(item.get(k), str) and item.get(k) for k in ("path", "env"))]


def _reason_in(detail: str, label: str) -> str:
    """The reason a sign-in row's detail states, when the detail begins with the sign-in engine's own sentence
    for it (signins.py); "" otherwise."""
    if not detail:
        return ""
    try:
        sentences = getattr(importlib.import_module(f"{__package__}.signins"), "_SENTENCES", {})
    except Exception:
        return ""
    for reason, text in sentences.items() if isinstance(sentences, dict) else ():
        try:
            if detail.startswith(str(text).format(label=label)):
                return str(reason)
        except (IndexError, KeyError):
            continue
    return ""


def _reason_while_on(state: str, kind: str, reason: str, where: bool) -> str:
    """The sentence a launcher row gets: its own reason where that fits its state, else the state's."""
    if state == READY:
        if reason in ("signed_in", "signed_in_shared", "retrying") or (reason == "key_on_approval" and kind == "key"):
            return reason
        return ("key" if where else "key_plain") if kind == "key" else "signed_in"
    if state == NEEDS_SIGN_IN:
        return reason if reason in ("not_signed_in", "shared_not_carried", "expired") else "not_signed_in"
    if state == EXPIRED:
        return "lapsed" if reason == "lapsed" else "expired"
    if state == UNAVAILABLE:
        return reason if reason in _WHY_UNAVAILABLE else ""
    return state if state in (WITHHELD, KEY_IN_CONFIG) else ""


def _sentence(reason: str, *, on: bool = False, **values) -> str:
    text = (_SENTENCES_ON.get(reason) if on else None) or _SENTENCES.get(reason)
    return text.format(**{"label": "", "where": "", "env": "", "uses": "", **values}) if text else ""


def _row(row_id, label, kind: str, state: str, detail, *, main: bool = False, fallback: bool = False,
         env: str = "", path: str = "") -> dict:
    row = {"id": _text(row_id, 200), "label": _text(label, 80), "kind": kind, "state": state,
           "detail": _text(detail, 400), "main": bool(main)}
    if fallback:
        row["fallback"] = True  # a fallback model uses it; only said where it is so
    if env:
        row["env"] = _text(env, 80)
    if path:
        row["path"] = _text(path, 160)
    return row


def _ordered(rows: list) -> list:
    """Keys to move first, then the main model's provider, then what needs attention, then what works."""
    def rank(row: dict) -> int:
        return 0 if row["state"] == KEY_IN_CONFIG else 1 if row.get("main") else 3 if row["state"] == READY else 2

    return sorted(rows, key=rank)  # a stable sort: within a group the rows keep the order they were found in


def _main(item: dict) -> bool:
    used = item.get("used_by")
    return isinstance(used, (list, tuple)) and "model" in used


def _fallback(item: dict) -> bool:
    """Whether a fallback model uses it: ``used_by`` names a place in the fallback chain."""
    used = item.get("used_by")
    return isinstance(used, (list, tuple)) and any(isinstance(use, str) and use.startswith("fallback") for use in used)


def _host_item(host) -> str:
    if isinstance(host, dict):
        return _host_text(host.get("host"), host.get("port"))
    text = str(host or "").strip()
    named = re.fullmatch(r"([^\[\]:]+):(\d{1,5})", text)
    return _host_text(named.group(1), int(named.group(2))) if named else _host_text(text, None)


def _host_text(host, port) -> str:
    """An address as the page names it: the host, with its port when that is not the https one. A server on
    this computer is ``localhost`` with its port, whichever of its names the profile uses: the sentence around
    it already says "this computer" once."""
    host = _text(host, 120).lower()
    if not host:
        return ""
    if host in _THIS_COMPUTER:
        return f"localhost:{port}" if port else "localhost"
    return host if port in (None, 443, "443") else f"{host}:{port}"


def _join(parts) -> str:
    parts = list(dict.fromkeys(str(part) for part in parts if part))
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1] if parts else ""


def _text(value, limit: int) -> str:
    """*value* as one line of at most *limit* characters; "" for anything that is not text."""
    text = " ".join(value.split()) if isinstance(value, str) else ""
    return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."


def _plain(exc: BaseException) -> str:
    """An exception in a few plain words: its message's first line, else its kind."""
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return text or type(exc).__name__


def _stamp(layout: ProfileLayout) -> tuple:
    """What the rows of a profile that is off are read from: they are read again when any of it changes."""
    marks = []
    watched = [layout.home / name for name in _WATCHED]
    try:
        from . import pins

        watched.append(pins.pin_dir(layout) / pins.PIN_FILE)
    except Exception:  # a layout without a state folder: the home's files decide
        pass
    for path in watched:
        try:
            st = path.stat()
            marks.append((path.name, st.st_mtime_ns, st.st_size))
        except OSError:
            marks.append((path.name, None, None))
    return tuple(marks)
