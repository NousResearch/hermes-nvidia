"""The one destination the launcher opens by itself: where Hermes sends the usage data a profile shares with Nous.

Hermes's shared metrics are two answers in the profile's own config.yaml (``telemetry.shared_metrics.enabled``
collects, ``.send`` uploads once a day). The profile's backend does the upload, and in a sandboxed profile that
backend runs inside the sandbox, where every site is refused until it is allowed. While both answers are on, the
launcher adds one rule for ``HOST`` to the sandbox's network policy, usable by Hermes's interpreter like the
destinations on the Sandbox page; when sharing is turned off the rule goes again. The drivers decide each time
they build the policy's network rules (sandbox start, every network update, a restored revision), and the
launcher's card loop picks up an answer given while the sandbox runs (``Cards._watch_usage_data``).

The host is fixed here. The ``endpoint`` key beside the two answers is never opened: the sandboxed agent can write
its own profile's config.yaml, so honouring it would let the agent open any host. A profile whose config names
another endpoint gets no rule at all (Hermes would send there, and that stays refused); the launcher logs it once.

The rule is not a grant. It is never saved in the sandbox spec, reading the live policy back leaves it out
(``openshell_driver.network_from_policy``), so the page's edits and the cards' answers neither remove nor keep it,
and whatever else a policy holds under its name is dropped. For Hermes's interpreter the destination is allowed, so
it is never refused and raises no card. The rule names that interpreter only: on Windows another program in the
sandbox that asks for the host (the agent's ``curl.exe``) is refused like any site and gets the usual website card,
whose Allow is an ordinary grant of the user's, listed and removable under "Allowed from chat". The Sandbox page
lists the built-in destination among the allowed destinations with its reason (``destinations``).

Known limit: a sandboxed agent that edits its profile's config.yaml can turn sharing on. That opens this one host
on port 443 and nothing else.
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from pathlib import Path
from typing import Optional

log = logging.getLogger("openshell.usage_data")

HOST = "telemetry.nousresearch.com"
PORT = 443
BUILTIN_PREFIX = "hermes_builtin_"  # rule names the launcher keeps for itself: never a saved or approved rule
RULE_NAME = BUILTIN_PREFIX + "usage_data"
REASON = "Usage data this profile shares with Nous"

_cache: dict[str, tuple] = {}  # config path -> (file signature, (shared, other endpoint))
_logged: set = set()           # (config path, other endpoint) already logged


def _section(config) -> dict:
    telemetry = config.get("telemetry") if isinstance(config, dict) else None
    section = telemetry.get("shared_metrics") if isinstance(telemetry, dict) else None
    return section if isinstance(section, dict) else {}


def _is_ours(endpoint: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(endpoint)
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "") == HOST and port in (None, PORT)


def _endpoint_host(endpoint: str) -> str:
    """Where a config-named endpoint points, for the log line: host and port only (never a path or a login)."""
    try:
        parts = urllib.parse.urlsplit(endpoint)
        return f"{parts.hostname or '?'}:{parts.port}" if parts.port else (parts.hostname or "?")
    except ValueError:
        return "?"


def answers(config) -> tuple[bool, Optional[str]]:
    """``(shared, other endpoint)`` from a profile's raw config, read the way Hermes reads it: both answers must
    be the YAML value true, and a missing or blank ``endpoint`` means Hermes's own. ``other endpoint`` is what the
    config names when that is not ``HOST`` over https on ``PORT``; then nothing is shared through the sandbox."""
    section = _section(config)
    wanted = section.get("enabled") is True and section.get("send") is True
    endpoint = section.get("endpoint")
    endpoint = endpoint.strip() if isinstance(endpoint, str) else ""
    other = endpoint if endpoint and not _is_ours(endpoint) else None
    return wanted and other is None, other if wanted else None


def _read(home) -> tuple[bool, Optional[str]]:
    if home is None:
        return False, None
    path = Path(home) / "config.yaml"
    try:
        stat = os.stat(path)
        signature = (stat.st_mtime_ns, stat.st_size, stat.st_ctime_ns, stat.st_ino)
    except OSError:
        signature = None
    key = str(path)
    hit = _cache.get(key)
    if hit is not None and signature is not None and hit[0] == signature:
        return hit[1]
    from hermes_cli.config_backend import config_exists, read_config_doc

    try:
        config = read_config_doc(path) if config_exists(path) else {}
    except Exception:  # unreadable or not YAML: Hermes shares nothing either
        config = {}
    result = answers(config)
    _cache[key] = (signature, result)
    if result[1] and (key, result[1]) not in _logged:
        _logged.add((key, result[1]))
        log.warning("This profile sends its usage data to %s (telemetry.shared_metrics.endpoint in its config.yaml). "
                    "The sandbox opens only %s for usage data, so nothing is opened and none is sent from inside.",
                    _endpoint_host(result[1]), HOST)
    return result


def shared(home) -> bool:
    """Whether the profile at *home* shares its usage data with Nous right now (so the rule belongs in the policy)."""
    return _read(home)[0]


def destinations(home) -> list[dict]:
    """What the Sandbox page lists among the allowed destinations: the host, its port and the reason, while the
    profile shares its usage data; nothing otherwise."""
    return [{"host": HOST, "port": PORT, "reason": REASON, "rule": RULE_NAME}] if shared(home) else []


def rules(network_policies: dict, home, binaries) -> dict:
    """*network_policies* (OpenShell rules by name) as the sandbox of the profile at *home* gets them: nothing
    under a built-in name but this rule, present while the profile shares its usage data and bound to *binaries*
    (Hermes's interpreter, as for the page's destinations)."""
    out = {name: rule for name, rule in (network_policies or {}).items() if not str(name).startswith(BUILTIN_PREFIX)}
    paths = [str(b) for b in binaries or () if b]
    if paths and shared(home):
        out[RULE_NAME] = {"name": RULE_NAME, "endpoints": [{"host": HOST, "port": PORT}],
                          "binaries": [{"path": p} for p in paths]}
    return out
