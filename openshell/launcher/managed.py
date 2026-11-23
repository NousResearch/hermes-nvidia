"""The managed scope the sandboxed backend runs under.

The profile's config.yaml can name its own terminal backend, and Git Bash cannot start in the
container. Managed scope outranks the profile's config, so the launcher pins the busybox backend
there. An administrator's managed config on the host is carried over, with the pin on top.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict

import hermes_yaml


def _merge(base: Dict[str, Any], top: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in top.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def write_managed_scope(target: Path, pins: Dict[str, Any]) -> Path:
    """Write ``target/config.yaml``: the host's managed config with *pins* on top.

    The host's managed .env is not copied: it can hold credentials, and this directory is readable
    from inside the sandbox.
    """
    from hermes_cli import managed_scope

    target.mkdir(parents=True, exist_ok=True)
    host = managed_scope.load_managed_config() if managed_scope.get_managed_dir() else {}
    (target / "config.yaml").write_text(
        hermes_yaml.safe_dump(_merge(host, pins), sort_keys=False), encoding="utf-8")
    return target
