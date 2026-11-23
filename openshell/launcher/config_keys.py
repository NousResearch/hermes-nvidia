"""Keys written in a profile's ``config.yaml``.

The sandbox reads and writes its profile's ``config.yaml``, so a key written there is a key the sandbox holds.
Keys belong in the profile's ``.env``: the sandbox never sees that file, and each key in it reaches the sandbox
as a placeholder. The Sandbox switch therefore refuses to turn on while ``inline_keys`` finds a key in the
config, and ``move_to_env`` moves the ones it found.

What counts as a key
--------------------

A non-empty string in one of these places:

* ``api_key`` of a model route: ``model``, ``fallback_model``, each entry of ``fallback_providers``, each task
  under ``auxiliary``, each saved endpoint under ``providers`` and ``custom_providers`` (a list or a mapping),
  and ``delegation``.
* A header of an MCP server (``mcp_servers.<name>.headers.<Header>``) or a variable it is started with
  (``mcp_servers.<name>.env.<NAME>``) whose name says it holds a secret.
* Any other value in those sections whose key says it holds a secret (``token``, ``client_secret``, and so on).

Which names say so is Hermes's own rule for masking config values (``hermes_cli.config``), with the same list
kept here for a Hermes that does not have it. A value that only refers to variables (``${NAME}``, also inside
``Bearer ${NAME}``) is a reference, never a key, and neither is the name of a variable (``key_env``,
``api_key_env``).

Where a key moves to
--------------------

``inline_keys`` names the variable for each key. A model route's key goes to the variable the route names
(``key_env`` or ``api_key_env``), else to the first variable Hermes registers for the route's provider, else to
a name made from the place (``MODEL_API_KEY``, ``CUSTOM_<NAME>_API_KEY``). An MCP server's value goes to
``MCP_<SERVER>_<NAME>``. ``move_to_env`` writes the variable into ``.env`` and leaves ``${NAME}`` in the config
where the key was (after the scheme word for a ``Bearer`` header); a route whose variable Hermes would not find
by itself also gets ``key_env``.

No copy of a key is left behind
-------------------------------

After a move that completed, the key is in ``.env`` and in no other file. The move keeps both files as they were
in memory until it has read both back, never on disk, and ``sweep`` removes what an earlier move could have left:
the copies an earlier version of this module kept for good, and a temp file of a move that was killed.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

log = logging.getLogger("openshell.config_keys")

CONFIG_FILE = "config.yaml"
ENV_FILE = ".env"
BACKUP_DIRNAME = "config-key-backups"  # where an earlier version kept both files, keys included: only swept now
STALE_TEMP = 60.0  # seconds after which a temp file in the profile cannot be a running move's
_TEMP_PREFIX, _TEMP_SUFFIX = ".keys-", ".tmp"
_IN_USE = "Another program may have it open."
ROUTE_SECTIONS = ("model", "fallback_model", "fallback_providers", "auxiliary", "providers", "custom_providers",
                  "delegation")
SECTIONS = (*ROUTE_SECTIONS, "mcp_servers")

# Hermes's own lists (hermes_cli.config), for a Hermes that does not have the function.
_SECRET_KEYS = frozenset({"api_key", "apikey", "key", "token", "access_token", "refresh_token", "id_token", "secret",
                          "client_secret", "password", "passwd", "authorization", "private_key", "bearer", "jwt"})
_SECRET_SUFFIXES = ("_api_key", "_token", "_secret", "_password", "_key", "_access_key")
_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_SCHEME = re.compile(r"(?i)^(bearer|basic|token)\s+(?=\S)")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BARE_VALUE = re.compile(r"[A-Za-z0-9_\-./+=:@%,]+")


class MoveError(RuntimeError):
    """A key could not be moved. Nothing was changed unless the message says so."""


def _names_a_secret(path: tuple) -> bool:
    key = ".".join(str(part) for part in path)
    try:
        from hermes_cli.config import _is_secret_config_key

        return bool(_is_secret_config_key(key))
    except Exception:
        leaf = str(path[-1]).lower().replace("-", "_")
        return leaf in _SECRET_KEYS or leaf.endswith(_SECRET_SUFFIXES)


def is_reference(value: Any) -> bool:
    """Whether *value* only refers to variables: ``${NAME}``, alone or after a scheme word."""
    if not isinstance(value, str):
        return False
    rest = _SCHEME.sub("", value.strip())
    return bool(_REFERENCE.search(rest)) and not _REFERENCE.sub("", rest).strip()


def _leaves(node: Any, path: tuple) -> Iterator[tuple[tuple, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _leaves(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _leaves(value, (*path, index))
    elif isinstance(node, str):
        yield path, node


def _registered_variable(provider: Any) -> str:
    try:
        from hermes_cli.auth import PROVIDER_REGISTRY

        row = PROVIDER_REGISTRY.get(str(provider or ""))
        names = tuple(getattr(row, "api_key_env_vars", ()) or ())
    except Exception:
        names = ()
    if not names and str(provider or "").strip().lower() == "openrouter":
        names = ("OPENROUTER_API_KEY",)  # Hermes's default provider, which its registry does not list
    return str(names[0]) if names else ""


def _slug(text: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(text).upper()).strip("_")


def _variable_for(config: dict, path: tuple) -> tuple[str, bool]:
    """``(variable, hint)`` for the key at *path*: the variable it moves to, and whether the route needs
    ``key_env`` set to it so that Hermes finds it."""
    if path[0] == "mcp_servers":
        return "MCP_" + _slug("_".join(str(part) for part in path[1:] if part not in ("headers", "env"))), False
    entry: Any = config
    for step in path[:-1]:
        entry = entry[step]
    entry = entry if isinstance(entry, dict) else {}
    if path[-1] in ("api_key", "apikey", "key"):
        for hint in ("key_env", "api_key_env"):
            named = entry.get(hint)
            if isinstance(named, str) and _ENV_NAME.fullmatch(named.strip()):
                return named.strip(), False
        registered = _registered_variable(entry.get("provider"))
        if registered and not str(entry.get("base_url") or "").strip():
            return registered, False
    if path[0] == "model":
        return _slug("MODEL_" + "_".join(str(p) for p in path[1:])), path[-1] in ("api_key", "apikey", "key")
    label = entry.get("name") if isinstance(entry.get("name"), str) and entry.get("name").strip() else None
    middle = [label] if label else [str(part) for part in path[1:-1]]
    prefix = "CUSTOM" if path[0] in ("providers", "custom_providers") else _slug(path[0])
    return _slug("_".join([prefix, *middle, str(path[-1])])), path[-1] in ("api_key", "apikey", "key")


def inline_keys(config: Any) -> list[dict]:
    """The keys written in the config document *config*: ``[{"path", "env"}]``, ``path`` as a dotted place
    (``model.api_key``, ``custom_providers.0.api_key``, ``mcp_servers.github.headers.Authorization``) and
    ``env`` the variable the key would move to. Two keys never get the same variable. No value is returned."""
    if not isinstance(config, dict):
        return []
    found, taken = [], set()
    for section in SECTIONS:
        for path, value in _leaves(config.get(section), (section,)):
            if not value.strip() or is_reference(value) or not _names_a_secret(path):
                continue
            variable, hint = _variable_for(config, path)
            base, count = variable or "CONFIG_KEY", 1
            variable = base
            while variable in taken:
                count += 1
                variable = f"{base}_{count}"
            taken.add(variable)
            found.append({"path": ".".join(str(part) for part in path), "env": variable, "key_env": hint})
    return found


def describe(items: Iterable[dict]) -> str:
    """The places of *items* as one phrase for a sentence."""
    paths = [str(item["path"]) for item in items]
    return paths[0] if len(paths) == 1 else ", ".join(paths[:-1]) + " and " + paths[-1]


def _state_dir(home: Path) -> Path:
    """The launcher's folder for the profile in *home* (``<Hermes root>/openshell/<profile>``)."""
    from .layout import STATE_DIRNAME

    home = Path(home)
    if home.parent.name == "profiles":
        return home.parent.parent / STATE_DIRNAME / home.name
    return home / STATE_DIRNAME / "default"


def _quoted(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise MoveError("a key with a line break cannot be written to .env")
    if _BARE_VALUE.fullmatch(value):
        return value
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _env_names(text: str) -> dict:
    names = {}
    for line in text.splitlines():
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
        if match:
            names[match.group(1)] = match.group(2).strip()
    return names


def _write_whole(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=_TEMP_PREFIX, suffix=_TEMP_SUFFIX)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _not_read_back(env_path: Path, secrets: dict) -> list[str]:
    """The variables of *secrets* that Hermes's own reader does not read back from *env_path* as written."""
    try:
        from agent.secret_scope import load_env_file

        read = dict(load_env_file(env_path))
    except ImportError:
        return []
    except Exception:
        return sorted(secrets)
    return sorted(name for name, value in secrets.items() if read.get(name) != value)


def sweep(home) -> list[str]:
    """Remove what an earlier move left on disk with a key in it: the copies of both files an earlier version of
    this module kept (``config-key-backups`` in the launcher's folder for the profile), and a temp file of
    ``.env`` a killed move left in the profile, once it is too old to be a running move's. Returns the names
    removed. None of it is needed to finish or to undo a move (``move_to_env``)."""
    home = Path(home)
    removed = []
    kept = _state_dir(home) / BACKUP_DIRNAME
    if kept.is_dir():
        shutil.rmtree(kept, ignore_errors=True)
        if kept.exists():
            log.warning("%s could not be removed; it holds copies of config.yaml with keys in them", kept)
        else:
            removed.append(BACKUP_DIRNAME)
    now = time.time()
    for left in sorted(home.glob(_TEMP_PREFIX + "*" + _TEMP_SUFFIX)):
        try:
            if now - left.stat().st_mtime > STALE_TEMP:
                left.unlink()
                removed.append(left.name)
        except OSError:
            continue
    return removed


def move_to_env(home, items: Optional[Iterable[dict]] = None) -> list[str]:
    """Move the keys *items* (rows of ``inline_keys``; every key found when None) from the ``config.yaml`` of
    the profile home *home* to its ``.env``. Returns the places moved. Call it with the sandbox off.

    Only the two files are written, and no copy of either is kept on disk: both are held in memory as they
    were until the move has been checked. ``.env`` gets the variables first, written whole and renamed into
    place, and is read back with Hermes's own reader. Only then is the config written without the keys, and
    read back: one that still holds a key puts both files back as they were.

    A stop between the two writes (the process ended, the power went) leaves each key in ``.env`` and in
    ``config.yaml`` and nowhere else. The switch still refuses, the page still names the key, and the next
    move finds the variable in ``.env`` as it is and finishes with the config. A place that no longer holds a
    key is skipped. A file that cannot be read or written raises ``MoveError`` with a sentence that says so."""
    from hermes_cli.config_backend import config_exists, read_config_doc, write_config_document

    home = Path(home)
    config_path, env_path = home / CONFIG_FILE, home / ENV_FILE
    sweep(home)
    try:
        there = config_exists(config_path)
        config_bytes = config_path.read_bytes() if there else b""
        config_mode = stat.S_IMODE(config_path.stat().st_mode) if there else 0o600
        config = read_config_doc(config_path) if there else {}
    except OSError:
        raise MoveError(f"{CONFIG_FILE} can't be read. {_IN_USE}") from None
    except Exception:  # Hermes's YAML reader refused the text
        raise MoveError(f"{CONFIG_FILE} isn't valid YAML.") from None
    if not isinstance(config, dict):
        raise MoveError("config.yaml does not hold settings")
    current = {item["path"]: item for item in inline_keys(config)}
    wanted = list(current.values()) if items is None else [current[str(item.get("path"))] for item in items
                                                           if str(item.get("path")) in current]
    if not wanted:
        return []
    try:
        env_bytes: Optional[bytes] = env_path.read_bytes()
    except FileNotFoundError:
        env_bytes = None
    except OSError:
        raise MoveError(f"{ENV_FILE} can't be read. {_IN_USE}") from None
    env_text = (env_bytes or b"").decode("utf-8-sig")
    present = _env_names(env_text)
    lines, moved, secrets = [], [], {}
    for item in wanted:
        path = [int(part) if part.isdigit() else part for part in item["path"].split(".")]
        holder: Any = config
        for step in path[:-1]:
            holder = holder[step]
        value = holder[path[-1]]
        scheme = _SCHEME.match(value.strip())
        secret = value.strip()[scheme.end():] if scheme else value
        variable, base, count = item["env"], item["env"], 1
        line = f"{variable}={_quoted(secret)}"
        while variable in present and present[variable] != line.split("=", 1)[1]:
            count += 1  # the variable holds another value: this key gets a name of its own
            variable = f"{base}_{count}"
            line = f"{variable}={_quoted(secret)}"
        secrets[variable] = secret
        if variable not in present:
            lines.append(line)
            present[variable] = line.split("=", 1)[1]
        holder[path[-1]] = (scheme.group(0) if scheme else "") + "${" + variable + "}"
        if item.get("key_env") and isinstance(holder, dict) and not holder.get("key_env") \
                and not holder.get("api_key_env"):
            holder["key_env"] = variable
        moved.append(item["path"])

    def env_back() -> None:
        if env_bytes is None:
            env_path.unlink(missing_ok=True)
        else:
            _write_whole(env_path, env_bytes)

    if lines:
        joined = env_text + ("" if not env_text or env_text.endswith("\n") else "\n") + "\n".join(lines) + "\n"
        try:
            _write_whole(env_path, joined.encode("utf-8"))
        except OSError:
            raise MoveError(f"{ENV_FILE} can't be written. {_IN_USE}") from None
        unread = _not_read_back(env_path, secrets)
        if unread:
            # Hermes would read another value than the key: the env file goes back as it was, the config is untouched.
            env_back()
            raise MoveError(f"{', '.join(unread)} could not be written to .env as it is; nothing was moved")
    try:
        write_config_document(config_path, config)
    except OSError:
        raise MoveError(f"{CONFIG_FILE} can't be written. {_IN_USE} The key is now in .env as well; move it "
                        f"again to finish.") from None
    try:
        after = read_config_doc(config_path)
    except Exception:
        after = None
    if not isinstance(after, dict) or {item["path"] for item in inline_keys(after)} & set(moved):
        # The write did not take the keys out: both files go back as they were, from memory.
        _write_whole(config_path, config_bytes, config_mode)
        if lines:
            env_back()
        raise MoveError(f"{CONFIG_FILE} still holds the key after it was written; nothing was moved")
    log.info("moved %d key(s) from %s to %s", len(moved), config_path, env_path)
    return moved
