"""Keys written in a profile's ``config.yaml``.

The sandbox reads and writes its profile's ``config.yaml``, so a key written there is a key the sandbox holds.
Keys belong in the profile's ``.env``: the sandbox never sees that file, and each key in it reaches the sandbox
as a placeholder. The Sandbox switch therefore refuses to turn on while ``inline_keys`` finds a key in the
config, and ``move_to_env`` moves the ones it found.

What counts as a key
--------------------

The whole document is read. A value that only refers to variables (``${NAME}``, also inside ``Bearer ${NAME}``)
is a reference, never a key, and neither is the name of a variable (``key_env``, ``api_key_env``). A non-empty
string that is no reference is a key when one of these holds.

* It is in one of the sections ``move_to_env`` moves (``SECTIONS``: the model routes and the MCP servers) and
  its name says it holds a secret by Hermes's own rule for masking config values (``hermes_cli.config``, with
  the same list kept here for a Hermes that does not have it).
* It is anywhere else, and its name can only be a credential's (``_CREDENTIAL_NAMES``, ``_CREDENTIAL_ENDINGS``):
  ``api_key``, ``apikey``, ``access_key``, ``secret_key``, ``token``, ``secret``, ``client_secret``,
  ``password``, ``passwd``, ``authorization``, ``bearer``, ``jwt``, and a name that ends in ``_api_key``,
  ``_access_key``, ``_secret_key``, ``_token``, ``_secret`` or ``_password``. Any value under such a name counts.
* It is anywhere else, its name is a key of some kind (``key``, ``private_key``, a name that ends in ``_key``),
  and the value looks like a credential (``_looks_like_a_credential``): 16 characters or more, no white space,
  not written as a path (``~``, ``/``, ``./``, ``../``, a drive letter, two separators), and a run of 12 or
  more letters and digits that holds both. A private key written as a PEM block counts too. So a keyboard key
  (``ctrl+p``), a sort key (``created_at``), a cache key, a name made of words and a number
  (``notes-by-day-2026``) and the path of a key file are no keys. A name that says the value is public
  (``public_key``, ``pubkey``, a name that ends in ``_public_key`` or ``_pubkey``) never counts.
* It follows a flag in a list of arguments, and the flag's name counts by the two rules above:
  ``["--api-key", "..."]`` and ``["--token", "..."]`` always, ``["--key", "name"]`` only for a value that looks
  like a credential.
* The value itself has the shape of a secret, whatever its name: an ``Authorization`` value, a URL that carries
  a password or a token in its query, a webhook URL, a secret handed to a command, a key with a vendor's
  prefix, a signed web token (``_SECRET_SHAPES``).

A name is compared in lower case, with ``-`` read as ``_``; a value in a list has the name of the list. The
names outside the moved sections are this module's own lists, so what keeps the switch off does not change
with the Hermes that is installed. A long value under a name that says nothing (a voice id) is not a key.

A copy of ``config.yaml`` that a person or an editor left beside it (``config.yaml.bak``, ``config.yaml~``) is
read the same way (``keys_in_copies``): the sandbox reads that file too. A copy that cannot be read as a config
document keeps the switch off as well.

Where a key moves to
--------------------

``move_to_env`` moves the keys of the model routes and of the MCP servers (``SECTIONS``, by their names). A key
anywhere else, and a value that is a key by its shape, is named and left to the user: its row has no ``env``,
``by_hand`` set, and ``variable``, the name ``describe`` suggests for it.

``inline_keys`` names the variable for each key it moves. A model route's key goes to the variable the route names
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
from itertools import islice
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
SECTIONS = (*ROUTE_SECTIONS, "mcp_servers")  # where ``move_to_env`` moves a key; a key elsewhere is moved by hand
# Outside those sections a setting is a key by its name, in lower case with ``-`` read as ``_``. A name that can
# only be a credential's: every value under it counts.
_CREDENTIAL_NAMES = frozenset({"api_key", "apikey", "access_key", "secret_key", "token", "secret", "client_secret",
                               "password", "passwd", "authorization", "bearer", "jwt"})
_CREDENTIAL_ENDINGS = ("_api_key", "_access_key", "_secret_key", "_token", "_secret", "_password")
# A name that is a key of some kind (of a keyboard, of a sort, of a cache, for signing): the value decides.
_KEY_NAMES, _KEY_ENDING = frozenset({"key", "private_key"}), "_key"
# A name that says the value is public: never a key by its name.
_PUBLIC_NAMES, _PUBLIC_ENDINGS = frozenset({"public_key", "pubkey"}), ("_public_key", "_pubkey")
# What a value under a key-like name has when it is a credential: this many characters, and a run of this many
# letters and digits that holds both. Words joined by marks have no such run.
_CREDENTIAL_CHARS, _CREDENTIAL_RUN = 16, 12
_MIXED_RUN = re.compile(r"[A-Za-z0-9]{%d,}" % _CREDENTIAL_RUN)
_WRITTEN_AS_A_PATH = re.compile(r"~|\.{0,2}[\\/]|[A-Za-z]:[\\/]")  # ~, /, ./, ../, two separators, a drive letter
_PEM_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
# The sandbox writes config.yaml and can leave copies of it, so what reads them is bounded whatever they hold:
# how deep and how many values of a document are looked at, how much of one value is searched for the shape of
# a secret, how many copies are read, how large one copy and all of them together are, and how deep a copy's
# text nests before it is handed to the YAML reader. Every pattern below takes time in proportion to the text.
_MAX_DEPTH, _MAX_VALUES, _SCAN_CHARS = 32, 20_000, 65_536
_COPY_LIMIT, _COPY_BYTES, _COPIES_BYTES, _COPY_NESTING = 16, 262_144, 262_144, 64
_NAMED, _NAME_CHARS = 12, 160  # how many files or places one sentence names, and how much of one name it shows
_VARIABLE_CHARS = 64
# How an editor names its own file for one it has open: ``.NAME.swp``, ``#NAME#``, ``.#NAME``, ``~NAME``.
_CONFIG_COPY = re.compile(r"config\.yaml.+|\.config\.yaml\.sw.|#config\.yaml#|\.#config\.yaml|~config\.yaml")
# A value that is a secret by its shape. A reference (``${NAME}``) in the secret's place never matches.
_TOKEN = r"(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{16,}"
_SECRET_SHAPES = tuple(re.compile(shape) for shape in (
    r"(?i)\bbearer\s+" + _TOKEN,
    r"(?i)\bauthorization['\"]?\s*[:=]\s*['\"]?(?:(?:basic|token)\s+)?" + _TOKEN,
    r"(?i)(?<=[a-z0-9+.-])://[^/\s:@'\"]+:(?!\$\{)[^/\s@'\"]+@[^\s/]",
    r"(?i)[?&](?:access_token|api_key|apikey|auth|key|password|secret|sig|signature|token)=(?!\$\{)[^&\s'\"]{8,}",
    r"(?i)https://(?:discord(?:app)?\.com/api/webhooks/\d+/[\w-]{12,}|hooks\.slack\.com/services/[\w/]{12,})",
    r"(?i)(?:^|\s)--?[a-z0-9-]*(?:api-key|apikey|password|secret|token)(?:=|\s+)"
    r"['\"]?(?!\$|\d+(?:\s|$))[^\s'\"-][^\s'\"]{7,}",
    r"(?:^|[\s;&|'\"(])(?:export\s+)?[A-Z0-9_]*(?:ACCESS_KEY|API_KEY|APIKEY|PASSWD|PASSWORD|SECRET|TOKEN)="
    r"['\"]?(?!\$|\d+(?:\s|$))[^\s'\"]{8,}",
    r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{20,}|xox[abeoprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}|AIza[A-Za-z0-9_-]{30,}|AKIA[A-Z0-9]{16})",
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
))
_FLAG = re.compile(r"--?([A-Za-z][A-Za-z0-9_-]*)")
_VAULT_REFERENCE = re.compile(r"op://\S+")  # where a secret manager keeps a value (``secrets.onepassword.env``)

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


def _strings(config: dict) -> tuple[list, Optional[tuple]]:
    """``(strings, stopped)``: every string in *config* with its place, in the document's order, and the place
    where the walk stopped short, or None. The walk takes no step per level of the call stack, goes
    ``_MAX_DEPTH`` levels down and looks at ``_MAX_VALUES`` values, so a document that nests without end, points
    back at itself or holds a great many values costs no more than that."""
    found, stopped, waiting, looked = [], None, [((), config)], 0
    while waiting:
        path, node = waiting.pop()
        if looked >= _MAX_VALUES:
            return found, stopped or path
        looked += 1
        if isinstance(node, str):
            found.append((path, node))
        elif isinstance(node, (dict, list)):
            if len(path) >= _MAX_DEPTH:
                stopped = stopped or path
                continue
            below = islice(node.items() if isinstance(node, dict) else enumerate(node), _MAX_VALUES + 1)
            waiting.extend(reversed([((*path, key), value) for key, value in below]))
    return found, stopped


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


def _looks_like_a_credential(value: str) -> bool:
    """Whether *value*, found under a key-like name, is a credential and not a key of a keyboard, a column or a
    cache: ``_CREDENTIAL_CHARS`` characters or more, no white space, not written as a path, and a run of
    ``_CREDENTIAL_RUN`` or more letters and digits that holds both. A private key written as a PEM block is one
    too. One pass over at most ``_SCAN_CHARS`` characters."""
    text = value[:_SCAN_CHARS].strip()
    if _PEM_PRIVATE_KEY.search(text):
        return True
    if len(text) < _CREDENTIAL_CHARS or _WRITTEN_AS_A_PATH.match(text) or any(char.isspace() for char in text):
        return False
    return any(not run.isdigit() and not run.isalpha() for run in _MIXED_RUN.findall(text))


def _credential_by_name(name: Any, value: str) -> bool:
    """Whether a value called *name* (a setting, or a flag before it) is a key by this module's own lists: a name
    that can only be a credential's, or a key-like name with a value that looks like a credential."""
    leaf = str(name).lower().replace("-", "_")
    if leaf in _PUBLIC_NAMES or leaf.endswith(_PUBLIC_ENDINGS):
        return False
    if leaf in _CREDENTIAL_NAMES or leaf.endswith(_CREDENTIAL_ENDINGS):
        return True
    return (leaf in _KEY_NAMES or leaf.endswith(_KEY_ENDING)) and _looks_like_a_credential(value)


def _named_a_key(path: tuple, value: str) -> bool:
    """Whether the value at *path* is a key by its name: by Hermes's rule in the sections ``move_to_env`` moves,
    by this module's lists anywhere else. A value in a list has the name of the list."""
    if path[0] in SECTIONS:
        return _names_a_secret(path)
    return _credential_by_name(next((part for part in reversed(path) if isinstance(part, str)), ""), value)


def _after_a_secret_flag(config: dict, path: tuple, value: str) -> bool:
    """Whether the value at *path* is the argument of a flag that names a secret: ``["--api-key", "..."]`` for
    any value, ``["--key", "..."]`` for a value that looks like a credential."""
    if len(path) < 2 or not isinstance(path[-1], int) or path[-1] == 0:
        return False
    holder: Any = config
    for step in path[:-1]:
        holder = holder[step]
    before = holder[path[-1] - 1]
    flag = _FLAG.fullmatch(before.strip()) if isinstance(before, str) else None
    return flag is not None and _credential_by_name(flag.group(1), value)


def inline_keys(config: Any) -> list[dict]:
    """The keys written in the config document *config*, wherever they are: ``[{"path", "env", "key_env"}]``,
    ``path`` as a dotted place (``model.api_key``, ``custom_providers.0.api_key``, ``tts.openai.api_key``,
    ``mcp_servers.github.headers.Authorization``).

    What counts as a key is in the module's docstring. A key ``move_to_env`` moves (one in ``SECTIONS``, a key
    by its name) has ``env``, the variable it would move to. Every other key has an empty ``env``, ``by_hand``
    set and ``variable``, the name to give it in ``.env``.
    Two keys never get the same variable. No value is returned.

    A part of the document that is past what is looked at counts as well, with ``unread`` set beside ``by_hand``:
    a value longer than ``_SCAN_CHARS``, and the place where the walk stopped (``_strings``). What cannot be
    shown to hold no key keeps the switch off like a key."""
    if not isinstance(config, dict):
        return []
    found, taken = [], set()
    strings, stopped = _strings(config)
    for path, value in strings:
        if not value.strip() or is_reference(value) or _VAULT_REFERENCE.fullmatch(value.strip()):
            continue
        place = ".".join(str(part) for part in path)
        named = _named_a_key(path, value)
        shaped = any(shape.search(value[:_SCAN_CHARS]) for shape in _SECRET_SHAPES)
        if not (named or shaped or _after_a_secret_flag(config, path, value)):
            if len(value) > _SCAN_CHARS:
                found.append({"path": place, "env": "", "key_env": False, "by_hand": True, "unread": True})
            continue
        moved = named and path[0] in SECTIONS
        # (a key moved by hand gets a name made from the end of its place, short whatever the place is)
        variable, hint = _variable_for(config, path) if moved else (_slug(place[-_VARIABLE_CHARS:]), False)
        base, count = variable or "CONFIG_KEY", 1
        variable = base
        while variable in taken:
            count += 1
            variable = f"{base}_{count}"
        taken.add(variable)
        if moved:
            found.append({"path": place, "env": variable, "key_env": hint})
        else:
            found.append({"path": place, "env": "", "key_env": False, "by_hand": True, "variable": variable})
    if stopped is not None:
        found.append({"path": ".".join(str(part) for part in stopped), "env": "", "key_env": False, "by_hand": True,
                      "unread": True})
    return found


def _cut(name: str) -> str:
    """*name* as a sentence shows it: whole up to ``_NAME_CHARS`` characters, else its start and three dots."""
    return name if len(name) <= _NAME_CHARS else name[:_NAME_CHARS - 3] + "..."


def _listed(names: list) -> str:
    """*names* as one phrase: the first ``_NAMED`` of them, then how many more there are."""
    shown = list(names[:_NAMED])
    if len(names) > _NAMED:
        shown.append(f"{len(names) - _NAMED} more")
    return shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " and " + shown[-1]


def describe(items: Iterable[dict]) -> str:
    """The places of *items* as one phrase for a sentence. A key that is moved by hand says where it goes, and a
    part that was not looked through says so."""
    named = []
    for item in items:
        place = _cut(str(item["path"]))
        if item.get("unread"):
            place += " (too much there to check for keys)"
        elif item.get("by_hand") and item.get("variable"):
            place += " (move it by hand: {0} in .env, ${{{0}}} in config.yaml)".format(item["variable"])
        named.append(place)
    return _listed(named)


def config_copies(home) -> list[str]:
    """The names at the top of the profile home *home* that are a copy of ``config.yaml`` the sandbox can read:
    ``config.yaml`` with something after it, or wrapped the way an editor names its own file, without regard to
    case. The copies Hermes's own writers leave are not among them: those are hidden from the sandbox
    (``layout.credential_paths``). Sorted; [] when the folder cannot be listed."""
    from hermes_cli.profiles import profile_path_is_private

    try:
        with os.scandir(home) as entries:
            names = [entry.name for entry in entries if entry.is_file()]
    except OSError:
        return []
    return sorted(name for name in names
                  if _CONFIG_COPY.fullmatch(name.casefold()) and not profile_path_is_private((name,)))


def _nests_past(text: str, limit: int) -> bool:
    """Whether *text*, read as YAML, could nest more than *limit* levels: by brackets, by indentation, or by
    block markers in a row at the start of a line. Judged from the characters alone in one pass, so brackets in
    a quoted string count too."""
    depth = 0
    for char in text:
        if char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}" and depth:
            depth -= 1
    for line in text.splitlines():
        at, end, markers = len(line) - len(line.lstrip(" ")), len(line), 0
        if at > 4 * limit:
            return True
        while at + 1 < end and line[at] in "-?" and line[at + 1] == " ":
            markers, at = markers + 1, at + 2
            while at < end and line[at] == " ":
                at += 1
        if markers > limit:
            return True
    return False


def keys_in_copies(home) -> list[dict]:
    """The copies of ``config.yaml`` in *home* (``config_copies``) that keep the switch off:
    ``[{"file", "paths", "unread"}]``. One that holds a key has the places of its keys as ``inline_keys`` finds
    them. One that cannot be shown to hold none has ``unread`` set: a file that is not a config document (an
    editor's swap file), one over ``_COPY_BYTES`` or nested past ``_COPY_NESTING``, and every copy after the
    first ``_COPY_LIMIT`` or after ``_COPIES_BYTES`` in all. Never raises."""
    found = []
    try:
        import hermes_yaml

        names, left = config_copies(home), _COPIES_BYTES
        for name in names[:_COPY_LIMIT]:
            path, paths, unread = Path(home) / name, [], False
            try:
                size = path.stat().st_size
                text = path.read_text(encoding="utf-8-sig") if size <= min(_COPY_BYTES, left) else None
                if text is None or _nests_past(text, _COPY_NESTING):
                    unread = True
                else:
                    left -= size
                    document = hermes_yaml.safe_load(text)
                    paths = [item["path"] for item in inline_keys(document)]
                    unread = document is not None and not isinstance(document, dict)
            except Exception:  # not readable, not text, not YAML
                unread = True
            if paths or unread:
                found.append({"file": name, "paths": paths, "unread": unread and not paths})
        found += [{"file": name, "paths": [], "unread": True} for name in names[_COPY_LIMIT:]]
    except Exception:
        log.warning("the copies of config.yaml could not be looked through", exc_info=True)
    return found


def describe_copies(found: Iterable[dict]) -> str:
    """The refusal for copies of ``config.yaml`` that keep the switch off (``keys_in_copies``)."""
    found = list(found)
    names = _listed([_cut(str(item["file"])) for item in found])
    if len(found) == 1:
        what = (f"with a key in it ({_listed([_cut(str(place)) for place in found[0]['paths']])})" if found[0]["paths"]
                else "that can't be checked for keys")
        return (f"{names} in the profile folder is a copy of config.yaml {what}, and the sandbox could read it. "
                "Delete it or move it out of the profile folder first.")
    return (f"{names} in the profile folder are copies of config.yaml that hold a key or can't be checked for one, "
            "and the sandbox could read them. Delete them or move them out of the profile folder first.")


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
    """Move the keys *items* (rows of ``inline_keys`` that have an ``env``; every such key when None) from the
    ``config.yaml`` of the profile home *home* to its ``.env``. Returns the places moved. Call it with the
    sandbox off.

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
    current = {item["path"]: item for item in inline_keys(config) if item["env"]}  # a key moved by hand stays
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
