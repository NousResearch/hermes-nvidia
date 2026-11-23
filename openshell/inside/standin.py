"""A stand-in sign-in store for a sandboxed Hermes.

A profile that is signed in to a provider (Nous Portal, OpenAI Codex, xAI, MiniMax, Anthropic) keeps its tokens
in files in the profile home. Those tokens never enter the sandbox. Instead:

* On the host, ``build_template`` copies the shape of the sign-in files Hermes wrote and takes every secret out.
  It returns the template and the list of credentials the template refers to. The launcher registers one
  OpenShell provider per credential and records, in ``template["credentials"][id]["env"]``, the environment
  variable that holds that credential's placeholder inside the sandbox.
* Inside the sandbox, ``fill`` puts a JWT-shaped alias of each placeholder where the token was, so that Hermes
  finds itself signed in. OpenShell replaces the alias with the real token on requests to the provider's
  address, exactly as it replaces a placeholder.
* The sandbox's start command runs this module first::

      python -m <plugin package>.inside.standin -- <command...>

  It reads the template named by ``HERMES_OPENSHELL_STANDIN``, writes the stand-in files into the profile home,
  exports the aliases of tokens that live in environment variables, and then runs the command. Without
  ``HERMES_OPENSHELL_STANDIN`` it runs the command unchanged.

This module uses the standard library only. It imports nothing from Hermes and nothing from the launcher, so the
files are in place before any Hermes code runs.

What the template keeps
-----------------------

The template is derived from the store, not written per provider, so it follows the store when Hermes changes a
row. Numbers, booleans and nulls are copied. A string is copied only under a key in ``SAFE_KEYS``, and only when
it has the shape that key is known to hold. Every other string is left out, so a field a later Hermes adds can be
missing from the stand-in but can never carry a secret into it.

=====================================  ================================================================
Key                                    Why it holds no secret
=====================================  ================================================================
``token_type``                         The name of the HTTP authorization scheme (``Bearer``).
``scope``                              The names of the OAuth scopes that were granted.
``client_id``                          The public OAuth client id Hermes uses at that issuer.
``auth_mode``, ``auth_type``,          Short words Hermes writes itself to say how a row was signed in.
``auth_method``
``region``                             The provider region the user chose (``global``, ``cn``).
``source``                             Where a row came from (``device_code``, ``manual``).
``provider``, ``active_provider``      Provider ids.
``id``                                 The short random id of a row in the credential pool.
``label``                              The display name the Accounts page shows for a row.
``portal_base_url``,                   Service addresses. Kept only as plain http or https addresses
``inference_base_url``, ``base_url``   without user information, query or fragment.
``obtained_at``, ``last_refresh``,     Times of the last sign-in or refresh. Kept only when they parse as
``agent_key_obtained_at``,             a date and time.
``updated_at``
=====================================  ================================================================

Strings under ``TOKEN_KEYS`` become markers, strings under ``GRANT_KEYS`` (refresh grants) become the fixed word
``held-on-the-host``, and values under ``EXPIRY_KEYS`` become an expiry ten years after the sandbox starts. A
dictionary key itself is kept only when it is a short name (see ``_NAME``). A row of the credential pool whose
source is an environment variable is left out: Hermes rebuilds that row from the variable when it starts. The
lists under ``suppressed_sources`` (the row sources a user removed, per provider) are kept as plain words.
"""
from __future__ import annotations

import base64
import errno
import json
import math
import os
import re
import secrets
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

TEMPLATE_ENV = "HERMES_OPENSHELL_STANDIN"
HOME_ENV = "HERMES_HOME"
VERSION = 1
# The sign-in files of a profile home, and the provider a file belongs to when the file itself does not say.
STORE_FILES = {"auth.json": None, ".anthropic_oauth.json": "anthropic"}

PLACEHOLDER_PREFIX = "openshell:resolve:env:"
ALIAS_MARKER = "OPENSHELL-RESOLVE-ENV-"
# What OpenShell issues after the prefix: a stable handle or a revision, then the environment key.
_ISSUED = re.compile(r"(?:s[0-9a-f]{64}|v[0-9]+)_([A-Za-z0-9_]+)")
_ALIAS_HEADER = {"alg": "RS256", "typ": "JWT"}

NO_REFRESH = "held-on-the-host"
FAR_SECONDS = 10 * 365 * 24 * 3600
EXIT_START_ERROR = 78  # the start-up step could not prepare the sign-in store (EX_CONFIG)

TOKEN_KEYS = ("agent_key", "access_token", "accessToken")
GRANT_KEYS = ("refresh_token", "refreshToken", "anon_token")
EXPIRY_KEYS = ("expires_at", "agent_key_expires_at", "expires_at_ms", "expiresAt", "expires_in",
               "agent_key_expires_in")
SAFE_KEYS = {
    "token_type": "word", "scope": "word", "client_id": "word", "auth_mode": "word", "auth_type": "word",
    "auth_method": "word", "region": "word", "source": "word", "provider": "word", "active_provider": "word",
    "id": "word", "label": "text", "portal_base_url": "url", "inference_base_url": "url", "base_url": "url",
    "obtained_at": "time", "agent_key_obtained_at": "time", "last_refresh": "time", "updated_at": "time",
}
# Lists of plain words, by the top-level key they are under: the row sources a user removed, per provider.
SAFE_LISTS = {"suppressed_sources": "word"}
# The claims Hermes reads from a token it holds. Only these are copied from a real token into its alias.
CLAIMS_READ = ("scope", "scp", "sub", "org_id", "client_id", "product_id", "nous_client", "account_tier",
               "paid_access", "subscription_tier", "policy_present", "managed_tools", "tool_access")
# The account block of an OpenAI token, and the entries of it that Hermes reads.
_ACCOUNT_CLAIM = "https://api.openai.com/auth"
_ACCOUNT_CLAIM_KEYS = ("chatgpt_account_id", "chatgpt_data_residency", "chatgpt_compute_residency")

VALUE_BOUND = 24  # no string outside SAFE_KEYS in a template's files is longer than this
KEY_BOUND = 64  # no dictionary key in a template's files is longer than this
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,%d}" % KEY_BOUND)
_WORD = re.compile(r"[A-Za-z0-9_.:/@+ -]{1,128}")
_MARKER = re.compile(r"@@(alias|placeholder):([0-9]{1,4})@@")
_FAR = {"@@far:iso@@", "@@far:seconds@@", "@@far:ms@@", "@@far:epoch@@"}
_DROP = object()


class StandinError(Exception):
    """The stand-in store cannot be built. The message names the provider and holds no secret."""


# -- host: from the stores Hermes wrote to a template without secrets -------------------------------------------

def build_template(stores, env_tokens=(), *, without_grants=()):
    """Return ``(template, credentials)`` for the sign-in files in *stores*.

    *stores* maps a file name relative to the profile home (a key of ``STORE_FILES``) to its parsed JSON content,
    or to ``None`` when the profile has no such file (the start-up step then removes that file inside).
    *env_tokens* names the environment variables that carry a sign-in token (``ANTHROPIC_TOKEN``); a mapping
    may give each variable's provider id. *without_grants* names providers whose refresh grants are left out
    of the stand-in instead of becoming the fixed word: Hermes then has nothing to try a refresh with.

    ``template`` holds no secret. ``credentials`` has one entry per secret the template refers to: ``id``,
    ``provider``, ``field``, ``claims`` (what Hermes reads from that token, taken from the token itself),
    ``expires_at`` (seconds since the epoch, or ``None``), and ``file`` and ``path``, which say where the value
    is in *stores* (``credential_value`` reads it). The function is pure: the same stores give the same result.
    """
    unknown = sorted(name for name in stores if name not in STORE_FILES)
    if unknown:
        raise ValueError(f"not a sign-in file of a profile home: {', '.join(unknown)}")
    held = sorted({text for name in stores for text in _secrets_in(stores[name])}, key=len, reverse=True)
    found: list[dict] = []
    files: dict = {}
    for name in sorted(stores):
        doc = stores[name]
        if doc is None:
            files[name] = None
            continue
        if not isinstance(doc, dict):
            raise ValueError(f"{name} does not hold a JSON object")
        files[name] = _copy(doc, "", [], {"file": name, "held": held, "found": found, "row": None, "above": None,
                                          "no_grants": frozenset(without_grants)})
    by_value: dict = {}
    for place in found:
        by_value.setdefault(place["value"], []).append(place)
    credentials, taken = [], set()
    for value, places in by_value.items():
        first = min(places, key=_place_rank)
        ident = base = _place_id(first)
        count = 1
        while ident in taken:
            count += 1
            ident = f"{base}~{count}"
        taken.add(ident)
        entry = {"id": ident, "provider": first["provider"], "field": first["field"],
                 "claims": _claims_read(value), "expires_at": _expiry_of(value, first),
                 "file": first["file"], "path": list(first["path"])}
        for extra in ("source", "auth_type"):
            word = (first["row"] or {}).get(extra)
            if isinstance(word, str) and _WORD.fullmatch(word):
                entry[extra] = word
        credentials.append((entry, places))
    env_providers = dict(env_tokens) if isinstance(env_tokens, dict) else {name: None for name in env_tokens}
    exports: dict = {}
    for name in sorted(env_providers):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"not an environment variable name: {name!r}")
        credentials.append(({"id": f"env:{name}", "provider": env_providers[name], "field": name, "claims": {},
                             "expires_at": None, "file": None, "path": []}, [{"export": name}]))
    credentials.sort(key=lambda pair: pair[0]["id"])
    listed: dict = {}
    for number, (entry, places) in enumerate(credentials, 1):
        listed[entry["id"]] = {"marker": number, "provider": entry["provider"], "field": entry["field"],
                               "claims": entry["claims"]}
        for place in places:
            if "export" in place:
                exports[place["export"]] = f"@@alias:{number}@@"
            else:
                place["holder"][place["key"]] = f"@@{place['form']}:{number}@@"
    template = {"version": VERSION, "files": files, "env": exports, "credentials": listed}
    return template, [entry for entry, _ in credentials]


def credential_value(stores, credential):
    """The current value of *credential* (an entry ``build_template`` returned) in *stores*, or ``None``.

    For the launcher: this is the secret it registers with OpenShell, and reads again after a refresh.
    """
    node = stores.get(credential.get("file"))
    for step in credential.get("path") or [None]:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            return None
    return node if isinstance(node, str) and node else None


def without(template, ids):
    """A copy of *template* without the credentials *ids* and without the rows that need them.

    For a credential the launcher does not hand to the sandbox: the row that held it (a provider's row, one row
    of the credential pool, an exported variable, or a whole file) is left out, so Hermes inside does not find
    a sign-in it cannot use.
    """
    out = json.loads(json.dumps(template))
    numbers = {out["credentials"].pop(i)["marker"] for i in ids if i in out.get("credentials", {})}
    if not numbers:
        return out
    out["env"] = {name: text for name, text in out.get("env", {}).items()
                  if int(_MARKER.fullmatch(text).group(2)) not in numbers}
    for name, doc in list(out.get("files", {}).items()):
        rows = {_row_of(path) for path, text in _strings(doc, [])
                if _MARKER.fullmatch(text) and int(_MARKER.fullmatch(text).group(2)) in numbers}
        if () in rows:  # the file is one row: it has to be absent inside
            out["files"][name] = None
            continue
        for row in sorted(rows, key=lambda r: (len(r), r[-1] if isinstance(r[-1], int) else 0), reverse=True):
            holder = doc
            for step in row[:-1]:
                holder = holder[step]
            del holder[row[-1]]
    return out


def _row_of(path) -> tuple:
    """The row a place belongs to: a provider's row, one row of a list of rows, or the whole file."""
    if len(path) >= 4 and isinstance(path[2], int):
        return tuple(path[:3])
    return tuple(path[:2]) if len(path) >= 3 else ()


def _strings(node, path):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, [*path, key])
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _strings(value, [*path, index])
    elif isinstance(node, str):
        yield path, node


def _secrets_in(node, key=""):
    """Every token and refresh grant in a store, so that no kept string can repeat one."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield from _secrets_in(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from _secrets_in(value, key)
    elif isinstance(node, str) and len(node.strip()) >= 8 and key in TOKEN_KEYS + GRANT_KEYS:
        yield node.strip()


def _env_row(node) -> bool:
    """A row of the credential pool that mirrors an environment variable."""
    return isinstance(node, dict) and isinstance(node.get("source"), str) and node["source"].startswith("env:")


def _copy(node, key, path, state):
    """The template's copy of *node*: the same shape, with every string decided by the key it is under."""
    if isinstance(node, dict):
        out: dict = {}
        inner = {**state, "row": node, "above": state["row"]}
        for name, value in node.items():
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                continue
            kept = _copy_leaf(value, name, [*path, name], inner, out)
            if kept is not _DROP:
                out[name] = kept
        return out
    if isinstance(node, list):
        kept = [_copy(item, key, [*path, index], state) for index, item in enumerate(node) if not _env_row(item)]
        return [item for item in kept if item is not _DROP]
    return _copy_leaf(node, key, path, state, None)


def _copy_leaf(node, key, path, state, holder):
    if isinstance(node, (dict, list)):
        return _copy(node, key, path, state)
    if node is None or isinstance(node, bool):
        return node
    if key in EXPIRY_KEYS:
        if isinstance(node, str):
            return "@@far:iso@@"
        if key.endswith("_in"):
            return "@@far:seconds@@"
        return "@@far:ms@@" if key in ("expires_at_ms", "expiresAt") else "@@far:epoch@@"
    if isinstance(node, (int, float)):
        return node if math.isfinite(node) else _DROP
    if not isinstance(node, str):
        return _DROP
    if key in TOKEN_KEYS:
        if not node.strip():
            return ""
        if holder is None:  # a token directly in a list: no row to read its kind from
            return _DROP
        row = state["row"] or {}
        state["found"].append({
            "value": node.strip(), "file": state["file"], "path": path, "field": key, "holder": holder, "key": key,
            "row": row, "above": state["above"], "provider": _provider_of(state["file"], path),
            "form": "placeholder" if row.get("auth_type") == "api_key" else "alias"})
        return ""  # replaced by the marker once every credential has its number
    if key in GRANT_KEYS:
        if _provider_of(state["file"], path) in state["no_grants"]:
            return _DROP
        return NO_REFRESH if node.strip() else ""
    kind = SAFE_LISTS.get(path[0]) if holder is None else SAFE_KEYS.get(key)
    if kind is None or not _shaped(kind, node) or any(secret in node for secret in state["held"]):
        return _DROP
    return node


def _shaped(kind: str, text: str) -> bool:
    if text.startswith("@@") or len(text) > 512 or any(ord(ch) < 32 for ch in text):
        return False
    if kind == "word":
        return bool(_WORD.fullmatch(text))
    if kind == "text":
        return len(text) <= 128
    if kind == "time":
        return _epoch(text) is not None
    if kind == "url":
        try:
            parts = urlsplit(text)
            parts.port  # raises for a port that is not a number
            return (parts.scheme in ("http", "https") and bool(parts.hostname) and parts.username is None
                    and parts.password is None and not parts.query and not parts.fragment)
        except ValueError:
            return False
    return False


def _provider_of(file: str, path: list):
    if STORE_FILES.get(file):
        return STORE_FILES[file]
    return str(path[1]) if len(path) >= 3 else None


def _place_rank(place: dict) -> tuple:
    top = place["path"][0] if place["path"] else ""
    return (0 if top == "providers" else 2 if top == "credential_pool" else 1,
            TOKEN_KEYS.index(place["field"]), json.dumps(place["path"]))


def _place_id(place: dict) -> str:
    provider, path = place["provider"] or "store", place["path"]
    if len(path) >= 3 and isinstance(path[2], int):
        row = place["row"].get("id")
        row = row if isinstance(row, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,16}", row) else f"row{path[2]}"
        return f"{provider}:{row}:{place['field']}"
    return f"{provider}:{place['field']}"


def _jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _plain(value, depth: int = 0) -> bool:
    """A small JSON value: what a claim that carries account metadata looks like."""
    if value is None or isinstance(value, (bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value) <= 256
    if depth < 3 and isinstance(value, list):
        return len(value) <= 64 and all(_plain(item, depth + 1) for item in value)
    if depth < 3 and isinstance(value, dict):
        return len(value) <= 64 and all(isinstance(k, str) and len(k) <= 64 and _plain(v, depth + 1)
                                        for k, v in value.items())
    return False


def _claims_read(token: str) -> dict:
    """The claims of *token* that Hermes reads, and nothing else of its payload."""
    claims = _jwt_claims(token)
    out = {name: claims[name] for name in CLAIMS_READ if name in claims and _plain(claims[name])}
    account = claims.get(_ACCOUNT_CLAIM)
    if isinstance(account, dict):
        kept = {name: account[name] for name in _ACCOUNT_CLAIM_KEYS
                if isinstance(account.get(name), str) and len(account[name]) <= 256}
        if kept:
            out[_ACCOUNT_CLAIM] = kept
    return out


def _epoch(value):
    """Seconds since the epoch for a number (seconds or milliseconds) or a date and time, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1000.0 if value > 1e11 else float(value)
    if isinstance(value, str) and 8 <= len(value) <= 40:
        try:
            when = datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)
        except ValueError:
            return None
        return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).timestamp()
    return None


def _expiry_of(token: str, place: dict):
    exp = _jwt_claims(token).get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        return float(exp)
    names = ("agent_key_expires_at",) if place["field"] == "agent_key" else ("expires_at_ms", "expiresAt", "expires_at")
    for row in (place["row"], place["above"]):
        for name in names:
            when = _epoch((row or {}).get(name))
            if when is not None:
                return when
    return None


# -- inside: from the template and the environment to the stand-in files ----------------------------------------

def alias(placeholder: str, claims: dict) -> str:
    """The JWT-shaped alias of a placeholder OpenShell issued to this workload.

    ``base64url(header).base64url(claims).OPENSHELL-RESOLVE-ENV-<what follows the placeholder's prefix>``:
    the whole issued handle and environment key stay in the signature segment, as OpenShell documents for
    clients that parse JWT claims. The claims are local metadata; the alias is not a credential.
    """
    if not isinstance(placeholder, str) or not placeholder.startswith(PLACEHOLDER_PREFIX) \
            or not _ISSUED.fullmatch(placeholder[len(PLACEHOLDER_PREFIX):]):
        raise ValueError("not a placeholder OpenShell issued")
    return f"{_b64(_ALIAS_HEADER)}.{_b64(claims)}.{ALIAS_MARKER}{placeholder[len(PLACEHOLDER_PREFIX):]}"


def _b64(value) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8")).rstrip(b"=").decode("ascii")


def fill(template, environ, *, now=None):
    """Return ``(files, exports)``: the stand-in files and the variables to export, for *template*.

    ``files`` maps a file name to its JSON content (``None``: the file is to be absent); ``exports`` maps an
    environment variable to the alias it gets. Every marker becomes the alias of the placeholder found in the
    variable the launcher recorded for its credential, carrying the listed claims and an expiry ten years
    ahead; a place whose client does not parse the token gets the placeholder itself. Nothing is returned
    unless every credential has a well-formed placeholder: a missing one raises ``StandinError`` naming the
    provider.
    """
    if not isinstance(template, dict) or template.get("version") != VERSION:
        raise StandinError("the sign-in template is not one this version reads")
    now = time.time() if now is None else float(now)
    files, exports, listed = template.get("files"), template.get("env"), template.get("credentials")
    if not isinstance(files, dict) or not isinstance(exports, dict) or not isinstance(listed, dict):
        raise StandinError("the sign-in template is incomplete")
    for name in files:
        if name not in STORE_FILES:
            raise StandinError(f"the sign-in template names a file that is not a sign-in file: {name!r}")
    issued: dict = {}
    for ident in sorted(listed):
        entry = listed[ident] if isinstance(listed[ident], dict) else {}
        who = _who(ident, entry)
        number, variable, claims = entry.get("marker"), entry.get("env"), entry.get("claims")
        if not isinstance(number, int) or isinstance(number, bool) or number in issued or not isinstance(claims, dict):
            raise StandinError(f"the sign-in template is damaged at {who}")
        if not isinstance(variable, str) or not variable:
            raise StandinError(f"{who}: the launcher named no environment variable for its placeholder")
        value = environ.get(variable)
        if not value:
            raise StandinError(f"{who}: the environment variable {variable} holds no placeholder")
        key = _ISSUED.fullmatch(value[len(PLACEHOLDER_PREFIX):]) if value.startswith(PLACEHOLDER_PREFIX) else None
        if key is None or key.group(1).lower() != variable.lower():
            raise StandinError(f"{who}: the environment variable {variable} does not hold a placeholder "
                               f"OpenShell issued for it")
        issued[number] = (value, {**claims, "iat": int(now), "exp": int(now + FAR_SECONDS)}, who)
    far = {"@@far:iso@@": datetime.fromtimestamp(now + FAR_SECONDS, tz=timezone.utc).isoformat(),
           "@@far:seconds@@": FAR_SECONDS, "@@far:ms@@": int((now + FAR_SECONDS) * 1000),
           "@@far:epoch@@": int(now + FAR_SECONDS)}

    def filled(node):
        if isinstance(node, dict):
            return {key: filled(value) for key, value in node.items()}
        if isinstance(node, list):
            return [filled(item) for item in node]
        if isinstance(node, str) and node.startswith("@@"):
            if node in far:
                return far[node]
            mark = _MARKER.fullmatch(node)
            if mark is None or int(mark.group(2)) not in issued:
                raise StandinError("the sign-in template refers to a credential it does not list")
            placeholder, claims, _ = issued[int(mark.group(2))]
            return alias(placeholder, claims) if mark.group(1) == "alias" else placeholder
        return node

    out_files = {name: (None if doc is None else filled(doc)) for name, doc in files.items()}
    out_env = {}
    for name, text in exports.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not isinstance(text, str):
            raise StandinError("the sign-in template is damaged in its exported variables")
        out_env[name] = filled(text)
    return out_files, out_env


def _who(ident: str, entry: dict) -> str:
    provider = entry.get("provider")
    if isinstance(provider, str) and provider:
        return f"sign-in for {provider} ({ident})"
    return f"sign-in token {ident}"


# -- the start-up step ------------------------------------------------------------------------------------------

def install(template, home, environ=None, *, now=None) -> dict:
    """Write the stand-in files for *template* into the profile home *home*; return the variables to export.

    Everything is checked before the first file is touched. A file is written under a new name of its own and
    then moved over the final name, so whatever was there (a file, a link, a folder) is replaced and nothing
    is ever written through a link or outside *home*.
    """
    environ = os.environ if environ is None else environ
    files, exports = fill(template, environ, now=now)
    home = os.fspath(home)
    if not os.path.isdir(home):
        raise StandinError(f"the profile home is not a folder: {home}")
    for name in sorted(files):
        if files[name] is None:
            try:
                _clear(os.path.join(home, name))
            except OSError as exc:
                raise StandinError(f"could not remove {name} from the profile home: {exc.strerror or exc}") from exc
        else:
            _write(home, name, json.dumps(files[name], indent=2).encode("utf-8"))
    return exports


def _clear(path: str) -> None:
    """Remove whatever is at *path* without following it."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    # On Windows a link to a folder (a junction, a directory link) is a folder with a reparse point.
    attributes = getattr(info, "st_file_attributes", 0)
    linked = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    folder = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0)) if linked else stat.S_ISDIR(info.st_mode)
    if folder and not linked:
        shutil.rmtree(path)
    elif folder:
        os.rmdir(path)  # takes the link away, never what it points to
    else:
        try:
            os.unlink(path)
        except PermissionError:  # a read-only file on Windows
            os.chmod(path, stat.S_IWRITE)
            os.unlink(path)


def _write(home: str, name: str, data: bytes) -> None:
    final = os.path.join(home, name)
    fresh = os.path.join(home, f".{name.lstrip('.')}.{secrets.token_hex(8)}.new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(fresh, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(fresh, final)
            except OSError as exc:
                if exc.errno == errno.EBUSY:  # the name is a mounted file: it cannot be replaced, only rewritten
                    _rewrite(final, data)
                    os.unlink(fresh)
                    return
                _clear(final)  # a folder, or a link to one, stands where the file goes
                os.replace(fresh, final)
        except BaseException:
            try:
                os.unlink(fresh)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise StandinError(f"could not write {name} in the profile home: {exc.strerror or exc}") from exc


def _rewrite(path: str, data: bytes) -> None:
    """Write *data* into the regular file at *path* in place (a file mounted at that name)."""
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "wb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(errno.EPERM, "not a plain file")
        handle.truncate(0)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def prepare(environ=None) -> dict:
    """Read the template named by ``HERMES_OPENSHELL_STANDIN`` and install it; return the variables to export.

    Without that variable nothing is read or written and nothing is exported.
    """
    environ = os.environ if environ is None else environ
    path = environ.get(TEMPLATE_ENV)
    if not path:
        return {}
    try:
        with open(path, "rb") as handle:
            raw = handle.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("the file is too large")
        template = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise StandinError(f"could not read the sign-in template {path}: {exc}") from exc
    home = environ.get(HOME_ENV)
    if not home:
        raise StandinError(f"{HOME_ENV} is not set: the profile home is unknown")
    return install(template, home, environ)


def _same_interpreter(program: str) -> bool:
    names = {os.path.normcase(os.path.abspath(p)) for p in (sys.executable, getattr(sys, "_base_executable", None)) if p}
    return os.path.normcase(os.path.abspath(program)) in names


def _mode_for(command: list, system=None) -> str:
    """How the command runs so that the sandbox holds the processes it holds without this step.

    Where a program can replace itself (``exec``), it does: the process the sandbox started becomes the command.
    Windows has no such call, so a command of this interpreter (``python -m module ...``) runs in this very
    process, as ``python -m`` would run it; any other command runs as a child whose exit code is passed on.
    """
    if (system or os.name) != "nt":
        return "exec"
    if len(command) >= 3 and command[1] == "-m" and _same_interpreter(command[0]):
        return "inline"
    return "child"


def run(command: list, mode=None) -> int:
    """Run *command* with the current environment. Returns only when the command has ended (or never)."""
    mode = mode or _mode_for(command)
    sys.stdout.flush()
    sys.stderr.flush()
    if mode == "exec":
        os.execvp(command[0], command)
    if mode == "inline":
        import runpy

        # Leave no trace of this step in the interpreter the command starts in.
        package = __spec__.name.split(".")[0] if __spec__ else ""
        for name in [m for m in sys.modules if package and (m == package or m.startswith(package + "."))]:
            del sys.modules[name]
        here = os.path.dirname(os.path.abspath(__file__))
        if sys.path and os.path.abspath(sys.path[0] or os.getcwd()) == here:
            sys.path[0] = os.getcwd()
        sys.argv = [command[2], *command[3:]]
        runpy.run_module(command[2], run_name="__main__", alter_sys=True)
        return 0
    import signal
    import subprocess

    child = subprocess.Popen(command)
    passed = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK") if hasattr(signal, name)]
    before = {}
    for number in passed:
        try:
            before[number] = signal.signal(number, lambda received, _frame: _pass_on(child, received))
        except (OSError, ValueError):
            pass
    try:
        code = child.wait()
    finally:
        for number, handler in before.items():
            signal.signal(number, handler)
    if code < 0 and os.name != "nt":  # the command was ended by a signal: end the same way
        signal.signal(-code, signal.SIG_DFL)
        os.kill(os.getpid(), -code)
    return code


def _pass_on(child, number) -> None:
    try:
        if os.name == "nt":
            child.terminate()
        else:
            child.send_signal(number)
    except OSError:
        pass


def main(argv=None, mode=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[argv.index("--") + 1:] if "--" in argv else []
    if not command:
        print("usage: python -m <plugin package>.inside.standin -- <command...>", file=sys.stderr)
        return 2
    try:
        exports = prepare()
    except StandinError as exc:
        print(f"sandbox start: the sign-in store could not be prepared: {exc}", file=sys.stderr, flush=True)
        return EXIT_START_ERROR
    os.environ.update(exports)
    try:
        return run(command, mode)
    except OSError as exc:
        print(f"sandbox start: could not run {command[0]}: {exc.strerror or exc}", file=sys.stderr, flush=True)
        return 127 if isinstance(exc, FileNotFoundError) else 126


if __name__ == "__main__":
    sys.exit(main())
