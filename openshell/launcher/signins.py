"""Sign-ins of a sandboxed profile, kept current on this computer.

A profile that is signed in to a provider (Nous Portal, OpenAI Codex, xAI, MiniMax, Hermes's own Anthropic
sign-in) holds a short-lived token and the grant that renews it. The sandbox gets neither. It holds a placeholder;
the launcher hands the short-lived token to the sandbox driver, which puts it on requests to the provider's
addresses, and renews it here, on the host, with Hermes's own code.

* ``report`` says, before the switch, which of the profile's providers work in the sandbox.
* ``SignIns.declare`` asks Hermes for each sign-in's current token, its expiry and the addresses it travels to,
  and hands it to the driver's ``CredentialSink``. The addresses are the ones the profile's model needs. A
  sign-in whose token Hermes's tools also present (Nous Portal: the tool gateway) is bound to a tool's host only
  once the user approved that tool's category in a chat (categories.py); ``SignIns.rebind`` declares it again
  with the hosts of the categories approved by then, before a sandbox starts again.
* ``SignIns.step`` (``run`` calls it in a loop) renews each token ahead of its expiry and replaces the value in
  the sink at a moment no reply is streaming; at the last moment before the expiry it replaces it anyway. How
  often a sign-in is renewed does not rest on what its token says: two renewals are never closer than a floor,
  the wait grows while an issuer answers with nothing usable, and past a count within an hour the sign-in is left
  alone and reads as expired (the numbers and their reasons are beside ``MIN_BETWEEN_RENEWALS``).
* ``SignIns.for_start`` settles, before every sandbox start, which declared sign-ins that sandbox gets. One
  that has ended, or whose token ran out with nothing newer to hand over, is left out: the sandbox starts
  without it and Hermes inside reads as not signed in to that provider, instead of the start failing on a
  credential OpenShell withholds.
* ``copy_states`` and ``settled`` are what the pins need to give the sign-in files back to the profile when the
  sandbox is switched off.

Every call into Hermes runs with the launcher's host-only copy of the profile's stores bound as the Hermes home
(``bound``), never with the profile's own home. Hermes writes a renewed sign-in into the store it read it from,
so the copy holds the newest refresh token from the moment the issuer answered, and a launcher that is killed
right after leaves a copy that still signs in. The copy is the live sign-in while the sandbox is on; the file in
the profile's home goes stale and is replaced by the copy at switch-off.

What a call reads and writes outside the copy:

* Every Nous Portal renewal takes part in Hermes's shared Nous store (``shared/nous_auth.json`` in the Hermes
  root, with its lock). A named profile that signed in to Nous Portal on a computer whose default profile is
  signed in holds the same grant as that profile: Hermes keeps it in each profile's own ``auth.json`` and in the
  shared store. Whichever Hermes renews writes the new pair to its own store and to the shared one; every other
  Hermes takes it from there at its next renewal and never presents its own, spent refresh token. The engine is
  one of them, over the copy: a pair the default profile's Hermes renewed is taken instead of renewing, and a
  pair renewed here is written to the shared store, where that Hermes finds it. Neither signs the other out.
* A profile without its own Nous Portal or OpenAI Codex sign-in uses the default profile's, as Hermes does
  everywhere. Hermes then reads and renews that sign-in in the Hermes root's ``auth.json``, under that store's
  own lock (``auth.lock`` beside it), which every Hermes on this computer takes for the same step. The copy never
  receives it.
* When Hermes loads a sign-in's credential pool it takes the root store's lock and reads the root's ``auth.json``
  and ``.anthropic_oauth.json``, looking for a grant that the bound home and the root both hold (the same pair in
  both, or a row copied with a cloned profile). If it finds one it keeps the newer pair in the root and drops the
  copy's row, and the profile uses the default profile's sign-in from then on. The engine follows (``_placed``):
  the sign-in is renewed in the root's ``auth.json`` from there, and the copy that goes back at switch-off has
  no row for it, as the profile's own store would have none had Hermes folded the grant there.

Sign-ins kept by another program (Claude Code, the Codex CLI) are not read while the copy is bound: the copy's
``config.yaml`` turns that off (``write_copy_config``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urlsplit

from . import categories
from .credential_sink import CredentialDecl, CredentialSink, Endpoint

log = logging.getLogger("openshell.signins")

# The sign-in files of a profile home. The pins copy them at switch-on and put them back at switch-off.
SIGN_IN_FILES = ("auth.json", ".anthropic_oauth.json")
CONFIG_FILE = "config.yaml"
# The parts of the profile's config.yaml Hermes reads to answer which provider a model route uses.
CONFIG_SECTIONS = ("model", "fallback_providers", "fallback_model", "auxiliary", "providers", "custom_providers",
                   "nous", "credential_pool_strategies")

# The schedule. Hermes's own keepalive looks at a Nous token four times per lifetime and renews it once it would
# not outlive the next look plus its two-minute lead (hermes_cli/nous_auth_keepalive.py); the same margins apply
# here to every sign-in.
REFRESH_LEAD = 120.0  # Hermes renews two minutes before an expiry on its own request path
LOOKS_PER_LIFETIME = 4
SHORTEST_LOOK = 60.0
LONGEST_LOOK = 900.0
ASSUMED_LIFETIME = 900.0  # planned for a token that does not say when it expires
QUIET_POLL = 2.0  # how often a due renewal asks the sink whether a reply is streaming
BACKOFF = (5.0, 10.0, 20.0, 40.0, 60.0)  # waits after a failed renewal; the last one repeats
UPDATE_RETRY = 2.0  # wait after the sink refused a value
LONGEST_SLEEP = 60.0

# How often one sign-in is renewed, whatever its token and its issuer say. A token decides when it is due, and a
# token can be wrong: it can arrive already expired (an issuer's fault, or this computer's clock ahead of the
# issuer's by more than the token lasts), last a few seconds, or be the one that was to be replaced. Renewing
# when the token says so would then mean asking the issuer again at once, each time with a new grant, for as long
# as the sandbox is on. Every wait and count that keeps that from happening is here.
#
# The floor between two renewals of one sign-in. The shortest token the schedule carries without a gap lasts a
# minute (SHORTEST_LOOK) and is due at half its life, thirty seconds after it arrived; five seconds less than that
# leaves room for the request itself. By this number alone a sign-in is renewed 144 times an hour at most.
MIN_BETWEEN_RENEWALS = 25.0
# The longest of the growing waits below: ten minutes, six requests an hour, which is what a fifteen-minute
# token asks of its issuer anyway. A sign-in whose issuer keeps answering with nothing usable is asked that
# often and no more, and is back to normal with the first token that lasts.
LONGEST_WAIT = 600.0
# The ceiling: attempts to renew one sign-in within any hour, failed ones included. An attempt is one call of
# Hermes's own refresh, which asks the issuer once (its Anthropic refresh asks a second address when the first
# one fails). A one-minute token is renewed 120 times an hour and the floor allows 144; 150 is above both, so the
# schedule alone never reaches it. Failed attempts on top of renewals do, or a fault in this module. Past it the
# sign-in is not asked about again by this engine (a new one is made when the sandbox is turned off and on) and
# its row reads as expired.
MOST_RENEWALS_PER_HOUR = 150
# The same ceiling for values offered to the sink: one per renewal, so the same number.
MOST_UPDATES_PER_HOUR = 150
HOUR = 3600.0
# The least a pass answers as the wait until the next one, so that the loop that calls ``step`` cannot spin
# whatever went wrong inside a pass.
SHORTEST_PASS = 1.0

# What a value must have left when a sandbox start is prepared, to be handed to that sandbox. OpenShell's gateway
# withholds a value that has run out by the time the sandbox asks for it, and by the time the launcher asks
# whether it arrived: the stand-in sign-in store would then name a credential the sandbox never got, and the
# start would fail. A start with its question takes well under a minute; a value the schedule keeps current has
# two minutes left or more (``last_moment``). For a token that lasts less than eight minutes it is an eighth of
# the lifetime, which stays below the quarter at which the schedule replaces such a token whatever streams.
START_MARGIN = 60.0

WORKS = "works"
NEEDS_SIGN_IN = "needs_sign_in"
NOT_AVAILABLE = "not_available"
KEY = "key"  # a provider that uses a key: the key discovery decides, not this module

_SENTENCES = {
    "signed_in": "Signed in. Kept signed in on this computer; the sandbox holds a placeholder.",
    "signed_in_shared": ("Signed in with the default profile's sign-in. Kept signed in on this computer; the "
                         "sandbox holds a placeholder."),
    "not_signed_in": "Not signed in. Sign in to {label} with the sandbox off.",
    "expired": "Sign-in expired. Sign in again.",
    "shared_not_carried": ("{label} is signed in for the default profile, not for this one. Sign in for this "
                           "profile with the sandbox off."),
    "own_program": "Not available in the sandbox: {label} signs in through its own program.",
    "outside_profile": "Not available in the sandbox: {label} keeps its sign-in in a file outside this profile.",
    "claude_code": ("Not available in the sandbox: {label} is signed in through Claude Code, which keeps its "
                    "sign-in outside this profile."),
    "cloud_sdk": "Not available in the sandbox: {label} signs in through a cloud SDK on this computer.",
    "not_carried": "Not available in the sandbox: the {label} sign-in is not carried into the sandbox yet.",
    "unknown": "Not available in the sandbox: this Hermes does not know the provider \"{label}\".",
    "retrying": "Couldn't reach {label} to renew the sign-in. Trying again.",
    "lapsed": "The {label} sign-in could not be renewed in time. The model answers again once it is renewed.",
}
_EXPIRED_ACTION = "Turn the sandbox off, sign in to {label}, then turn it on again."


class Unavailable(RuntimeError):
    """This Hermes cannot be asked: it is not importable, or it lacks a call this module needs."""


class NotACopy(ValueError):
    """The folder is a profile's own home. A renewal made there would leave the launcher's copy with a spent
    refresh token."""


# -- Hermes -----------------------------------------------------------------------------------------

def _core() -> SimpleNamespace:
    """The Hermes modules this module calls, imported when first needed."""
    try:
        import hermes_constants
        from agent import anthropic_credentials, credential_pool, runtime_scope
        from hermes_cli import auth, auth_nous, config
    except ImportError as exc:
        raise Unavailable(f"Hermes is not importable: {exc}") from None
    return SimpleNamespace(auth=auth, auth_nous=auth_nous, config=config, constants=hermes_constants,
                           pool=credential_pool, anthropic=anthropic_credentials, runtime_scope=runtime_scope,
                           AuthError=auth.AuthError)


_METADATA_OFF = "AWS_EC2_METADATA_DISABLED"
_metadata_lock = threading.Lock()
_metadata_users = 0
_metadata_before: Optional[str] = None


@contextmanager
def no_metadata_lookup() -> Iterator[None]:
    """Run a body in which no call into Hermes asks the cloud metadata address.

    Hermes finds the provider of a profile that names none by looking at what this computer has. The last place
    it looks is the AWS credential chain, which ends by asking the instance metadata address (169.254.169.254)
    and, on a computer that is not a cloud machine, waiting for that to time out. Nothing this module asks
    Hermes needs that answer, so that one step is left out for the length of the body, with the variable AWS's
    own library reads. AWS keys and profiles kept on this computer are still found; a cloud machine's own role
    is not. The variable is the process's: bodies in several threads share one setting, and the user's own value
    is put back when the last of them ends."""
    global _metadata_users, _metadata_before
    with _metadata_lock:
        if _metadata_users == 0:
            _metadata_before = os.environ.get(_METADATA_OFF)
            os.environ[_METADATA_OFF] = "true"
        _metadata_users += 1
    try:
        yield
    finally:
        with _metadata_lock:
            _metadata_users -= 1
            if _metadata_users == 0:
                if _metadata_before is None:
                    os.environ.pop(_METADATA_OFF, None)
                else:
                    os.environ[_METADATA_OFF] = _metadata_before


@contextmanager
def bound(home) -> Iterator[SimpleNamespace]:
    """Run a body with *home* bound as the Hermes home: its stores, its env file as the secret scope, and no
    secret source and no command started for it. Nothing in the body asks the cloud metadata address."""
    core = _core()
    with no_metadata_lookup(), core.runtime_scope.bind_profile_scope(str(home), hydrate_secrets=False):
        yield core


def _same(left, right) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve()
    except OSError:
        return Path(left) == Path(right)


def _refuse_profile_home(core, copy: Path) -> None:
    """A renewal never runs bound to a profile's own home."""
    process_home = core.constants.get_process_hermes_home()
    root = core.constants.get_default_hermes_root()
    if _same(copy, process_home) or _same(copy, root) or _same(copy.parent, Path(root) / "profiles"):
        raise NotACopy(f"{copy} is a profile's home; sign-ins are renewed in the launcher's copy only")


# -- small readers ------------------------------------------------------------------------------------

def _claims(token: Any) -> dict:
    """The claims of a token in JWT shape, unverified; {} for any other token."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        return {}
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return {}
    return claims if isinstance(claims, dict) else {}


def _token_expiry(token: Any) -> Optional[float]:
    exp = _claims(token).get("exp")
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _epoch(value: Any) -> Optional[float]:
    """Seconds since the epoch for an ISO time or a number; None when there is none."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    from datetime import datetime, timezone

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def _plain(exc: BaseException) -> str:
    """An error as one short line for a log or a status row. Hermes's sign-in errors carry no token."""
    text = str(exc).strip().splitlines()[0][:200] if str(exc).strip() else ""
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _endpoints(urls) -> tuple[Endpoint, ...]:
    """One endpoint per distinct host and port of *urls*, in order."""
    seen, out = set(), []
    for url in urls:
        parts = urlsplit(str(url or ""))
        if not parts.hostname:
            continue
        port = parts.port or (80 if parts.scheme == "http" else 443)
        if (parts.hostname, port) not in seen:
            seen.add((parts.hostname, port))
            out.append(Endpoint(host=parts.hostname, port=port))
    return tuple(out)


def _uses(core, sign_in, token, approved) -> list[tuple[Endpoint, str]]:
    """Every address *sign_in*'s token may be used at, each with what it is for: ``model``, or the id of the
    approved tool category whose gateway host it is. One row per address; the model's come first."""
    out: list[tuple[Endpoint, str]] = []
    seen = set()
    for endpoint in _endpoints(sign_in.urls(core, token)):
        seen.add((endpoint.host, endpoint.port))
        out.append((endpoint, "model"))
    if sign_in.tools:
        for category in categories.CATEGORIES:
            if category.id not in approved:
                continue
            for host, port in categories.gateway_endpoints(category):
                if (host, port) not in seen:
                    seen.add((host, port))
                    out.append((Endpoint(host=host, port=port), category.id))
    return out


def _hosts(uses) -> list[dict]:
    return [{"host": endpoint.host, "port": endpoint.port, "use": use} for endpoint, use in uses]


# -- the sign-ins this module carries -------------------------------------------------------------------

@dataclass(frozen=True)
class Token:
    """A sign-in's current token as Hermes resolved it."""
    value: str
    expires_at: Optional[float]
    base_url: str = ""
    taken_at: float = 0.0


class _Refused(Exception):
    """A renewal Hermes reported without raising. ``gone``: the user must sign in again."""

    def __init__(self, text: str, gone: bool):
        super().__init__(text)
        self.gone = gone


class _SignIn:
    """One provider's sign-in, through Hermes's own functions. Every method runs inside ``bound``."""
    provider = ""
    field = "access_token"
    file = "auth.json"
    # Whether the default profile's sign-in may be used. Only where Hermes renews it under the lock of the store
    # it came from: two Hermes processes then never spend the same refresh token.
    shared_ok = False
    claims: tuple[str, ...] = ()
    default_url = ""
    # Whether Hermes's tools present this sign-in's token at the Nous tool gateway. Its hosts are bound per
    # tool category, once the user approved the category (categories.py).
    tools = False

    @property
    def id(self) -> str:
        return f"{self.provider}:{self.field}"

    def label(self, core) -> str:
        row = core.auth._registry_lookup(self.provider)
        return str(getattr(row, "name", "") or self.provider)

    def state(self, core) -> tuple[Optional[dict], Optional[Path]]:
        """The stored sign-in and the file it is in (the bound home's, else the Hermes root's). Reads only."""
        state, source = core.auth._load_provider_state_with_source(core.auth._load_auth_store(), self.provider)
        return (state, Path(source)) if isinstance(state, dict) and source is not None else (None, None)

    def used(self, core) -> bool:
        """Whether Hermes would use this sign-in for the provider at all."""
        return True

    def signed_in(self, state: dict) -> bool:
        tokens = state.get("tokens")
        return isinstance(tokens, dict) and bool(tokens.get("access_token")) and bool(tokens.get("refresh_token"))

    def stored(self, core) -> Optional[Token]:
        """The token as it is stored now: nothing is renewed and nothing is written."""
        raise NotImplementedError

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        """The current token. *renew* False: Hermes renews only when it finds the token about to expire.
        *renew* True: a renewal at the issuer, unless another Hermes already replaced *stale* in the store."""
        raise NotImplementedError

    def gone(self, core, exc: BaseException) -> bool:
        """Whether *exc* means the grant is gone and the user must sign in again."""
        if isinstance(exc, _Refused):
            return exc.gone
        return isinstance(exc, core.AuthError) and bool(getattr(exc, "relogin_required", False))

    def urls(self, core, token: Token) -> list[str]:
        """Where the profile's model sends this token: the provider's inference address."""
        return [token.base_url or self.default_url]


class _Nous(_SignIn):
    """Only the inference host is the model's. Inside the sandbox Hermes reads the account from the token it
    holds and asks the Portal for nothing a reply needs, so the Portal's host is not bound."""
    provider = "nous"
    field = "agent_key"
    shared_ok = True
    tools = True
    claims = ("scope", "scp", "exp", "sub", "org_id", "client_id", "product_id", "nous_client", "policy_present",
              "paid_access", "subscription_tier", "tool_access", "account_tier", "managed_tools")
    default_url = "https://inference-api.nousresearch.com/v1"

    def signed_in(self, state: dict) -> bool:
        return bool(state.get("refresh_token")) and bool(state.get("access_token") or state.get("agent_key"))

    def stored(self, core) -> Optional[Token]:
        state, _ = self.state(core)
        value = (state or {}).get("agent_key") or (state or {}).get("access_token")
        if not value:
            return None
        expires = _epoch(state.get("agent_key_expires_at")) or _token_expiry(value) or _epoch(state.get("expires_at"))
        return Token(str(value), expires, str(state.get("inference_base_url") or self.default_url))

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        creds = core.auth.resolve_nous_runtime_credentials(force_refresh=renew,
                                                           stale_access_token=stale if renew else None)
        value = str(creds["api_key"])
        return Token(value, _epoch(creds.get("expires_at")) or _token_expiry(value), str(creds.get("base_url") or ""))


class _Codex(_SignIn):
    provider = "openai-codex"
    shared_ok = True
    claims = ("exp", "https://api.openai.com/auth")
    default_url = "https://chatgpt.com/backend-api/codex"

    def _token(self, creds: dict) -> Token:
        value = str(creds["api_key"])
        return Token(value, _token_expiry(value), str(creds.get("base_url") or ""))

    def stored(self, core) -> Optional[Token]:
        try:
            return self._token(core.auth.resolve_codex_runtime_credentials(read_only=True))
        except core.AuthError:
            return None

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        return self._token(core.auth.resolve_codex_runtime_credentials(force_refresh=renew))


class _Xai(_SignIn):
    provider = "xai-oauth"
    claims = ("exp",)
    default_url = "https://api.x.ai/v1"

    def _token(self, creds: dict) -> Token:
        value = str(creds["api_key"])
        return Token(value, _token_expiry(value), str(creds.get("base_url") or ""))

    def stored(self, core) -> Optional[Token]:
        try:
            return self._token(core.auth.resolve_xai_oauth_runtime_credentials(refresh_if_expiring=False))
        except core.AuthError:
            return None

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        return self._token(core.auth.resolve_xai_oauth_runtime_credentials(force_refresh=renew))


class _MiniMax(_SignIn):
    provider = "minimax-oauth"
    default_url = "https://api.minimax.io/anthropic"

    def signed_in(self, state: dict) -> bool:
        return bool(state.get("access_token")) and bool(state.get("refresh_token"))

    def _token(self, state: dict) -> Token:
        return Token(str(state["access_token"]), _epoch(state.get("expires_at")),
                     str(state.get("inference_base_url") or self.default_url))

    def stored(self, core) -> Optional[Token]:
        state, _ = self.state(core)
        return self._token(state) if state and state.get("access_token") else None

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        if not renew:
            core.auth.resolve_minimax_oauth_runtime_credentials()
            return self.stored(core)
        # Hermes's own renewal, forced, with the steps its resolver takes around it: the store's lock for the
        # whole exchange, and the dead tokens cleared when the grant is gone.
        with core.auth._auth_store_lock(timeout_seconds=max(core.auth.AUTH_LOCK_TIMEOUT_SECONDS, 20.0)):
            state = core.auth.get_provider_auth_state(self.provider)
            if not state or not state.get("access_token"):
                raise _Refused("not signed in", gone=True)
            from hermes_cli import auth_minimax

            try:
                return self._token(auth_minimax._refresh_minimax_oauth_state(state, force=True))
            except core.AuthError as exc:
                auth_minimax._minimax_oauth_quarantine_on_terminal_refresh(state, exc)
                raise


class _Anthropic(_SignIn):
    """Hermes's own Anthropic sign-in (``.anthropic_oauth.json`` in the home), renewed through Hermes's
    credential pool. A sign-in borrowed from Claude Code lives outside the profile and is not carried."""
    provider = "anthropic"
    field = "oauth_token"
    file = ".anthropic_oauth.json"
    default_url = "https://api.anthropic.com"
    _ENV = ("ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")

    def state(self, core) -> tuple[Optional[dict], Optional[Path]]:
        own = core.anthropic.read_hermes_oauth_credentials()
        if own:
            return own, Path(core.anthropic._get_hermes_oauth_file())
        root = core.anthropic._root_hermes_oauth_file()
        try:
            shared = json.loads(Path(root).read_text(encoding="utf-8")) if root else None
        except (OSError, ValueError):
            shared = None
        if isinstance(shared, dict) and shared.get("accessToken"):
            return shared, Path(root)
        return None, None

    def used(self, core) -> bool:
        """Hermes uses its Anthropic sign-in only for a profile set up for Anthropic, and never beside a key or
        a token in the env file (those go into the sandbox as keys)."""
        if any(core.config.get_env_value(name) for name in self._ENV):
            return False
        return bool(core.auth.is_provider_explicitly_configured(self.provider))

    def signed_in(self, state: dict) -> bool:
        return bool(state.get("accessToken")) and bool(state.get("refreshToken"))

    def stored(self, core) -> Optional[Token]:
        state, _ = self.state(core)
        if not state or not state.get("accessToken"):
            return None
        expires = state.get("expiresAt")
        return Token(str(state["accessToken"]), float(expires) / 1000.0 if isinstance(expires, (int, float)) else None,
                     self.default_url)

    def _entry(self, core):
        pool = core.pool.load_pool(self.provider)
        return pool, next((entry for entry in pool.entries() if entry.source == "hermes_pkce"), None)

    def resolve(self, core, *, renew: bool, stale: Optional[str]) -> Token:
        pool, entry = self._entry(core)
        if entry is None or not entry.access_token:
            raise _Refused("not signed in", gone=True)
        expires = float(entry.expires_at_ms) / 1000.0 if entry.expires_at_ms else None
        if renew or (expires is not None and expires - time.time() <= REFRESH_LEAD):
            renewed = pool.try_refresh_matching(credential_id=entry.id)
            if renewed is None:
                left = next((row for row in pool.entries() if row.id == entry.id), None)
                dead = left is None or left.last_status == getattr(core.pool, "STATUS_DEAD", "dead")
                raise _Refused("the renewal was refused" if dead else "the renewal did not go through", gone=dead)
            entry = renewed
            expires = float(entry.expires_at_ms) / 1000.0 if entry.expires_at_ms else None
        return Token(str(entry.access_token), expires, self.default_url)


SIGN_INS: tuple[_SignIn, ...] = (_Nous(), _Codex(), _Xai(), _MiniMax(), _Anthropic())
_BY_PROVIDER = {sign_in.provider: sign_in for sign_in in SIGN_INS}


def _look(core, sign_in: _SignIn, home: Path) -> Optional[dict]:
    """What stands in the bound home for *sign_in*, without renewing or writing anything. None when the profile
    has no such sign-in and Hermes would not use one."""
    state, source = sign_in.state(core)
    label = sign_in.label(core)
    row = {"provider": sign_in.provider, "label": label, "kind": "sign_in", "shared": False, "file": sign_in.file}
    if state is None or not sign_in.used(core):
        return None
    shared = not _same(source, Path(home) / sign_in.file)
    row["shared"] = shared
    if not sign_in.signed_in(state):
        expired = isinstance(state.get("last_auth_error"), dict)
        return {**row, "state": NEEDS_SIGN_IN, "reason": "expired" if expired else "not_signed_in"}
    if shared and not sign_in.shared_ok:
        return {**row, "state": NEEDS_SIGN_IN, "reason": "shared_not_carried"}
    return {**row, "state": WORKS, "reason": "signed_in_shared" if shared else "signed_in"}


def _sentence(row: dict) -> dict:
    text = _SENTENCES.get(row.get("reason") or "", "")
    out = {**row, "sentence": text.format(label=row.get("label") or row.get("provider"))}
    if row.get("reason") == "expired":
        out["action"] = _EXPIRED_ACTION.format(label=row.get("label") or row.get("provider"))
    return out


# -- the report before the switch -----------------------------------------------------------------------

def _routes(core) -> dict[str, list[str]]:
    """The provider each model route of the bound home names, as Hermes reads them: the main model, the fallback
    chain and every auxiliary task set to a provider of its own. ``{provider as named: [where it is used]}``."""
    named: dict[str, list[str]] = {}

    def add(name: Any, where: str) -> None:
        name = str(name or "").strip().lower()
        if name:
            named.setdefault(name, []).append(where)

    from agent.auxiliary_client import _resolve_task_provider_model
    from hermes_cli import fallback_config, runtime_provider

    add(runtime_provider.resolve_requested_provider(), "model")
    try:
        config = core.config.load_config_readonly() or {}
    except Exception as exc:
        log.warning("could not read the model routes: %s", _plain(exc))
        config = {}
    for position, entry in enumerate(fallback_config.get_fallback_chain(config), 1):
        add(entry.get("provider"), f"fallback {position}")
    auxiliary = config.get("auxiliary")
    for task in sorted(auxiliary) if isinstance(auxiliary, dict) else ():
        provider = _resolve_task_provider_model(task)[0]
        if provider and provider != "auto":
            add(provider, f"auxiliary {task}")
    return named


def _other(core, provider: str) -> dict:
    """A provider this module does not carry: a key (the key discovery decides) or one the sandbox cannot use."""
    row = core.auth._registry_lookup(provider)
    label = str(getattr(row, "name", "") or provider)
    kind = str(getattr(row, "auth_type", "") or "")
    out = {"provider": provider, "label": label, "kind": "key", "shared": False, "state": KEY, "reason": "key"}
    if provider == "anthropic":
        if any(core.config.get_env_value(name) for name in _Anthropic._ENV):
            return out
        if core.anthropic.claude_code_credentials_path().is_file():  # its presence only; the file is not read
            return {**out, "kind": "sign_in", "state": NOT_AVAILABLE, "reason": "claude_code"}
        return out
    if provider == "qwen-oauth":
        return {**out, "kind": "sign_in", "state": NOT_AVAILABLE, "reason": "outside_profile"}
    if kind == "external_process":
        return {**out, "kind": "program", "state": NOT_AVAILABLE, "reason": "own_program"}
    no_key = provider == "azure-foundry" and not core.config.get_env_value("AZURE_FOUNDRY_API_KEY")
    if kind in ("aws_sdk", "vertex") or no_key:
        return {**out, "kind": "cloud_sdk", "state": NOT_AVAILABLE, "reason": "cloud_sdk"}
    if kind.startswith("oauth"):
        return {**out, "kind": "sign_in", "state": NOT_AVAILABLE, "reason": "not_carried"}
    return out


def report(home, approved=()) -> list[dict]:
    """One row per provider the profile in *home* uses, for the Sandbox page to show before the switch (bound to
    the profile's home) or while the sandbox is on (bound to the launcher's copy). Nothing is renewed and nothing
    is written. *approved*: the ids of the tool categories whose approval is saved for the profile.

    A row: ``provider``, ``label``, ``used_by`` (the model routes that name it), ``state`` and ``sentence``. A
    sign-in that works also has ``hosts``: every address its token would be used at (``{host, port, use}``).
    ``state`` is ``works``, ``needs_sign_in`` (with ``action`` when there is more to say), ``not_available``, or
    ``key`` for a provider that uses a key, which the key discovery decides (no sentence)."""
    home = Path(home)
    with bound(home) as core:
        used: dict[str, list[str]] = {}
        rows: list[dict] = []
        for name, where in _routes(core).items():
            try:
                provider = core.auth.resolve_provider(name)
            except Exception as exc:
                from hermes_cli.runtime_provider import has_named_custom_provider

                if name == "auto" or has_named_custom_provider(name):
                    continue  # nothing set up yet, or a saved endpoint with a key
                log.info("provider %r is not known to this Hermes: %s", name, _plain(exc))
                rows.append({"provider": name, "label": name, "kind": "unknown", "shared": False, "used_by": where,
                             "state": NOT_AVAILABLE, "reason": "unknown"})
                continue
            used.setdefault(provider, []).extend(where)
        for sign_in in SIGN_INS:
            row = _look(core, sign_in, home)
            if row is None and sign_in.provider in used and sign_in.provider != "anthropic":
                row = {"provider": sign_in.provider, "label": sign_in.label(core), "kind": "sign_in", "shared": False,
                       "file": sign_in.file, "state": NEEDS_SIGN_IN, "reason": "not_signed_in"}
            if row is not None:
                if row["state"] == WORKS:
                    try:
                        stored = sign_in.stored(core)
                    except Exception:
                        stored = None
                    if stored is not None:
                        row = {**row, "hosts": _hosts(_uses(core, sign_in, stored, set(approved)))}
                rows.append({**row, "used_by": used.pop(sign_in.provider, [])})
        for provider, where in used.items():
            rows.append({**_other(core, provider), "used_by": where})
    return [_sentence(row) for row in rows]


# -- the copy -------------------------------------------------------------------------------------------

def write_copy_config(home, copy) -> Path:
    """Write the copy's ``config.yaml`` from the profile's, at switch-on, when the home is still the user's alone.

    It holds the parts Hermes reads to tell which provider a model route uses (``CONFIG_SECTIONS``) and one
    setting of its own: sign-ins kept by another program (Claude Code, the Codex CLI) are not taken over while
    the copy is bound, so no call made for the sandbox reads or renews a sign-in outside the profile."""
    try:
        from hermes_cli.config_backend import config_exists, read_config_doc

        source = Path(home) / CONFIG_FILE
        doc = read_config_doc(source) if config_exists(source) else {}
    except Exception as exc:  # absent, unreadable or not YAML: the copy gets the one setting
        log.warning("could not read %s: %s", Path(home) / CONFIG_FILE, _plain(exc))
        doc = {}
    doc = doc if isinstance(doc, dict) else {}
    out = {name: doc[name] for name in CONFIG_SECTIONS if name in doc}
    out["auth"] = {"adopt_external_logins": False}
    import hermes_yaml

    target = Path(copy) / CONFIG_FILE
    _write_whole(target, hermes_yaml.safe_dump(out, sort_keys=False).encode("utf-8"))
    return target


def _write_whole(path: Path, data: bytes) -> None:
    """Write *data* to *path* whole or not at all, owner-only: a temp file beside it, then a rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".signin-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def copy_states(copy) -> dict[str, Optional[dict]]:
    """What stands in *copy* for each sign-in file now, in the shape the pins record (``{"sha256", "link"}``),
    or None for a file that is absent or is not a sign-in store Hermes could have written (not a JSON object).

    The copy is the live sign-in while the sandbox is on: Hermes replaces these files whole, by a rename, every
    time it renews a sign-in. So the state to put back at switch-off is the copy's as it is now, not the one
    recorded at switch-on, also after a launcher was killed before it could record anything."""
    states: dict[str, Optional[dict]] = {}
    for name in SIGN_IN_FILES:
        try:
            data = (Path(copy) / name).read_bytes()
            whole = isinstance(json.loads(data.decode("utf-8-sig")), dict)
        except (OSError, ValueError):
            whole = False
        states[name] = {"sha256": hashlib.sha256(data).hexdigest(), "link": None} if whole else None
    return states


@contextmanager
def settled(copy) -> Iterator[None]:
    """Hold Hermes's own lock of the copy's sign-in store for a body: no renewal is under way in this or any
    other process while it runs, and none starts. For the moments the copy's files are read to be put back, or a
    host route rewrites the store."""
    core = _core()
    with core.auth._auth_store_lock(target_path=Path(copy) / "auth.json"):
        yield


# -- the schedule ---------------------------------------------------------------------------------------

def lead(lifetime: float) -> float:
    """How long before its expiry a token of *lifetime* seconds is due for renewal: one look of Hermes's
    keepalive (a quarter of the lifetime, between one and fifteen minutes) plus Hermes's two-minute lead, and
    never more than half the lifetime."""
    look = min(max(lifetime / LOOKS_PER_LIFETIME, SHORTEST_LOOK), LONGEST_LOOK)
    return min(look + REFRESH_LEAD, lifetime / 2.0)


def last_moment(lifetime: float) -> float:
    """How long before its expiry a token is replaced whether or not a reply is streaming: Hermes's two-minute
    lead, or a quarter of a shorter lifetime."""
    return min(REFRESH_LEAD, lifetime / 4.0)


def start_margin(lifetime: float) -> float:
    """What the value of a token of *lifetime* seconds must have left to be handed to a sandbox that starts:
    ``START_MARGIN``, or an eighth of a shorter lifetime."""
    return min(START_MARGIN, lifetime / 8.0)


def wait_after(times: int, first: float) -> float:
    """The wait after the *times*-th answer in a row that brought nothing to go on with: *first*, then twice as
    long each time, and never more than ``LONGEST_WAIT``."""
    return min(first * 2.0 ** max(0, times - 1), LONGEST_WAIT)


@dataclass(frozen=True)
class Declared:
    """One sign-in as it was handed to the sink. ``env`` is the variable that holds its placeholder inside;
    ``claims`` are the claims of the token Hermes reads, for the stand-in store the sandbox gets."""
    id: str
    provider: str
    label: str
    env: str
    expires_at: Optional[float]
    endpoints: tuple[Endpoint, ...]
    claims: dict
    file: str
    shared: bool


@dataclass
class _Entry:
    sign_in: _SignIn
    decl: CredentialDecl
    label: str
    shared: bool
    token: Token
    pending: Optional[Token] = None
    failures: int = 0
    retry_at: float = 0.0
    gone: bool = False
    error: str = ""
    told: set = field(default_factory=set)
    env: str = ""
    uses: list = field(default_factory=list)  # (Endpoint, "model" or a tool category's id) per bound address
    not_before: float = 0.0  # no renewal before this moment: the floor, or a longer wait
    early: int = 0  # renewals in a row that brought no token that lasts (one already at its end, or the old one)
    refusals: int = 0  # value updates in a row the sink refused
    offer_at: float = 0.0  # a refused value is not offered again before this moment
    asked: list = field(default_factory=list)  # when a renewal was tried, the last hour
    offered: list = field(default_factory=list)  # when the sink was offered a value, the last hour
    left_out: bool = False  # not handed to the sandbox that was started last (``for_start``)
    returned: bool = False  # left out, and renewed since: the next sandbox start hands it over again

    def plan(self) -> tuple[float, float, Optional[float]]:
        """``(due, last moment, expiry)`` of the value the sink holds."""
        expires = self.token.expires_at
        end = expires if expires is not None else self.token.taken_at + ASSUMED_LIFETIME
        lifetime = max(1.0, end - self.token.taken_at)
        return end - lead(lifetime), end - last_moment(lifetime), expires


class SignIns:
    """The sign-ins of one sandboxed profile: declared to the driver's sink, then kept current.

    *copy* is the launcher's host-only copy of the profile's stores: ``auth.json``, ``.anthropic_oauth.json``,
    the env files and the ``config.yaml`` that ``write_copy_config`` wrote. *clock* and *sleep* are the time
    source and the wait of ``run``. *on_change* is called with the names of the copy's sign-in files after a call
    into Hermes rewrote them, for the pins to record their new state. *approved* answers with the ids of the
    tool categories the user approved (categories.py); without it none is."""

    def __init__(self, copy, sink: CredentialSink, *, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], Any] = time.sleep, on_change: Optional[Callable[[list], Any]] = None,
                 approved: Optional[Callable[[], Any]] = None):
        self.copy = Path(copy)
        self._sink, self._clock, self._sleep, self._on_change = sink, clock, sleep, on_change
        self._approved = approved
        self._lock = threading.RLock()
        self._entries: dict[str, _Entry] = {}
        self._left: dict[str, dict] = {}
        self._notes: list[str] = []
        self._closed = False
        self._cut = False  # in the pass under way, a value went in at its last moment

    # -- binding ------------------------------------------------------------------------------------

    @contextmanager
    def _bound(self) -> Iterator[SimpleNamespace]:
        """The copy bound as the Hermes home. A sign-in file the body rewrote is reported to *on_change*."""
        core = _core()
        _refuse_profile_home(core, self.copy)
        before = self._marks()
        try:
            with no_metadata_lookup(), core.runtime_scope.bind_profile_scope(str(self.copy), hydrate_secrets=False):
                yield core
        finally:
            changed = sorted(name for name, mark in self._marks().items() if mark != before.get(name))
            if changed and self._on_change is not None:
                try:
                    self._on_change(changed)
                except Exception as exc:
                    log.warning("the new state of %s could not be recorded: %s", ", ".join(changed), _plain(exc))

    def _marks(self) -> dict[str, Optional[str]]:
        marks: dict[str, Optional[str]] = {}
        for name in SIGN_IN_FILES:
            try:
                marks[name] = hashlib.sha256((self.copy / name).read_bytes()).hexdigest()
            except OSError:
                marks[name] = None
        return marks

    # -- declaring ----------------------------------------------------------------------------------

    def declare(self) -> list[Declared]:
        """Before the sandbox starts: ask Hermes for every sign-in's current token and hand each to the sink.

        A sign-in whose grant is gone, or that the sandbox cannot carry, is not declared: ``status`` has its row.
        A token that cannot be renewed right now (the issuer does not answer) is declared with the value the
        store holds, and the schedule keeps trying."""
        declared: list[Declared] = []
        with self._lock, self._bound() as core:
            for sign_in in SIGN_INS:
                row = _look(core, sign_in, self.copy)
                if row is None:
                    continue
                if row["state"] != WORKS:
                    self._left[sign_in.provider] = row
                    continue
                token, error = self._first(core, sign_in)
                if token is None:
                    self._left[sign_in.provider] = {**row, "state": NEEDS_SIGN_IN, "reason": "expired", "error": error}
                    continue
                # Hermes moves a profile's copy of the default profile's sign-in back into the root when it
                # finds one (its repair of sign-ins cloned with a profile): look again at where it lives now.
                row = _look(core, sign_in, self.copy) or row
                if row["state"] != WORKS:
                    self._left[sign_in.provider] = row
                    continue
                uses = _uses(core, sign_in, token, self._approved_now())
                decl = CredentialDecl(id=sign_in.id, label=row["label"],
                                      endpoints=tuple(endpoint for endpoint, _use in uses),
                                      placement="bearer", expires=True)
                env = self._sink.declare(decl, token.value, token.expires_at)
                entry = _Entry(sign_in=sign_in, decl=decl, label=row["label"], shared=row["shared"], token=token,
                               env=env, uses=uses)
                # Hermes may just have renewed this sign-in to answer: the floor counts from here.
                entry.not_before = self._clock() + MIN_BETWEEN_RENEWALS
                if error:
                    entry.failures, entry.error = 1, error
                    entry.retry_at = self._clock() + BACKOFF[0]
                self._entries[sign_in.id] = entry
                held = _claims(token.value)
                declared.append(Declared(id=sign_in.id, provider=sign_in.provider, label=row["label"], env=env,
                                         expires_at=token.expires_at, endpoints=decl.endpoints,
                                         claims={name: held[name] for name in sign_in.claims if name in held},
                                         file=sign_in.file, shared=row["shared"]))
        return declared

    def _approved_now(self) -> set:
        try:
            return {str(cid) for cid in (self._approved() if callable(self._approved) else ())}
        except Exception as exc:  # nothing a tool needs is bound; the model's addresses are
            log.warning("the approved tool categories could not be read: %s", _plain(exc))
            return set()

    def rebind(self) -> list[str]:
        """Before a sandbox starts again: declare each sign-in again whose addresses changed, because a tool
        category was approved or its approval removed since. The sandbox that starts next is bound to the new
        set and holds a new placeholder; the one that still runs keeps what it started with. Returns the ids
        declared again. No request is made."""
        changed: list[str] = []
        with self._lock:
            if self._closed:
                return changed
            approved = self._approved_now()
            for entry in self._entries.values():
                if entry.gone or not entry.sign_in.tools:
                    continue
                with self._bound() as core:
                    uses = _uses(core, entry.sign_in, entry.token, approved)
                if [endpoint for endpoint, _use in uses] == list(entry.decl.endpoints):
                    entry.uses = uses
                    continue
                decl = CredentialDecl(id=entry.decl.id, label=entry.decl.label,
                                      endpoints=tuple(endpoint for endpoint, _use in uses),
                                      placement=entry.decl.placement, name=entry.decl.name, expires=entry.decl.expires)
                held = entry.pending or entry.token
                entry.env = self._sink.declare(decl, held.value, held.expires_at)
                if entry.pending is not None:
                    entry.token, entry.pending = entry.pending, None
                entry.decl, entry.uses = decl, uses
                changed.append(decl.id)
        return changed

    def tool_hosts(self, category_id: str) -> list[dict]:
        """The addresses an approval of the tool category *category_id* binds a declared sign-in to:
        ``[{host, port, label}]`` with the sign-in's name. Empty when no declared sign-in is used by tools.
        A sign-in that has ended gets no new address: for it these are the addresses the sandbox that runs
        still has bound for the category, so that removing the approval restarts the sandbox and closes them.
        A sign-in the sandbox started without has none."""
        category = categories.by_id(category_id)
        out: list[dict] = []
        if category is None:
            return out
        with self._lock:
            for entry in self._entries.values():
                if entry.left_out or not entry.sign_in.tools:
                    continue
                bound = categories.gateway_endpoints(category) if not entry.gone else \
                    [(endpoint.host, endpoint.port) for endpoint, use in entry.uses if use == category.id]
                for host, port in bound:
                    out.append({"host": host, "port": port, "label": entry.label})
        return out

    def _first(self, core, sign_in: _SignIn) -> tuple[Optional[Token], str]:
        """``(token, error)`` at declare time. The token is None when the grant is gone or nothing is stored."""
        now = self._clock()
        try:
            token = sign_in.resolve(core, renew=False, stale=None)
            return Token(token.value, token.expires_at, token.base_url, now), ""
        except Exception as exc:
            if sign_in.gone(core, exc):
                log.warning("the %s sign-in is gone: %s", sign_in.provider, _plain(exc))
                return None, _plain(exc)
            log.warning("the %s sign-in could not be renewed now: %s", sign_in.provider, _plain(exc))
            try:
                stored = sign_in.stored(core)
            except Exception:
                stored = None
            if stored is None:
                return None, _plain(exc)
            return Token(stored.value, stored.expires_at, stored.base_url, now), _plain(exc)

    # -- keeping fresh ------------------------------------------------------------------------------

    def run(self, stopped: Callable[[], bool]) -> None:
        """Keep every declared sign-in current until *stopped* answers True. Blocks: run it in a thread of its
        own, with a *sleep* that returns early when the launcher stops."""
        while not stopped() and not self._closed:
            self._sleep(self.step())

    def step(self) -> float:
        """One pass over the declared sign-ins. Returns the seconds until the next pass is due."""
        with self._lock:
            if self._closed:
                return LONGEST_SLEEP
            waits = [LONGEST_SLEEP]
            self._cut = False
            # A value that goes in at its last moment closes whatever was streaming, and Hermes then asks the
            # model again, a few times at most for one reply. Every other sign-in that is due goes in in the same
            # pass, so a long reply is not cut once more at each sign-in's own last moment. A renewal is a round
            # trip to an issuer, so values are never handed over with a renewal in between: the sign-ins at
            # their last moment are renewed first (*hold*) and handed over together, then every other one that
            # is due is renewed and those are handed over together. The reply is closed twice at most in a
            # pass, however many sign-ins are due.
            for urgent, cut, hold in ((True, True, True), (False, False, False), (False, True, True), (False, True, False)):
                if cut and not urgent and not self._cut:
                    break
                for entry in self._entries.values():
                    try:
                        if urgent and (entry.gone or self._clock() < entry.plan()[1]):
                            continue  # not at its last moment: the next turn looks at it
                        wait = self._advance(entry, cut=cut, hold=hold)
                    except Unavailable:
                        raise
                    except Exception as exc:  # one sign-in's trouble never stops the others
                        if hold:
                            continue  # the turn that hands over meets it again and says it
                        log.warning("the %s sign-in could not be looked at: %s", entry.sign_in.provider, _plain(exc))
                        wait = BACKOFF[0]
                    if not hold:
                        waits.append(wait)
            return max(SHORTEST_PASS, min(waits))

    def _advance(self, entry: _Entry, cut: bool = False, hold: bool = False) -> float:
        """One sign-in's turn in a pass. *cut*: a value already went in at its last moment in this pass, so what
        is due goes in whatever streams. *hold*: renew what is due and keep the new value for the next turn."""
        now = self._clock()
        due, last, expires = entry.plan()
        if expires is not None and now >= expires:
            self._tell(entry, "lapsed")
        if entry.gone:
            return LONGEST_SLEEP if expires is None or now >= expires else expires - now
        if entry.pending is None:
            if now < due:
                return due - now
            if now < max(entry.retry_at, entry.not_before):
                return max(entry.retry_at, entry.not_before) - now
            if now < last and not cut and not self._quiet():
                return min(QUIET_POLL, last - now)
            self._renew(entry)
            now = self._clock()
        if entry.pending is not None:
            # The renewed value goes to the sink between replies; at the last moment it goes whatever streams,
            # and so it does in a pass in which another value already went in that way (*cut*).
            if hold:
                return 0.0
            if now < entry.offer_at:
                return entry.offer_at - now
            if now < last and not cut and not self._quiet():
                return min(QUIET_POLL, last - now)
            if not self._push(entry):
                # Offered again later, without a second renewal: twice at the usual wait, then twice as long
                # each time.
                return LONGEST_SLEEP if entry.gone else wait_after(entry.refusals - 1, UPDATE_RETRY)
            if now >= last:
                self._cut = True
            return max(0.0, max(entry.plan()[0], entry.not_before) - self._clock())
        if entry.gone:
            return LONGEST_SLEEP if expires is None or now >= expires else expires - now
        return max(0.0, max(entry.retry_at, entry.not_before) - now)

    def _quiet(self) -> bool:
        try:
            return bool(self._sink.quiet())
        except Exception as exc:  # not known: wait for the last moment
            log.warning("the sink could not say whether a reply is streaming: %s", _plain(exc))
            return False

    def _renew(self, entry: _Entry) -> None:
        """Renew *entry*'s token with Hermes's own refresh, in the store it lives in and under that store's lock.
        On success the new token waits in ``pending`` for the sink."""
        sign_in, now = entry.sign_in, self._clock()
        entry.asked = [at for at in entry.asked if now - at < HOUR]
        if len(entry.asked) >= MOST_RENEWALS_PER_HOUR:
            self._stop(entry, f"{entry.label} was asked to renew the sign-in {len(entry.asked)} times within an "
                              "hour. It is not asked again until the sandbox is turned off and on.")
            return
        entry.asked.append(now)
        try:
            with self._bound() as core:
                try:
                    token = self._newer(core, entry, now) or sign_in.resolve(core, renew=True, stale=entry.token.value)
                except Exception as exc:
                    if not sign_in.gone(core, exc):
                        raise
                    entry.gone, entry.error = True, _plain(exc)
                    log.warning("the %s sign-in is gone; the sandbox keeps its last token until it expires: %s",
                                sign_in.provider, entry.error)
                    self._tell(entry, "expired")
                    return
                self._placed(core, entry)
            if token.value == entry.token.value and (token.expires_at or 0.0) <= (entry.token.expires_at or 0.0):
                # The issuer answered and there is nothing new to hand over: the next request waits longer
                # each time this happens in a row, also past the last of the waits after a failure.
                entry.early += 1
                entry.not_before = self._clock() + wait_after(entry.early, BACKOFF[0])
                raise _Refused("the renewal returned the token it was to replace", gone=False)
        except Unavailable:
            raise
        except Exception as exc:
            entry.failures += 1
            entry.error = _plain(exc)
            entry.retry_at = self._clock() + BACKOFF[min(entry.failures, len(BACKOFF)) - 1]
            log.warning("the %s sign-in was not renewed (attempt %d): %s", sign_in.provider, entry.failures, entry.error)
            return
        now = self._clock()
        entry.pending = Token(token.value, token.expires_at, token.base_url, now)
        entry.failures, entry.error, entry.retry_at = 0, "", 0.0
        # The floor, whatever the new token says. A token that ends before the floor is over cannot be kept
        # alive by renewing it: each one in a row makes the wait twice as long, and the first token that lasts
        # ends that.
        ends = token.expires_at if token.expires_at is not None else now + ASSUMED_LIFETIME
        entry.early = entry.early + 1 if ends - now < MIN_BETWEEN_RENEWALS else 0
        entry.not_before = now + wait_after(entry.early, MIN_BETWEEN_RENEWALS)

    def _stop(self, entry: _Entry, why: str) -> None:
        """A ceiling was met: this engine asks nothing more for *entry*. The sink keeps the value it has, the
        copy keeps the grant, and the row reads as an expired sign-in with *why* as its reason."""
        entry.gone, entry.error = True, why
        log.warning("the %s sign-in is left alone from here on: %s", entry.sign_in.provider, why)
        self._tell(entry, "expired")

    def _placed(self, core, entry: _Entry) -> None:
        """Note where *entry*'s sign-in lives now. Hermes keeps one grant per account: when it finds the copy
        and the Hermes root holding the same one, it keeps the newer pair in the root and drops the copy's row,
        at whatever call first loads the sign-in's pool. From then on the sign-in is the default profile's."""
        row = _look(core, entry.sign_in, self.copy)
        if row is not None:
            entry.shared = bool(row["shared"])

    def catch_up(self) -> None:
        """Before a sandbox starts again: make the value the sink holds the current one for every declared
        sign-in, so the new sandbox starts with it. A renewed token that was waiting for a quiet moment is
        handed over now (nothing streams in a sandbox that is down). A token another Hermes on this computer
        put in the store in place of ours (the same sign-in, renewed by the default profile's Hermes) is taken
        as it is. Nothing is renewed and no request is made."""
        with self._lock:
            if self._closed:
                return
            for entry in self._entries.values():
                if entry.gone:
                    continue
                try:
                    with self._bound() as core:
                        self._placed(core, entry)
                        stored = entry.sign_in.stored(core) if entry.pending is None else None
                    now = self._clock()
                    # The store only moves forward: a token in it that is not the sink's replaced the sink's.
                    if stored is not None and stored.value != entry.token.value \
                            and (stored.expires_at is None or stored.expires_at > now):
                        entry.pending = Token(stored.value, stored.expires_at, stored.base_url, now)
                    if entry.pending is not None:
                        self._push(entry)
                except Unavailable:
                    raise
                except Exception as exc:  # the sandbox starts with the value the sink has; the schedule goes on
                    log.warning("the %s sign-in could not be brought up to date: %s", entry.sign_in.provider,
                                _plain(exc))

    def for_start(self) -> list[str]:
        """Before a sandbox starts, after ``declare`` or ``catch_up``: settle which declared sign-ins that
        sandbox gets. Returns the ids of the ones it starts without. No request is made.

        Left out are a sign-in that has ended (its row reads as expired), one this computer is no longer signed
        in to, and one whose value runs out within ``START_MARGIN`` with nothing newer to hand over. OpenShell
        withholds a value that has run out, and a start that counts on it fails; a sandbox that starts without
        it runs, and only the model that needs it does not answer. The sink is told (``withdraw``): no provider
        is registered and no address is bound for it. ``variable_of`` no longer names it, so the stand-in store
        the sandbox gets has no row for it and Hermes inside reads as not signed in to that provider. Its row
        here keeps its sentence. A sign-in that was left out and has a value that lasts again is declared
        again, under the same variable."""
        out: list[str] = []
        with self._lock:
            if self._closed:
                return out
            for entry in self._entries.values():
                if not entry.gone:
                    self._still_there(entry)
                leave = entry.gone or self._runs_out(entry)
                if leave:
                    self._sink.withdraw(entry.decl.id)
                    out.append(entry.decl.id)
                elif entry.left_out:
                    entry.env = self._sink.declare(entry.decl, entry.token.value, entry.token.expires_at)
                entry.left_out, entry.returned = leave, False
        return out

    def _runs_out(self, entry: _Entry) -> bool:
        """Whether the value the sink holds for *entry* ends before a sandbox that starts now could use it."""
        expires = entry.token.expires_at
        if expires is None:
            return False
        lifetime = max(1.0, expires - entry.token.taken_at)
        return self._clock() >= expires - start_margin(lifetime)

    def _still_there(self, entry: _Entry) -> None:
        """Mark *entry* as ended when Hermes no longer finds its sign-in on this computer (the user signed out
        of a sign-in the profile shares with the default profile). A store that cannot be read says nothing."""
        try:
            with self._bound() as core:
                row = _look(core, entry.sign_in, self.copy)
        except Unavailable:
            raise
        except Exception as exc:
            log.warning("the %s sign-in could not be looked at: %s", entry.sign_in.provider, _plain(exc))
            return
        if row is None or row["state"] != WORKS:
            entry.gone = True
            entry.error = _SENTENCES["not_signed_in"].format(label=entry.label)
            log.warning("the %s sign-in is no longer on this computer", entry.sign_in.provider)
            self._tell(entry, "expired")

    def returned(self) -> list[str]:
        """The ids of the sign-ins the running sandbox started without that have been renewed since and whose
        value lasts as a start needs it (``for_start`` leaves out one that runs out). A sandbox that starts now
        gets them; the one that runs has no placeholder for them. A renewal that brought a token of a second or
        two, or one that has run out again, is not among them: a restart could not hand it in."""
        with self._lock:
            return [entry.decl.id for entry in self._entries.values()
                    if entry.left_out and entry.returned and not self._runs_out(entry)]

    def _newer(self, core, entry: _Entry, now: float) -> Optional[Token]:
        """A token another Hermes already put in the store in place of ours (a sign-in shared with the default
        profile), when it has enough life left: it is taken as it is and no refresh token is spent."""
        if not entry.shared:
            return None
        stored = entry.sign_in.stored(core)
        if stored is None or stored.value == entry.token.value or stored.expires_at is None:
            return None
        remaining = stored.expires_at - now
        return stored if remaining > 2 * REFRESH_LEAD and stored.expires_at > (entry.token.expires_at or 0.0) else None

    def _push(self, entry: _Entry) -> bool:
        token, now = entry.pending, self._clock()
        if entry.left_out:
            # The sandbox that runs started without this sign-in and the sink holds nothing to replace: the new
            # value is kept here, and the next sandbox start hands it over (``for_start``).
            entry.token, entry.pending, entry.error, entry.returned = token, None, "", True
            return True
        entry.offered = [at for at in entry.offered if now - at < HOUR]
        if len(entry.offered) >= MOST_UPDATES_PER_HOUR:
            self._stop(entry, f"The sandbox was offered a new {entry.label} token {len(entry.offered)} times within "
                              "an hour. It is not offered again until the sandbox is turned off and on.")
            return False
        entry.offered.append(now)
        try:
            self._sink.update(entry.decl.id, token.value, token.expires_at)
        except Exception as exc:
            entry.refusals += 1
            entry.offer_at = now + wait_after(entry.refusals - 1, UPDATE_RETRY)
            entry.error = _plain(exc)
            log.warning("the sink did not take the new %s token: %s", entry.sign_in.provider, entry.error)
            return False
        entry.token, entry.pending, entry.error, entry.refusals, entry.offer_at = token, None, "", 0, 0.0
        if not entry.early:  # a token that does not last says nothing new: the note of the first one stands
            entry.told.discard("lapsed")
        return True

    def _tell(self, entry: _Entry, what: str) -> None:
        """One note per turn of events, for the launcher to put in the chat."""
        if what in entry.told:
            return
        entry.told.add(what)
        if what == "expired":
            self._notes.append(f"The {entry.label} sign-in expired on this computer. "
                               + _EXPIRED_ACTION.format(label=entry.label))
        elif not entry.gone:
            self._notes.append(_SENTENCES["lapsed"].format(label=entry.label))

    # -- what the stand-in store is made from ---------------------------------------------------------

    def variable_of(self, value: Any) -> Optional[str]:
        """The variable of the declared sign-in whose token is *value* (the one the sink holds, or a renewed
        one that waits for a quiet moment), or None. For the launcher to tell which secret of the copy's stores
        is which declared credential; nothing is returned but the variable's name."""
        if not isinstance(value, str) or not value:
            return None
        with self._lock:
            for entry in self._entries.values():
                held = [entry.token.value] + ([entry.pending.value] if entry.pending is not None else [])
                if value in held:
                    return None if entry.left_out else entry.env or None
        return None

    def stores(self) -> dict[str, Optional[dict]]:
        """The copy's sign-in files as parsed JSON (None for a file that is absent), as they are now, read under
        Hermes's lock of the copy. A declared sign-in the profile shares with the default profile is not in the
        copy: its row is added as Hermes reads it from the Hermes root, in memory only, so the stand-in store
        the sandbox gets has a row for it. Nothing is written."""
        with self._lock:
            shared = [entry.sign_in for entry in self._entries.values() if entry.shared]
            out: dict[str, Optional[dict]] = {}
            with settled(self.copy):
                for name in SIGN_IN_FILES:
                    try:
                        doc = json.loads((self.copy / name).read_bytes().decode("utf-8-sig"))
                    except (OSError, ValueError):
                        doc = None
                    out[name] = doc if isinstance(doc, dict) else None
            if shared:
                with bound(self.copy) as core:
                    for sign_in in shared:
                        state, _source = sign_in.state(core)
                        if not isinstance(state, dict):
                            continue
                        if sign_in.file == "auth.json":
                            store = out.get("auth.json") or {"version": 1, "providers": {}}
                            store.setdefault("providers", {})[sign_in.provider] = json.loads(json.dumps(state))
                            out["auth.json"] = store
                        else:
                            out[sign_in.file] = json.loads(json.dumps(state))
            return out

    # -- what the page and the chat show --------------------------------------------------------------

    def status(self) -> list[dict]:
        """One row per sign-in of the profile: the declared ones with the state of their schedule, then the ones
        that were not declared, each with the sentence the Sandbox page shows."""
        with self._lock:
            now, rows = self._clock(), []
            for entry in self._entries.values():
                due, last, expires = entry.plan()
                lapsed = expires is not None and now >= expires
                if lapsed:
                    self._tell(entry, "lapsed")
                if entry.gone:
                    state, reason = NEEDS_SIGN_IN, "expired"
                elif lapsed or entry.left_out:
                    state, reason = "lapsed", "lapsed"
                elif entry.failures:
                    state, reason = "retrying", "retrying"
                else:
                    state, reason = WORKS, "signed_in_shared" if entry.shared else "signed_in"
                rows.append(_sentence({
                    "id": entry.decl.id, "provider": entry.sign_in.provider, "label": entry.label, "kind": "sign_in",
                    "shared": entry.shared, "file": entry.sign_in.file, "state": state, "reason": reason,
                    "hosts": _hosts(entry.uses), "expires_at": expires, "usable": not lapsed and not entry.left_out,
                    "renew_at": None if entry.gone else max(due, entry.retry_at, entry.not_before),
                    "last_moment": None if entry.gone else last, "failures": entry.failures, "error": entry.error}))
            rows.extend(_sentence(row) for row in self._left.values())
            return rows

    def notes(self) -> list[str]:
        """The notes that came up since the last call, each one line: a sign-in that expired for good, a token
        that could not be renewed in time."""
        with self._lock:
            now = self._clock()
            for entry in self._entries.values():
                expires = entry.plan()[2]
                if expires is not None and now >= expires:
                    self._tell(entry, "lapsed")
            notes, self._notes = self._notes, []
            return notes

    def close(self) -> None:
        """Stop the schedule. Returns once no renewal of this object is under way; the copy is then ready to be
        put back."""
        with self._lock:
            self._closed = True
