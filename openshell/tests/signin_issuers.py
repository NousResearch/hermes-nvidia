"""Loopback stand-ins for the sign-in issuers Hermes talks to, for the sign-in engine's tests.

One HTTP server on 127.0.0.1 answers for every issuer: Nous Portal, OpenAI (Codex), xAI, MiniMax and Anthropic.
It offers what each sign-in needs (the device-code steps and the token endpoint) and behaves like a strict issuer:

* every refresh replaces the refresh token, and a spent refresh token ends the whole sign-in (every later
  refresh is refused), so a refresh whose new refresh token was lost shows as a sign-in that no longer works;
* tokens expire on a clock the test owns (``Clock``);
* a test can make the next answers of an issuer fail: ``invalid_grant``, a server error, or no answer in time.

Every value it issues is made up here. Its record (``calls``) keeps kinds, never values: which provider was asked,
whether the refresh token presented was the current one, a spent one or one it never issued, and the answer.

Hermes asks for ``https://<issuer host>/...``. ``redirect`` moves those connections to the server and names the
host that was asked for in ``X-Issuer-Host``; the request keeps its address, so Hermes's own checks of an
address still see the one it chose. ``loopback_only`` refuses every other connection and lists it.
"""
from __future__ import annotations

import base64
import json
import secrets
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOSTS = {"portal.nousresearch.com": "nous", "auth.openai.com": "openai-codex", "auth.x.ai": "xai-oauth",
         "api.minimax.io": "minimax-oauth", "platform.claude.com": "anthropic", "console.anthropic.com": "anthropic"}
NOUS_CLAIMS = {"scope": "inference:invoke", "sub": "user-1", "org_id": "org-1", "paid_access": True,
               "tool_access": {"web": True}, "email": "someone@example.test"}
CODEX_CLAIMS = {"https://api.openai.com/auth": {"chatgpt_account_id": "account-1"}, "sub": "user-1",
                "email": "someone@example.test"}
XAI_CLAIMS = {"sub": "user-1", "email": "someone@example.test"}
CLAIMS = {"nous": NOUS_CLAIMS, "openai-codex": CODEX_CLAIMS, "xai-oauth": XAI_CLAIMS}


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def claims_of(token: str) -> dict:
    """The claims of a token in JWT shape; {} for any other token."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return {}


class Clock:
    """The time every test component reads. It starts at the real time and only moves forward, so a token
    issued on it is never expired for code that reads the real clock."""

    def __init__(self):
        self.offset = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += max(0.0, float(seconds))

    def sleep(self, seconds: float) -> None:
        """What the engine sleeps with: nothing waits, the clock moves."""
        self.slept.append(float(seconds))
        self.advance(seconds)


class Issuers:
    """The loopback server and the sign-ins it has open."""

    def __init__(self, clock=None):
        self.clock = clock or Clock()
        self.lock = threading.RLock()
        self.ttl = {"nous": 900, "openai-codex": 3600, "xai-oauth": 900, "minimax-oauth": 900, "anthropic": 3600}
        self.grants: dict[str, dict] = {}
        self.faults: dict[str, list[str]] = {}
        self.calls: list[dict] = []
        self.issued: list[str] = []  # every token handed out, for tests that look where tokens end up
        self.delay = 0.0  # seconds a refresh answer is held back (widens the window two refreshers race in)
        self.plain: set[str] = set()  # providers whose tokens say nothing about their expiry
        self._codes: dict[str, str] = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.issuers = self  # type: ignore[attr-defined]
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    # -- what a test sets and reads ------------------------------------------------------------

    def fail(self, provider: str, *kinds: str) -> None:
        """The next refreshes of *provider* answer ``invalid_grant``, ``server_error`` or ``timeout``, in order."""
        with self.lock:
            self.faults.setdefault(provider, []).extend(kinds)

    def refreshes(self, provider: str) -> list[dict]:
        with self.lock:
            return [dict(c) for c in self.calls if c["provider"] == provider and c["step"] == "refresh"]

    def valid(self, provider: str, token: str) -> bool:
        """Whether *token* is an access token of *provider*'s open sign-in that has not expired on the clock."""
        with self.lock:
            grant = self.grants.get(provider) or {}
            expires = (grant.get("access") or {}).get(token)
            return bool(expires and not grant.get("ended") and expires > self.clock())

    def current_refresh_token(self, provider: str) -> str:
        with self.lock:
            return str((self.grants.get(provider) or {}).get("refresh") or "")

    def ended(self, provider: str) -> bool:
        with self.lock:
            return bool((self.grants.get(provider) or {}).get("ended"))

    def open(self, provider: str) -> dict:
        """Open a sign-in for *provider* without the device-code steps; returns its first token pair."""
        with self.lock:
            self.grants[provider] = {"refresh": "", "spent": set(), "access": {}, "ended": False}
            return self._issue(provider)

    def timed_out(self, host: str, path: str) -> bool:
        """Asked by ``redirect`` before a request leaves: True when the next refresh of that issuer is to get no
        answer in time (the fault is used up)."""
        provider = HOSTS.get(host.split(":")[0])
        if provider is None or not path.endswith("/token"):
            return False
        with self.lock:
            queue = self.faults.get(provider) or []
            if queue and queue[0] == "timeout":
                queue.pop(0)
                self.calls.append({"provider": provider, "step": "refresh", "presented": "unseen", "answer": "timeout"})
                return True
        return False

    # -- issuing -------------------------------------------------------------------------------

    def _access_token(self, provider: str, expires: float) -> str:
        if provider in CLAIMS and provider not in self.plain:
            claims = {**CLAIMS[provider], "iat": int(self.clock()), "exp": int(expires), "jti": secrets.token_hex(4)}
            return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(claims)}.{secrets.token_urlsafe(24)}"
        return f"made-up-access-{secrets.token_hex(12)}"

    def _issue(self, provider: str) -> dict:
        grant = self.grants[provider]
        expires = self.clock() + self.ttl[provider]
        access = self._access_token(provider, expires)
        grant["access"][access] = expires
        if grant["refresh"]:
            grant["spent"].add(grant["refresh"])
        grant["refresh"] = f"made-up-refresh-{secrets.token_hex(12)}"
        self.issued += [access, grant["refresh"]]
        return {"access_token": access, "refresh_token": grant["refresh"], "token_type": "Bearer",
                "expires_in": self.ttl[provider], "scope": CLAIMS.get(provider, {}).get("scope", "")}

    def _refresh(self, provider: str, presented: str) -> tuple[int, dict]:
        if self.delay:
            time.sleep(self.delay)
        with self.lock:
            grant = self.grants.get(provider)
            queue = self.faults.get(provider) or []
            fault = queue.pop(0) if queue else None
            kind = ("current" if grant and presented and presented == grant["refresh"]
                    else "spent" if grant and presented in grant["spent"] else "unknown")
            call = {"provider": provider, "step": "refresh", "presented": kind}
            self.calls.append(call)
            if fault == "server_error":
                call["answer"] = "server_error"
                return 503, {"error": "temporarily_unavailable"}
            if fault == "invalid_grant":
                call["answer"] = "invalid_grant"
                if grant:
                    grant["ended"] = True
                return 400, {"error": "invalid_grant", "error_description": "the sign-in was revoked"}
            if not grant or grant["ended"] or kind != "current":
                if grant and kind == "spent":
                    grant["ended"] = True  # a spent refresh token ends the whole sign-in
                call["answer"] = "refresh_token_reused" if kind == "spent" else "invalid_grant"
                return 400, {"error": call["answer"], "error_description": "this refresh token is not the current one"}
            call["answer"] = "rotated"
            return 200, self._issue(provider)

    def _sign_in(self, provider: str) -> dict:
        with self.lock:
            self.calls.append({"provider": provider, "step": "sign-in", "presented": "none", "answer": "issued"})
            return self.open(provider)

    # -- the endpoints -------------------------------------------------------------------------

    def answer(self, host: str, method: str, path: str, form: dict, body: dict, headers) -> tuple[int, dict]:
        provider = HOSTS.get(host.split(":")[0])
        grant_type = str(form.get("grant_type") or body.get("grant_type") or "")
        presented = str(form.get("refresh_token") or body.get("refresh_token") or "")
        if provider == "nous":
            if path.endswith("/api/oauth/device/code"):
                return 200, {"device_code": "device-1", "user_code": "CODE-1", "expires_in": 600, "interval": 1,
                             "verification_uri": f"https://{host}/device",
                             "verification_uri_complete": f"https://{host}/device?code=CODE-1"}
            if path.endswith("/api/oauth/token"):
                if grant_type == "refresh_token":  # the refresh token rides in a header
                    return self._refresh("nous", headers.get("x-nous-refresh-token") or "")
                return 200, self._sign_in("nous")
        if provider == "openai-codex":
            if path.endswith("/deviceauth/usercode"):
                return 200, {"user_code": "CODE-1", "device_auth_id": "device-1", "interval": "1"}
            if path.endswith("/deviceauth/token"):
                return 200, {"authorization_code": "code-1", "code_verifier": "verifier-1"}
            if path.endswith("/oauth/token"):
                renewal = grant_type == "refresh_token"
                return self._refresh(provider, presented) if renewal else (200, self._sign_in(provider))
        if provider == "xai-oauth":
            if path.endswith("/.well-known/openid-configuration"):
                return 200, {"authorization_endpoint": f"https://{host}/oauth2/authorize",
                             "token_endpoint": f"https://{host}/oauth2/token"}
            if path.endswith("/oauth2/device/code"):
                return 200, {"device_code": "device-1", "user_code": "CODE-1", "expires_in": 600, "interval": 1,
                             "verification_uri": f"https://{host}/device",
                             "verification_uri_complete": f"https://{host}/device?code=CODE-1"}
            if path.endswith("/oauth2/token"):
                renewal = grant_type == "refresh_token"
                return self._refresh(provider, presented) if renewal else (200, self._sign_in(provider))
        if provider == "minimax-oauth":
            if path.endswith("/oauth/code"):
                return 200, {"user_code": "CODE-1", "verification_uri": f"https://{host}/device", "expired_in": 600,
                             "state": form.get("state")}
            if path.endswith("/oauth/token"):
                status, payload = (self._refresh(provider, presented) if grant_type == "refresh_token"
                                   else (200, self._sign_in(provider)))
                if status == 200:
                    payload = {"status": "success", "access_token": payload["access_token"],
                               "refresh_token": payload["refresh_token"], "expired_in": payload["expires_in"],
                               "token_type": "Bearer"}
                return status, payload
        if provider == "anthropic" and path.endswith("/v1/oauth/token"):
            return self._refresh(provider, presented)
        return 404, {"error": "not_found"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _serve(self):
        issuers: Issuers = self.server.issuers  # type: ignore[attr-defined]
        raw = self.rfile.read(int(self.headers.get("content-length") or 0)).decode("utf-8", "replace")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        try:
            body = json.loads(raw) if raw.strip().startswith("{") else {}
        except ValueError:
            body = {}
        host = self.headers.get("x-issuer-host") or ""
        status, payload = issuers.answer(host, self.command, urllib.parse.urlsplit(self.path).path, form,
                                         body if isinstance(body, dict) else {}, self.headers)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _serve


def _loopback(host) -> bool:
    return str(host or "").lower() in ("127.0.0.1", "localhost", "::1", "")


def arrivals_on(clock, patch=None) -> None:
    """Make Hermes stamp a Nous sign-in's arrival on *clock*, the machine's clock of a test.

    Hermes judges a Nous token by when it arrived: it stamps the arrival with the machine's clock and counts
    the token's own lifetime (``exp`` - ``iat``) from there, so that a machine whose clock disagrees with the
    issuer's does not end a fresh token. A test's ``Clock`` runs ahead of the real one once the test has moved
    it. Stamped with the real time, a token issued after that would be read as having arrived in the past,
    and one issued a lifetime in as expired on arrival. A Hermes that reads ``exp`` alone does not use the
    stamp, and nothing changes for it. *patch* as in ``redirect``."""
    try:
        from hermes_cli import auth_nous
    except ImportError:
        return
    real = getattr(auth_nous, "datetime", None)
    if not isinstance(real, type):
        return

    class WorldDatetime(real):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(clock(), tz)

    (patch or setattr)(auth_nous, "datetime", WorldDatetime)


def redirect(port: int, issuers=None, patch=None) -> None:
    """Send every httpx and urllib request of this process to the server on *port*. *issuers* (same process
    only) lets a request get no answer in time. *patch* is ``monkeypatch.setattr`` in a test and plain
    ``setattr`` in a helper process."""
    import http.client
    import urllib.request

    import httpx

    patch = patch or setattr

    def moved(request):
        url = request.url
        if _loopback(url.host) and url.port == port:
            return request
        origin = f"{url.host}:{url.port or (443 if url.scheme == 'https' else 80)}"
        if issuers is not None and issuers.timed_out(origin, url.path):
            raise httpx.ReadTimeout("timed out", request=request)
        headers = [(k, v) for k, v in request.headers.raw if k.lower() not in (b"host", b"x-issuer-host")]
        headers += [(b"host", f"127.0.0.1:{port}".encode()), (b"x-issuer-host", origin.encode())]
        return httpx.Request(request.method, url.copy_with(scheme="http", host="127.0.0.1", port=port),
                             headers=headers, stream=request.stream, extensions=request.extensions)

    send = httpx.HTTPTransport.handle_request
    patch(httpx.HTTPTransport, "handle_request", lambda self, request: send(self, moved(request)))

    do_open = urllib.request.AbstractHTTPHandler.do_open

    def urllib_do_open(self, http_class, req, **http_conn_args):
        parts = urllib.parse.urlsplit(req.full_url)
        if _loopback(parts.hostname) and parts.port == port:
            return do_open(self, http_class, req, **http_conn_args)
        origin = f"{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
        if issuers is not None and issuers.timed_out(origin, parts.path):
            raise TimeoutError("timed out")
        req.add_unredirected_header("X-issuer-host", origin)
        asked = req.host
        req.host = f"127.0.0.1:{port}"
        try:
            return do_open(self, http.client.HTTPConnection, req)
        finally:
            req.host = asked

    patch(urllib.request.AbstractHTTPHandler, "do_open", urllib_do_open)


def loopback_only(patch=None) -> list[str]:
    """Refuse and list every connection or name lookup that is not loopback."""
    patch = patch or setattr
    refused: list[str] = []
    connect, getaddrinfo = socket.socket.connect, socket.getaddrinfo

    def guarded_connect(self, address, *args):
        if isinstance(address, tuple) and not _loopback(address[0]):
            refused.append(f"connect {address[0]}:{address[1]}")
            raise ConnectionRefusedError(f"{address[0]}:{address[1]} is not loopback")
        return connect(self, address, *args)

    def guarded_getaddrinfo(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name is not None and not _loopback(name):
            refused.append(f"lookup {name}")
            raise socket.gaierror(f"{name} is not loopback")
        return getaddrinfo(host, *args, **kwargs)

    patch(socket.socket, "connect", guarded_connect)
    patch(socket, "getaddrinfo", guarded_getaddrinfo)
    return refused


class Sink:
    """A sandbox driver's credential sink, recording what it is handed. ``busy`` scripts ``quiet()``: while it is
    True a reply is streaming."""

    def __init__(self, clock=None):
        self.clock = clock or time.time
        self.declared: dict[str, dict] = {}
        self.values: dict[str, tuple] = {}
        self.updates: list[dict] = []
        self.busy = False
        self.asked_quiet = 0
        self.fail_updates = 0
        self.withdrawn: list[str] = []

    def declare(self, decl, value, expires_at):
        assert decl.id not in self.declared, f"{decl.id} declared twice"
        self.declared[decl.id] = {"decl": decl, "expires_at": expires_at}
        self.values[decl.id] = (value, expires_at)
        return "SANDBOX_" + "".join(c if c.isalnum() else "_" for c in decl.id).upper()

    def update(self, cred_id, value, expires_at):
        assert cred_id in self.declared, f"{cred_id} was never declared"
        if self.fail_updates:
            self.fail_updates -= 1
            raise RuntimeError("the driver could not replace the value")
        self.values[cred_id] = (value, expires_at)
        self.updates.append({"id": cred_id, "at": self.clock(), "quiet": not self.busy, "expires_at": expires_at})

    def withdraw(self, cred_id):
        self.withdrawn.append(cred_id)
        self.declared.pop(cred_id, None)
        self.values.pop(cred_id, None)

    def quiet(self):
        self.asked_quiet += 1
        return not self.busy
