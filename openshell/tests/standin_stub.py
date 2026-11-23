"""A loopback stand-in for every provider host, for the stand-in sign-in store tests. Fabricated values only.

One server answers as the sign-in issuers (device-code and authorization-code flows, refresh), and as the model
hosts (chat completions, messages, responses, model lists). For every request it records WHERE a credential
was carried and of what KIND, never the value:

* ``real``           a token or key this stub issued (what must never be inside a sandbox)
* ``refresh-token``  a refresh grant this stub issued
* ``placeholder``    an OpenShell placeholder (``openshell:resolve:env:...``)
* ``alias``          a JWT-shaped alias whose signature segment is ``OPENSHELL-RESOLVE-ENV-...``
* ``fixed-word``     the word a stand-in store holds where a refresh grant was
* ``other``          anything else in a credential position
* ``absent``         nothing in any credential position

``install_redirect`` sends every httpx, urllib and requests call to the server over loopback HTTP and names the
host the caller asked for in ``X-Stub-Host``. ``install_netguard`` refuses and lists every connection or name
lookup that is not loopback, so no test can reach a real provider.
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

PLACEHOLDER_PREFIX = "openshell:resolve:env:"
ALIAS_MARKER = "OPENSHELL-RESOLVE-ENV-"
FIXED_WORD = "held-on-the-host"
_CRED_HEADERS = ("authorization", "proxy-authorization", "x-api-key", "api-key", "x-goog-api-key",
                 "x-nous-refresh-token", "cookie", "x-auth-token", "x-access-token")
_CRED_QUERY = ("key", "api_key", "apikey", "access_token", "token")

NOUS_CLAIMS = {"scope": "inference:invoke", "sub": "user-fabricated", "org_id": "org-fabricated",
               "email": "someone@example.test", "paid_access": True,
               "tool_access": {"enabled": True, "coverage": {"web": True}}}
CODEX_CLAIMS = {"https://api.openai.com/auth": {"chatgpt_account_id": "acct-fabricated", "chatgpt_plan_type": "plus",
                                                "chatgpt_user_id": "user-fabricated"},
                "sub": "user-fabricated", "email": "someone@example.test"}
XAI_CLAIMS = {"sub": "user-fabricated", "scope": "openid profile email offline_access grok-cli:access api:access"}


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def claims_of(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def placeholder(env: str, *, stable: bool = True) -> str:
    """A placeholder in the shape OpenShell issues for the credential in *env* (a stable handle, or a revision)."""
    return f"{PLACEHOLDER_PREFIX}{'s' + secrets.token_hex(32) if stable else 'v7'}_{env}"


class Kinds:
    def __init__(self):
        self.real: set[str] = set()
        self.refresh: set[str] = set()

    def new_real(self, prefix: str = "REAL-") -> str:
        value = prefix + secrets.token_hex(24)
        self.real.add(value)
        return value

    def new_real_jwt(self, claims: dict) -> str:
        value = f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.{secrets.token_urlsafe(32)}"
        self.real.add(value)
        return value

    def new_refresh(self) -> str:
        value = "RT-" + secrets.token_hex(24)
        self.refresh.add(value)
        return value

    def issued(self) -> set[str]:
        return self.real | self.refresh

    def kind(self, value) -> str:
        v = (value or "").strip() if isinstance(value, str) else ""
        if not v:
            return "absent"
        if v in self.real:
            return "real"
        if v in self.refresh:
            return "refresh-token"
        if v == FIXED_WORD:
            return "fixed-word"
        if v.startswith(PLACEHOLDER_PREFIX):
            return "placeholder"
        parts = v.split(".")
        if len(parts) == 3 and parts[2].startswith(ALIAS_MARKER):
            return "alias"
        return "other"

    def inside(self, text: str) -> list[str]:
        """Kinds of credential found anywhere in *text* (a body, a path, an unusual header)."""
        found = []
        if any(v in text for v in self.real):
            found.append("real")
        if any(v in text for v in self.refresh):
            found.append("refresh-token")
        if PLACEHOLDER_PREFIX in text:
            found.append("placeholder")
        if ALIAS_MARKER in text:
            found.append("alias")
        if FIXED_WORD in text:
            found.append("fixed-word")
        return found


def _chat_completion(model: str) -> dict:
    return {"id": "chatcmpl-stub", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _chat_sse(model: str) -> bytes:
    def chunk(delta, finish=None):
        return {"id": "chatcmpl-stub", "object": "chat.completion.chunk", "created": int(time.time()),
                "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    rows = [chunk({"role": "assistant", "content": ""}), chunk({"content": "ok"}), chunk({}, "stop")]
    return "".join(f"data: {json.dumps(r)}\n\n" for r in rows).encode() + b"data: [DONE]\n\n"


def _anthropic_message(model: str) -> dict:
    return {"id": "msg_stub", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}


def _anthropic_sse(model: str) -> bytes:
    msg = dict(_anthropic_message(model), content=[], stop_reason=None)
    events = [("message_start", {"type": "message_start", "message": msg}),
              ("content_block_start", {"type": "content_block_start", "index": 0,
                                       "content_block": {"type": "text", "text": ""}}),
              ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                       "delta": {"type": "text_delta", "text": "ok"}}),
              ("content_block_stop", {"type": "content_block_stop", "index": 0}),
              ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                 "usage": {"output_tokens": 1}}),
              ("message_stop", {"type": "message_stop"})]
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()


def _responses_object(model: str, status: str = "completed") -> dict:
    item = {"id": "msg_stub", "type": "message", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": "ok", "annotations": []}]}
    return {"id": "resp_stub", "object": "response", "created_at": int(time.time()), "status": status,
            "model": model, "output": [item] if status == "completed" else [], "parallel_tool_calls": True,
            "tool_choice": "auto", "tools": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                      "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}


def _responses_sse(model: str) -> bytes:
    done = _responses_object(model)
    item = done["output"][0]
    part = item["content"][0]
    events = [
        {"type": "response.created", "response": _responses_object(model, "in_progress")},
        {"type": "response.output_item.added", "output_index": 0, "item": dict(item, content=[], status="in_progress")},
        {"type": "response.content_part.added", "item_id": "msg_stub", "output_index": 0, "content_index": 0,
         "part": dict(part, text="")},
        {"type": "response.output_text.delta", "item_id": "msg_stub", "output_index": 0, "content_index": 0,
         "delta": "ok", "logprobs": []},
        {"type": "response.output_text.done", "item_id": "msg_stub", "output_index": 0, "content_index": 0,
         "text": "ok", "logprobs": []},
        {"type": "response.content_part.done", "item_id": "msg_stub", "output_index": 0, "content_index": 0,
         "part": part},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": done},
    ]
    out = []
    for seq, event in enumerate(events):
        event["sequence_number"] = seq
        out.append(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n")
    return "".join(out).encode()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _serve(self):
        stub: Stub = self.server.stub  # type: ignore[attr-defined]
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        if (self.headers.get("content-encoding") or "").lower() == "zstd":
            try:
                from compression import zstd
                raw = zstd.decompress(raw)
            except Exception:
                pass
        text = raw.decode("utf-8", "replace")
        parts = urllib.parse.urlsplit(self.path)
        host = self.headers.get("x-stub-host") or f"loopback:{self.server.server_port}"
        cred: dict[str, str] = {}
        kinds = stub.kinds
        for name, value in self.headers.items():
            low = name.lower()
            if low == "x-stub-host":
                continue
            if low in ("authorization", "proxy-authorization"):
                scheme, _, token = value.partition(" ")
                cred[f"{low}:{scheme.lower()}"] = kinds.kind(token)
            elif low in _CRED_HEADERS:
                cred[low] = kinds.kind(value)
            else:
                for kind in kinds.inside(value):
                    cred[f"header:{low}"] = kind
        for name, values in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items():
            for value in values:
                kind = kinds.kind(value)
                if name.lower() in _CRED_QUERY or kind != "other":
                    cred[f"query:{name}"] = kind
        for kind in kinds.inside(urllib.parse.unquote(parts.path)):
            cred["path"] = kind
        for kind in kinds.inside(text):
            cred["body"] = kind
        try:
            body = json.loads(text) if text.strip().startswith("{") else {}
        except ValueError:
            body = {}
        record = {"host": host, "method": self.command, "path": parts.path, "cred": cred or {"none": "absent"},
                  "client": (self.headers.get("user-agent") or "").split("/")[0][:24],
                  "account_header": bool(self.headers.get("chatgpt-account-id"))}
        if isinstance(body, dict):
            record["body_keys"] = sorted(body)[:40]
        with stub.lock:
            stub.requests.append(record)
        status, payload, ctype = stub.answer(host, self.command, parts.path, body, self.headers, text)
        if status == 0:  # unreachable: no answer at all
            self.close_connection = True
            self.connection.close()
            return
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _serve


class Stub:
    """One loopback server standing in for every issuer and every model host."""

    def __init__(self):
        self.kinds = Kinds()
        self.lock = threading.Lock()
        self.requests: list[dict] = []
        # Every request to a token endpoint: which issuer, which grant, and the kind of what it presented.
        self.token_calls: list[dict] = []
        self.grants: dict[str, dict] = {}  # issuer -> {"refresh": current refresh grant, "ttl": seconds, "claims": {...}}
        self.inference_error: tuple[int, dict] | None = None  # the answer once a placeholder no longer resolves
        # What a refresh gets instead of the issuer's own answer: ``(status, body)`` from something in between
        # (a proxy that refuses the address), or ``"unreachable"`` (the connection ends without an answer).
        self.refresh_answer = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.stub = self  # type: ignore[attr-defined]
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    # -- issuers -------------------------------------------------------------------------------------
    def _grant(self, issuer: str, claims: dict | None, ttl: int) -> dict:
        grant = self.grants.setdefault(issuer, {"spent": []})
        grant.update(refresh=self.kinds.new_refresh(), ttl=ttl, claims=claims)
        return grant

    def _access(self, issuer: str) -> str:
        grant = self.grants[issuer]
        if grant["claims"] is None:  # an issuer whose tokens are opaque strings
            return self.kinds.new_real("sk-ant-oat01-" if issuer == "anthropic" else "REAL-")
        now = int(time.time())
        return self.kinds.new_real_jwt({**grant["claims"], "iat": now, "exp": now + grant["ttl"],
                                         "jti": secrets.token_hex(4)})

    def _token(self, issuer: str, grant_type: str, presented: str, claims, ttl: int) -> tuple[int, dict]:
        """Answer a token endpoint. A first grant (device or authorization code) opens the sign-in; a refresh
        must present the current refresh grant, and gets a new one (every refresh grant works once)."""
        refresh = grant_type == "refresh_token"
        current = self.grants.get(issuer, {}).get("refresh")
        with self.lock:
            self.token_calls.append({"issuer": issuer, "grant": "refresh" if refresh else "sign-in",
                                     "presented": self.kinds.kind(presented) if refresh else "code"})
        if refresh:
            if self.refresh_answer == "unreachable":
                return 0, {}
            if self.refresh_answer is not None:
                return self.refresh_answer
            if not current or presented != current:
                return 400, {"error": "invalid_grant", "error_description": "stub: not the current refresh grant"}
            self.grants[issuer]["spent"].append(presented)
            self.grants[issuer]["refresh"] = self.kinds.new_refresh()
        else:
            self._grant(issuer, claims, ttl)
        grant = self.grants[issuer]
        access = self._access(issuer)
        scope = (grant["claims"] or {}).get("scope", "")
        return 200, {"access_token": access, "refresh_token": grant["refresh"], "token_type": "Bearer",
                     "expires_in": grant["ttl"], "scope": scope,
                     "id_token": self.kinds.new_real_jwt({"sub": "user-fabricated", "email": "someone@example.test"})}

    def refreshes(self) -> list[dict]:
        return [call for call in self.token_calls if call["grant"] == "refresh"]

    def _issuer(self, host, path, body, headers, text):
        form = {k: v[0] for k, v in urllib.parse.parse_qs(text).items()} if not text.lstrip().startswith("{") else {}
        sent = {**form, **(body if isinstance(body, dict) else {})}
        grant_type = str(sent.get("grant_type") or "")
        device = {"device_code": "device-fabricated", "user_code": "ABCD-EFGH", "verification_uri": f"https://{host}/device",
                  "verification_uri_complete": f"https://{host}/device?user_code=ABCD-EFGH", "expires_in": 600,
                  "interval": 1}
        if host.startswith("portal.nousresearch.com"):
            if path.endswith("/api/oauth/device/code"):
                return 200, device
            if path.endswith("/api/oauth/token"):
                held = headers.get("x-nous-refresh-token") or sent.get("refresh_token") or ""
                refresh = bool(held) or grant_type == "refresh_token"
                return self._token("nous", "refresh_token" if refresh else grant_type, held, NOUS_CLAIMS, 900)
        if host.startswith("auth.openai.com"):
            if path.endswith("/deviceauth/usercode"):
                return 200, {"user_code": "ABCD-EFGH", "device_auth_id": "device-fabricated", "interval": "1"}
            if path.endswith("/deviceauth/token"):
                return 200, {"authorization_code": "code-fabricated", "code_verifier": "verifier-fabricated"}
            if path.endswith("/oauth/token"):
                return self._token("openai-codex", grant_type, str(sent.get("refresh_token") or ""), CODEX_CLAIMS, 3600)
        if host.startswith("auth.x.ai"):
            if path.endswith("/.well-known/openid-configuration"):
                return 200, {"authorization_endpoint": "https://auth.x.ai/oauth2/auth",
                             "token_endpoint": "https://auth.x.ai/oauth2/token"}
            if path.endswith("/oauth2/device/code"):
                return 200, device
            if path.endswith("/oauth2/token"):
                return self._token("xai-oauth", grant_type, str(sent.get("refresh_token") or ""), XAI_CLAIMS, 900)
        if host.startswith(("api.minimax.io", "api.minimaxi.com")):
            if path.endswith("/oauth/code"):
                return 200, {"user_code": "ABCD-EFGH", "verification_uri": f"https://{host}/device", "expired_in": 600,
                             "interval": 1, "state": sent.get("state")}
            if path.endswith("/oauth/token"):
                status, payload = self._token("minimax-oauth", grant_type, str(sent.get("refresh_token") or ""),
                                              None, 3600)
                return status, {**payload, "status": "success", "expired_in": 3600,
                                "resource_url": "https://api.minimax.io/resource"} if status == 200 else payload
        if host.startswith(("platform.claude.com", "console.anthropic.com")) and path.endswith("/oauth/token"):
            return self._token("anthropic", grant_type, str(sent.get("refresh_token") or ""), None, 3600)
        return None

    # -- answers -------------------------------------------------------------------------------------
    def answer(self, host, method, path, body, headers, text):
        issued = self._issuer(host, path, body, headers, text)
        if issued is not None:
            return issued[0], issued[1], "application/json"
        model = str(body.get("model") or "stub-model") if isinstance(body, dict) else "stub-model"
        stream = bool(isinstance(body, dict) and body.get("stream"))
        inference = path.endswith(("/chat/completions", "/messages", "/responses"))
        if inference and self.inference_error is not None:
            return self.inference_error[0], self.inference_error[1], "application/json"
        if path.endswith("/chat/completions"):
            return (200, _chat_sse(model), "text/event-stream") if stream else (200, _chat_completion(model), "application/json")
        if path.endswith("/messages"):
            return (200, _anthropic_sse(model), "text/event-stream") if stream else (200, _anthropic_message(model), "application/json")
        if path.endswith("/responses"):
            return (200, _responses_sse(model), "text/event-stream") if stream else (200, _responses_object(model), "application/json")
        if path.endswith("/models") or "/models/" in path:
            return 200, {"object": "list", "data": [{"id": "stub-model", "object": "model", "context_length": 200000}],
                         "models": [{"slug": "stub-model", "id": "stub-model", "name": "models/stub-model"}]}, "application/json"
        return 200, {}, "application/json"

    # -- reading the record --------------------------------------------------------------------------
    def rows(self) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.requests]

    def table(self) -> list[str]:
        """One line per distinct (host, method, path, credential placement)."""
        seen, out = set(), []
        for r in self.rows():
            cred = ", ".join(f"{k}={v}" for k, v in sorted(r["cred"].items()))
            line = f"{r['host']} {r['method']} {r['path']} :: {cred}"
            if line not in seen:
                seen.add(line)
                out.append(line)
        return out

    def kinds_seen(self) -> set[str]:
        return {v for r in self.rows() for v in r["cred"].values()}

    def clear(self):
        with self.lock:
            self.requests.clear()
            self.token_calls.clear()


def _loopback(host) -> bool:
    return str(host or "").lower() in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "")


def install_redirect(monkeypatch, port: int) -> None:
    """Send every httpx / urllib / requests call to the stub on *port*, naming the asked host in X-Stub-Host."""
    import urllib.request

    import httpx

    def rewrite(request: httpx.Request) -> httpx.Request:
        url = request.url
        if _loopback(url.host) and url.port == port:
            return request
        origin = f"{url.host}:{url.port or (443 if url.scheme in ('https', 'wss') else 80)}"
        headers = [(k, v) for k, v in request.headers.raw if k.lower() not in (b"host", b"x-stub-host")]
        headers += [(b"host", f"127.0.0.1:{port}".encode()), (b"x-stub-host", origin.encode())]
        return httpx.Request(request.method, url.copy_with(scheme="http", host="127.0.0.1", port=port),
                             headers=headers, stream=request.stream, extensions=request.extensions)

    sync_send = httpx.HTTPTransport.handle_request
    async_send = httpx.AsyncHTTPTransport.handle_async_request
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", lambda self, request: sync_send(self, rewrite(request)))

    async def handle_async(self, request):
        return await async_send(self, rewrite(request))

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle_async)

    # urllib: move only the connection. The request keeps its address, so a caller that compares the opened
    # origin with the one it asked for still sees its own, and leaves the credential where it put it.
    import http.client

    do_open = urllib.request.AbstractHTTPHandler.do_open

    def urllib_do_open(self, http_class, req, **http_conn_args):
        parts = urllib.parse.urlsplit(req.full_url)
        if _loopback(parts.hostname) and parts.port == port:
            return do_open(self, http_class, req, **http_conn_args)
        origin = f"{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
        req.add_unredirected_header("X-stub-host", origin)
        asked = req.host
        req.host = f"127.0.0.1:{port}"
        try:
            return do_open(self, http.client.HTTPConnection, req)
        finally:
            req.host = asked

    monkeypatch.setattr(urllib.request.AbstractHTTPHandler, "do_open", urllib_do_open)

    try:
        import requests
    except ImportError:
        return
    session_send = requests.sessions.Session.send

    def requests_send(self, request, **kwargs):
        parts = urllib.parse.urlsplit(request.url)
        if _loopback(parts.hostname) and parts.port == port:
            return session_send(self, request, **kwargs)
        origin = f"{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
        sent = request.copy()
        sent.url = urllib.parse.urlunsplit(("http", f"127.0.0.1:{port}", parts.path, parts.query, ""))
        sent.headers["X-Stub-Host"] = origin
        kwargs.pop("verify", None)
        response = session_send(self, sent, **kwargs)
        response.url, response.request = request.url, request  # the caller sees the address it asked for
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", requests_send)


def install_netguard(monkeypatch) -> list[str]:
    """Refuse and list every connection or name lookup that is not loopback."""
    escaped: list[str] = []
    real_connect, real_getaddrinfo = socket.socket.connect, socket.getaddrinfo

    def connect(self, address, *args):
        host = address[0] if isinstance(address, tuple) else ""
        if isinstance(address, tuple) and not _loopback(host):
            escaped.append(f"connect {host}:{address[1]}")
            raise ConnectionRefusedError(f"netguard: {host}:{address[1]} is not loopback")
        return real_connect(self, address, *args)

    def getaddrinfo(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name is not None and not _loopback(name):
            escaped.append(f"lookup {name}")
            raise socket.gaierror(f"netguard: {name} is not loopback")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return escaped
