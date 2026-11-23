"""Authenticating reverse proxy in front of the sandboxed backend.

Threat model: MXC host loopback is all-or-nothing, so the sandbox can connect to this port too. The
outer token therefore never enters the sandbox (it is stripped from every forwarded header and query
string and replaced by the inner token), and the inner token the sandbox holds never authenticates
here. Host-side routes (``host_routes``) are answered before anything is forwarded.

Each client connection carries one request: the proxy parses the request head strictly, forwards
exactly the framed body, asks the backend to close after its response, and closes the client after
it. WebSocket upgrades become a byte splice once the head is forwarded. Nothing the client sends after
the first request is ever read, so no second request can ride past the authentication check.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from typing import Awaitable, Callable, Optional

log = logging.getLogger("openshell.proxy")

MAX_HEAD = 64 * 1024
MAX_HOST_BODY = 1024 * 1024
HEAD_TIMEOUT = 30.0
CONNECT_TIMEOUT = 10.0
_CHUNK = 64 * 1024
SESSION_HEADER = "x-hermes-session-token"
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
# Mirrors hermes_cli.web_server._QUERY_TOKEN_API_PATHS: the only non-WebSocket route taking ?token=.
_QUERY_TOKEN_PATHS = frozenset({"/api/files/download"})
_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_REQUEST_LINE_RE = re.compile(r"([A-Z]+) (/\S*) (HTTP/1\.[01])")
# Dropped from forwarded requests: client credentials (replaced), hop-by-hop, forwarding claims.
_DROP = frozenset({"host", SESSION_HEADER, "authorization", "keep-alive", "proxy-connection", "te",
                   "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded"})


class BadRequest(Exception):
    def __init__(self, detail: str, status: int = 400):
        super().__init__(detail)
        self.status = status


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    raw_path: str
    path: str
    query: str
    authenticated: bool = False  # set by the proxy before a host route runs

    def all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def get(self, name: str) -> Optional[str]:
        values = self.all(name)
        return values[0] if values else None

    @property
    def is_upgrade(self) -> bool:
        conn = {t.strip().lower() for v in self.all("connection") for t in v.split(",")}
        return "upgrade" in conn and (self.get("upgrade") or "").strip().lower() == "websocket"

    def query_values(self, key: str) -> list[str]:
        return [v for k, v in urllib.parse.parse_qsl(self.query, keep_blank_values=True) if k == key]


def parse_head(raw: bytes) -> Request:
    lines = raw.decode("latin-1").split("\r\n")
    if len(lines) < 3 or lines[-1] or lines[-2]:
        raise BadRequest("malformed request head")
    m = _REQUEST_LINE_RE.fullmatch(lines[0])
    if not m:
        raise BadRequest("malformed request line")
    headers = []
    for line in lines[1:-2]:
        if not line or line[0] in " \t":
            raise BadRequest("folded or empty header line")
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN_RE.fullmatch(name) or "\x00" in value:
            raise BadRequest("malformed header")
        headers.append((name, value.strip(" \t")))
    method, target, version = m.groups()
    split = urllib.parse.urlsplit(target)
    return Request(method, target, version, headers, split.path, urllib.parse.unquote(split.path), split.query)


def body_framing(req: Request) -> tuple[str, int]:
    te, cl = req.all("transfer-encoding"), req.all("content-length")
    if te:
        if cl or len(te) != 1 or te[0].lower() != "chunked":
            raise BadRequest("unsupported transfer-encoding")
        return "chunked", 0
    if cl:
        if len(set(cl)) != 1 or not cl[0].isdigit():
            raise BadRequest("bad content-length")
        return "length", int(cl[0])
    return "none", 0


def host_is_loopback(host_header: str) -> bool:
    value = (host_header or "").strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host == "::1" and (not rest or re.fullmatch(r":\d+", rest) is not None)
    host, _, port = value.partition(":")
    return host.lower() in _LOOPBACK and (not port or port.isdigit())


async def copy_exact(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, n: int) -> None:
    while n > 0:
        chunk = await reader.read(min(n, _CHUNK))
        if not chunk:
            raise ConnectionError("client closed mid-body")
        writer.write(chunk)
        await writer.drain()
        n -= len(chunk)


async def copy_chunked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Forward one chunked body verbatim, stopping exactly at its end."""
    while True:
        size_line = await reader.readuntil(b"\r\n")
        size_text = size_line[:-2].split(b";", 1)[0].strip()
        if not size_text or not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_text):
            raise BadRequest("bad chunk size")
        size = int(size_text, 16)
        writer.write(size_line)
        if size == 0:
            while True:  # trailers, then the terminating empty line
                line = await reader.readuntil(b"\r\n")
                writer.write(line)
                if line == b"\r\n":
                    await writer.drain()
                    return
        await copy_exact(reader, writer, size)
        crlf = await reader.readexactly(2)
        if crlf != b"\r\n":
            raise BadRequest("bad chunk terminator")
        writer.write(crlf)


async def read_body(reader: asyncio.StreamReader, framing: tuple[str, int], limit: int = MAX_HOST_BODY) -> bytes:
    kind, n = framing
    if kind == "none":
        return b""
    if kind == "length":
        if n > limit:
            raise BadRequest("body too large", 413)
        return await reader.readexactly(n)
    buf = bytearray()

    class _Sink:
        def write(self, data: bytes) -> None:
            buf.extend(data)
            if len(buf) > limit + 1024:
                raise BadRequest("body too large", 413)

        async def drain(self) -> None:
            return None

    await copy_chunked(reader, _Sink())  # type: ignore[arg-type]
    return _dechunk(bytes(buf))


def _dechunk(data: bytes) -> bytes:
    out, pos = bytearray(), 0
    while True:
        end = data.index(b"\r\n", pos)
        size = int(data[pos:end].split(b";", 1)[0], 16)
        if size == 0:
            return bytes(out)
        out += data[end + 2:end + 2 + size]
        pos = end + 2 + size + 2


def response_bytes(status: int, body: bytes, content_type: str = "application/json",
                   extra: Optional[dict] = None) -> bytes:
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = ""
    head = [f"HTTP/1.1 {status} {reason}", f"Content-Type: {content_type}", f"Content-Length: {len(body)}",
            "Cache-Control: no-store", "Connection: close"]
    head += [f"{k}: {v}" for k, v in (extra or {}).items()]
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


def json_response(status: int, payload, extra: Optional[dict] = None) -> bytes:
    return response_bytes(status, json.dumps(payload).encode("utf-8"), extra=extra)


@dataclass
class Upstream:
    host: str
    port: int
    token: str


HostHandler = Callable[[Request, bytes], Awaitable[tuple[int, object, dict]]]


class Proxy:
    def __init__(self, *, outer_token: str, upstream: Callable[[], Optional[Upstream]],
                 unavailable: Callable[[], dict], own_profile: Callable[[str], bool],
                 host_route: Callable[[str, str], Optional[HostHandler]], public_paths: frozenset[str],
                 ws_relay=None, hold_status: Callable[[], bool] = lambda: False,
                 hold_note: Callable[[], Optional[dict]] = lambda: None):
        self._outer = outer_token
        self._upstream = upstream
        self._unavailable = unavailable
        self._own_profile = own_profile
        self._host_route = host_route
        self._public = public_paths
        # Frame relay for authenticated /api/ws (cards.Cards.relay): strips access wording from approval
        # frames the sandbox sends, and carries the launcher's in-chat cards.
        self._ws_relay = ws_relay
        # While the sandbox restarts or stops on purpose (a folder grant, the switch turning off),
        # GET /api/status answers the sandbox's last 200 instead of 503: the desktop counts failed
        # status probes and, after three, drops this backend and re-dials it, a dial that then waits
        # minutes for a launcher that is going away and that the profile's switch-off cannot cancel.
        self._hold_status = hold_status
        # Why it is down, added to that held answer as ``openshell_sandbox`` ({"state": "restarting",
        # "reason": "folder", "folder": "...outside", "label": "Restarting the sandbox to add outside", ...}),
        # the same record the plugin status reports as ``restarting`` / ``restart`` (Supervisor.restarting_view).
        self._hold_note = hold_note
        self._status_cache: dict[bool, bytes] = {}  # authenticated? -> the last full 200 response
        self._splices: set = set()  # (client writer, upstream writer) of WebSocket upgrades spliced as bytes
        self._connections: set = set()  # the task of every connection being handled (``handle``)

    def _relayed(self, req: Request, authed: bool) -> bool:
        return self._ws_relay is not None and authed and req.is_upgrade and req.path == "/api/ws"

    def close_upgrades(self, why: str = "restarting") -> int:
        """The backend is going down (``Supervisor.on_down``): end every byte-spliced WebSocket now (the
        relayed chat socket gets a 1012 close frame from the relay; a splice can only be cut, since a
        frame may be half through). Returns how many were cut."""
        pairs = list(self._splices)
        for pair in pairs:
            for w in pair:
                try:
                    w.close()
                except (OSError, RuntimeError):
                    pass
        return len(pairs)

    def authenticated(self, req: Request) -> bool:
        presented = list(req.all(SESSION_HEADER))
        presented += [v[7:] for v in req.all("authorization") if v[:7].lower() == "bearer "]
        if req.is_upgrade or req.path in _QUERY_TOKEN_PATHS:
            presented += req.query_values("token")
        expected = self._outer.encode()
        return any(hmac.compare_digest(p.strip().encode(), expected) for p in presented)

    def open_connections(self) -> int:
        """How many connections are being handled now."""
        return len(self._connections)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # asyncio refers to a connection's task only through the transport's pending read. Once the client has
        # stopped sending there is none, and a request still waiting for the backend's answer would be
        # unreachable while pending: the collector then runs the cleanup below on whichever thread it runs
        # on, and a stream closed from a thread that is not the loop's can end the loop (on Windows the
        # proactor's poll raises InvalidStateError when the cancelled read completes). So every connection's
        # task is held here until it is done.
        task = asyncio.current_task()
        self._connections.add(task)
        try:
            await self._handle(reader, writer)
        finally:
            self._connections.discard(task)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
                return
            try:
                req = parse_head(raw)
                if not host_is_loopback(req.get("host") or ""):
                    raise BadRequest("Host must be a loopback name")
                framing = body_framing(req)
                await self._dispatch(req, framing, reader, writer)
            except BadRequest as exc:
                writer.write(json_response(exc.status, {"detail": str(exc)}))
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.exception("proxy request failed")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, req: Request, framing, reader, writer) -> None:
        authed = self.authenticated(req)
        req.authenticated = authed
        handler = self._host_route(req.method, req.path)
        # A ticket route (the switch's switch/off) checks its own one-time ticket: the page calls it
        # directly once the desktop no longer routes the profile here, and must be able to read the answer.
        ticketed = handler is not None and getattr(handler, "ticket_auth", False)
        foreign = [v for v in req.query_values("profile") if not self._own_profile(v)]
        if handler is not None and not authed and not ticketed:
            return await _send(writer, json_response(401, {"detail": "Unauthorized"}))
        if foreign:
            return await _send(writer, json_response(403, {"detail": f"This sandboxed backend serves one profile; "
                                                                    f"{foreign[0]!r} is not it."}))
        if handler is not None:
            body = await read_body(reader, framing)
            try:
                status, payload, extra = await handler(req, body)
            except Exception as exc:
                log.exception("host route %s %s failed", req.method, req.path)
                status, payload, extra = 500, {"detail": f"{type(exc).__name__}: {exc}"}, {}
            if ticketed:
                extra = {**extra, "Access-Control-Allow-Origin": "*"}
            if status == 204:
                return await _send(writer, response_bytes(204, b"", extra=extra))
            return await _send(writer, json_response(status, payload, extra))
        public = req.method in ("GET", "HEAD", "OPTIONS") and (req.path in self._public or req.method == "OPTIONS")
        if not (authed or public):
            return await _send(writer, json_response(401, {"detail": "Unauthorized"}))
        upstream = self._upstream()
        if upstream is None:
            cached = self._status_cache.get(authed) if _is_status(req) else None
            if cached is not None and self._hold_status():
                return await _send(writer, _with_note(cached, self._hold_note()))
            return await _send(writer, json_response(503, {"detail": "Sandbox is not running.", **self._unavailable()}))
        await self._forward(req, framing, reader, writer, upstream, authed)

    def _forward_head(self, req: Request, upstream: Upstream, authed: bool) -> bytes:
        # The outer token is swapped for the inner one wherever it appears (query, Referer, cookies),
        # authenticated or not, so it can never reach the sandbox; the inner credential header is
        # added only for an authenticated request.
        def swap(s: str) -> str:
            return s.replace(self._outer, upstream.token)

        target = swap(req.target)
        if authed and req.is_upgrade and not req.query_values("token"):
            target += ("&" if "?" in target else "?") + "token=" + urllib.parse.quote(upstream.token, safe="")
        lines = [f"{req.method} {target} {req.version}", f"Host: 127.0.0.1:{upstream.port}"]
        for name, value in req.headers:
            low = name.lower()
            if low in _DROP or (low == "connection" and not req.is_upgrade):
                continue
            if low == "sec-websocket-extensions" and self._relayed(req, authed):
                continue  # no permessage-deflate on a relayed socket (frames must stay readable)
            lines.append(f"{name}: {swap(value)}")
        if authed:
            lines.append(f"X-Hermes-Session-Token: {upstream.token}")
        if not req.is_upgrade:
            lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        if self._outer.encode() in head:  # unreachable by construction; the boundary is worth a check
            raise BadRequest("outer credential in forwarded head")
        return head

    async def _forward(self, req, framing, reader, writer, upstream: Upstream, authed: bool) -> None:
        head = self._forward_head(req, upstream, authed)
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream.host, upstream.port, limit=MAX_HEAD), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return await _send(writer, json_response(502, {"detail": "Sandboxed backend unreachable."}))
        try:
            up_writer.write(head)
            await up_writer.drain()
            if req.is_upgrade:
                if self._relayed(req, authed):
                    await self._ws_relay(reader, writer, up_reader, up_writer)
                else:
                    pair = (writer, up_writer)
                    self._splices.add(pair)
                    try:
                        await _splice(reader, writer, up_reader, up_writer)
                    finally:
                        self._splices.discard(pair)
                return
            kind, n = framing
            send_body = (copy_exact(reader, up_writer, n) if kind == "length"
                         else copy_chunked(reader, up_writer) if kind == "chunked" else None)
            body_task = asyncio.ensure_future(send_body) if send_body else None
            try:
                if _is_status(req):
                    response = await _pipe_kept(up_reader, writer, STATUS_CACHE_MAX)
                    if response is not None and response.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
                        self._status_cache[authed] = response
                else:
                    await _pipe(up_reader, writer)  # concurrent with the body: Expect: 100-continue, early errors
            finally:
                if body_task is not None and not body_task.done():
                    body_task.cancel()
                if body_task is not None:
                    try:
                        await body_task
                    except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError, BadRequest):
                        pass
        finally:
            up_writer.close()


async def _send(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


STATUS_CACHE_MAX = 64 * 1024


def _with_note(response: bytes, note: Optional[dict]) -> bytes:
    """A held status answer with ``openshell_sandbox`` added (a plain JSON object body only; anything
    else, e.g. a compressed or chunked body, goes out as it was)."""
    if not note:
        return response
    head, sep, body = response.partition(b"\r\n\r\n")
    lowered = head.lower()
    if not sep or b"content-encoding:" in lowered or b"transfer-encoding:" in lowered:
        return response
    try:
        obj = json.loads(body)
    except ValueError:
        return response
    if not isinstance(obj, dict):
        return response
    return json_response(200, {**obj, "openshell_sandbox": note})


def _is_status(req: Request) -> bool:
    return req.method == "GET" and req.path == "/api/status" and not req.is_upgrade


async def _pipe_kept(src: asyncio.StreamReader, dst: asyncio.StreamWriter, limit: int) -> Optional[bytes]:
    """``_pipe``, keeping a copy of what passed (None once it exceeds *limit*)."""
    kept: Optional[bytearray] = bytearray()
    while True:
        chunk = await src.read(_CHUNK)
        if not chunk:
            return bytes(kept) if kept is not None else None
        if kept is not None:
            kept += chunk
            if len(kept) > limit:
                kept = None
        dst.write(chunk)
        await dst.drain()


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    while True:
        chunk = await src.read(_CHUNK)
        if not chunk:
            return
        dst.write(chunk)
        await dst.drain()


async def _splice(c_reader, c_writer, u_reader, u_writer) -> None:
    async def one_way(src, dst):
        try:
            await _pipe(src, dst)
        except (ConnectionError, OSError):
            pass

    tasks = [asyncio.ensure_future(one_way(c_reader, u_writer)), asyncio.ensure_future(one_way(u_reader, c_writer))]
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
