"""Behaviour tests for the sandbox launcher's proxy and grant layout (no sandbox needed).

The proxy runs against a fake upstream that records each request head it receives, so every test
checks what actually crossed into the "sandbox" side. HERMES_HOME is a temp dir (conftest.py), set before Hermes
is imported.

Run: PYTHONPATH="<hermes checkout>;<this repo>" <hermes python> -m pytest openshell/tests -q
"""
import asyncio
from pathlib import Path


import pytest  # noqa: E402

from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher.proxy import MAX_HEAD, Proxy, Upstream, parse_head  # noqa: E402

OUTER = "outer-" + "o" * 40
INNER = "inner-" + "i" * 40


class FakeUpstream:
    """Records request heads; answers 101 + echo for upgrades, else 200 with the received body size."""

    def __init__(self):
        self.heads: list[bytes] = []
        self.bodies: list[bytes] = []

    async def handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        self.heads.append(head)
        req = parse_head(head)
        if req.is_upgrade:
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            await writer.drain()
            data = await reader.read(100)
            writer.write(b"echo:" + data)
            await writer.drain()
        else:
            body = b""
            if req.get("content-length"):
                body = await reader.readexactly(int(req.get("content-length")))
            elif (req.get("transfer-encoding") or "").lower() == "chunked":
                while True:
                    size = int((await reader.readuntil(b"\r\n"))[:-2], 16)
                    if size == 0:
                        await reader.readuntil(b"\r\n")
                        break
                    body += await reader.readexactly(size)
                    await reader.readexactly(2)
            self.bodies.append(body)
            payload = f"got {len(body)}".encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(payload), payload))
            await writer.drain()
        writer.close()


async def _host_status(req, body):
    return 200, {"ok": True}, {}


def _with_proxy(scenario):
    """Run *scenario(port, upstream)* against a proxy in front of a fake upstream."""
    async def main():
        upstream = FakeUpstream()
        up_server = await asyncio.start_server(upstream.handle, "127.0.0.1", 0)
        up_port = up_server.sockets[0].getsockname()[1]
        proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", up_port, INNER),
                      unavailable=lambda: {}, own_profile=lambda name: name in ("", "work", "current"),
                      host_route=lambda m, p: _host_status if p == "/api/plugins/openshell/status" else None,
                      public_paths=frozenset({"/api/status"}))
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
        port = server.sockets[0].getsockname()[1]
        try:
            return await scenario(port, upstream)
        finally:
            server.close()
            up_server.close()
    return asyncio.run(main())


async def _exchange(port, raw: bytes, *, then: bytes = b"") -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    if then:
        await asyncio.sleep(0.2)
        writer.write(then)
        await writer.drain()
    out = b""
    try:
        while chunk := await asyncio.wait_for(reader.read(65536), 3):
            out += chunk
    except asyncio.TimeoutError:
        pass
    writer.close()
    return out


def _get(path, port, *headers):
    lines = [f"GET {path} HTTP/1.1", f"Host: 127.0.0.1:{port}", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def test_status_keeps_its_last_answer_while_the_sandbox_is_down_on_purpose():
    """A folder restart or the switch turning off takes the sandbox down for seconds: GET /api/status
    answers the last 200 meanwhile (the desktop drops and re-dials a backend after three failed status
    probes), other calls still say 503, and a sandbox that died says 503 for status too."""
    state = {"up": True, "hold": False}

    async def main():
        upstream = FakeUpstream()
        up_server = await asyncio.start_server(upstream.handle, "127.0.0.1", 0)
        up_port = up_server.sockets[0].getsockname()[1]
        proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", up_port, INNER) if state["up"] else None,
                      unavailable=lambda: {"state": "restarting"}, own_profile=lambda name: True,
                      host_route=lambda m, p: None, public_paths=frozenset({"/api/status"}),
                      hold_status=lambda: state["hold"])
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
        port = server.sockets[0].getsockname()[1]
        try:
            live = await _exchange(port, _get("/api/status", port))
            assert live.startswith(b"HTTP/1.1 200") and live.endswith(b"got 0")
            state.update(up=False, hold=True)
            held = await _exchange(port, _get("/api/status", port))
            assert held == live and len(upstream.heads) == 1  # the kept answer, nothing forwarded
            other = await _exchange(port, _get("/api/config", port, f"X-Hermes-Session-Token: {OUTER}"))
            assert other.startswith(b"HTTP/1.1 503")
            state["hold"] = False  # down without a reason (a crash): the truth
            assert (await _exchange(port, _get("/api/status", port))).startswith(b"HTTP/1.1 503")
        finally:
            server.close()
            up_server.close()

    asyncio.run(main())


def test_unauthenticated_api_call_never_reaches_the_sandbox():
    async def scenario(port, upstream):
        out = await _exchange(port, _get("/api/config", port))
        assert out.startswith(b"HTTP/1.1 401")
        assert upstream.heads == []
    _with_proxy(scenario)


@pytest.mark.parametrize("header", [f"X-Hermes-Session-Token: {OUTER}", f"Authorization: Bearer {OUTER}"])
def test_outer_token_is_swapped_for_the_inner_one(header):
    async def scenario(port, upstream):
        out = await _exchange(port, _get("/api/config?profile=work", port, header, f"Referer: http://x/?token={OUTER}"))
        assert out.startswith(b"HTTP/1.1 200")
        (head,) = upstream.heads
        assert OUTER.encode() not in head
        assert f"X-Hermes-Session-Token: {INNER}".encode() in head
        assert b"Host: 127.0.0.1:" in head and b"Connection: close" in head
    _with_proxy(scenario)


def test_inner_token_does_not_authenticate_the_proxy():
    async def scenario(port, upstream):
        for header in (f"X-Hermes-Session-Token: {INNER}", f"Authorization: Bearer {INNER}"):
            assert (await _exchange(port, _get("/api/config", port, header))).startswith(b"HTTP/1.1 401")
        out = await _exchange(port, _get("/api/plugins/openshell/status", port, f"X-Hermes-Session-Token: {INNER}"))
        assert out.startswith(b"HTTP/1.1 401")
        assert upstream.heads == []
    _with_proxy(scenario)


def test_query_token_only_authenticates_websocket_upgrades():
    async def scenario(port, upstream):
        assert (await _exchange(port, _get(f"/api/config?token={OUTER}", port))).startswith(b"HTTP/1.1 401")
        upgrade = _get(f"/api/ws?token={OUTER}&profile=work", port, "Connection: Upgrade", "Upgrade: websocket",
                       "Sec-WebSocket-Key: x", "Sec-WebSocket-Version: 13")
        out = await _exchange(port, upgrade, then=b"frame")
        assert out.startswith(b"HTTP/1.1 101") and out.endswith(b"echo:frame")
        (head,) = upstream.heads
        assert f"token={INNER}".encode() in head and OUTER.encode() not in head
    _with_proxy(scenario)


def test_public_path_is_forwarded_without_credentials():
    async def scenario(port, upstream):
        assert (await _exchange(port, _get("/api/status", port))).startswith(b"HTTP/1.1 200")
        (head,) = upstream.heads
        assert INNER.encode() not in head
    _with_proxy(scenario)


def test_foreign_profile_and_non_loopback_host_are_refused():
    async def scenario(port, upstream):
        auth = f"X-Hermes-Session-Token: {OUTER}"
        assert (await _exchange(port, _get("/api/config?profile=other", port, auth))).startswith(b"HTTP/1.1 403")
        rebind = f"GET /api/status HTTP/1.1\r\nHost: evil.example\r\n{auth}\r\n\r\n".encode()
        assert (await _exchange(port, rebind)).startswith(b"HTTP/1.1 400")
        assert upstream.heads == []
    _with_proxy(scenario)


def test_a_pipelined_second_request_is_never_forwarded():
    async def scenario(port, upstream):
        out = await _exchange(port, _get("/api/status", port) + _get("/api/config", port))
        assert out.count(b"HTTP/1.1 ") == 1
        assert len(upstream.heads) == 1
    _with_proxy(scenario)


def test_bodies_are_forwarded_exactly_and_smuggling_shapes_refused():
    async def scenario(port, upstream):
        auth = f"X-Hermes-Session-Token: {OUTER}"
        chunked = (f"POST /api/x HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nGARBAGE").encode()
        assert (await _exchange(port, chunked)).endswith(b"got 11")
        assert upstream.bodies == [b"hello world"]
        both = (f"POST /api/x HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\nContent-Length: 3\r\n"
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n").encode()
        assert (await _exchange(port, both)).startswith(b"HTTP/1.1 400")
        assert len(upstream.heads) == 1
    _with_proxy(scenario)


def test_host_routes_need_the_outer_token_and_never_forward():
    async def scenario(port, upstream):
        assert (await _exchange(port, _get("/api/plugins/openshell/status", port))).startswith(b"HTTP/1.1 401")
        out = await _exchange(port, _get("/api/plugins/openshell/status", port, f"X-Hermes-Session-Token: {OUTER}"))
        assert out.startswith(b"HTTP/1.1 200") and out.endswith(b'{"ok": true}')
        assert upstream.heads == []
    _with_proxy(scenario)


# --- grant layout ------------------------------------------------------------------------------------

def _runtime(tmp: Path) -> L.Runtime:
    for d in ("code", "env", "base", "store", "installs/k"):
        (tmp / d).mkdir(parents=True, exist_ok=True)
    return L.Runtime(python=tmp / "env" / "python.exe", code_dir=tmp / "code", env_dir=tmp / "env",
                     base_python=tmp / "base", store=tmp / "store", install_state=tmp / "installs" / "k")


def test_named_profile_grants(tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    (home / ".env").write_text("K=v\n")
    (home / "auth.json.bak").write_text("{}")
    layout = L.ProfileLayout(name="work", home=home, root=root)
    g = L.profile_grants(layout, _runtime(tmp_path), [{"path": str(tmp_path / "ws"), "access": "rw"}])
    assert home in g.readwrite and tmp_path / "ws" in g.readwrite
    assert home / "plugins" in g.readonly and home / "desktop-plugins" in g.readonly
    assert (home / "plugins").is_dir()  # created so the read-only grant exists
    for p in (home / ".env", home / "auth.json", home / "auth.json.bak", home / "mcp-tokens",
              home / "auth", home / "platforms", home / ".config", tmp_path / "installs" / "k"):
        assert p in g.denied, p
    # Every deny inside the home is directly under it (MXC needs its parent to exist), except stores below a
    # folder the sandbox writes, which the Windows driver checks one by one (test_rename_safe.py).
    for p in g.denied:
        if home in p.parents:
            assert p.parent == home or p.relative_to(home).parts[0] in L.WRITABLE_STORE_DIRS, p
    assert layout.state_dir not in g.readwrite and root not in g.readwrite


def test_default_profile_carves_infrastructure_out_of_the_home(tmp_path):
    root = tmp_path / "root"
    for d in ("hermes-agent", "tools", "installs", "cache/uv", "cache/terminal"):
        (root / d).mkdir(parents=True)
    layout = L.ProfileLayout(name="default", home=root, root=root)
    g = L.profile_grants(layout, _runtime(tmp_path), [])
    assert root in g.readwrite
    assert root / "hermes-agent" in g.readonly and root / "tools" in g.readonly and root / "cache" / "uv" in g.readonly
    assert root / "cache" not in g.readonly  # the profile's own caches (terminal state, scratch) stay writable
    for p in (root / "profiles", root / "openshell", root / "installs"):
        assert p in g.denied
    assert all(b in g.readwrite for b in L.box_dirs(layout).values())  # nested under the denied state dir


def test_folder_validation_refuses_broad_or_sensitive_roots(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    layout = L.ProfileLayout(name="work", home=root / "profiles" / "work", root=root)
    for bad in (Path(tmp_path.anchor), Path.home(), root, root / "profiles"):
        bad.mkdir(parents=True, exist_ok=True)
        with pytest.raises(L.LayoutError):
            L.validate_folder(str(bad), layout)
    ok = tmp_path / "project"
    ok.mkdir()
    assert L.validate_folder(str(ok), layout) == ok.resolve()
