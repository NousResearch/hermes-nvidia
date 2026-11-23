"""A planned restart as the desktop sees it: the launcher's status says
``restarting`` with ``restart: {reason, folder}`` BEFORE the backend goes down (one source for the plugin
status and the held ``/api/status``), and every relayed chat socket is closed with 1012 the moment a
restart begins or the backend dies, instead of staying open until the desktop's heartbeat gives up.
Real sockets for the relay; the supervisor's driver and start are stand-ins (no sandbox)."""
import asyncio
import json
from pathlib import Path

from openshell.launcher import cards as C
from openshell.launcher import layout as L
from openshell.launcher.driver import SandboxDriver
from openshell.launcher.proxy import MAX_HEAD, Proxy, Upstream
from openshell.launcher.spec import load_spec
from openshell.launcher.supervisor import Supervisor

OUTER = "outer-" + "o" * 40
INNER = "inner-" + "i" * 40


class RecordingDriver(SandboxDriver):
    name = "fake"
    uses_host_shell = False
    capabilities_info = {"label": "Fake", "network_live": True, "network_live_interrupts": False}

    def __init__(self, seen):
        self.seen = seen
        self.code = None

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return self.code

    def stop(self, timeout=20.0):
        self.seen.append(("driver.stop", None))

    def policy(self):
        return {}


def _supervisor(tmp_path, seen):
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path, env_dir=tmp_path, base_python=tmp_path,
                        store=None)
    sup = Supervisor(layout, runtime, load_spec(layout), RecordingDriver(seen), outer_port=1)

    async def start_locked():  # the real one launches a sandbox; here it only records what the status said
        sup.state = "starting"  # as the real one does; a restart still reports "restarting" (one state)
        seen.append(("start", sup.status()["state"], sup.status()["restart"]))
        sup.state = "running"

    sup._start_locked = start_locked
    sup.state = "running"
    return sup


def test_a_folder_restart_says_why_before_the_backend_goes_down(tmp_path):
    seen = []
    sup = _supervisor(tmp_path, seen)
    outside = str(tmp_path / "folders" / "outside")

    def listener(why):
        status = sup.status()
        seen.append(("on_down", why, status["state"], status["restart"], sup.unavailable().get("restart")))

    sup.on_down.append(listener)
    note = {"why": "folders", "reason": "folder", "folder": outside, "add": [outside], "remove": [],
            "label": "Restarting the sandbox to add outside", "since": 1.0}
    assert sup.status()["restart"] is None and sup.status()["switching_off"] is False

    async def main():
        real_stop = sup.driver.stop

        def stop(timeout=20.0):
            status = sup.status()
            seen.append(("driver.stop", status["state"], status["restart"], sup.restarting_view()))
            real_stop(timeout)

        sup.driver.stop = stop
        await sup.restart(note=note)

    asyncio.run(main())
    restart = {"reason": "folder", "folder": outside}
    assert seen[0] == ("on_down", "restarting", "restarting", restart, restart)  # listeners first, state set
    assert seen[1][:3] == ("driver.stop", "restarting", restart)
    # the held /api/status note (openshell_sandbox) is the same record, with the page's label
    assert seen[1][3]["reason"] == "folder" and seen[1][3]["label"] == "Restarting the sandbox to add outside"
    assert seen[3] == ("start", "restarting", restart)  # still says why (and "restarting") while it starts
    assert sup.status()["restart"] is None and sup.restart_note is None and sup.state == "running"
    # a removal says so too; a plain restart (the page's Restart button) has no reason
    sup.state, sup.restart_note = "restarting", {**note, "reason": "remove", "add": [], "remove": [outside]}
    assert sup.status()["restart"] == {"reason": "remove", "folder": outside}
    sup.state, sup.restart_note = "restarting", None
    assert sup.status()["restart"] is None and sup.status()["state"] == "restarting"


def test_a_stop_and_a_dead_sandbox_tell_the_listeners_too(tmp_path):
    seen = []
    sup = _supervisor(tmp_path, seen)
    sup.on_down.append(lambda why: seen.append(("on_down", why, sup.state)))

    async def main():
        sup.driver.code = 3  # died on its own
        watch = asyncio.ensure_future(sup.watch())
        for _ in range(40):
            await asyncio.sleep(0.05)
            if any(e[0] == "on_down" for e in seen):
                break
        watch.cancel()
        sup.driver.code = None
        sup.state = "running"
        await sup.stop()

    asyncio.run(main())
    assert [e for e in seen if e[0] == "on_down"] == [("on_down", "exited", "exited"), ("on_down", "stopping", "stopping")]


# -- the relay closes the desktop's socket ---------------------------------------------------------

def _frames(data: bytes):
    """(opcode, payload) for each unmasked server frame in *data*."""
    out, i = [], 0
    while i + 2 <= len(data):
        op, n, i = data[i] & 0x0F, data[i + 1] & 0x7F, i + 2
        if n == 126:
            n, i = int.from_bytes(data[i:i + 2], "big"), i + 2
        elif n == 127:
            n, i = int.from_bytes(data[i:i + 8], "big"), i + 8
        out.append((op, data[i:i + n]))
        i += n
    return out


async def _relay_scenario(upstream_behaviour, after_open=None):
    """A desktop socket through the real proxy and relay to a fake backend; returns what the desktop got
    after the 101 (raw bytes until EOF) and whether it saw EOF."""
    cards = C.Cards(None, None, cards=False)
    cards.start()
    ups = {}

    async def backend(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        await writer.drain()
        ups["writer"] = writer
        await upstream_behaviour(reader, writer)

    up_server = await asyncio.start_server(backend, "127.0.0.1", 0)
    up_port = up_server.sockets[0].getsockname()[1]
    proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", up_port, INNER), unavailable=dict,
                  own_profile=lambda n: True, host_route=lambda m, p: None, public_paths=frozenset(),
                  ws_relay=cards.relay)
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write((f"GET /api/ws?token={OUTER} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert head.startswith(b"HTTP/1.1 101")
        for _ in range(50):
            if cards._conns:
                break
            await asyncio.sleep(0.02)
        if after_open is not None:
            await after_open(cards, proxy)
        got = b""
        try:
            while chunk := await asyncio.wait_for(reader.read(65536), 5):
                got += chunk
            eof = True
        except asyncio.TimeoutError:
            eof = False
        writer.close()
        return got, eof
    finally:
        server.close()
        up_server.close()
        await cards.stop()


def test_the_relay_closes_the_desktop_socket_with_1012_when_the_backend_ends():
    async def dies(reader, writer):
        writer.write(C.server_text_frame({"jsonrpc": "2.0", "method": "event", "params": {"type": "gateway.ready"}}))
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()  # the backend went away without a close frame

    got, eof = asyncio.run(_relay_scenario(dies))
    frames = _frames(got)
    assert eof and [op for op, _ in frames] == [0x1, 0x8]
    assert int.from_bytes(frames[1][1][:2], "big") == 1012


def test_a_restart_closes_relayed_sockets_at_once_even_while_the_backend_hangs():
    async def hangs(reader, writer):
        await asyncio.sleep(30)  # a backend that neither answers nor closes (what timed the heartbeat out)

    async def restart_begins(cards, proxy):
        await cards.close_clients("restarting")  # Supervisor.on_down

    got, eof = asyncio.run(_relay_scenario(hangs, restart_begins))
    frames = _frames(got)
    assert eof and len(frames) == 1 and frames[0][0] == 0x8
    assert int.from_bytes(frames[0][1][:2], "big") == 1012 and frames[0][1][2:] == b"service restart"


def test_the_backends_own_close_is_relayed_once():
    async def closes(reader, writer):
        writer.write(bytes([0x88, 2]) + (1000).to_bytes(2, "big"))
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()

    got, eof = asyncio.run(_relay_scenario(closes))
    frames = _frames(got)
    assert eof and len(frames) == 1 and int.from_bytes(frames[0][1][:2], "big") == 1000


def test_the_launcher_wires_restarts_to_the_socket_closers():
    source = (Path(__file__).resolve().parents[1] / "launcher_cli.py").read_text(encoding="utf-8")
    assert "sup.on_down += [cards.close_clients, proxy.close_upgrades]" in source
    assert json.dumps(C.CLOSE_RESTART) == "1012"
