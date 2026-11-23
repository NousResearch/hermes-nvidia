"""The proxy holds the task of every connection it is handling.

Why: asyncio refers to a connection's task only through the transport's pending read. Once a client has stopped
sending (it closed, or it shut down its sending side and waits) there is no pending read, and a request that is
still waiting for the backend's answer is unreachable while it is pending. The collector then finalizes it on
whichever thread it happens to run on: "Task was destroyed but it is pending!", and the handler's cleanup closes
both streams from that thread. A stream closed from a thread that is not the loop's can end the loop: on
Windows the proactor's poll raises InvalidStateError when the cancelled read completes, and the launcher's
process ends with the sandbox still switched on.

Also here: the supervisor's watch does not hop to a thread for a driver that keeps no credential files.
"""
import asyncio
import gc
import logging
import socket
import sys
import threading
import types

import pytest

from openshell.launcher import openshell_driver as OD
from openshell.launcher import supervisor as S
from openshell.launcher.openshell_windows import OpenShellWindowsDriver
from openshell.launcher.proxy import MAX_HEAD, Proxy, Upstream

OUTER = "outer-" + "o" * 40
INNER = "inner-" + "i" * 40
REQUEST = f"GET /api/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Hermes-Session-Token: {OUTER}\r\n\r\n".encode()
ANSWER = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlate"


class SlowBackend:
    """Takes the request and answers only when told to: the request is in flight meanwhile."""

    def __init__(self):
        self.got, self.answer = asyncio.Event(), asyncio.Event()

    async def handle(self, reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            self.got.set()
            await self.answer.wait()
            writer.write(ANSWER)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()


def _read_all(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    out = b""
    try:
        while chunk := sock.recv(65536):
            out += chunk
    except OSError:
        pass
    return out


async def _until(done, seconds: float = 5.0) -> bool:
    for _ in range(int(seconds / 0.05)):
        if done():
            return True
        await asyncio.sleep(0.05)
    return done()


@pytest.mark.parametrize("client", ["closed", "done sending"])
def test_a_request_whose_client_left_stays_whole_until_the_backend_answers(client, caplog, monkeypatch):
    unraisable, closes = [], []
    monkeypatch.setattr(sys, "unraisablehook", lambda u: unraisable.append(f"{u.err_msg}: {u.exc_value!r}"))
    real_close = asyncio.StreamWriter.close

    def close(self):
        closes.append(threading.current_thread())
        return real_close(self)

    monkeypatch.setattr(asyncio.StreamWriter, "close", close)

    async def scenario():
        backend = SlowBackend()
        up_server = await asyncio.start_server(backend.handle, "127.0.0.1", 0)
        up_port = up_server.sockets[0].getsockname()[1]
        proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", up_port, INNER),
                      unavailable=lambda: {}, own_profile=lambda name: True, host_route=lambda m, p: None,
                      public_paths=frozenset())
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
        sock = socket.create_connection(("127.0.0.1", server.sockets[0].getsockname()[1]))
        try:
            sock.sendall(REQUEST)
            if client == "closed":
                sock.close()
            else:
                sock.shutdown(socket.SHUT_WR)
            await asyncio.wait_for(backend.got.wait(), 5)
            await asyncio.sleep(0.2)  # the client's end-of-file has reached the proxy
            closes.clear()
            # A collection on a worker thread, as one runs whenever a host route's helper allocates there.
            await asyncio.to_thread(gc.collect)
            await asyncio.sleep(0.1)
            destroyed = [r.getMessage() for r in caplog.records if "destroyed but it is pending" in r.getMessage()]
            assert destroyed == [], "a request still waiting for the backend was collected"
            assert unraisable == []
            assert closes == [], "the collector closed a stream from its own thread"
            backend.answer.set()
            if client == "done sending":  # it still waits for the answer, and gets all of it
                answer = await asyncio.to_thread(_read_all, sock)
                assert answer.startswith(b"HTTP/1.1 200") and answer.endswith(b"late")
            # ... and the proxy lets go of the connection once it is done.
            assert await _until(lambda: proxy.open_connections() == 0)
            assert closes and set(closes) == {threading.current_thread()}
        finally:
            sock.close()
            server.close()
            up_server.close()

    with caplog.at_level(logging.ERROR, logger="asyncio"):
        asyncio.run(scenario())


def test_the_proxy_counts_a_connection_only_while_it_handles_it():
    async def scenario():
        backend = SlowBackend()
        up_server = await asyncio.start_server(backend.handle, "127.0.0.1", 0)
        up_port = up_server.sockets[0].getsockname()[1]
        proxy = Proxy(outer_token=OUTER, upstream=lambda: Upstream("127.0.0.1", up_port, INNER),
                      unavailable=lambda: {}, own_profile=lambda name: True, host_route=lambda m, p: None,
                      public_paths=frozenset())
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, limit=MAX_HEAD)
        port = server.sockets[0].getsockname()[1]
        assert proxy.open_connections() == 0
        socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]
        try:
            for sock in socks[:2]:
                sock.sendall(REQUEST)
            assert await _until(lambda: proxy.open_connections() == 3)  # two in flight, one that sent nothing yet
            socks[2].close()  # a connection that never sends a request is let go as well
            assert await _until(lambda: proxy.open_connections() == 2)
            backend.answer.set()
            for sock in socks[:2]:
                assert (await asyncio.to_thread(_read_all, sock)).endswith(b"late")
            assert await _until(lambda: proxy.open_connections() == 0)
        finally:
            for sock in socks:
                sock.close()
            server.close()
            up_server.close()

    asyncio.run(scenario())


def _watching(driver, monkeypatch):
    """What one look of the supervisor's watch does with *driver*: (the guard's answer, the thread hops made)."""
    hops = []

    async def to_thread(fn, *args, **kwargs):
        hops.append(getattr(fn, "__name__", repr(fn)))
        return fn(*args, **kwargs)

    monkeypatch.setattr(S.asyncio, "to_thread", to_thread)
    sup = types.SimpleNamespace(driver=driver, layout=types.SimpleNamespace(name="work"), state="running",
                                _guard_repairs=[])
    return asyncio.run(S.Supervisor.guard(sup)), hops


def test_the_watch_makes_no_thread_hop_for_a_driver_that_keeps_no_files(monkeypatch):
    # The Windows driver hides credential files by path and keeps none: nothing to look at four times a second.
    driver = object.__new__(OpenShellWindowsDriver)
    assert _watching(driver, monkeypatch) == ([], [])


def test_the_watch_still_asks_the_driver_that_keeps_files(monkeypatch):
    driver = object.__new__(OD.OpenShellDriver)
    driver._request = driver._plan = None  # no sandbox started: its guard has nothing to repair
    assert _watching(driver, monkeypatch) == ([], ["guard"])
