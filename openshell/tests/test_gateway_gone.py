"""The sandbox's gateway ends while the sandbox is on (launcher/gateway_watch.py, the two drivers, the supervisor,
the terminal's switch-off).

Seen on Windows with OpenShell 0.1.9: the gateway's process ended and every sandbox process ended with it (the
gateway holds each in a job); the gateway's login task read "Ready" with no process, and nothing listened on its
port. The launcher went on reading the sandbox as running. Its look at the sandbox, one ``openshell sandbox get``
made on the event loop, failed with a refused connection after about three seconds, was taken for a hiccup and
was made again at once, for as long as anyone watched. Nothing else got a turn: the status route, the page's
switch and ``sandbox status`` got no answer, and a switch-off from a terminal took minutes.

The fakes here behave as those logs show: a CLI whose every call is refused, a gateway port nothing listens on,
a login service that is not running.
"""
import asyncio
import json
import socket
import threading
import time

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell import launcher_cli as CLI
from openshell.launcher import gateway_service as GS
from openshell.launcher import gateway_watch as GW
from openshell.launcher import layout as L
from openshell.launcher import openshell_windows as W
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher.driver import SandboxDriver
from openshell.launcher.spec import load_spec
from test_switch_flow import _on, env  # noqa: F401  (the switch fixture)

REFUSED = ("Error:   x transport error\n  tcp connect error\n  No connection could be made because the target "
           "machine actively refused it. (os error 10061)")
SENTENCE = "The sandbox's gateway stopped. Turn the sandbox off, then on again."


class Gateway:
    """What listens at the gateway's address, registered where the driver's CLI looks. ``end`` is its process
    ending: nothing listens there any more."""

    def __init__(self, registration):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        (registration / "mtls").mkdir(parents=True, exist_ok=True)
        for name in ("ca.crt", "tls.crt", "tls.key"):
            (registration / "mtls" / name).write_text("x", encoding="utf-8")
        (registration / "metadata.json").write_text(json.dumps(
            {"gateway_endpoint": f"https://127.0.0.1:{self.port}", "auth_mode": "mtls"}), encoding="utf-8")
        self.sock.settimeout(0.05)
        self._ended = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while not self._ended.is_set():
            try:
                self.sock.accept()[0].close()
            except OSError:  # nobody connected in this slice of time
                continue
        self.sock.close()

    def end(self):
        """Returns once nothing listens (on Linux a socket closed under a waiting ``accept`` takes one more
        connection, so the thread that accepts is the one that closes)."""
        self._ended.set()
        self._thread.join()


class RefusedCli(WD.FakeCli):
    """The CLI once the gateway's process has ended: every call is refused, after *takes* seconds."""

    def __init__(self):
        super().__init__()
        self.dead, self.takes, self.refused = False, 0.0, []

    def __call__(self, argv, env=None, **kw):
        if self.dead:
            self.refused.append(list(argv[1:]))
            time.sleep(self.takes)
            return WD.Done(1, "", REFUSED)
        return super().__call__(argv, env=env, **kw)


@pytest.fixture
def windows(tmp_path, monkeypatch):
    """A Windows sandbox that runs: the supervisor, its driver, the CLI and the gateway's port. The gateway's
    login task reads "Ready" with no process (``stopped``)."""
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": WD.SECRET})
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    gateway = Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-oswin")
    cli = RefusedCli()
    driver = WD._driver(cfg, cli, tmp_path)
    driver._gateway = GW.GatewayWatch(cfg, service=lambda: "stopped")
    sup = WD._supervisor(layout, runtime, driver, bb)
    return {"sup": sup, "driver": driver, "cli": cli, "gateway": gateway}


def _look(driver):
    driver._checked = 0.0  # the next look is due
    return driver.exit_code()


# -- telling a gateway that is gone from one that will answer again -------------------------------------------

def test_gone_is_nothing_listening_and_a_service_that_is_not_running_twice_in_a_row():
    now, says = [0.0], ["stopped"]
    watch = GW.GatewayWatch(None, probe=lambda: says[0], clock=lambda: now[0])
    assert watch.unanswered() is False  # one look that got no answer is not enough
    assert watch.unanswered() is True and watch.lost
    watch.reset()
    assert not watch.lost and watch.unanswered() is False  # counted anew after an answer


def test_a_gateway_its_service_manager_is_starting_again_is_waited_for():
    """Linux: systemd starts a gateway that died again after a few seconds. Until then nothing listens, and the
    launcher does nothing; only a gateway that stays away is gone."""
    now, says = [0.0], ["starting"]
    watch = GW.GatewayWatch(None, probe=lambda: says[0], clock=lambda: now[0])
    for now[0] in (0.0, 2.0, 4.0, 6.0, GW.GRACE - 1.0):
        assert watch.unanswered() is False
    says[0] = None  # it listens again: what did not answer was a hiccup
    assert watch.unanswered() is False
    says[0] = "starting"
    now[0] = 100.0
    assert watch.unanswered() is False  # the wait starts anew
    now[0] = 100.0 + GW.GRACE
    assert watch.unanswered() is True


def test_a_gateway_that_came_back_is_remembered_for_a_minute():
    """Linux: the gateway that systemd started again ends the sandbox the one before it had. The driver reads
    "exited" then; that the gateway had just been away says why."""
    now, says = [0.0], ["starting"]
    watch = GW.GatewayWatch(None, probe=lambda: says[0], clock=lambda: now[0])
    watch.answered()
    assert watch.back() is False  # it was never away
    assert watch.unanswered() is False and watch.silent
    says[0] = None  # it listens again, and is not ready to answer yet
    assert watch.unanswered() is False and watch.silent
    now[0] = 9.0
    watch.answered()
    assert watch.back() is True and not watch.silent and not watch.lost
    now[0] = 9.0 + GW.AFTERMATH
    assert watch.back() is False
    now[0] = 9.0
    watch.reset()  # a new sandbox starts
    assert watch.back() is False


def test_one_look_asks_nothing_of_a_gateway_that_listens(tmp_path):
    cfg = WD._tree(tmp_path)[2]
    gateway = Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-oswin")
    asked = []
    watch = GW.GatewayWatch(cfg, service=lambda: asked.append("service") or "stopped")
    assert watch.down() is None and asked == []  # it listens: the service manager is not even asked
    gateway.end()
    assert watch.down() == "stopped" and asked == ["service"]
    assert GW.GatewayWatch(cfg, service=lambda: "running").down() == "starting"
    unregistered = type("Cfg", (), {"gateway_dir": tmp_path / "nowhere", "managed_root": None})()
    assert GW.GatewayWatch(unregistered).down() is None  # an address nobody knows is never called gone


def test_the_plugins_own_gateway_is_asked_about_through_its_login_service(tmp_path, monkeypatch):
    """The launcher owns the gateway's service: "Ready with no process" is the service manager's own answer."""
    cfg = WD._tree(tmp_path)[2]
    Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-oswin").end()
    assert GW.GatewayWatch(cfg).down() == "starting"  # a gateway the spec names: nobody to ask, so it is waited for
    asked = []
    cfg.managed_root = tmp_path / "root"
    monkeypatch.setattr(GS, "service_state", lambda root: asked.append(root) or "stopped")
    assert GW.GatewayWatch(cfg).down() == "stopped" and asked == [tmp_path / "root"]
    monkeypatch.undo()

    class Service:
        def __init__(self, defn):
            self.defn = defn

        def state(self):
            return "running" if self.defn.name.startswith("hermes-openshell-gateway-") else "absent"

    runtime = type("Runtime", (), {"python": tmp_path / "python", "base_python": tmp_path})()
    assert GS.service_state(tmp_path / "root", runtime=runtime, manager=Service) == "running"


# -- the Windows driver, with the CLI and the port of the two sessions ---------------------------------------

def test_a_refused_gateway_is_not_an_exit_and_after_two_looks_it_is_gone(windows):
    sup, driver, cli, gateway = (windows[k] for k in ("sup", "driver", "cli", "gateway"))

    async def scenario():
        await sup.start()
        try:
            assert _look(driver) is None and driver.gateway_lost() is False
            cli.dead = True
            gateway.end()
            assert _look(driver) is None  # not "the sandbox exited"
            assert driver.gateway_lost() is False
            assert _look(driver) is None
            assert driver.gateway_lost() is True
            assert [call[:2] for call in cli.refused] == [["sandbox", "get"]] * 2  # one CLI call per look
            cli.dead = False  # a start brings the gateway back (here: the CLI answers again)
            await sup.restart()
            assert driver.gateway_lost() is False and _look(driver) is None  # counted anew from the start
            cli.dead = True
            assert _look(driver) is None and _look(driver) is None and driver.gateway_lost() is True
        finally:
            await sup.stop()
        assert driver.gateway_lost() is False  # nothing runs: nothing is lost

    asyncio.run(scenario())


def test_a_gateway_that_still_listens_and_does_not_answer_is_a_hiccup(windows):
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]

    async def scenario():
        await sup.start()
        try:
            cli.dead = True  # the CLI fails, the port is open: busy, or being restarted
            for _ in range(4):
                assert _look(driver) is None
            assert driver.gateway_lost() is False
        finally:
            cli.dead = False
            await sup.stop()

    asyncio.run(scenario())


def test_a_stop_asks_nothing_of_a_gateway_that_is_not_listening(windows):
    """``sandbox off`` and the launcher's own stop: no ``sandbox delete`` and no wait for it. Before, the
    stop made both calls and each waited out a refused connection."""
    sup, driver, cli, gateway = (windows[k] for k in ("sup", "driver", "cli", "gateway"))

    async def scenario():
        await sup.start()
        cli.dead, cli.takes = True, 0.4
        gateway.end()
        assert _look(driver) is None  # the watch's look, every two seconds: it got no answer
        started = time.monotonic()
        await sup.stop()
        assert [call[:2] for call in cli.refused] == [["sandbox", "get"]]  # the stop asked the gateway nothing
        # (what is left: one connect to the gateway's port and the look whether the backend still answers)
        assert time.monotonic() - started < 5.0
        assert sup.status()["state"] == "stopped"

    asyncio.run(scenario())


def test_the_wait_for_the_next_look_counts_from_the_end_of_one_that_got_no_answer(windows, monkeypatch):
    """A look that waits out a refused connection takes longer than the wait between two looks: counted from
    its start, the next look was due the moment it returned, and one CLI process followed the other."""
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]
    monkeypatch.setattr(W, "_STATE_CHECK_INTERVAL", 0.3)

    async def scenario():
        await sup.start()
        try:
            cli.dead, cli.takes = True, 0.5
            assert _look(driver) is None and len(cli.refused) == 1
            assert driver.exit_code() is None and len(cli.refused) == 1  # not due again yet
            time.sleep(0.35)
            assert driver.exit_code() is None and len(cli.refused) == 2
        finally:
            cli.dead, cli.takes = False, 0.0
            await sup.stop()

    asyncio.run(scenario())


def test_a_second_caller_takes_the_last_answer_while_a_look_is_out(windows):
    """The watch's look waits on a worker thread. Whoever asks meanwhile, after the wait between two looks is
    over, starts no second CLI call and does not wait."""
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]

    async def scenario():
        await sup.start()
        try:
            cli.dead, cli.takes = True, 0.8
            first = threading.Thread(target=_look, args=(driver,))
            first.start()
            until = time.monotonic() + 5.0
            while not cli.refused and time.monotonic() < until:
                time.sleep(0.01)
            assert len(cli.refused) == 1  # the look is out
            driver._checked = 0.0
            started = time.monotonic()
            assert driver.exit_code() is None
            assert time.monotonic() - started < 0.4 and len(cli.refused) == 1
            first.join()
            assert len(cli.refused) == 1
        finally:
            cli.dead, cli.takes = False, 0.0
            await sup.stop()

    asyncio.run(scenario())


def test_a_new_start_forgets_that_the_gateway_had_been_away(windows, monkeypatch):
    """A sandbox that ends a moment after its gateway came back has ended with the gateway. The sandbox that is
    started after that is a new one: when it ends on its own, that is "the sandbox exited"."""
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]
    monkeypatch.setattr(W, "_START_GRACE", 0.0)  # no second look at a sandbox that reads ended right after a start

    async def scenario():
        await sup.start()
        try:
            name = driver._name
            driver._gateway.silent = True  # the gateway did not answer a look ...
            assert _look(driver) is None and driver._gateway.back() is True  # ... and answers this one
            cli.sandboxes[name] = {"name": name, "phase": "Error", "exit_code": 1}
            assert _look(driver) == 1 and driver.gateway_lost() is True
            await sup.restart()
            assert _look(driver) is None
            cli.sandboxes[name] = {"name": name, "phase": "Error", "exit_code": 1}
            assert _look(driver) == 1 and driver.gateway_lost() is False
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_event_loop_keeps_its_turns_while_the_look_at_the_sandbox_waits(windows, monkeypatch):
    """The status route during the loop: every look takes 0.6 s here (three seconds with the real CLI). The loop must
    not wait for it: the status is answered meanwhile."""
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]
    monkeypatch.setattr(W, "_STATE_CHECK_INTERVAL", 0.05)

    async def scenario():
        await sup.start()
        watcher = asyncio.create_task(sup.watch())
        try:
            cli.dead, cli.takes = True, 0.6  # the port still listens: the looks go on, none is answered
            late, slow = [], []
            for _ in range(60):
                before = time.monotonic()
                await asyncio.sleep(0.025)
                late.append(time.monotonic() - before - 0.025)
                asked = time.monotonic()
                assert sup.status()["state"] == "running"
                assert sup.upstream() is not None  # a request of the desktop's: answered from the last look
                slow.append(time.monotonic() - asked)
            assert len(cli.refused) >= 2  # the looks were made
            assert max(late) < 0.3, max(late)
            assert max(slow) < 0.3, max(slow)  # and no request made a look of its own
        finally:
            watcher.cancel()
            cli.takes = 0.0
            await sup.stop()

    asyncio.run(scenario())


def test_the_linux_driver_tells_them_apart_the_same_way(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    gateway = Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-gw")
    driver._gateway = GW.GatewayWatch(driver.cfg, service=lambda: "stopped")
    real_state, real_delete, asked = api.sandbox_state, api.delete_sandbox, []

    def refused(*args, **kwargs):
        asked.append(args)
        raise ConnectionError("failed to connect to all addresses; connection refused")

    async def scenario():
        await sup.start()
        try:
            assert _look(driver) is None and driver.gateway_lost() is False
            api.sandbox_state = api.delete_sandbox = refused
            gateway.end()
            assert _look(driver) is None and driver.gateway_lost() is False
            assert _look(driver) is None and driver.gateway_lost() is True
            looks = len(asked)
        finally:
            await sup.stop()
        assert len(asked) == looks  # the stop asked the gateway nothing
        # No container program here: the sandbox's container may still run, and its credential files stay out
        # of its reach.
        assert driver.sandbox_gone() is False and driver.gateway_lost() is False
        api.sandbox_state, api.delete_sandbox = real_state, real_delete

    asyncio.run(scenario())


def test_a_sandbox_that_ended_with_a_gateway_that_came_back_is_not_a_sandbox_that_exited(tmp_path, monkeypatch):
    """Seen on Linux with OpenShell v0.1.9: the gateway's process was killed, systemd started it again nine
    seconds later, and the new gateway ended the sandbox ("sandbox exited with 1")."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    gateway = Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-gw")
    driver._gateway = GW.GatewayWatch(driver.cfg, service=lambda: "running")  # systemd is starting it again
    real_state = api.sandbox_state

    def refused(*args, **kwargs):
        raise ConnectionError("failed to connect to all addresses; connection refused")

    async def scenario():
        await sup.start()
        try:
            api.sandboxes["hermes-work"] = {"phase": "ERROR", "exit_code": 1}
            assert _look(driver) == 1 and driver.gateway_lost() is False  # it exited on its own
            api.sandboxes["hermes-work"] = {"phase": "READY", "exit_code": None}
            assert _look(driver) is None
            api.sandbox_state = refused
            gateway.end()
            assert _look(driver) is None and driver.gateway_lost() is False  # away, and being started again
            api.sandbox_state = real_state  # the new gateway answers: the sandbox it had is gone
            api.sandboxes["hermes-work"] = {"phase": "ERROR", "exit_code": 1}
            assert _look(driver) == 1 and driver.gateway_lost() is True
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_linux_driver_forgets_at_a_new_start_that_the_gateway_had_been_away(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver

    async def scenario():
        await sup.start()
        try:
            driver._gateway.silent = True  # the gateway did not answer a look ...
            assert _look(driver) is None and driver._gateway.back() is True  # ... and answers this one
            await sup.restart()
            api.sandboxes["hermes-work"] = {"phase": "ERROR", "exit_code": 1}
            assert _look(driver) == 1 and driver.gateway_lost() is False  # the new sandbox exited on its own
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_start_after_a_gateway_that_did_not_answer_makes_a_new_connection(tmp_path):
    """Seen on Linux: the launcher started its gateway again, and the first call of the new start was answered
    "connection refused" at once by the old connection, which was still waiting before its next try."""
    closed = []
    connection = type("Connection", (), {"close": lambda self: closed.append(self)})()
    driver = LD.OD.OpenShellDriver(LD._cfg(tmp_path))  # makes its own connection, as the launcher's does
    driver._api = connection
    driver._fresh_connection()
    assert driver._api is connection and closed == []  # the gateway answered all along: kept
    driver._gateway.silent = True
    driver._fresh_connection()
    assert driver._api is None and closed == [connection]
    given = LD.OD.OpenShellDriver(LD._cfg(tmp_path), api=connection)  # a connection handed in is not the driver's
    given._gateway.silent = True
    given._fresh_connection()
    assert given._api is connection and closed == [connection]


def test_the_start_that_follows_is_made_on_the_new_connection(tmp_path, monkeypatch):
    """The same through a start, which is what the launcher's one recovery runs."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    driver._own_api = True  # as the launcher's driver: it made its connection itself
    made, closed = [], []
    api.close = lambda: closed.append("the old one")
    monkeypatch.setattr(LD.OD, "GatewayApi", lambda cfg: made.append(cfg) or api)

    async def scenario():
        await sup.start()
        try:
            await sup.restart()
            assert made == [] and closed == []  # the gateway answered all along: the connection is kept
            driver._gateway.silent = True
            await sup.restart()
            assert closed == ["the old one"] and len(made) == 1
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_without_its_gateway_a_linux_sandbox_is_ended_through_the_container_program(tmp_path, monkeypatch):
    """On Linux the sandbox's containers outlive the gateway. A stop that cannot ask the gateway removes exactly
    this sandbox's, by the two labels the gateway gave them; only then do the held credential files go back."""
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    driver = sup.driver
    gateway = Gateway(tmp_path / "xdg" / "openshell" / "gateways" / "hermes-gw")
    driver._gateway = GW.GatewayWatch(driver.cfg, service=lambda: "stopped")
    real_run, left, calls, asked = driver._run, ["first", "second"], [], []

    def refused(*args, **kwargs):
        asked.append(args)
        raise ConnectionError("failed to connect to all addresses; connection refused")

    def run(argv, **kwargs):
        if argv[0] != "docker":
            return real_run(argv, **kwargs)
        calls.append(list(argv))
        if argv[1] == "rm":
            assert argv[2:] == ["-f", "first", "second"]
            del left[:]
        return WD.Done(0, "\n".join(left))

    async def scenario():
        await sup.start()
        driver.cfg.container_cli, driver._run = "docker", run  # (after the start: no log follower in this test)
        gateway.end()
        api.sandbox_state = api.delete_sandbox = refused
        assert _look(driver) is None and len(asked) == 1  # the watch's look got no answer
        await sup.stop()
        assert len(asked) == 1  # the stop asked the gateway nothing
        # Later, with the gateway still away and nothing known of it (a stop after a start that failed): the
        # delete is tried, fails, and the containers are looked for again: none is left.
        driver._gateway.reset()
        driver.stop()
        assert len(asked) == 2 and driver.sandbox_gone() is True

    asyncio.run(scenario())
    assert [call[1] for call in calls] == ["ps", "rm", "ps", "ps"]
    assert "label=openshell.ai/sandbox-name=hermes-work" in calls[0]
    assert "label=openshell.ai/sandbox-namespace=hermes-gw" in calls[0]
    assert driver.sandbox_gone() is True


# -- the supervisor: once, then a plain sentence ---------------------------------------------------------------

class GatewayDriver(SandboxDriver):
    name = "fake"
    uses_host_shell = False
    asks_gateway = True
    capabilities_info = {"label": "Fake"}

    def __init__(self):
        self.lost, self.starts, self.stops, self.looks = False, 0, 0, 0
        self.start_error, self.start_takes, self.code = None, 0.0, None

    def preflight(self):
        return {}

    def start(self, request):
        self.starts += 1
        time.sleep(self.start_takes)
        if self.start_error is not None:
            raise self.start_error
        self.lost, self.code = False, None  # the gateway was started again and answers

    def exit_code(self):
        self.looks += 1
        return self.code

    def gateway_lost(self):
        return self.lost

    def stop(self, timeout=20.0):
        self.stops += 1

    def policy(self):
        return {}


def _supervisor(tmp_path):
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    runtime = L.Runtime(python=tmp_path / "python.exe", code_dir=tmp_path, env_dir=tmp_path, base_python=tmp_path,
                        store=None)
    driver = GatewayDriver()
    sup = S.Supervisor(layout, runtime, load_spec(layout), driver, outer_port=1)

    async def start_locked():  # the real one launches a sandbox; this one keeps its states and its failure rule
        sup.state, sup._last_error = "starting", None
        try:
            await asyncio.to_thread(driver.start, None)
        except Exception as exc:
            sup.state, sup._last_error = "failed", str(exc)
            await asyncio.to_thread(driver.stop)
            raise
        sup.state = "running"

    sup._start_locked = start_locked
    sup.state = "running"
    return sup, driver


async def _until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.02)


def test_the_gateway_and_the_sandbox_are_started_again_once(tmp_path):
    sup, driver = _supervisor(tmp_path)
    seen = []
    sup.on_down.append(lambda why: seen.append((why, sup.status()["state"], sup.status()["error"])))

    async def scenario():
        watcher = asyncio.create_task(sup.watch())
        try:
            driver.start_takes = 0.4
            driver.lost = True
            await _until(lambda: driver.starts == 1)
            status = sup.status()  # while the gateway and the sandbox start again
            assert status["state"] == "restarting"
            assert status["restarting"]["label"] == "Restarting the sandbox after its gateway stopped"
            assert sup.status_on_hold() is True
            await _until(lambda: sup.state == "running")
            # A reply in flight ends as it does when the sandbox ends on its own: the listeners that close the
            # chat sockets hear "exited" first, with the state and the reason already set.
            assert seen[0] == ("exited", "exited", SENTENCE)
            assert seen[1][:2] == ("restarting", "restarting")
            assert sup.status()["error"] is None and driver.stops == 1 and driver.starts == 1
        finally:
            watcher.cancel()

    asyncio.run(scenario())


def test_a_sandbox_that_ended_with_its_gateway_is_started_again_too(tmp_path):
    """Linux: the gateway is back by itself and the sandbox reads as exited. One start, as above; a sandbox
    that exits on its own stays ``exited``, as before."""
    sup, driver = _supervisor(tmp_path)

    async def scenario():
        watcher = asyncio.create_task(sup.watch())
        try:
            driver.code, driver.lost = 1, True
            await _until(lambda: driver.starts == 1 and sup.state == "running")
            assert sup.status()["error"] is None
            driver.code = 1  # and now it exits on its own
            await _until(lambda: sup.state == "exited")
            await asyncio.sleep(0.6)
            assert driver.starts == 1 and sup.status()["error"] == "sandbox exited with 1"
        finally:
            watcher.cancel()

    asyncio.run(scenario())


def test_a_second_loss_within_ten_minutes_is_not_retried_and_nothing_loops(tmp_path):
    sup, driver = _supervisor(tmp_path)

    async def scenario():
        watcher = asyncio.create_task(sup.watch())
        try:
            driver.lost = True
            await _until(lambda: driver.starts == 1 and sup.state == "running")
            driver.lost = True  # gone again, a moment later
            await _until(lambda: sup.state == "failed")
            assert sup.status()["error"] == SENTENCE and sup.unavailable()["error"] == SENTENCE
            assert driver.starts == 1 and driver.stops == 2  # stopped (the forward ends), not started
            await asyncio.sleep(1.0)  # four looks of the watch later: still nothing is started
            assert driver.starts == 1 and driver.stops == 2
            assert sup.status()["state"] == "failed" and sup.status()["sandboxed"] is True
            assert sup.upstream() is None and sup.status_on_hold() is False
        finally:
            watcher.cancel()

    asyncio.run(scenario())
    assert GW.RETRY_WINDOW == 600.0


def test_a_loss_after_the_ten_minutes_is_recovered_from_again(tmp_path, monkeypatch):
    sup, driver = _supervisor(tmp_path)
    monkeypatch.setattr(GW, "RETRY_WINDOW", 0.2)

    async def scenario():
        watcher = asyncio.create_task(sup.watch())
        try:
            driver.lost = True
            await _until(lambda: driver.starts == 1 and sup.state == "running")
            await asyncio.sleep(0.4)
            driver.lost = True
            await _until(lambda: driver.starts == 2 and sup.state == "running")
            assert sup.status()["error"] is None
        finally:
            watcher.cancel()

    asyncio.run(scenario())


def test_a_recovery_that_fails_ends_in_the_sentence_and_is_not_tried_again(tmp_path):
    sup, driver = _supervisor(tmp_path)
    driver.start_error = RuntimeError("the OpenShell gateway service stopped before it listened on 127.0.0.1:1")

    async def scenario():
        watcher = asyncio.create_task(sup.watch())
        try:
            driver.lost = True
            await _until(lambda: sup.state == "failed")
            assert sup.status()["error"] == SENTENCE  # one plain sentence, not the driver's own words
            await asyncio.sleep(1.0)
            assert driver.starts == 1 and sup.status()["state"] == "failed"
        finally:
            watcher.cancel()

    asyncio.run(scenario())


def test_a_driver_without_a_gateway_is_looked_at_on_the_loop_as_before(tmp_path):
    """The base class has no gateway: its look costs nothing, so no worker thread is woken for it."""
    assert SandboxDriver.asks_gateway is False and SandboxDriver.gateway_lost(object()) is False
    assert W.OpenShellWindowsDriver.asks_gateway is True and LD.OD.OpenShellDriver.asks_gateway is True


# -- `sandbox off` and `sandbox status` from a terminal ---------------------------------------------------------

def test_sandbox_off_does_not_wait_for_a_launcher_that_does_not_answer(env, monkeypatch):  # noqa: F811
    """Seen: the terminal's switch-off was handed to a launcher that had no turn left on its loop, and
    waited 253 seconds for it. A launcher that does not answer its status in a few seconds is not asked: its
    service is ended and removed here, the review is made from the files, and the marker goes."""
    layout = env["layout"]
    _on(env)
    monkeypatch.setattr(SW, "running_launcher", lambda _layout: {"port": 47972, "pid": 1})
    asked = []

    def no_answer(port, token, method, route, body=None, timeout=5.0):
        asked.append((method, route, timeout))
        return 0, None

    monkeypatch.setattr(SW, "launcher_call", no_answer)
    del env["log"][:]
    result = SW.turn_off_here(layout, runtime=env["runtime"], manager=env["manager"], sleep=lambda s: None)
    assert asked == [("GET", "status", 5.0)]  # never the switch-off, which waits minutes for a teardown
    assert result["stopped"] == "service" and result["marker_cleared"] is True and result["state"] == "off"
    assert "stop" in env["log"] and "uninstall" in env["log"] and not SW.is_marked(layout)


def test_sandbox_status_prints_the_failed_state_and_exits_zero(monkeypatch, capsys, tmp_path):
    """A state the launcher knows is an answer, whatever the state is: exit 0. Exit 1 is for no answer."""
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=tmp_path / "root")
    monkeypatch.setattr(L, "current_profile", lambda: layout)
    failed = {"profile": "work", "sandboxed": True, "state": "failed", "error": SENTENCE, "handback": {"kept": 0}}
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: (failed, None))
    assert CLI._cmd_status(None) == 0
    assert json.loads(capsys.readouterr().out) == failed
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: (None, "did not answer"))
    assert CLI._cmd_status(None) == 1
