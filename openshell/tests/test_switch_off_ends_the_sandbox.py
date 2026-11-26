"""A switch-off gives the profile back to this computer only once its sandbox is gone from the gateway.

``hermes sandbox off`` with no launcher to hand the work to (the launcher was killed, hangs, or its state file is
gone) stops the login service, asks the gateway to delete exactly this profile's sandbox and waits until the
sandbox is gone from it. Only then is the service removed, the home handed back and the marker cleared. A
sandbox that cannot be confirmed gone keeps the profile marked and switched on, and the command says what to
run. The launcher's own ``switch/off`` refuses the same way when its driver says the sandbox is not gone.

The launcher's token is sent only to the launcher whose state file names a process that is alive. A gateway
counts as ended, and its sandboxes with it, only on the word of its own login service; a registration that is
there and cannot be read says nothing.

The fakes: one gateway that holds the sandboxes of two profiles (``qt`` is switched off, ``qp`` must never be
touched), as the Windows driver sees it (the CLI) and as the Linux driver sees it (the SDK), a loopback socket
that stands for the gateway's address, a login service and core's marker. Nothing starts a sandbox, and no test
asks this computer's service manager or runs an OpenShell program.
"""
import asyncio
import shutil
import socket
import threading
from types import SimpleNamespace

import pytest

import test_gateway_gone as GG
import test_handback as TH
import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import gateway_watch as GW
from openshell.launcher import handback as H
from openshell.launcher import host_routes as HR
from openshell.launcher import login_service as LS
from openshell.launcher import openshell_driver as OD
from openshell.launcher import switch as SW
from openshell.launcher.driver import DriverUnavailable
from openshell.launcher.layout import ProfileLayout
from openshell.launcher.spec import load_spec, save_spec
from test_gateway_gone import windows  # noqa: F401  (a Windows sandbox that runs)
from test_handback_wiring import _off, _user_home
from test_switch_flow import FakeMarkers, FakeRuntime, FakeService, _routes, env  # noqa: F401

BUSY = 'Error:   x status: Unavailable, message: "the compute driver is busy"'
TOKEN = "outer-" + "t" * 40
LAUNCHER_CALL = SW.launcher_call  # the real call, for the test that shows where a request arrives


class Cli(GG.RefusedCli):
    """The gateway's CLI. *keeps*: the gateway does not delete the sandbox and cannot say what became of it.
    *once_gone*: called once, right after the gateway first says that a sandbox it deleted is gone."""

    def __init__(self, log):
        super().__init__()
        self.log, self.keeps, self.kept, self.once_gone, self.deleted = log, False, set(), None, set()

    def __call__(self, argv, env=None, **kw):
        args = list(argv[1:])
        if not self.dead and args[:2] == ["sandbox", "delete"]:
            self.log.append(f"delete {args[2]}")
            if self.keeps:
                self.calls.append((list(argv), dict(env or {})))
                self.kept.add(args[2])
                return WD.Done(1, "", BUSY)
            self.deleted.add(args[2])
        if not self.dead and args[:2] == ["sandbox", "get"] and args[2] in self.kept:
            self.calls.append((list(argv), dict(env or {})))
            return WD.Done(1, "", BUSY)
        done = super().__call__(argv, env=env, **kw)
        if self.once_gone and args[:2] == ["sandbox", "get"] and args[2] in self.deleted and done.returncode:
            hook, self.once_gone = self.once_gone, None
            hook()
        return done


class Api(LD.FakeApi):
    """The gateway as the SDK reaches it. *keeps*: a delete fails; *dead*: no call is answered; *once_gone*:
    called once, right after the first sandbox is deleted."""

    def __init__(self, log):
        super().__init__()
        self.log, self.keeps, self.dead, self.unregistered, self.once_gone = log, False, False, False, None

    def sandbox_state(self, name):
        if self.unregistered:
            raise DriverUnavailable("gateway 'hermes-gw' is not registered")
        if self.dead:
            raise ConnectionError("failed to connect to all addresses; connection refused")
        return super().sandbox_state(name)

    def delete_sandbox(self, name, timeout):
        self.log.append(f"delete {name}")
        if self.keeps:
            raise RuntimeError("deadline exceeded while the sandbox was deleted")
        super().delete_sandbox(name, timeout)
        if self.once_gone:
            hook, self.once_gone = self.once_gone, None
            hook()


class Containers:
    """The container program: lists and removes the containers the gateway labelled."""

    def __init__(self, ids=(), fails=False):
        self.ids, self.fails, self.calls = list(ids), fails, []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.fails:
            return WD.Done(1, "", "Cannot connect to the Docker daemon")
        if argv[1] == "rm":
            self.ids = [i for i in self.ids if i not in argv[3:]]
        return WD.Done(0, "\n".join(self.ids))


class Side:
    """One operating system's driver with the fake gateway behind it."""

    def __init__(self, kind, tmp_path, log):
        self.kind = kind
        self.cfg = OD.OpenShellConfig(gateway="hermes-gw", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe",
                                      run_as=("1000", "1000"), container_cli=None)
        self.listener = GG.Gateway(self.cfg.gateway_dir)
        self.containers = Containers()
        if kind == "windows":
            self.gateway = Cli(log)
            self.driver = WD._driver(self.cfg, self.gateway, tmp_path)
        else:
            self.gateway = Api(log)
            self.driver = OD.OpenShellDriver(self.cfg, api=self.gateway, run=self.containers.run)
        self.driver._gateway = GW.GatewayWatch(self.cfg, service=lambda: "stopped")
        self.sandboxes = self.gateway.sandboxes
        for name in ("hermes-qt", "hermes-qp"):
            self.sandboxes[name] = {"name": name, "phase": "Ready" if kind == "windows" else "READY", "exit_code": None}

    def asked(self):
        """What the gateway was asked while it did not answer."""
        return self.gateway.refused if self.kind == "windows" else self.gateway.calls


@pytest.fixture
def two(tmp_path, monkeypatch):
    """Two profiles that are switched on and marked, and no launcher that answers for either."""
    root = tmp_path / "root"
    log: list = []
    markers = FakeMarkers(log)
    monkeypatch.setattr(SW, "marker_api", lambda: markers)
    monkeypatch.setattr(SW, "launcher_call", lambda *a, **kw: (0, None))
    runtime = FakeRuntime(tmp_path / "py.exe", tmp_path)
    layouts = {}
    for name in ("qt", "qp"):
        home = root / "profiles" / name
        home.mkdir(parents=True)
        layouts[name] = ProfileLayout(name=name, home=home, root=root)
        LS.write_definition(LS.define(layouts[name], runtime, {}))
        markers.marked.add(name)
    services: list = []

    def manager(defn):
        services.append(FakeService(defn, log))
        return services[-1]

    return SimpleNamespace(qt=layouts["qt"], qp=layouts["qp"], log=log, markers=markers, runtime=runtime,
                           manager=manager, services=services, tmp=tmp_path)


@pytest.fixture(params=["windows", "linux"])
def side(request, two, monkeypatch):
    made = Side(request.param, two.tmp, two.log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: made.driver)
    yield made
    made.listener.end()


def _off_here(two, answer=None):
    return SW.turn_off_here(two.qt, handback_answer=answer, runtime=two.runtime, manager=two.manager,
                            sleep=lambda s: None)


def _still_on(two):
    return "qt" in two.markers.marked and LS.switched_on(two.qt)


SENTENCE = ("The sandbox couldn't be stopped ({why}). It stays switched on. "
            "Run `hermes -p qt sandbox off` again.")


# -- the switch-off with no launcher ---------------------------------------------------------------------------

def test_the_profiles_own_sandbox_is_deleted_before_the_marker_goes_and_the_other_profiles_stays(two, side):
    result = _off_here(two)
    # The service stops first (its launcher cannot start the sandbox again), the marker goes last.
    assert two.log == ["stop", "delete hermes-qt", "uninstall", "clear"]
    assert sorted(side.sandboxes) == ["hermes-qp"]
    assert result["stopped"] == "service" and result["state"] == "off" and result["marker_cleared"] is True
    assert two.markers.marked == {"qp"} and not LS.switched_on(two.qt) and LS.switched_on(two.qp)


def test_a_sandbox_the_gateway_does_not_delete_keeps_the_profile_marked_and_nothing_is_reverted(two, side):
    _user_home(two.qt)
    assert H.take_baseline(two.qt.home, two.qt.state_dir)["taken"] is True
    TH.put(two.qt.home / "scripts" / "planted.sh", "x\n")
    side.gateway.keeps = True
    with pytest.raises(SW.SwitchError) as err:
        _off_here(two, "revert")
    assert err.value.status == 502
    said = str(err.value)
    assert said.startswith("The sandbox couldn't be stopped (") and said.endswith(SENTENCE.split(")", 1)[1])
    assert two.log == ["stop", "delete hermes-qt"] and _still_on(two)  # not removed, not cleared
    assert (two.qt.home / "scripts" / "planted.sh").exists() and H.is_open(two.qt.state_dir)
    assert sorted(side.sandboxes) == ["hermes-qp", "hermes-qt"]
    # Once the gateway deletes it, the same command finishes the job.
    side.gateway.keeps = False
    if side.kind == "windows":
        side.gateway.kept.clear()
    result = _off_here(two, "revert")
    assert result["marker_cleared"] is True and result["handback"]["reverted"] == ["file:scripts/planted.sh"]
    assert sorted(side.sandboxes) == ["hermes-qp"] and not (two.qt.home / "scripts" / "planted.sh").exists()


def test_a_gateway_that_listens_and_does_not_answer_keeps_the_profile_marked(two, side):
    side.gateway.dead = True
    with pytest.raises(SW.SwitchError) as err:
        _off_here(two)
    assert err.value.status == 502 and "It stays switched on." in str(err.value)
    assert two.log == ["stop"] and _still_on(two) and sorted(side.sandboxes) == ["hermes-qp", "hermes-qt"]


def test_on_windows_a_gateway_that_is_not_running_has_no_sandbox(two, monkeypatch):
    """OpenShell ends every sandbox process with its gateway on Windows (the gateway holds each in a job)."""
    side = Side("windows", two.tmp, two.log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: side.driver)
    side.gateway.dead = True
    side.listener.end()
    result = _off_here(two)
    # Asked before the service's definition goes and once more after it; nothing is deleted.
    assert side.asked() == [["sandbox", "get", "hermes-qt", "-o", "json"]] * 2
    assert two.log == ["stop", "uninstall", "clear"] and result["marker_cleared"] is True


def test_on_linux_the_containers_of_a_gateway_that_is_not_running_are_ended_first(two, monkeypatch):
    """A Linux sandbox's containers outlive its gateway: this profile's are removed by the gateway's labels."""
    side = Side("linux", two.tmp, two.log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: side.driver)
    side.gateway.dead = True
    side.listener.end()
    side.cfg.container_cli, side.containers.ids = "docker", ["first", "second"]
    result = _off_here(two)
    calls = side.containers.calls
    # (the last look is the one after the service's definition has gone: none is left)
    assert [call[1] for call in calls] == ["ps", "rm", "ps", "ps"] and calls[1][2:] == ["-f", "first", "second"]
    assert "label=openshell.ai/sandbox-name=hermes-qt" in calls[0]
    assert "label=openshell.ai/sandbox-namespace=hermes-gw" in calls[0]
    assert two.log == ["stop", "uninstall", "clear"] and result["marker_cleared"] is True


def test_on_linux_containers_that_cannot_be_listed_keep_the_profile_marked(two, monkeypatch):
    side = Side("linux", two.tmp, two.log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: side.driver)
    side.gateway.dead = True
    side.listener.end()
    side.cfg.container_cli, side.containers.fails = "docker", True
    with pytest.raises(SW.SwitchError) as err:
        _off_here(two)
    assert err.value.status == 502 and [call[1] for call in side.containers.calls] == ["ps"]
    assert two.log == ["stop"] and _still_on(two)


def test_with_no_gateway_registered_the_switch_turns_off_and_asks_no_program(two, side):
    """A Hermes root whose gateway was removed, or never installed: there is nothing to ask and nothing runs."""
    side.listener.end()
    shutil.rmtree(side.cfg.gateway_dir)
    side.gateway.unregistered = True
    result = _off_here(two)
    assert two.log == ["stop", "uninstall", "clear"] and result["marker_cleared"] is True
    if side.kind == "windows":
        assert side.gateway.calls == []  # the CLI finds its gateway through the registration: it is not run


@pytest.mark.parametrize("down, ended", [(None, False), ("starting", False), ("stopped", True)])
def test_a_windows_sandbox_ended_with_its_gateway_only_when_the_gateways_service_is_not_running(two, monkeypatch,
                                                                                               down, ended):
    """The gateway does not answer. ``None``: something listens at its address. ``starting``: nothing listens,
    and its login service runs, cannot be asked, or is not the plugin's. ``stopped``: nothing listens and its
    service is not running, so its process has ended and every sandbox process with it."""
    side = Side("windows", two.tmp, two.log)
    monkeypatch.setattr("openshell.launcher_cli.make_driver", lambda spec: side.driver)
    side.driver._gateway = GW.GatewayWatch(side.cfg, probe=lambda: down)
    side.gateway.dead = True
    try:
        if ended:
            assert _off_here(two)["marker_cleared"] is True and two.log == ["stop", "uninstall", "clear"]
        else:
            with pytest.raises(SW.SwitchError):
                _off_here(two)
            assert two.log == ["stop"] and _still_on(two)
    finally:
        side.listener.end()


@pytest.mark.parametrize("content", [b"\x00\x01 not json", b"{}"], ids=["not json", "no address"])
def test_a_gateway_registration_that_cannot_be_read_keeps_the_profile_marked(two, side, content):
    """No registration file means no gateway and no sandbox. A file that is there and cannot be read says
    nothing of the gateway: whether a sandbox runs is not known."""
    side.listener.end()
    (side.cfg.gateway_dir / "metadata.json").write_bytes(content)
    side.gateway.unregistered = True  # the SDK finds its gateway through the same file
    with pytest.raises(SW.SwitchError) as err:
        _off_here(two)
    assert err.value.status == 502 and two.log == ["stop"] and _still_on(two)
    if side.kind == "windows":
        assert "the registration of gateway hermes-gw cannot be read" in str(err.value)
        assert side.gateway.calls == []  # the CLI is not run


def test_a_launcher_the_service_manager_started_again_leaves_no_sandbox_behind(two, side):
    """The service manager starts the launcher again while the sandbox is being deleted. That launcher finds its
    definition and a marked profile, and creates the sandbox again right after the gateway said it was gone."""
    box, at_clear = dict(side.sandboxes["hermes-qt"]), []
    clear = two.markers.clear_profile_run_elsewhere
    two.markers.clear_profile_run_elsewhere = lambda *a, **kw: (at_clear.append(sorted(side.sandboxes)),
                                                                clear(*a, **kw))[1]

    def the_launcher_comes_back():
        if LS.switched_on(two.qt) and "qt" in two.markers.marked:
            two.services[-1].running = True
            side.sandboxes["hermes-qt"] = box

    side.gateway.once_gone = the_launcher_comes_back
    result = _off_here(two)
    assert two.log == ["stop", "delete hermes-qt", "stop", "delete hermes-qt", "uninstall", "clear"]
    assert at_clear == [["hermes-qp"]]  # the marker went only after the gateway had no sandbox of this profile
    assert sorted(side.sandboxes) == ["hermes-qp"] and result["marker_cleared"] is True
    assert not two.services[-1].running and not LS.switched_on(two.qt)


def test_a_sandbox_the_launcher_made_again_and_the_gateway_keeps_leaves_the_profile_marked(two, side):
    """The launcher came back and the gateway does not delete its sandbox: the definition has gone and the
    marker stays. The same command finishes the job once the gateway deletes."""
    box = dict(side.sandboxes["hermes-qt"])

    def the_launcher_comes_back():
        two.services[-1].running = True
        side.sandboxes["hermes-qt"] = box
        side.gateway.keeps = True

    side.gateway.once_gone = the_launcher_comes_back
    with pytest.raises(SW.SwitchError) as err:
        _off_here(two)
    assert err.value.status == 502 and "It stays switched on." in str(err.value)
    assert two.log == ["stop", "delete hermes-qt", "stop", "delete hermes-qt"]  # not handed back, not cleared
    assert "qt" in two.markers.marked and "hermes-qt" in side.sandboxes
    side.gateway.keeps = False
    if side.kind == "windows":
        side.gateway.kept.clear()
    del two.log[:]
    result = _off_here(two)
    assert two.log == ["stop", "delete hermes-qt", "uninstall", "clear"]
    assert result["marker_cleared"] is True and sorted(side.sandboxes) == ["hermes-qp"]


# -- the launcher's token ---------------------------------------------------------------------------------------

class Listener:
    """A program of the test's own at a loopback port: it keeps every request it is sent and answers 404."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.requests: list = []
        self._ended = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._ended.is_set():
            try:
                conn = self.sock.accept()[0]
            except OSError:  # nobody connected in this slice of time
                continue
            with conn:
                conn.settimeout(1.0)
                try:
                    self.requests.append(conn.recv(65536))
                    conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    self.requests.append(b"")
        self.sock.close()

    def end(self):
        self._ended.set()
        self._thread.join()


def test_with_no_recorded_launcher_process_the_token_is_sent_to_nobody(two, side, monkeypatch):
    """The launcher's state file is gone. The port the profile's spec keeps is held by another program: it is
    sent nothing, the service is ended and the gateway deletes the sandbox."""
    listener = Listener()
    spec = load_spec(two.qt)
    spec["port"] = listener.port
    save_spec(two.qt, spec)
    two.qt.token_path.parent.mkdir(parents=True, exist_ok=True)
    two.qt.token_path.write_text(TOKEN, encoding="utf-8")
    monkeypatch.setattr(SW, "launcher_call", LAUNCHER_CALL)  # a call that is made arrives at the listener
    assert SW.running_launcher(two.qt) is None
    try:
        result = _off_here(two)
    finally:
        listener.end()
    assert listener.requests == []
    assert result["stopped"] == "service" and result["marker_cleared"] is True
    assert two.log == ["stop", "delete hermes-qt", "uninstall", "clear"] and sorted(side.sandboxes) == ["hermes-qp"]


# -- a launcher that answers ------------------------------------------------------------------------------------

def test_the_terminal_names_the_command_when_the_launcher_could_not_stop_its_sandbox(env, monkeypatch):  # noqa: F811
    answers = {("GET", "status"): (200, {"profile": "work", "state": "running"}),
               ("POST", "switch/off"): (409, {"detail": "The sandbox couldn't be stopped. It stays switched on.",
                                              "code": "sandbox_not_stopped"})}
    monkeypatch.setattr(SW, "running_launcher", lambda lay: {"port": 47999})
    monkeypatch.setattr(SW, "launcher_call", lambda port, token, method, route, body=None, timeout=5.0:
                        answers[(method, route)])
    with pytest.raises(SW.SwitchError) as err:
        SW.turn_off_here(env["layout"], runtime=env["runtime"], manager=env["manager"], sleep=lambda s: None)
    assert str(err.value) == ("The sandbox couldn't be stopped. It stays switched on. "
                              "Run `hermes -p work sandbox off` again.")
    assert err.value.status == 502 and env["services"] == [] and "clear" not in env["log"]


# -- the launcher's own switch/off -----------------------------------------------------------------------------

def test_the_launchers_switch_off_keeps_the_marker_while_its_sandbox_is_not_gone(env, monkeypatch):  # noqa: F811
    routes = _routes(env, monkeypatch, [])
    handed, gone = [], [False]
    monkeypatch.setattr(HR, "hand_back", lambda *a, **kw: (handed.append(kw), {"result": None, "blocked": None})[1])
    routes._sup.driver = SimpleNamespace(sandbox_gone=lambda: gone[0])  # its delete failed
    routes._sup.switching_off = False
    status, payload, _ = _off(routes)
    assert status == 409 and payload == {"detail": "The sandbox couldn't be stopped. It stays switched on.",
                                         "code": "sandbox_not_stopped"}
    assert env["log"] == ["sandbox stopped"] and handed == []  # not handed back, not unregistered, not cleared
    assert routes._sup.switching_off is False
    gone[0] = True  # asked again, the driver's stop deletes it
    status, payload, _ = _off(routes)
    assert status == 200 and payload["state"] == "off" and len(handed) == 1
    assert env["log"] == ["sandbox stopped", "sandbox stopped", "unregistered", "clear"]


def test_the_windows_driver_says_whether_its_sandbox_is_gone_and_a_second_stop_deletes_it(windows):  # noqa: F811
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]

    async def scenario():
        await sup.start()
        assert "hermes-default" in cli.sandboxes
        cli.dead = True  # the gateway listens and does not answer: the delete fails
        await sup.stop()
        assert driver.sandbox_gone() is False and "hermes-default" in cli.sandboxes
        cli.dead = False
        await sup.stop()
        assert driver.sandbox_gone() is True and "hermes-default" not in cli.sandboxes

    asyncio.run(scenario())


@pytest.mark.parametrize("looked", [False, True], ids=["at the stop", "after a look that got no answer"])
@pytest.mark.parametrize("down, gone", [(None, False), ("starting", False), ("stopped", True)])
def test_a_windows_stop_that_deletes_nothing_says_gone_only_when_the_gateways_service_is_not_running(
        windows, down, gone, looked):  # noqa: F811
    sup, driver, cli = windows["sup"], windows["driver"], windows["cli"]

    async def scenario():
        await sup.start()
        driver._gateway = GW.GatewayWatch(driver.cfg, probe=lambda: down)
        cli.dead = True
        if looked:
            assert GG._look(driver) is None
        await sup.stop()
        assert driver.sandbox_gone() is gone

    asyncio.run(scenario())


def test_a_windows_sandbox_whose_gateway_ended_during_the_stop_is_gone(windows):  # noqa: F811
    sup, driver, cli, gateway = (windows[k] for k in ("sup", "driver", "cli", "gateway"))

    async def scenario():
        await sup.start()
        cli.dead = True
        gateway.end()  # nothing listens at its address and its login service is not running
        await sup.stop()
        assert driver.sandbox_gone() is True

    asyncio.run(scenario())
