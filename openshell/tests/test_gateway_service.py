"""The managed OpenShell gateway: config, first start, health, upgrades, release, and the login-service hooks.

Fake service managers and a fake CLI/gateway runner; nothing is registered with the OS and no
gateway process runs (the bootstrap is exercised as a real subprocess with a harmless command).
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from openshell.launcher import gateway_service as GS
from openshell.launcher import login_service as LS
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_install as inst
from openshell.launcher.driver import DriverUnavailable


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_ident(root: Path, ident_id: str, platform: str = "linux", current: bool = True) -> dict:
    exe = ".exe" if platform == "windows" else ""
    names = ["openshell", "openshell-gateway", "openshell-supervisor"] + (["openshell-windows-sandbox"]
                                                                          if platform == "windows" else [])
    d = inst.runtime_dir(root) / ident_id
    (d / "bin").mkdir(parents=True, exist_ok=True)
    bins = {}
    for n in names:
        data = f"{ident_id}:{n}".encode()
        (d / "bin" / (n + exe)).write_bytes(data)
        bins[n + exe] = sha(data)
    ident = {"id": ident_id, "version": ident_id.rsplit("-", 1)[-1], "platform": platform, "binaries": bins,
             "sdk": False, "images": {"openshell-supervisor": {"ref": "ghcr.invalid/sup@sha256:aa"},
                                      "openshell-sandbox": {"ref": "ghcr.invalid/sbx@sha256:bb"}}}
    (d / inst.IDENTITY_FILE).write_text(json.dumps(ident), encoding="utf-8")
    if current:
        (inst.runtime_dir(root) / inst.INSTALLED_FILE).write_text(json.dumps({"current": ident_id}), encoding="utf-8")
    return ident


class FakeService:
    kind = "fake"
    registry: dict = {}

    def __init__(self, defn, world):
        self.defn, self.world = defn, world

    def state(self):
        return self.world.state.get(self.defn.name, "absent")

    def install(self):
        self.world.calls.append(("install", self.defn.name))
        self.world.state.setdefault(self.defn.name, "stopped")

    def start(self):
        self.world.calls.append(("start", self.defn.name))
        self.world.state[self.defn.name] = "running"
        self.world.listening = True

    def stop(self):
        self.world.calls.append(("stop", self.defn.name))
        if self.world.state.get(self.defn.name) == "running":
            self.world.state[self.defn.name] = "stopped"
        self.world.listening = False

    def uninstall(self):
        self.world.calls.append(("uninstall", self.defn.name))
        self.world.state.pop(self.defn.name, None)


class World:
    """The OS service manager, the gateway port and the CLI, faked together."""

    def __init__(self, monkeypatch, sandboxes=()):
        self.state, self.calls, self.cli_calls, self.listening = {}, [], [], False
        self.sandboxes = list(sandboxes)
        self.status_text = "Gateway: hermes-x\nStatus: Connected\nAuth: mTLS\n"
        monkeypatch.setattr(GS, "port_open", lambda port, *a, **k: self.listening)

    def manager(self, defn):
        return FakeService(defn, self)

    def run(self, cmd, **kw):
        self.cli_calls.append(cmd)
        if "generate-certs" in cmd:
            out = Path(cmd[cmd.index("--output-dir") + 1])
            for f in GS.PKI_FILES:
                (out / f).parent.mkdir(parents=True, exist_ok=True)
                (out / f).write_text("pem", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        args = cmd[1:]
        env = kw.get("env") or {}
        if args[:2] == ["gateway", "add"]:
            name = args[args.index("--name") + 1]
            meta = Path(env["XDG_CONFIG_HOME"]) / "openshell" / "gateways" / name / "metadata.json"
            meta.write_text(json.dumps({"name": name, "gateway_endpoint": args[2], "auth_mode": "mtls"}),
                            encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "added", "")
        if args[:1] == ["status"]:
            return subprocess.CompletedProcess(cmd, 0, self.status_text, "")
        if args[:2] == ["sandbox", "list"]:
            body = "NAME PHASE\n" + "".join(f"{s} Ready\n" for s in self.sandboxes)
            return subprocess.CompletedProcess(cmd, 0, body, "")
        if args[:2] == ["sandbox", "delete"]:
            self.sandboxes.remove(args[2])
        return subprocess.CompletedProcess(cmd, 0, "", "")


class Runtime:
    python = Path(sys.executable)
    code_dir = Path(".")


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "hermes-root"
    r.mkdir()
    return r


def ensure(root, world, monkeypatch, ident, kind="docker", **kw):
    monkeypatch.setattr(inst, "ensure_installed", lambda *a, **k: ident)
    return GS.ensure_gateway(root, kind=kind, manager=world.manager, run=world.run, runtime=Runtime(),
                             base_image=False, sleep=lambda s: None, timeout=5, **kw)


# -- config -------------------------------------------------------------------------------------

def test_docker_config_binds_loopback_requires_mtls_and_pins_the_runtime_images(root):
    ident = make_ident(root, "openshell-v0.1.5")
    text = GS.render_config("docker", gw=GS.gateway_dir(root), name="hermes-abc", port=17710, root=root, ident=ident)
    assert 'bind_address = "127.0.0.1:17710"' in text and 'compute_driver = "docker"' in text
    assert "[openshell.gateway.mtls_auth]\nenabled = true" in text
    assert "enable_bind_mounts = true" in text and "allow_driver_config = true" in text
    assert 'image_pull_policy = "never"' in text
    assert 'supervisor_image = "ghcr.invalid/sup@sha256:aa"' in text
    assert "allow_unauthenticated" not in text and "0.0.0.0" not in text


def test_mxc_config_has_tls_user_auth_jwt_and_a_supervisor_log_dir(root):
    ident = make_ident(root, "openshell-windows-x", platform="windows")
    gw = GS.gateway_dir(root)
    text = GS.render_config("mxc", gw=gw, name="hermes-abc", port=17710, root=root, ident=ident,
                            wxc_exec=Path("C:/mxc/wxc-exec.exe"))
    assert 'compute_driver = "mxc"' in text and "[openshell.gateway.tls]" in text and "client_ca_path" in text
    assert "[openshell.gateway.mtls_auth]\nenabled = true" in text and "[openshell.gateway.gateway_jwt]" in text
    assert "state_dir = " in text and "mxc-state" in text and "debug = false" in text
    assert "openshell-windows-sandbox.exe" in text and "wxc-exec.exe" in text
    with pytest.raises(DriverUnavailable, match="wxc-exec"):
        GS.render_config("mxc", gw=gw, name="n", port=1, root=root, ident=ident)
    spec = GS.service_spec("mxc", gw=gw, port=17710, root=root, ident=ident)
    assert spec["argv"][-4:] == ["--port", "17710", "--log-level", "info"]
    assert spec["env"]["OPENSHELL_OCSF_JSON"] == "1"
    # every sandbox's supervisor loads a policy update and flushes a blocked request within ~2 s (cards)
    assert spec["env"]["OPENSHELL_POLICY_POLL_INTERVAL_SECS"] == "2"
    assert spec["env"]["OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS"] == "2"
    assert any(p.endswith("openshell-windows-sandbox.exe") for p in spec["verify"])


# -- first start, reuse, health -----------------------------------------------------------------

def test_first_ensure_generates_pki_config_registration_and_starts_the_login_service(root, monkeypatch):
    world = World(monkeypatch)
    ident = make_ident(root, "openshell-v0.1.5")
    monkeypatch.setenv(GS.PORT_ENV, "17710")
    info = ensure(root, world, monkeypatch, ident)
    gw = GS.gateway_dir(root)
    name = GS.gateway_name(root)
    assert info["gateway"] == name and info["port"] == 17710 and info["runtime_id"] == "openshell-v0.1.5"
    assert Path(info["cli"]) == inst.bin_path(root, ident, "openshell")
    assert Path(info["config_home"]) == gw / "cli"
    state = json.loads((gw / GS.GATEWAY_FILE).read_text())
    assert state["active"]["runtime_id"] == "openshell-v0.1.5" and state["port"] == 17710
    svc = json.loads((gw / "service" / GS.SERVICE_FILE).read_text())
    assert svc["argv"][0] == str(inst.bin_path(root, ident, "openshell-gateway"))
    assert svc["env"]["OPENSHELL_LOCAL_TLS_DIR"] == str(gw / "pki")
    assert svc["verify"][str(inst.bin_path(root, ident, "openshell-gateway"))] == ident["binaries"]["openshell-gateway"]
    assert (gw / "service" / GS.BOOTSTRAP_FILE).is_file() and (gw / "gateway.toml").is_file()
    meta = json.loads((gw / "cli" / "openshell" / "gateways" / name / "metadata.json").read_text())
    assert meta["gateway_endpoint"] == "https://127.0.0.1:17710" and meta["auth_mode"] == "mtls"
    assert (gw / "cli" / "openshell" / "gateways" / name / "mtls" / "tls.key").is_file()
    assert [c for c in world.calls if c[0] in ("install", "start")] == [
        ("install", f"hermes-openshell-gateway-{LS._root_tag(root)}"), ("start", f"hermes-openshell-gateway-{LS._root_tag(root)}")]
    if os.name != "nt":
        assert oct((gw / "pki").stat().st_mode & 0o777) == "0o700"
        assert oct((gw / "pki" / "client" / "tls.key").stat().st_mode & 0o777) == "0o600"
        assert oct(gw.stat().st_mode & 0o777) == "0o700"
    # the CLI never sees the user's own OpenShell/Hermes settings
    status = next(c for c in world.cli_calls if c[1:2] == ["status"])
    assert status[0] == str(inst.bin_path(root, ident, "openshell"))


def test_a_healthy_gateway_is_reused_without_restarting(root, monkeypatch):
    world = World(monkeypatch)
    ident = make_ident(root, "openshell-v0.1.5")
    ensure(root, world, monkeypatch, ident)
    world.calls.clear()
    info = ensure(root, world, monkeypatch, ident)
    assert world.calls == [] and info["upgrade_pending"] is False


def test_a_stopped_gateway_is_started_again(root, monkeypatch):
    world = World(monkeypatch)
    ident = make_ident(root, "openshell-v0.1.5")
    ensure(root, world, monkeypatch, ident)
    for s in world.state:
        world.state[s] = "stopped"
    world.listening = False
    world.calls.clear()
    ensure(root, world, monkeypatch, ident)
    assert [c[0] for c in world.calls] == ["start"]


def test_an_unhealthy_gateway_is_reported_with_its_log(root, monkeypatch):
    world = World(monkeypatch)
    world.status_text = "Status: Disconnected"
    ident = make_ident(root, "openshell-v0.1.5")
    gw = GS.gateway_dir(root)
    (gw / "logs").mkdir(parents=True)
    (gw / "logs" / "gateway.log").write_text("boom: address in use\n", encoding="utf-8")
    with pytest.raises(DriverUnavailable, match="not healthy.*boom: address in use"):
        ensure(root, world, monkeypatch, ident)


# -- upgrades -----------------------------------------------------------------------------------

def test_a_new_pinned_runtime_waits_while_sandboxes_run_then_restarts_and_prunes(root, monkeypatch):
    world = World(monkeypatch, sandboxes=["hermes-work"])
    old = make_ident(root, "openshell-v0.1.5")
    ensure(root, world, monkeypatch, old)
    new = make_ident(root, "openshell-v0.1.6")
    world.calls.clear()
    info = ensure(root, world, monkeypatch, new)
    assert info["upgrade_pending"] is True and info["runtime_id"] == "openshell-v0.1.5"
    assert info["pending"]["runtime_id"] == "openshell-v0.1.6" and info["sandboxes"] == ["hermes-work"]
    assert Path(info["cli"]) == inst.bin_path(root, old, "openshell")  # launchers keep the running version's CLI
    assert world.calls == []  # nothing restarted under a running sandbox
    world.sandboxes.clear()
    info = ensure(root, world, monkeypatch, new)
    assert info["upgrade_pending"] is False and info["runtime_id"] == "openshell-v0.1.6"
    assert [c[0] for c in world.calls] == ["stop", "install", "start"]
    assert not (inst.runtime_dir(root) / "openshell-v0.1.5").exists()
    svc = json.loads((GS.gateway_dir(root) / "service" / GS.SERVICE_FILE).read_text())
    assert "openshell-v0.1.6" in svc["argv"][0]


# -- who uses it, release -----------------------------------------------------------------------

def switch_on(root: Path, profile: str) -> None:
    d = root / "openshell" / profile / "service"
    d.mkdir(parents=True, exist_ok=True)
    (d / "service.json").write_text("{}", encoding="utf-8")


def test_profiles_in_use_counts_switched_on_and_running_launchers_but_not_the_runtime(root):
    switch_on(root, "work")
    (root / "openshell" / "runtime" / "service").mkdir(parents=True)
    (root / "openshell" / "runtime" / "service" / "service.json").write_text("{}", encoding="utf-8")
    live = root / "openshell" / "fg"
    live.mkdir(parents=True)
    (live / "state.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    dead = root / "openshell" / "old"
    dead.mkdir(parents=True)
    (dead / "state.json").write_text(json.dumps({"pid": 0}), encoding="utf-8")
    assert GS.profiles_in_use(root) == ["fg", "work"]
    assert GS.profiles_in_use(root, leaving="work") == ["fg"]


def test_release_keeps_the_gateway_while_another_profile_is_on_and_removes_it_after(root, monkeypatch):
    world = World(monkeypatch, sandboxes=["hermes-stale"])
    ident = make_ident(root, "openshell-v0.1.5")
    ensure(root, world, monkeypatch, ident)
    switch_on(root, "work")
    switch_on(root, "play")
    kept = GS.release_if_unused(root, leaving="play", manager=world.manager, runtime=Runtime(), run=world.run)
    assert kept == {"removed": False, "in_use": ["work"]} and GS.gateway_dir(root).is_dir()
    (root / "openshell" / "work" / "service" / "service.json").unlink()
    world.calls.clear()
    done = GS.release_if_unused(root, leaving="play", manager=world.manager, runtime=Runtime(), run=world.run)
    assert done["removed"] is True and done["sandboxes_deleted"] == ["hermes-stale"]
    assert [c[0] for c in world.calls] == ["stop", "uninstall"]
    assert not GS.gateway_dir(root).exists()  # PKI, DB, config and registration gone
    assert inst.installed(root)["id"] == "openshell-v0.1.5"  # the verified runtime stays as a cache
    assert GS.release_if_unused(root, manager=world.manager, runtime=Runtime()) == {"removed": False,
                                                                                     "reason": "no gateway"}


def test_remove_refuses_while_in_use_unless_forced(root, monkeypatch):
    world = World(monkeypatch)
    ensure(root, world, monkeypatch, make_ident(root, "openshell-v0.1.5"))
    switch_on(root, "work")
    with pytest.raises(DriverUnavailable, match="in use by: work"):
        GS.remove_gateway(root, manager=world.manager, runtime=Runtime(), run=world.run)
    assert GS.remove_gateway(root, force=True, manager=world.manager, runtime=Runtime(), run=world.run)["removed"]


# -- the bootstrap the login service runs -------------------------------------------------------

def write_bootstrap(tmp_path, cfg):
    folder = tmp_path / "svc"
    folder.mkdir(exist_ok=True)
    (folder / GS.BOOTSTRAP_FILE).write_text(GS.BOOTSTRAP, encoding="utf-8")
    if cfg is not None:
        (folder / GS.SERVICE_FILE).write_text(json.dumps(cfg), encoding="utf-8")
    return folder / GS.BOOTSTRAP_FILE


def test_bootstrap_starts_nothing_without_its_service_file(tmp_path):
    boot = write_bootstrap(tmp_path, None)
    assert subprocess.run([sys.executable, str(boot)], timeout=60).returncode == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows: the bootstrap holds the gateway in a kill-on-close job")
def test_killing_the_windows_bootstrap_ends_the_gateway_it_started(tmp_path):
    import psutil

    cfg = {"argv": [sys.executable, "-c", "import time; time.sleep(120)"], "env": {}, "cwd": str(tmp_path),
           "log": str(tmp_path / "g.log"), "verify": {}}
    boot = write_bootstrap(tmp_path, cfg)
    proc = subprocess.Popen([sys.executable, str(boot)])
    try:
        deadline = time.time() + 30
        kids = []
        while time.time() < deadline and not kids:
            kids = [c for c in psutil.Process(proc.pid).children(recursive=True) if "sleep(120)" in " ".join(c.cmdline())]
            time.sleep(0.2)
        assert kids, "the bootstrap did not start its child"
        proc.kill()  # what Task Scheduler's End does: only the process it started
        gone, alive = psutil.wait_procs(kids, timeout=15)
        assert not alive, "the gateway outlived its bootstrap"
    finally:
        if proc.poll() is None:
            proc.kill()


def test_the_windows_gateway_task_runs_the_base_interpreter_not_the_venv_redirector(tmp_path):
    base = tmp_path / "python-3.14"
    base.mkdir()
    (base / "pythonw.exe").write_bytes(b"")
    venv_py = tmp_path / "venv" / "Scripts" / "python"

    class Rt:
        python = venv_py
        base_python = base

    assert GS._bootstrap_python(Rt(), os_name="nt") == base / "pythonw.exe"
    assert GS._bootstrap_python(Rt(), os_name="posix") == venv_py


def test_bootstrap_refuses_a_binary_that_no_longer_matches_and_runs_one_that_does(tmp_path):
    binary = tmp_path / "fake-gateway"
    binary.write_bytes(b"pinned")
    log = tmp_path / "logs" / "gateway.log"
    script = "import os; print('gateway up', os.environ.get('XDG_STATE_HOME'), os.environ.get('HERMES_HOME'))"
    cfg = {"argv": [sys.executable, "-c", script], "env": {"XDG_STATE_HOME": "/gw/state"}, "cwd": str(tmp_path),
           "log": str(log), "verify": {str(binary): sha(b"something else")}}
    boot = write_bootstrap(tmp_path, cfg)
    env = {**os.environ, "HERMES_HOME": "/real/root"}
    assert subprocess.run([sys.executable, str(boot)], timeout=60, env=env).returncode == 3
    assert "does not match its pinned sha256" in log.read_text()
    cfg["verify"] = {str(binary): sha(b"pinned")}
    boot = write_bootstrap(tmp_path, cfg)
    assert subprocess.run([sys.executable, str(boot)], timeout=60, env=env).returncode == 0
    text = log.read_text()
    assert "gateway up /gw/state None" in text  # its own XDG dirs; no HERMES_* from the login environment


# -- the login-service hooks --------------------------------------------------------------------

def defn(tmp_path, root=None, profile="work"):
    return LS.ServiceDefinition(name="hermes-sandbox-work-x", profile=profile, python=Path(sys.executable),
                                bootstrap=tmp_path / "b.py", config=tmp_path / "s.json", cwd=tmp_path,
                                log=tmp_path / "launcher.log", root=root)


def ok_runner(calls):
    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


@pytest.mark.parametrize("cls", [LS.SystemdUser, LS.WindowsTask, LS.LaunchAgent])
def test_removing_a_profile_service_releases_the_gateway(tmp_path, monkeypatch, cls):
    released = []
    monkeypatch.setattr(GS, "release_if_unused", lambda root, leaving=None, **k: released.append((root, leaving)))
    calls = []
    kwargs = {"unit_dir": tmp_path} if cls is LS.SystemdUser else {"agent_dir": tmp_path, "uid": 501} \
        if cls is LS.LaunchAgent else {}
    cls(defn(tmp_path, root=tmp_path / "root"), runner=ok_runner(calls), **kwargs).uninstall()
    assert released == [(tmp_path / "root", "work")]
    released.clear()
    cls(defn(tmp_path, root=None, profile=""), runner=ok_runner(calls), **kwargs).uninstall()  # the gateway's own
    assert released == []


def test_a_failed_release_never_fails_the_switch(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("gateway busy")
    monkeypatch.setattr(GS, "release_if_unused", boom)
    LS.SystemdUser(defn(tmp_path, root=tmp_path), runner=ok_runner([]), unit_dir=tmp_path).uninstall()
    assert "could not release the OpenShell gateway: gateway busy" in (tmp_path / "launcher.log").read_text()


def test_a_launcher_removing_its_own_systemd_unit_is_not_stopped_mid_request(tmp_path, monkeypatch):
    monkeypatch.setattr(GS, "release_if_unused", lambda *a, **k: None)
    svc = LS.SystemdUser(defn(tmp_path), runner=ok_runner(calls := []), unit_dir=tmp_path)
    svc.unit_path.write_text("x", encoding="utf-8")
    monkeypatch.setattr(LS, "running_inside_unit", lambda unit: unit == svc.unit)
    svc.uninstall()
    assert ["systemctl", "--user", "disable", svc.unit] in calls and not svc.unit_path.exists()
    svc.unit_path.write_text("x", encoding="utf-8")
    monkeypatch.setattr(LS, "running_inside_unit", lambda unit: False)
    calls.clear()
    svc.uninstall()
    assert ["systemctl", "--user", "disable", "--now", svc.unit] in calls


def test_running_inside_unit_asks_systemd_for_the_units_main_pid():
    import subprocess as sp

    def runner(pids):
        def run(cmd, **kw):
            assert cmd[:5] == ["systemctl", "--user", "show", "--property=MainPID", "--value"]
            return sp.CompletedProcess(cmd, 0, stdout=f"{pids.get(cmd[5], 0)}\n", stderr="")
        return run

    assert LS.running_inside_unit("hermes-sandbox-work-x.service", runner({"hermes-sandbox-work-x.service": 4242}), 4242)
    assert not LS.running_inside_unit("other.service", runner({"hermes-sandbox-work-x.service": 4242}), 4242)
    assert not LS.running_inside_unit("x.service", runner({}), 4242)  # not running: MainPID 0

    def broken(cmd, **kw):
        raise OSError("no systemctl")
    assert not LS.running_inside_unit("x.service", broken, 4242)


def test_the_plugin_passes_hermes_install_scan():
    """Hermes's install scan rates the whole plugin "caution" on a single HIGH finding (a /proc process-introspection
    path was one), and "caution" blocks `hermes plugins install` from any non-catalog source without --force."""
    guard = pytest.importorskip("tools.plugin_guard")
    result = guard.scan_plugin(Path(LS.__file__).resolve().parent.parent, source="openshell")
    assert result.verdict == "safe", [(f.severity, f.file, f.pattern_id) for f in result.findings
                                      if f.severity in ("high", "critical")]


def test_gateway_unit_and_task_carry_their_own_description(tmp_path):
    d = LS.ServiceDefinition(name="hermes-openshell-gateway-x", profile="", python=Path(sys.executable),
                             bootstrap=tmp_path / "b.py", config=tmp_path / "g.json", cwd=tmp_path,
                             log=tmp_path / "g.log", args=[], description="Hermes OpenShell gateway")
    assert "Description=Hermes OpenShell gateway" in LS.SystemdUser(d, unit_dir=tmp_path).unit_text()
    assert "<Description>Hermes OpenShell gateway</Description>" in LS.WindowsTask(d).task_xml(user="U")


def test_the_build_dir_and_gateway_port_reach_the_launcher_service():
    assert "HERMES_OPENSHELL_BUILD_DIR" in LS._CARRIED_ENV and GS.PORT_ENV in LS._CARRIED_ENV


# -- the driver uses the managed gateway by default ---------------------------------------------

def test_no_gateway_in_the_spec_means_the_managed_gateway(monkeypatch):
    from hermes_constants import get_default_hermes_root

    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)
    root = get_default_hermes_root().resolve()
    cfg = OD.config_from_spec({"openshell": {}})
    assert cfg.managed_root == root and cfg.managed_image is True
    assert cfg.gateway == GS.gateway_name(root)
    assert cfg.config_home == GS.gateway_dir(root) / "cli"
    assert inst.runtime_dir(root) in cfg.cli.parents
    assert not inst.runtime_dir(root).exists()  # computing the paths installs nothing
    named = OD.config_from_spec({"openshell": {"gateway": "mine", "cli": sys.executable}})
    assert named.managed_root is None and named.gateway == "mine"
    pinned_image = OD.config_from_spec({"openshell": {"image": "my/image:1"}})
    assert pinned_image.managed_image is False and pinned_image.image == "my/image:1"


def test_ensure_managed_points_the_config_at_what_runs(monkeypatch, tmp_path):
    seen = {}

    def fake_ensure(root, **kw):
        seen.update(kw, root=root)
        return {"gateway": "hermes-zz", "config_home": tmp_path / "cli", "cli": tmp_path / "openshell",
                "sdk_path": tmp_path / "py", "image": "hermes-sandbox-base:abc-u1g1", "port": 17710}

    monkeypatch.setattr(GS, "ensure_gateway", fake_ensure)
    cfg = OD.OpenShellConfig(gateway="x", config_home=tmp_path, cli=tmp_path / "old", managed_root=tmp_path,
                             managed_image=True, container_cli="docker")
    OD.ensure_managed(cfg)
    assert (cfg.gateway, cfg.cli, cfg.image, cfg.sdk_path) == ("hermes-zz", tmp_path / "openshell",
                                                               "hermes-sandbox-base:abc-u1g1", tmp_path / "py")
    assert seen["container_cli"] == "docker" and seen["base_image"] is True
    plain = OD.OpenShellConfig(gateway="x", config_home=tmp_path, cli=tmp_path / "old")
    assert OD.ensure_managed(plain) is None and plain.gateway == "x"


def test_the_runtime_profile_name_is_reserved():
    from openshell import launcher_cli
    from openshell.launcher.layout import LayoutError, ProfileLayout

    with pytest.raises(LayoutError, match="can't be sandboxed"):
        launcher_cli._check_profile_name(ProfileLayout(name="runtime", home=Path("h"), root=Path("r")))
    launcher_cli._check_profile_name(ProfileLayout(name="work", home=Path("h"), root=Path("r")))


def test_generate_certs_never_writes_the_users_own_openshell_config(root, tmp_path, monkeypatch):
    """openshell-gateway generate-certs copies the client cert and key into
    $XDG_CONFIG_HOME/openshell/gateways/openshell/mtls (default ~/.config): it must get a throwaway config home
    inside the gateway folder, which is gone afterwards."""
    home = tmp_path / "user-home"
    (home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("OPENSHELL_SYSTEM_GATEWAY_DIR", str(home / "etc-openshell"))
    gw = GS.gateway_dir(root)
    seen = {}

    def run(cmd, **kw):  # behaves like the real binary (v0.1.5/v0.1.6): PKI to --output-dir plus the CLI copy
        env = kw["env"]
        seen.update(env)
        out = Path(cmd[cmd.index("--output-dir") + 1])
        for f in GS.PKI_FILES:
            (out / f).parent.mkdir(parents=True, exist_ok=True)
            (out / f).write_text("pem", encoding="utf-8")
        cfg = Path(env.get("XDG_CONFIG_HOME") or Path(env.get("HOME", str(home))) / ".config")
        mtls = cfg / "openshell" / "gateways" / "openshell" / "mtls"
        mtls.mkdir(parents=True, exist_ok=True)
        for f in ("ca.crt", "tls.crt", "tls.key"):
            (mtls / f).write_text("pem", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    pki = GS.ensure_pki(gw, root / "openshell-gateway", run=run)
    assert all((pki / f).is_file() for f in GS.PKI_FILES)
    assert not (home / ".config" / "openshell").exists()
    assert Path(seen["XDG_CONFIG_HOME"]).is_relative_to(gw) and Path(seen["XDG_STATE_HOME"]).is_relative_to(gw)
    assert Path(seen["OPENSHELL_SYSTEM_GATEWAY_DIR"]).is_relative_to(gw)
    assert not (gw / "pki-cli-scratch").exists()
