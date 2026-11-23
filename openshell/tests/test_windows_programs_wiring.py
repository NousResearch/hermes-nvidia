"""Where the two programs the plugin installs for a Windows sandbox are used (launcher/windows_programs.py):
the host check, the driver's start, the sandbox's shell, the gateway's own start, and what the ``hermes sandbox``
commands print. The installs themselves are in test_windows_programs.py; here they come from the same loopback
server through the installer's real downloader.
"""
import asyncio
import json
import os
from pathlib import Path

import pytest

from test_gateway_service import Runtime, World, make_ident, switch_on
from test_gateway_service import ensure as ensure_gateway
from test_openshell_install import root, sha, use_pins  # noqa: F401  (root is a fixture)
from test_openshell_windows import FakeCli, Forward, _driver, _supervisor, _tree, secrets_env  # noqa: F401
from test_windows_programs import (SHELL, WXC, X64, nothing_installed, own_copy, pins_for, program, site,  # noqa: F401
                                   windows_pc, world)
from openshell import launcher_cli
from openshell.launcher import compat as C
from openshell.launcher import gateway_service as GS
from openshell.launcher import mxc as M
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_install as inst
from openshell.launcher import openshell_windows as W
from openshell.launcher import supervisor as S
from openshell.launcher import switch as SW
from openshell.launcher import windows_programs as P
from openshell.launcher.driver import DriverUnavailable

windows_only = pytest.mark.skipif(os.name != "nt", reason="the Windows driver's preflight runs on Windows only")
GATE_OK = {"tier": "base-container", "needs_dacl_augmentation": False}


# -- the host check ---------------------------------------------------------------------------------------

def test_the_host_check_probes_with_the_file_the_driver_would_use(root, world, windows_pc, tmp_path):  # noqa: F811
    assert C.wxc_exec_for({}, root) is None  # Nothing is installed by asking: until then the OS table decides
    assert world.asked == [] and nothing_installed(root)
    installed = P.ensure(root, "wxc-exec")
    assert C.wxc_exec_for({}, root) == installed and C.wxc_exec_for(None, root) == installed
    mine = own_copy(tmp_path, "mine.exe")
    world.monkeypatch.setenv("OPENSHELL_WXC_EXEC_PATH", str(mine))
    assert C.wxc_exec_for({}, root) == mine.resolve()


def test_the_switch_asks_about_the_profiles_own_root(root, world, windows_pc):  # noqa: F811
    from openshell.launcher.layout import ProfileLayout

    installed = P.ensure(root, "wxc-exec")
    seen = []
    world.monkeypatch.setattr(C, "check", lambda wxc_exec=None, *, refresh=False: seen.append(wxc_exec) or {"ok": True})
    SW.host_check(ProfileLayout(name="work", home=root / "profiles" / "work", root=root))
    assert seen == [installed]


# -- the driver: wxc-exec before the MXC gate -----------------------------------------------------------------

def bare_driver(cfg, root, wxc_exec=None, own_shell=None):  # noqa: F811
    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=wxc_exec, gateway=W.CliGateway(cfg, run=FakeCli()),
                                      programs_root=root, own_shell=own_shell)
    driver.denied_paths_supported = True
    return driver


@pytest.fixture
def gate(monkeypatch):
    """The MXC gate and the managed gateway, recorded instead of run."""
    calls = []
    monkeypatch.setattr(M, "preflight", lambda exe: calls.append(("gate", Path(exe))) or dict(GATE_OK))
    monkeypatch.setattr(W, "ensure_managed", lambda cfg, **kw: calls.append(("gateway", kw.get("wxc_exec"))) and None)
    return calls


@windows_only
def test_preflight_installs_the_two_pinned_programs_and_uses_wxc_exec_for_the_gate_and_the_gateway(
        tmp_path, world, windows_pc, gate):
    layout, runtime, cfg, bb = _tree(tmp_path)
    driver = bare_driver(cfg, layout.root)
    assert driver.wxc_exec is None
    driver.preflight()
    installed = P.installed(layout.root, "wxc-exec")
    assert installed is not None and driver.wxc_exec == installed
    # Installed and checked first, then asked about this PC, then handed to the gateway's config
    assert gate == [("gate", installed), ("gateway", installed)]
    # The shell is installed at the switch-on too, so that the sandbox's first start finds it
    assert P.installed(layout.root, "busybox") is not None and world.asked == ["/mxc.tgz", "/busybox64u.exe"]
    driver.preflight()
    assert world.asked == ["/mxc.tgz", "/busybox64u.exe"]


@windows_only
def test_programs_of_the_persons_own_are_used_and_none_is_installed(tmp_path, world, windows_pc, gate):
    layout, runtime, cfg, bb = _tree(tmp_path)
    mine = own_copy(tmp_path, "wxc-exec.exe")
    driver = bare_driver(cfg, layout.root, wxc_exec=mine, own_shell=bb)
    driver.preflight()
    assert gate == [("gate", mine), ("gateway", mine)]
    assert world.asked == [] and nothing_installed(layout.root / "openshell")
    # Each program by itself: a shell of one's own does not keep the plugin's wxc-exec from being installed
    bare_driver(cfg, layout.root, own_shell=bb).preflight()
    assert world.asked == ["/mxc.tgz"] and P.installed(layout.root, "busybox") is None
    bare_driver(cfg, layout.root, wxc_exec=mine).preflight()
    assert world.asked == ["/mxc.tgz", "/busybox64u.exe"]


@windows_only
def test_a_shell_that_cannot_be_installed_stops_the_switch_before_anything_is_started(
        tmp_path, world, windows_pc, gate):
    layout, runtime, cfg, bb = _tree(tmp_path)
    (world.served / "busybox64u.exe").unlink()
    with pytest.raises(DriverUnavailable, match=r"busybox64u\.exe \(the sandbox's shell\) is not installed and "
                                                r"could not be downloaded: .*OPENSHELL_BUSYBOX"):
        bare_driver(cfg, layout.root).preflight()
    assert gate == []  # No question to MXC, no OpenShell install, no gateway


@windows_only
def test_a_wxc_exec_that_cannot_be_installed_stops_the_switch_with_the_reason(tmp_path, world, windows_pc, gate):
    layout, runtime, cfg, bb = _tree(tmp_path)
    (world.served / "mxc.tgz").unlink()
    with pytest.raises(DriverUnavailable, match=r"wxc-exec\.exe \(MXC, which starts the sandbox\) is not installed "
                                                r"and could not be downloaded: .*OPENSHELL_WXC_EXEC_PATH"):
        bare_driver(cfg, layout.root).preflight()
    assert gate == []  # Nothing was asked of a file that is not there, and no gateway was started


@windows_only
def test_a_wxc_exec_that_fails_a_check_is_never_handed_to_the_gate(tmp_path, world, windows_pc, gate):
    from openshell.launcher import authenticode

    layout, runtime, cfg, bb = _tree(tmp_path)
    world.monkeypatch.setattr(authenticode, "signature", lambda path: {
        "status": "valid", "signer": "Another Vendor Ltd", "code": 0, "detail": "valid"})
    with pytest.raises(DriverUnavailable, match="is signed by 'Another Vendor Ltd', not by Example Systems"):
        bare_driver(cfg, layout.root).preflight()
    assert gate == [] and nothing_installed(layout.root / "openshell")


def test_the_driver_made_from_a_spec_installs_into_this_hermes_root(tmp_path, world, windows_pc):
    if os.name != "nt":
        pytest.skip("the hook picks the Windows driver on Windows only")
    from hermes_constants import get_default_hermes_root

    layout, runtime, cfg, bb = _tree(tmp_path)
    spec = {"openshell": {"gateway": "hermes-oswin", "config_home": str(tmp_path / "xdg"), "cli": str(cfg.cli)}}
    driver = OD.OpenShellDriver.from_spec(spec)
    assert driver.wxc_exec is None and driver._programs_root == get_default_hermes_root().resolve()
    assert driver._own_shell is None
    mine = own_copy(tmp_path, "mine.exe")
    world.monkeypatch.setenv("OPENSHELL_WXC_EXEC_PATH", str(mine))
    assert OD.OpenShellDriver.from_spec(spec).wxc_exec == mine.resolve()
    world.monkeypatch.setenv("OPENSHELL_BUSYBOX", str(bb))
    assert OD.OpenShellDriver.from_spec(spec)._own_shell == bb.resolve()
    world.monkeypatch.delenv("OPENSHELL_BUSYBOX")
    assert OD.OpenShellDriver.from_spec({**spec, "busybox": str(mine)})._own_shell == mine.resolve()
    assert OD.OpenShellDriver.from_spec({**spec, "wxc_exec": str(bb)}).wxc_exec == bb.resolve()
    # A PC the plugin has no pinned build for: a wxc-exec on PATH is taken, as before the plugin installed one
    world.monkeypatch.delenv("OPENSHELL_WXC_EXEC_PATH")
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    world.monkeypatch.setattr(P.shutil, "which", lambda name, *a, **kw: str(mine) if name == "wxc-exec" else None)
    assert OD.OpenShellDriver.from_spec(spec).wxc_exec == mine.resolve()


def test_every_sandbox_start_checks_the_pinned_wxc_exec_again(tmp_path, world, windows_pc, gate, secrets_env):  # noqa: F811
    layout, runtime, cfg, bb = _tree(tmp_path)
    cfg.managed_root = layout.root
    fake = FakeCli()
    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=None, gateway=W.CliGateway(cfg, run=fake),
                                      popen=Forward, programs_root=layout.root)
    # This runtime cannot hide credential files, so each start ends right after its gateway step, before a
    # sandbox is created: what the start did with wxc-exec until then is what the test reads.
    driver.denied_paths_supported = False
    sup = _supervisor(layout, runtime, driver, bb)
    with pytest.raises(DriverUnavailable, match="cannot hide credential files"):
        asyncio.run(sup.start())
    installed = P.installed(layout.root, "wxc-exec")
    assert installed is not None and gate == [("gateway", installed)] and world.asked == ["/mxc.tgz"]
    installed.write_bytes(WXC["x86_64"] + b" changed on disk")
    with pytest.raises(DriverUnavailable, match="cannot hide credential files"):
        asyncio.run(sup.start())
    # The changed file was replaced by the pinned build before the gateway was pointed at it
    assert installed.read_bytes() == WXC["x86_64"] and world.asked == ["/mxc.tgz"] * 2
    assert gate == [("gateway", installed)] * 2 and fake.calls == []


# -- the sandbox's shell -----------------------------------------------------------------------------------

def test_the_sandbox_gets_the_plugins_own_shell_alone_in_its_folder(tmp_path, world, windows_pc, secrets_env):  # noqa: F811
    layout, runtime, cfg, bb = _tree(tmp_path)
    driver = _driver(cfg, FakeCli(), tmp_path)
    sup = _supervisor(layout, runtime, driver, bb)
    sup.spec.pop("busybox")
    request, _ = sup._launch_request()
    shell = P.installed(layout.root, "busybox")
    assert shell is not None and world.asked == ["/busybox64u.exe"]
    assert request.env["OPENSHELL_BUSYBOX"] == str(shell) and shell in request.grants.readonly
    env, extra_ro = driver._sandbox_env(request)
    # The folder goes first on the sandbox's PATH and is granted whole: it holds the shell and nothing else
    assert env["PATH"].split(os.pathsep)[0] == str(shell.parent) and shell.parent in extra_ro
    assert [p.name for p in shell.parent.iterdir()] == ["busybox64u.exe"]
    assert "OPENSHELL_BUSYBOX" not in env


def test_a_shell_of_the_persons_own_still_wins(tmp_path, world, windows_pc, secrets_env):  # noqa: F811
    layout, runtime, cfg, bb = _tree(tmp_path)
    sup = _supervisor(layout, runtime, _driver(cfg, FakeCli(), tmp_path), bb)
    request, _ = sup._launch_request()  # The profile's spec names one (--busybox)
    assert request.env["OPENSHELL_BUSYBOX"] == str(bb.resolve())
    sup.spec.pop("busybox")
    mine = own_copy(tmp_path, "busybox64u.exe")
    world.monkeypatch.setenv("OPENSHELL_BUSYBOX", str(mine))
    request, _ = sup._launch_request()
    assert request.env["OPENSHELL_BUSYBOX"] == str(mine.resolve())
    assert world.asked == [] and P.installed(layout.root, "busybox") is None


def test_a_shell_that_cannot_be_installed_stops_the_sandbox_start_with_the_reason(
        tmp_path, world, windows_pc, secrets_env):  # noqa: F811
    layout, runtime, cfg, bb = _tree(tmp_path)
    sup = _supervisor(layout, runtime, _driver(cfg, FakeCli(), tmp_path), bb)
    sup.spec.pop("busybox")
    (world.served / "busybox64u.exe").unlink()
    with pytest.raises(S.SandboxStartError, match=r"busybox64u\.exe \(the sandbox's shell\) is not installed and "
                                                  r"could not be downloaded: .*OPENSHELL_BUSYBOX"):
        sup._launch_request()


def test_the_default_profile_reads_the_shell_and_nothing_else_of_the_runtime(tmp_path, world, windows_pc, secrets_env):  # noqa: F811
    """For the default profile the Hermes root is the profile's own folder, and the launcher's state under it
    (``<root>/openshell``) is hidden from the sandbox. The shell's folder lies inside it: the deny list is carved
    around that one folder, each folder above it turns read-only, and everything beside it stays hidden: MXC's
    ``wxc-exec``, the gateway's keys, the OpenShell programs."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    rt = layout.root / "openshell" / "runtime"
    key = rt / "gateway" / "cli" / "openshell" / "gateways" / "hermes-oswin" / "mtls" / "tls.key"
    key.parent.mkdir(parents=True)
    key.write_text("x", encoding="utf-8")
    wxc = P.ensure(layout.root, "wxc-exec")
    fake = FakeCli()
    sup = _supervisor(layout, runtime, _driver(cfg, fake, tmp_path), bb)
    sup.spec.pop("busybox")

    async def scenario():
        await sup.start()
        try:
            shell = P.installed(layout.root, "busybox")
            denied = fake.driver_configs["hermes-default"]["denied_paths"]
            fs = fake.revisions["hermes-default"][0]["policy"]["filesystem_policy"]
            assert W.native(shell.parent) in fs["read_only"] and W.native(shell.parent) not in fs["read_write"]
            assert not any(W._inside(shell, d) for d in denied)
            for hidden in (wxc, key):
                assert any(W._inside(hidden, d) for d in denied), hidden
            # No folder above the shell can be renamed or written by the sandbox: each is read-only for it
            for above in (shell.parent.parent, rt, rt.parent):
                assert W.native(above) in fs["read_only"], above
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the gateway's own start, and the last switch-off --------------------------------------------------------

def test_the_gateway_service_rechecks_the_pinned_wxc_exec_before_every_start(root, world, windows_pc, tmp_path):  # noqa: F811
    installed = P.ensure(root, "wxc-exec")
    ident = make_ident(root, "openshell-windows-test", platform="windows")
    spec = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root, ident=ident, wxc_exec=installed)
    assert spec["verify"][str(installed)] == sha(WXC["x86_64"])
    # A copy of the person's own has no pin to be held to; the OpenShell programs are checked either way
    mine = own_copy(tmp_path, "wxc-exec.exe")
    own = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root, ident=ident, wxc_exec=mine)
    plain = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root, ident=ident)
    assert str(mine) not in own["verify"] and own["verify"] == plain["verify"]
    assert {k: v for k, v in spec["verify"].items() if k != str(installed)} == plain["verify"]


def test_the_gateway_is_configured_with_the_installed_wxc_exec_and_its_check(root, world, windows_pc, monkeypatch):  # noqa: F811
    installed = P.ensure(root, "wxc-exec")
    services = World(monkeypatch)
    ident = make_ident(root, "openshell-windows-test", platform="windows")
    ensure_gateway(root, services, monkeypatch, ident, kind="mxc", wxc_exec=installed)
    gw = GS.gateway_dir(root)
    assert f"wxc_exec_path = {GS._toml_str(installed)}" in (gw / "gateway.toml").read_text(encoding="utf-8")
    written = json.loads((gw / "service" / GS.SERVICE_FILE).read_text(encoding="utf-8"))
    assert written["verify"][str(installed)] == sha(WXC["x86_64"])


def test_the_last_switch_off_removes_the_builds_of_an_earlier_pin(root, world, monkeypatch):  # noqa: F811
    services = World(monkeypatch)
    ensure_gateway(root, services, monkeypatch, make_ident(root, "openshell-v0.1.5"))
    old = P.ensure(root, "busybox")
    newer = program(X64, b"a newer shell")
    (world.served / "busybox64u.exe").write_bytes(newer)
    pins = pins_for(world.base, shell_id="shell-test-2")
    pins["windows_programs"]["busybox"]["builds"]["x86_64"]["sha256"] = sha(newer)
    use_pins(monkeypatch, pins)
    new = P.ensure(root, "busybox")
    switch_on(root, "work")
    switch_on(root, "play")
    # Another profile is still switched on: its sandbox may be using the shell of the earlier pin
    kept = GS.release_if_unused(root, leaving="play", manager=services.manager, runtime=Runtime(), run=services.run)
    assert kept == {"removed": False, "in_use": ["work"]} and old.is_file() and new.is_file()
    (root / "openshell" / "work" / "service" / "service.json").unlink()
    done = GS.release_if_unused(root, leaving="play", manager=services.manager, runtime=Runtime(), run=services.run)
    assert done["removed"] is True and done["programs_removed"] == ["shell-test-1-x64"]
    assert new.is_file() and not old.exists()


# -- what the commands print ---------------------------------------------------------------------------------

class Args:
    def __init__(self, action, build_dir=None):
        self.action, self.build_dir = action, build_dir


@pytest.fixture
def cli(root, world, windows_pc, monkeypatch, capsys):  # noqa: F811
    """``hermes sandbox runtime <action>`` on a Windows PC with this root, OpenShell's own install faked."""
    from openshell.launcher import layout as L
    from openshell.launcher.layout import ProfileLayout

    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = ProfileLayout(name="work", home=home, root=root)
    monkeypatch.setattr(launcher_cli, "_hermes_root", lambda: root)
    monkeypatch.setattr(L, "current_profile", lambda: layout)
    monkeypatch.setattr(inst, "platform_key", lambda *a: "windows")
    monkeypatch.setattr(inst, "ensure_installed", lambda root, **kw: {"id": "openshell-windows-test"})

    def run(action):
        code = launcher_cli._cmd_runtime(Args(action))
        out = capsys.readouterr()
        return code, (json.loads(out.out) if out.out.strip() else None), out.err

    run.layout = layout
    return run


def test_runtime_install_installs_the_two_programs_too_and_prints_what_is_used(root, world, cli):  # noqa: F811
    code, shown, err = cli("install")
    assert code == 0 and err == "" and shown["installed"] == {"id": "openshell-windows-test"}
    wxc, shell = P.installed(root, "wxc-exec"), P.installed(root, "busybox")
    assert wxc is not None and shell is not None and sorted(world.asked) == ["/busybox64u.exe", "/mxc.tgz"]
    assert shown["programs"] == P.status(root, {})
    shown_wxc = shown["programs"]["wxc-exec"]
    assert (shown_wxc["file"], shown_wxc["source"]) == (str(wxc), "pinned install")
    assert (shown["programs"]["busybox"]["file"], shown["programs"]["busybox"]["installed"]) == (str(shell), True)
    # A second run downloads nothing
    assert cli("install")[0] == 0 and len(world.asked) == 2


def test_runtime_status_says_which_file_is_used_before_and_after_the_install(root, world, cli):  # noqa: F811
    code, shown, _ = cli("status")
    assert code == 0 and shown["programs"] == P.status(root, {})
    assert [shown["programs"][name]["installed"] for name in P.PROGRAMS] == [False, False]
    assert all(shown["programs"][name]["note"].startswith("not installed yet") for name in P.PROGRAMS)
    assert world.asked == []  # Status installs nothing
    cli("install")
    code, shown, _ = cli("status")
    assert [shown["programs"][name]["installed"] for name in P.PROGRAMS] == [True, True]
    assert shown["programs"]["wxc-exec"]["pinned"]["id"] == "mxc-test-1"


def test_runtime_install_leaves_a_program_the_person_named_alone_and_says_so(root, world, cli, tmp_path):  # noqa: F811
    mine = own_copy(tmp_path, "my-wxc.exe")
    world.monkeypatch.setenv("OPENSHELL_WXC_EXEC_PATH", str(mine))
    code, shown, _ = cli("install")
    assert code == 0 and world.asked == ["/busybox64u.exe"] and P.installed(root, "wxc-exec") is None
    assert shown["programs"]["wxc-exec"]["source"] == "variable OPENSHELL_WXC_EXEC_PATH"
    assert shown["programs"]["wxc-exec"]["file"] == str(mine.resolve())
    assert shown["programs"]["wxc-exec"]["is_pinned_build"] is False
    assert shown["programs"]["busybox"]["source"] == "pinned install"


def test_the_profiles_saved_spec_counts_for_what_the_commands_print(root, world, cli, tmp_path):  # noqa: F811
    from openshell.launcher.spec import load_spec, save_spec

    mine = own_copy(tmp_path, "busybox64u.exe")
    spec = load_spec(cli.layout)
    spec.update(busybox=str(mine), folders=[])
    save_spec(cli.layout, spec)
    code, shown, _ = cli("status")
    shell = shown["programs"]["busybox"]
    assert (shell["source"], shell["file"]) == ("spec", str(mine.resolve()))


def test_a_failed_program_install_fails_the_command_with_the_reason(root, world, cli):  # noqa: F811
    (world.served / "mxc.tgz").unlink()
    code, shown, err = cli("install")
    assert code == 1 and shown is None
    said = "hermes sandbox: wxc-exec.exe (MXC, which starts the sandbox) is not installed and could not be downloaded"
    assert said in err


def test_runtime_remove_removes_the_two_programs(root, world, cli):  # noqa: F811
    cli("install")
    assert P.programs_dir(root).is_dir()
    code, shown, _ = cli("remove")
    assert code == 0 and shown == {"removed": True}
    assert not P.programs_dir(root).exists() and P.installed(root, "busybox") is None
    code, shown, _ = cli("status")
    assert [shown["programs"][name]["installed"] for name in P.PROGRAMS] == [False, False]


def test_off_windows_the_runtime_commands_say_nothing_of_the_programs(root, world, cli, monkeypatch):  # noqa: F811
    monkeypatch.setattr(inst, "platform_key", lambda *a: "linux")
    monkeypatch.setattr(inst, "pinned", lambda *a, **kw: {"id": "openshell-v0"})
    for action in ("status", "install"):
        code, shown, _ = cli(action)
        assert code == 0 and "programs" not in shown
    assert world.asked == [] and not P.programs_dir(root).exists()


def test_sandbox_check_prints_the_two_programs_on_windows(root, world, cli, monkeypatch, capsys):  # noqa: F811
    from openshell.launcher import provider_rows

    monkeypatch.setattr(SW, "host_check", lambda layout, refresh=False: {
        "ok": True, "platform": "windows", "code": "ok", "reason": None, "action": None})
    monkeypatch.setattr(launcher_cli, "_call_running", lambda method, route, body=None: (None, "no sandbox running"))
    monkeypatch.setattr(provider_rows, "refusal", lambda layout, seen=None: None)
    P.ensure(root, "busybox")
    assert launcher_cli._cmd_check(None) == 0
    said = json.loads(capsys.readouterr().out)
    assert said["ok"] is True and said["programs"] == P.status(root, {})
    assert said["programs"]["busybox"]["installed"] is True and said["programs"]["wxc-exec"]["installed"] is False
    monkeypatch.setattr(inst, "platform_key", lambda *a: "linux")
    assert launcher_cli._cmd_check(None) == 0
    assert "programs" not in json.loads(capsys.readouterr().out)


# -- the suite's own rule: nothing is downloaded from the internet -------------------------------------------

def test_a_test_that_reaches_the_real_downloader_for_another_computer_is_stopped(tmp_path):
    for url in ("https://registry.npmjs.org/x.tgz", "http://example.invalid/busybox64u.exe"):
        with pytest.raises(AssertionError, match="a test must not download from another computer"):
            inst._download(url, tmp_path / "x")
    assert list(tmp_path.iterdir()) == []
