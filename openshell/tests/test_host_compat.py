"""The host compatibility check (launcher/compat.py) and where it gates the switch: every Windows and Linux
branch against faked registry values, probe JSON and kernel facts; the cache; switch.availability, turn_on
and the host routes. The check is read-only; nothing here installs or starts anything."""
import errno
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from openshell.launcher import compat as C
from openshell.launcher import switch as SW
from openshell.launcher.layout import ProfileLayout

pytestmark = pytest.mark.host_check

GOOD_PROBE = {"tier": "base-container", "needsDaclAugmentation": False, "warnings": [],
              "probes": {"baseContainerApiPresent": True, "baseContainerSupportsDenyPaths": True,
                         "baseContainerSupportsEnumeratePaths": True,
                         "baseContainerSupportsIngressHostLoopbackAllow": True,
                         "baseContainerSupportsIdentitylessLoopbackProxy": True}}
WXC = Path("C:/mxc/wxc-exec.exe")


def _probe(**changes) -> dict:
    data = json.loads(json.dumps(GOOD_PROBE))
    for key, value in changes.items():
        if key in data["probes"]:
            data["probes"][key] = value
        elif value is _DROP:
            data.pop(key, None)
        else:
            data[key] = value
    return data


_DROP = object()


@pytest.fixture
def windows(monkeypatch):
    """A Windows host with the given registry values and probe answer; returns the probe calls."""
    state = {"ver": {"build": "26200", "ubr": 9550, "display_version": "25H2", "installation_type": "Client"},
             "arch": "AMD64", "probe": {"code": 0, "stdout": json.dumps(GOOD_PROBE), "stderr": ""}, "calls": [],
             "exe_arch": None}
    monkeypatch.setattr(C, "_platform_key", lambda: "windows")
    monkeypatch.setattr(C, "_windows_version", lambda: dict(state["ver"]))
    monkeypatch.setattr(C, "_windows_arch", lambda: state["arch"])
    # WXC need not exist; a real file there (C:\mxc is upstream's default) must not decide the tests.
    monkeypatch.setattr(C, "_exe_arch", lambda exe: state["exe_arch"])

    def run(exe):
        state["calls"].append(exe)
        return state["probe"]

    monkeypatch.setattr(C, "_run_probe", run)
    return state


def _set(state, build, ubr, display=None, kind="Client"):
    state["ver"] = {"build": str(build), "ubr": ubr, "display_version": display, "installation_type": kind}


def _answer(state, data=None, **raw):
    state["probe"] = raw or {"code": 0, "stdout": json.dumps(data), "stderr": ""}


# -- Windows: the OS table ------------------------------------------------------------------------------

def test_a_serviced_build_passes_with_a_base_container_probe(windows):
    _set(windows, 26200, 9767, "25H2")
    got = C.check(WXC)
    assert got["ok"] and got["code"] == "ok" and got["reason"] is None and got["action"] is None
    assert got["facts"]["os"] == "Windows 11 25H2, build 26200.9767"
    assert got["facts"]["probe"]["tier"] == "base-container" and windows["calls"] == [WXC]


@pytest.mark.parametrize("build,ubr,display", [(26100, 9550, "24H2"), (26200, 9550, "25H2"), (26300, 9550, "26H2"),
                                               (28000, 3086, "26H1"), (28000, 3999, "26H1"), (26200, 9999, "25H2")])
def test_serviced_lines_at_their_floor_pass(windows, build, ubr, display):
    _set(windows, build, ubr, display)
    assert C.check(WXC)["ok"]


def test_windows_10_needs_windows_11(windows):
    _set(windows, 19045, 5011, "22H2")
    got = C.check(WXC)
    assert (got["ok"], got["code"], got["reason"], got["action"]) == (False, "windows-10", "Needs Windows 11.", None)
    assert got["detail"] == "This PC has Windows 10 22H2, build 19045.5011."
    assert windows["calls"] == []  # no probe on a host the table already refuses


@pytest.mark.parametrize("kind", ["Server", "Server Core", "Nano Server"])
def test_windows_server_is_not_supported(windows, kind):
    _set(windows, 26100, 9550, "24H2", kind)
    got = C.check(WXC)
    assert got["code"] == "windows-server" and got["reason"] == "Not supported on Windows Server."
    assert got["action"] is None and windows["calls"] == []


@pytest.mark.parametrize("arch,code", [("x86", "arch"), ("ARM", "arch"), ("ARM64", None), ("AMD64", None)])
def test_architecture(windows, arch, code):
    windows["arch"] = arch
    got = C.check(WXC)
    assert got["ok"] is (code is None)
    if code == "arch":
        assert got["reason"] == "Needs a 64-bit PC (x64 or Arm)."
    else:  # the shipped pin has an x64 and an Arm64 build (tests/test_arm64_windows.py: a pin without one)
        assert got["facts"]["openshell_builds"] == ["x86_64", "aarch64"]


def test_older_windows_11_needs_24h2(windows):
    _set(windows, 22631, 4890, "23H2")
    got = C.check(WXC)
    assert got["code"] == "windows-feature-update"
    assert got["reason"] == "Needs Windows 11 24H2 or newer. This PC has Windows 11 23H2, build 22631.4890."
    assert got["action"] == {"text": "Update in Settings > Windows Update, then check again."}


@pytest.mark.parametrize("build,ubr,display,kb", [(26200, 9278, "25H2", "KB5124010"), (26100, 9549, "24H2", "KB5124010"),
                                                  (26300, 9000, "26H2", "KB5124010"), (28000, 3085, "26H1", "KB5124006"),
                                                  (26200, 8000, "25H2", "KB5124010")])
def test_a_serviced_line_below_the_september_update_needs_it(windows, build, ubr, display, kb):
    _set(windows, build, ubr, display)
    got = C.check(WXC)
    assert got["code"] == "windows-update" and windows["calls"] == []
    assert got["reason"] == (f"Needs the September 2026 Windows update. This PC has Windows 11 {display}, "
                             f"build {build}.{ubr}.")
    assert got["action"] == {"text": "Install it in Settings > Windows Update, then check again."}
    assert kb in got["detail"]


def test_the_brief_example_25h2_august(windows):
    _set(windows, 26200, 9278, "25H2")
    assert C.check(WXC)["reason"] == ("Needs the September 2026 Windows update. This PC has Windows 11 25H2, "
                                      "build 26200.9278.")


@pytest.mark.parametrize("build", [26120, 27100, 29000])
def test_unknown_newer_builds_go_to_the_probe(windows, build):
    _set(windows, build, 1, None)
    got = C.check(WXC)
    assert got["ok"] and got["facts"]["os_table"] == "newer" and windows["calls"] == [WXC]
    C._cache.clear()
    _answer(windows, _probe(baseContainerApiPresent=False, tier="appcontainer-dacl", needsDaclAugmentation=True))
    assert C.check(WXC)["code"] == "isolation-missing"


def test_unreadable_build_is_a_check_again(windows):
    windows["ver"]["build"] = None
    got = C.check(WXC)
    assert got["code"] == "windows-unknown" and got["action"] == {"text": "Check again."}


def test_without_wxc_exec_the_os_table_decides(windows):
    got = C.check(None)
    assert got["ok"] and got["facts"]["probe"] == "skipped: wxc-exec not found" and windows["calls"] == []


# -- Windows: the probe --------------------------------------------------------------------------------

def test_api_present_but_a_fallback_tier_means_process_isolation_is_off(windows):
    _answer(windows, _probe(tier="appcontainer-dacl", needsDaclAugmentation=True))
    got = C.check(WXC)
    assert got["code"] == "isolation-off" and got["reason"] == "Process isolation is turned off on this PC."
    assert got["action"] == {"text": "Install the latest updates in Settings > Windows Update and restart, "
                                     "then check again."}
    assert "appcontainer-dacl" in got["detail"]


def test_mxc_main_shape_no_tier_and_an_error_means_off_too(windows):
    # MXC main omits tier and needsDaclAugmentation and reports error when PSEC can't serve the request.
    _answer(windows, _probe(tier=_DROP, needsDaclAugmentation=_DROP, error="PSEC rejected the request"))
    got = C.check(WXC)
    assert got["code"] == "isolation-off" and "PSEC rejected" in got["detail"]


@pytest.mark.parametrize("dacl", [True, None, _DROP])
def test_base_container_tier_still_needs_needs_dacl_augmentation_false(windows, dacl):
    _answer(windows, _probe(needsDaclAugmentation=dacl))
    assert C.check(WXC)["code"] == "isolation-off"


def test_api_absent_means_process_isolation_is_not_available(windows):
    _answer(windows, _probe(baseContainerApiPresent=False, tier="appcontainer-dacl", needsDaclAugmentation=True))
    got = C.check(WXC)
    assert got["code"] == "isolation-missing" and got["reason"] == "Process isolation isn't available on this PC."


@pytest.mark.parametrize("key", ["baseContainerSupportsIngressHostLoopbackAllow", "baseContainerSupportsDenyPaths"])
def test_no_host_loopback_or_deny_paths_needs_the_september_update(windows, key):
    _set(windows, 26200, 9550, "25H2")
    _answer(windows, _probe(**{key: False}))
    got = C.check(WXC)
    assert got["code"] == "windows-update" and key in got["detail"]
    assert got["reason"] == "Needs the September 2026 Windows update. This PC has Windows 11 25H2, build 26200.9550."


def test_an_unlisted_newer_build_without_host_loopback_needs_the_september_update(windows):
    _set(windows, 27100, 1000, "26H2")
    _answer(windows, _probe(baseContainerSupportsIngressHostLoopbackAllow=False))
    got = C.check(WXC)
    assert got["code"] == "windows-update"
    assert got["reason"] == "Needs the September 2026 Windows update. This PC has Windows 11 26H2, build 27100.1000."
    assert got["action"] == {"text": "Install it in Settings > Windows Update, then check again."}


@pytest.mark.parametrize("raw", [{"code": 1, "stdout": "", "stderr": "boom"}, {"code": 0, "stdout": "[1]", "stderr": ""},
                                 {"error": "wxc-exec --probe did not answer within 15 s"}])
def test_a_probe_that_gives_no_answer_says_so(windows, raw):
    _answer(windows, **raw)
    got = C.check(WXC)
    assert got["code"] == "probe-failed" and got["reason"] == "Couldn't check process isolation on this PC."
    assert got["action"] == {"text": "Check again."}


def test_the_probe_runs_hidden_with_a_timeout(monkeypatch):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, json.dumps(GOOD_PROBE), "")

    monkeypatch.setattr(C.subprocess, "run", fake_run)
    assert json.loads(C._run_probe(WXC)["stdout"]) == GOOD_PROBE
    argv, kwargs = seen[0]
    assert argv == [str(WXC), "--probe"] and kwargs["timeout"] == C.PROBE_TIMEOUT
    if os.name == "nt":
        assert kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW

    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(C.subprocess, "run", slow)
    assert "did not answer" in C._run_probe(WXC)["error"]

    def missing(argv, **kwargs):
        raise FileNotFoundError(2, "not found")

    monkeypatch.setattr(C.subprocess, "run", missing)
    assert "could not run" in C._run_probe(WXC)["error"]


# -- the cache, failures, other platforms --------------------------------------------------------------

def test_cached_briefly_and_refreshed_on_demand(windows, monkeypatch):
    first = C.check(WXC)
    assert C.check(WXC) is first and len(windows["calls"]) == 1
    _answer(windows, _probe(tier="appcontainer-dacl", needsDaclAugmentation=True))
    assert C.check(WXC)["ok"]  # still cached
    assert C.check(WXC, refresh=True)["code"] == "isolation-off" and len(windows["calls"]) == 2
    monkeypatch.setattr(C, "CACHE_TTL", 0.0)
    C.check(WXC)
    assert len(windows["calls"]) == 3


def test_a_check_that_breaks_answers_instead_of_raising(windows, monkeypatch):
    def broken():
        raise PermissionError("registry")

    monkeypatch.setattr(C, "_windows_version", broken)
    got = C.check(WXC)
    assert got["code"] == "check-failed" and got["reason"] == "Couldn't check this computer." and not got["ok"]


@pytest.mark.parametrize("key,reason", [("macos", "Not supported on macOS yet."), ("freebsd14", "Not supported on this system.")])
def test_other_platforms(monkeypatch, key, reason):
    monkeypatch.setattr(C, "_platform_key", lambda: key)
    got = C.check()
    assert not got["ok"] and got["reason"] == reason and got["action"] is None


def test_wxc_exec_for_follows_the_drivers_order(tmp_path, monkeypatch):
    a, b, c = (tmp_path / n for n in ("a.exe", "b.exe", "c.exe"))
    for p in (a, b, c):
        p.write_bytes(b"MZ")
    monkeypatch.setenv("OPENSHELL_WXC_EXEC_PATH", str(c))
    assert C.wxc_exec_for({"wxc_exec": str(a), "openshell": {"wxc_exec": str(b)}}) == a.resolve()
    assert C.wxc_exec_for({"wxc_exec": str(tmp_path / "gone.exe"), "openshell": {"wxc_exec": str(b)}}) == b.resolve()
    assert C.wxc_exec_for({}) == c.resolve()
    monkeypatch.delenv("OPENSHELL_WXC_EXEC_PATH")
    monkeypatch.setattr(C.shutil, "which", lambda name: None)
    assert C.wxc_exec_for(None) is None


@pytest.mark.skipif(os.name != "nt", reason="reads the Windows registry")
def test_the_real_registry_reads_back_a_build_and_arch():
    ver = C._windows_version()
    assert C._as_int(ver["build"]) and C._as_int(ver["ubr"]) is not None
    assert C._windows_arch().upper() in ("AMD64", "ARM64", "X86")


# -- Linux ------------------------------------------------------------------------------------------------

@pytest.fixture
def linux(monkeypatch):
    state = {"release": "6.8.0-45-generic", "machine": "x86_64", "libc": "glibc", "abi": (5, 0),
             "files": {"/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n",
                       "/proc/sys/kernel/seccomp/actions_avail": "kill_process kill_thread trap errno user_notif trace log allow\n"},
             "docker": "/usr/bin/docker", "docker_run": {"code": 0, "stdout": "29.4.0", "stderr": ""}}
    monkeypatch.setattr(C, "_platform_key", lambda: "linux")
    monkeypatch.setattr(C, "_kernel_release", lambda: state["release"])
    monkeypatch.setattr(C, "_machine", lambda: state["machine"])
    monkeypatch.setattr(C, "_libc", lambda: state["libc"])

    def abi():
        if isinstance(state["abi"], Exception):
            raise state["abi"]
        return state["abi"]

    monkeypatch.setattr(C, "_landlock_abi", abi)
    monkeypatch.setattr(C, "_read_text", lambda path: state["files"].get(path))
    monkeypatch.setattr(C.shutil, "which", lambda name: state["docker"] if name == "docker" else None)
    monkeypatch.setattr(C, "_docker_version", lambda cli: state["docker_run"])
    return state


def test_linux_passes_with_landlock_seccomp_and_docker(linux):
    got = C.check()
    assert got["ok"] and got["facts"]["landlock_abi"] == 5 and got["facts"]["docker_server"] == "29.4.0"


def test_wsl2_shape_passes_without_securityfs(linux):
    # WSL2 6.6: no /sys/kernel/security/lsm (securityfs not mounted); the syscall answers ABI 3.
    linux.update(release="6.6.87.1-microsoft-standard-WSL2", abi=(3, 0))
    linux["files"].pop("/sys/kernel/security/lsm")
    assert C.check()["ok"]


@pytest.mark.parametrize("machine,ok", [("armv7l", False), ("i686", False), ("aarch64", True)])
def test_linux_architecture(linux, machine, ok):
    linux["machine"] = machine
    got = C.check()
    assert got["ok"] is ok
    if not ok:
        assert got["reason"] == "Needs a 64-bit x86 or Arm computer."


def test_linux_needs_glibc(linux):
    linux["libc"] = ""
    assert C.check()["reason"] == "Needs a Linux distribution with glibc."


def test_landlock_abi_below_3_needs_linux_6_2(linux):
    linux.update(release="5.15.0-91-generic", abi=(2, 0))
    got = C.check()
    assert got["code"] == "linux-kernel"
    assert got["reason"] == "Needs Linux 6.2 or newer. This computer has Linux 5.15.0-91-generic."
    assert got["action"] == {"text": "Update the kernel, then check again."}


def test_no_landlock_on_an_old_kernel_needs_linux_6_2(linux):
    linux.update(release="5.10.0-28-amd64", abi=(-1, errno.ENOSYS))
    assert C.check()["code"] == "linux-kernel"


def test_no_landlock_on_a_new_kernel_is_a_kernel_without_it(linux):
    linux.update(abi=(-1, errno.ENOSYS))
    got = C.check()
    assert got["code"] == "landlock-missing" and got["reason"] == "This Linux kernel has no Landlock."


def test_landlock_built_in_but_off(linux):
    linux.update(abi=(-1, errno.EOPNOTSUPP))
    linux["files"]["/sys/kernel/security/lsm"] = "lockdown,capability,yama,apparmor"
    got = C.check()
    assert got["code"] == "landlock-off" and got["reason"] == "Landlock is turned off in this Linux kernel."
    assert "lsm=" in got["action"]["text"] and "apparmor" in got["detail"]


def test_landlock_blocked_by_a_container_seccomp_profile(linux):
    linux.update(abi=(-1, errno.EPERM))
    got = C.check()
    assert got["code"] == "landlock-blocked" and got["reason"] == "Landlock is blocked here."


def test_without_the_syscall_the_lsm_list_decides(linux):
    linux["abi"] = OSError("no libc")
    assert C.check()["ok"]  # landlock listed, kernel 6.8
    C._cache.clear()
    linux["files"]["/sys/kernel/security/lsm"] = "capability,yama"
    assert C.check()["code"] == "landlock-off"


@pytest.mark.parametrize("actions", ["kill_process kill_thread trap errno trace log allow", None])
def test_seccomp_user_notification_is_required(linux, actions):
    linux["files"]["/proc/sys/kernel/seccomp/actions_avail"] = actions
    if actions is None:
        linux["files"].pop("/proc/sys/kernel/seccomp/actions_avail")
    got = C.check()
    assert got["code"] == "seccomp"


def test_docker_missing_offers_the_install_guide(linux):
    linux["docker"] = None
    got = C.check()
    assert got["code"] == "docker-missing" and got["reason"] == "Needs Docker."
    assert got["action"] == {"text": "Install Docker Engine, then check again.", "label": "Install Docker",
                             "url": "https://docs.docker.com/engine/install/"}


def test_docker_permission(linux):
    linux["docker_run"] = {"code": 1, "stdout": "", "stderr": "permission denied while trying to connect to the "
                                                               "Docker daemon socket at unix:///var/run/docker.sock"}
    got = C.check()
    assert got["code"] == "docker-permission" and got["reason"] == "This user can't use Docker."


@pytest.mark.parametrize("run", [{"code": 1, "stdout": "", "stderr": "Cannot connect to the Docker daemon"},
                                 {"error": "docker version did not answer within 8 s"}])
def test_docker_not_running(linux, run):
    linux["docker_run"] = run
    got = C.check()
    assert got["code"] == "docker-unreachable" and got["reason"] == "Docker isn't running."
    assert got["action"] == {"text": "Start Docker, then check again."}


@pytest.mark.skipif(sys.platform != "linux", reason="the Landlock syscall is Linux only")
def test_the_real_landlock_probe_answers_on_linux():
    abi, err = C._landlock_abi()
    assert abi >= 1 or err


# -- where the check gates the switch ----------------------------------------------------------------------

class _Markers:
    def run_elsewhere(self, profile, *, root=None):
        return None


@pytest.fixture
def work(tmp_path, monkeypatch):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    monkeypatch.setattr(SW, "marker_api", lambda: _Markers())
    return ProfileLayout(name="work", home=home, root=root)


def _fake_check(monkeypatch, result, calls):
    def fake(wxc_exec=None, *, refresh=False):
        calls.append((wxc_exec, refresh))
        return result
    monkeypatch.setattr(C, "check", fake)


BAD = {"ok": False, "platform": "windows", "code": "windows-update",
       "reason": "Needs the September 2026 Windows update. This PC has Windows 11 25H2, build 26200.9278.",
       "action": {"text": "Install it in Settings > Windows Update, then check again."}, "facts": {}}


def test_availability_carries_the_host_verdict(work, monkeypatch):
    calls = []
    _fake_check(monkeypatch, BAD, calls)
    got = SW.availability(work)
    assert got == {"available": False, "reason": BAD["reason"], "action": BAD["action"], "host": BAD}
    _fake_check(monkeypatch, {"ok": True, "reason": None, "action": None}, calls)
    assert SW.availability(work)["available"] is True and calls[-1][1] is False


def test_the_spec_names_the_wxc_exec_the_check_probes(work, monkeypatch, tmp_path):
    from openshell.launcher.spec import load_spec, save_spec

    exe = tmp_path / "wxc-exec.exe"
    exe.write_bytes(b"MZ")
    spec = load_spec(work)
    spec["wxc_exec"] = str(exe)
    save_spec(work, spec)
    calls = []
    _fake_check(monkeypatch, BAD, calls)
    SW.host_check(work, refresh=True)
    assert calls == [(exe.resolve(), True)]


def test_a_running_sandbox_is_never_checked_so_off_always_works(work, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the host check ran for a sandboxed profile")

    monkeypatch.setattr(C, "check", boom)
    view = SW.switch_view(work, sandboxed=True)
    assert view["available"] is True and "host" not in view


def test_turn_on_refuses_with_the_same_reason_before_anything_starts(work, monkeypatch):
    calls = []
    _fake_check(monkeypatch, BAD, calls)

    def never(*a, **k):
        raise AssertionError("nothing may start on an incompatible host")

    with pytest.raises(SW.SwitchError) as err:
        SW.turn_on(work, runtime=object(), manager=never, make_driver=never, environ={})
    assert str(err.value) == BAD["reason"] and err.value.status == 409
    assert calls and calls[0][1] is True  # re-checked fresh, not the page's cached answer
    assert not work.spec_path.exists()


def _router(monkeypatch, layout):
    import importlib.util

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    plugin = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("openshell_plugin_api_compat", plugin / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    monkeypatch.setattr(api, "_profile", lambda: layout)
    monkeypatch.setattr(api._switch, "marker_api", lambda: _Markers())
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/openshell")
    return api, TestClient(app)


def test_the_page_routes_show_check_again_and_refuse(work, monkeypatch):
    import importlib

    api, client = _router(monkeypatch, work)
    router_compat = importlib.import_module(api._PKG + ".launcher.compat")  # the router's own copy
    calls = []

    def fake(wxc_exec=None, *, refresh=False):
        calls.append(refresh)
        return BAD

    monkeypatch.setattr(router_compat, "check", fake)
    st = client.get("/api/plugins/openshell/status").json()
    assert st["switch"]["available"] is False and st["switch"]["reason"] == BAD["reason"]
    assert st["switch"]["action"] == BAD["action"] and st["switch"]["host"]["code"] == "windows-update"
    assert calls == [False]
    again = client.post("/api/plugins/openshell/switch/check", json={})
    assert again.status_code == 200 and again.json()["switch"]["host"]["code"] == "windows-update"
    assert again.json()["profile"] == "work" and calls[-1] is True
    on = client.post("/api/plugins/openshell/switch/on", json={})
    assert on.status_code == 409 and on.json()["detail"] == BAD["reason"]
