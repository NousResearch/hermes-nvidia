"""Windows on Arm64: the machine's own architecture (also under an emulated x64 Python), the per-architecture
Windows build in runtime/pins.json and its installer, the host check on an Arm64 PC, the wxc-exec architecture
gate and busybox-w32's Arm64 build. Everything here simulates the host; nothing needs an Arm64 machine."""
import json
import os
import sys
import sysconfig
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from openshell.launcher import compat as C
from openshell.launcher import hostarch as H
from openshell.launcher import mxc as M
from openshell.launcher import openshell_install as inst
from openshell.launcher.driver import DriverUnavailable

NAMES = ("openshell.exe", "openshell-gateway.exe", "openshell-supervisor.exe", "openshell-windows-sandbox.exe",
         "libz3.dll")


def sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def pe_bytes(machine: int, body: bytes = b"") -> bytes:
    """A minimal PE header (DOS stub, ``e_lfanew`` at 0x3C, the PE signature and the COFF machine field)."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    return bytes(dos) + b"PE\0\0" + machine.to_bytes(2, "little") + b"\0" * 18 + body


X64 = {n: pe_bytes(0x8664, f"x64 {n}".encode()) for n in NAMES}
ARM64 = {n: pe_bytes(0xAA64, f"arm64 {n}".encode()) for n in NAMES}


def two_arch_pin(*, arm_id="openshell-windows-test-arm64", x64_archive=None, arm_archive=None) -> dict:
    win = {"id": "openshell-windows-test", "version": "0.0.0+test", "source": "test source",
           "features": ["mxc-driver-config-denied-paths"], "binaries": {n: sha(d) for n, d in X64.items()},
           "aarch64": {"id": arm_id, "binaries": {n: sha(d) for n, d in ARM64.items()}}}
    if x64_archive:
        win["archive"] = x64_archive
    if arm_archive:
        win["aarch64"]["archive"] = arm_archive
    return {"linux": {}, "windows": win, "base_image": {"repository": "r", "base": "b@sha256:" + "0" * 64}}


@pytest.fixture
def pins(monkeypatch):
    def use(p):
        monkeypatch.setattr(inst, "load_pins", lambda: json.loads(json.dumps(p)))
        return p
    return use


@pytest.fixture
def machine(monkeypatch):
    """Simulate the PC's architecture for the installer (``openshell_install.windows_arch``)."""
    def use(arch):
        monkeypatch.setattr(inst, "windows_arch", lambda: arch)
    return use


def build_dir(tmp_path: Path, files: dict, name: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    for n, data in files.items():
        (d / n).write_bytes(data)
    return d


# -- the machine's own architecture ------------------------------------------------------------------------

def test_the_kernel_answer_wins_over_an_emulated_environment(monkeypatch):
    # An x64 Python on Arm64: its environment says AMD64, IsWow64Process2's native machine says Arm64.
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setattr(H, "_wow64_native", lambda: "aarch64")
    monkeypatch.setattr(H, "_registry_arch", lambda: pytest.fail("the kernel answered first"))
    assert H.windows_native_arch() == "aarch64"


def test_the_registry_then_the_environment_answer_when_the_kernel_cannot(monkeypatch):
    monkeypatch.setattr(H, "_wow64_native", lambda: "")
    monkeypatch.setattr(H, "_registry_arch", lambda: "aarch64")
    assert H.windows_native_arch() == "aarch64"

    def no_registry():
        raise OSError("no key")

    monkeypatch.setattr(H, "_registry_arch", no_registry)
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.setenv("PROCESSOR_ARCHITEW6432", "ARM64")  # a 32-bit process on Arm64
    assert H.windows_native_arch() == "aarch64"
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432")
    assert H.windows_native_arch() == "x86_64"


@pytest.mark.parametrize("raw,want", [("AMD64", "x86_64"), ("x64", "x86_64"), ("ARM64", "aarch64"),
                                      ("aarch64", "aarch64"), ("x86", "x86"), ("IA64", ""), (None, "")])
def test_normalize(raw, want):
    assert H.normalize(raw) == want


@pytest.mark.skipif(os.name != "nt", reason="asks the Windows kernel and registry")
def test_the_real_machine_answers_the_same_from_the_kernel_and_the_registry():
    kernel, registry = H._wow64_native(), H._registry_arch()
    assert kernel in ("x86_64", "aarch64") and kernel == registry == H.windows_native_arch()
    assert C._windows_arch() == {"x86_64": "AMD64", "aarch64": "ARM64"}[kernel]


def test_pe_machine_reads_the_coff_header(tmp_path):
    for machine, want in ((0xAA64, "aarch64"), (0x8664, "x86_64"), (0x014C, "x86"), (0x1234, "0x1234")):
        (tmp_path / "a.exe").write_bytes(pe_bytes(machine))
        assert H.pe_machine(tmp_path / "a.exe") == want
    (tmp_path / "b.exe").write_bytes(b"MZ" + b"\0" * 10)  # truncated
    (tmp_path / "c.cmd").write_bytes(b"@type probe.json\r\n" * 8)  # a harness stand-in, not a PE file
    assert H.pe_machine(tmp_path / "b.exe") is None and H.pe_machine(tmp_path / "c.cmd") is None
    assert H.pe_machine(tmp_path / "missing.exe") is None


@pytest.mark.skipif(os.name != "nt", reason="reads a Windows executable")
def test_pe_machine_names_this_interpreters_build():
    want = {"win-amd64": "x86_64", "win-arm64": "aarch64", "win32": "x86"}[sysconfig.get_platform()]
    assert H.pe_machine(sys.executable) == want


# -- the per-architecture pin and its installer ----------------------------------------------------------

def test_the_shipped_pin_has_an_arm64_build_of_the_same_source():
    win = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))["windows"]
    arm = win["aarch64"]
    assert inst.windows_arches(win) == ["x86_64", "aarch64"]
    assert arm["id"] != win["id"] and arm["id"].startswith(win["id"])
    assert set(arm["binaries"]) == set(win["binaries"]) == set(NAMES) - {"libz3.dll"}  # Z3 is inside the gateway
    assert all(len(v) == 64 and int(v, 16) >= 0 for v in arm["binaries"].values())
    assert not set(arm["binaries"].values()) & set(win["binaries"].values())  # other bytes for every file
    got = inst.windows_pin(win, "aarch64")
    assert got["version"] == win["version"] and got["features"] == win["features"] and got["arch"] == "aarch64"
    assert got["signer"] == win["signer"]  # one publisher for both packages
    # its own zip on the same release, never the x64 one
    assert arm["archive"]["url"].startswith("https://") and len(arm["archive"]["sha256"]) == 64
    assert arm["archive"]["url"] != win["archive"]["url"] and arm["archive"]["sha256"] != win["archive"]["sha256"]
    assert arm["archive"]["url"].rsplit("/", 1)[0] == win["archive"]["url"].rsplit("/", 1)[0]
    assert arm["archive"]["url"].endswith("-arm64.zip") and win["archive"]["url"].endswith("-x64.zip")
    assert got["archive"] == arm["archive"] and inst.windows_pin(win, "x86_64")["archive"] == win["archive"]


def test_pinned_picks_the_build_for_the_machine(pins, machine):
    pins(two_arch_pin())
    machine("aarch64")
    arm = inst.pinned("windows")
    assert arm["id"] == "openshell-windows-test-arm64" and arm["arch"] == "aarch64"
    assert arm["binaries"] == {n: sha(d) for n, d in ARM64.items()} and "aarch64" not in arm
    assert arm["version"] == "0.0.0+test" and arm["features"] == ["mxc-driver-config-denied-paths"]
    machine("x86_64")
    x64 = inst.pinned("windows")
    assert x64["id"] == "openshell-windows-test" and x64["arch"] == "x86_64" and "aarch64" not in x64
    assert inst.pinned("windows", arch="aarch64")["id"] == "openshell-windows-test-arm64"


def test_an_arm64_build_never_inherits_the_x64_archive(pins, machine):
    x64_zip = {"url": "https://example.invalid/x64.zip", "sha256": "a" * 64}
    pins(two_arch_pin(x64_archive=x64_zip))
    machine("aarch64")
    assert "archive" not in inst.pinned("windows")
    machine("x86_64")
    assert inst.pinned("windows")["archive"] == x64_zip


def test_an_arm64_pc_without_a_pinned_arm64_build_is_refused_with_the_reason(pins, machine):
    pin = two_arch_pin()
    del pin["windows"]["aarch64"]
    pins(pin)
    machine("aarch64")
    with pytest.raises(inst.InstallError, match="has no build for Windows on Arm64; this plugin version supports x64"):
        inst.pinned("windows")
    assert inst.windows_arches(pin["windows"]) == ["x86_64"]


def test_an_arm64_pc_installs_only_the_arm64_build(pins, machine, tmp_path):
    pins(two_arch_pin())
    machine("aarch64")
    root = tmp_path / "root"
    arm_dir, x64_dir = build_dir(tmp_path, ARM64, "arm64"), build_dir(tmp_path, X64, "x64")
    with pytest.raises(inst.InstallError, match=r"not the pinned OpenShell build openshell-windows-test-arm64.*"
                                                r"It holds the x64 build openshell-windows-test; this PC needs the "
                                                r"Arm64 build openshell-windows-test-arm64"):
        inst.install_windows(root, x64_dir)
    assert inst.installed(root) is None
    ident = inst.install_windows(root, arm_dir)
    assert ident["id"] == "openshell-windows-test-arm64" and ident["arch"] == "aarch64"
    assert ident["binaries"] == {n: sha(d) for n, d in ARM64.items()}
    assert inst.installed(root) == ident
    for n, data in ARM64.items():
        assert (inst.identity_dir(root, ident) / "bin" / n).read_bytes() == data
    inst.verify(root, ident)
    assert inst.ensure_installed(root, platform="windows") == ident  # already current: nothing reinstalled


def test_an_x64_pc_names_an_arm64_build_dir_as_such(pins, machine, tmp_path):
    pins(two_arch_pin())
    machine("x86_64")
    with pytest.raises(inst.InstallError, match="It holds the Arm64 build openshell-windows-test-arm64; this PC "
                                                "needs the x64 build openshell-windows-test"):
        inst.install_windows(tmp_path / "root", build_dir(tmp_path, ARM64, "arm64"))
    ident = inst.install_windows(tmp_path / "root", build_dir(tmp_path, X64, "x64"))
    assert ident["arch"] == "x86_64" and ident["id"] == "openshell-windows-test"


def test_a_root_moved_to_another_architecture_gets_this_pcs_build(pins, machine, tmp_path):
    # Even a pin that gave both architectures one id must not keep the other architecture's install.
    pins(two_arch_pin(arm_id="openshell-windows-test"))
    root = tmp_path / "root"
    machine("x86_64")
    assert inst.ensure_installed(root, platform="windows",
                                 build_dir=build_dir(tmp_path, X64, "x64"))["arch"] == "x86_64"
    machine("aarch64")
    with pytest.raises(inst.InstallError, match="not installed"):
        inst.ensure_installed(root, platform="windows")  # no build dir, no archive: refuses, never runs the x64 one
    ident = inst.ensure_installed(root, platform="windows", build_dir=build_dir(tmp_path, ARM64, "arm64"))
    assert ident["arch"] == "aarch64" and inst.installed(root)["binaries"] == {n: sha(d) for n, d in ARM64.items()}


def test_the_not_installed_message_names_the_architecture_and_the_build(pins, machine, tmp_path, monkeypatch):
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    pins(two_arch_pin())
    machine("aarch64")
    with pytest.raises(inst.InstallError, match="Install the pinned Arm64 build openshell-windows-test-arm64 once"):
        inst.ensure_installed(tmp_path / "root", platform="windows")


def test_an_arm64_pc_downloads_the_arm64_archive(pins, machine, tmp_path, monkeypatch):
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, data in ARM64.items():
            z.writestr(n, data)
        z.writestr("LICENSE", b"license text")
    data = buf.getvalue()
    arm_url, x64_url = "https://example.invalid/arm64.zip", "https://example.invalid/x64.zip"
    pins(two_arch_pin(x64_archive={"url": x64_url, "sha256": "b" * 64},
                      arm_archive={"url": arm_url, "sha256": sha(data)}))
    machine("aarch64")
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        Path(dest).write_bytes(data)

    ident = inst.ensure_installed(tmp_path / "root", platform="windows", fetch=fetch)
    assert fetched == [arm_url] and ident["arch"] == "aarch64" and ident["archive_sha256"] == sha(data)
    assert ident["binaries"] == {n: sha(d) for n, d in ARM64.items()}


def package_zip(files: dict, top: str) -> bytes:
    """A zip laid out like NVIDIA's Windows package: the programs in <top>/bin/, other files around them."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{top}/README.md", b"readme")
        for n, data in files.items():
            z.writestr(f"{top}/bin/{n}", data)
        z.writestr(f"{top}/scripts/Install.ps1", b"exit 0")
        z.writestr(f"{top}/sdk/openshell-0.0.0-py3-none-any.whl", b"wheel")
    return buf.getvalue()


def test_each_architecture_installs_its_own_package_and_refuses_the_other(pins, machine, tmp_path, monkeypatch):
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    zips = {"https://example.invalid/pkg-x64.zip": package_zip(X64, "OpenShell-Windows-0.0.0-x64"),
            "https://example.invalid/pkg-arm64.zip": package_zip(ARM64, "OpenShell-Windows-0.0.0-arm64")}
    x64_url, arm_url = zips
    pins(two_arch_pin(x64_archive={"url": x64_url, "sha256": sha(zips[x64_url])},
                      arm_archive={"url": arm_url, "sha256": sha(zips[arm_url])}))
    served = dict(zips)
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        Path(dest).write_bytes(served[url])

    for arch, url, files in (("aarch64", arm_url, ARM64), ("x86_64", x64_url, X64)):
        machine(arch)
        root = tmp_path / f"root-{arch}"
        ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
        assert fetched[-1] == url and ident["arch"] == arch and ident["source_archive"] == url
        bin_dir = inst.identity_dir(root, ident) / "bin"
        assert {p.name: p.read_bytes() for p in bin_dir.iterdir()} == files
        assert all(H.pe_machine(bin_dir / n) == arch for n in NAMES)
    # the x64 package handed out at the Arm64 address: its sha256 is not the Arm64 pin's
    served[arm_url] = zips[x64_url]
    machine("aarch64")
    with pytest.raises(inst.InstallError, match=r"pkg-arm64\.zip has sha256 .*pinned"):
        inst.ensure_installed(tmp_path / "root-wrong", platform="windows", fetch=fetch)
    assert inst.installed(tmp_path / "root-wrong") is None
    # a pin whose Arm64 archive is the x64 package (matching sha256): every file fails its own pin, and the
    # message says which architecture the zip holds
    pins(two_arch_pin(x64_archive={"url": x64_url, "sha256": sha(zips[x64_url])},
                      arm_archive={"url": arm_url, "sha256": sha(zips[x64_url])}))
    with pytest.raises(inst.InstallError, match=r"pkg-arm64\.zip is not the pinned OpenShell build "
                                                r"openshell-windows-test-arm64.*It holds the x64 build "
                                                r"openshell-windows-test; this PC needs the Arm64 build"):
        inst.ensure_installed(tmp_path / "root-wrong", platform="windows", fetch=fetch)
    assert inst.installed(tmp_path / "root-wrong") is None
    assert not list(inst.runtime_dir(tmp_path / "root-wrong").glob(".staging-*"))


# -- the host check on an Arm64 PC -------------------------------------------------------------------------

GOOD_PROBE = {"tier": "base-container", "needsDaclAugmentation": False, "warnings": [],
              "probes": {"baseContainerApiPresent": True, "baseContainerSupportsDenyPaths": True,
                         "baseContainerSupportsIngressHostLoopbackAllow": True}}
WXC = Path("C:/mxc/arm64/wxc-exec.exe")


@pytest.fixture
def arm_pc(monkeypatch):
    """An Arm64 Windows 11 PC at the September update; the pin's builds, wxc-exec's architecture and the probe
    answer are set per test."""
    state = {"arch": "ARM64", "builds": ["x86_64", "aarch64"], "exe_arch": "aarch64", "probes": []}
    monkeypatch.setattr(C, "_platform_key", lambda: "windows")
    monkeypatch.setattr(C, "_windows_version", lambda: {"build": "26200", "ubr": 9767, "display_version": "25H2",
                                                        "installation_type": "Client"})
    monkeypatch.setattr(C, "_windows_arch", lambda: state["arch"])
    monkeypatch.setattr(C, "_pinned_windows_arches", lambda: list(state["builds"]))
    monkeypatch.setattr(C, "_exe_arch", lambda exe: state["exe_arch"])

    def probe(exe):
        state["probes"].append(exe)
        return {"code": 0, "stdout": json.dumps(GOOD_PROBE), "stderr": ""}

    monkeypatch.setattr(C, "_run_probe", probe)
    return state


@pytest.mark.host_check
def test_an_arm64_pc_passes_with_an_arm64_build_and_the_arm64_wxc_exec(arm_pc):
    got = C.check(WXC, refresh=True)
    assert got["ok"] and got["code"] == "ok" and got["facts"]["arch"] == "ARM64"
    assert got["facts"]["openshell_builds"] == ["x86_64", "aarch64"] and got["facts"]["wxc_exec_arch"] == "aarch64"
    assert arm_pc["probes"] == [WXC]  # the same probe gates as on x64


@pytest.mark.host_check
def test_the_arm64_probe_gates_are_the_x64_ones(arm_pc, monkeypatch):
    bad = json.loads(json.dumps(GOOD_PROBE))
    bad["tier"], bad["needsDaclAugmentation"] = "appcontainer-dacl", True
    monkeypatch.setattr(C, "_run_probe", lambda exe: {"code": 0, "stdout": json.dumps(bad), "stderr": ""})
    got = C.check(WXC, refresh=True)
    assert not got["ok"] and got["code"] == "isolation-off"


@pytest.mark.host_check
def test_an_arm64_pc_is_refused_when_the_pin_has_no_arm64_build(arm_pc):
    arm_pc["builds"] = ["x86_64"]
    got = C.check(WXC, refresh=True)
    assert not got["ok"] and got["code"] == "arch-arm64" and got["reason"] == "Not supported on Arm PCs yet."
    assert "builds for x86_64" in got["detail"] and arm_pc["probes"] == []


@pytest.mark.host_check
def test_an_x64_wxc_exec_on_an_arm64_pc_is_refused_before_the_probe(arm_pc):
    arm_pc["exe_arch"] = "x86_64"
    got = C.check(WXC, refresh=True)
    assert not got["ok"] and got["code"] == "wxc-exec-arch"
    assert got["reason"] == "wxc-exec is the x64 build. This PC needs the Arm64 one."
    assert got["action"] == {"text": "Use bin\\arm64\\wxc-exec.exe from the MXC package, then check again."}
    assert arm_pc["probes"] == []


@pytest.mark.host_check
def test_an_arm64_wxc_exec_on_an_x64_pc_is_refused_too(arm_pc):
    arm_pc["arch"] = "AMD64"
    got = C.check(WXC, refresh=True)
    assert got["code"] == "wxc-exec-arch" and got["reason"] == "wxc-exec is the Arm64 build. This PC needs the x64 one."


@pytest.mark.host_check
def test_an_unreadable_wxc_exec_is_left_to_the_probe(arm_pc):
    arm_pc["exe_arch"] = None
    assert C.check(WXC, refresh=True)["ok"] and arm_pc["probes"] == [WXC]


@pytest.mark.host_check
def test_the_page_reads_the_kernel_not_the_emulated_environment(monkeypatch):
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.setattr(H, "windows_native_arch", lambda: "aarch64")
    assert C._windows_arch() == "ARM64"


# -- the wxc-exec gate at switch-on ------------------------------------------------------------------------

def test_the_mxc_gate_refuses_a_wxc_exec_of_another_architecture(monkeypatch, tmp_path):
    exe = tmp_path / "wxc-exec.exe"
    exe.write_bytes(pe_bytes(0x8664))
    monkeypatch.setattr(M, "_on_windows", lambda: True)
    monkeypatch.setattr(M.hostarch, "windows_native_arch", lambda: "aarch64")
    monkeypatch.setattr(M, "_require_mxc1", lambda e: pytest.fail("ran the x64 wxc-exec on an Arm64 PC"))
    with pytest.raises(DriverUnavailable, match=r"built for x64 but this PC is Arm64: use MXC's bin/arm64/wxc-exec\.exe"):
        M.preflight(exe)


def test_the_mxc_gate_goes_on_with_a_native_wxc_exec(monkeypatch, tmp_path):
    import subprocess

    exe = tmp_path / "wxc-exec.exe"
    exe.write_bytes(pe_bytes(0xAA64))
    monkeypatch.setattr(M, "_on_windows", lambda: True)
    monkeypatch.setattr(M.hostarch, "windows_native_arch", lambda: "aarch64")
    monkeypatch.setattr(M, "_require_mxc1", lambda e: "1.0.1+test")
    monkeypatch.setattr(subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 0, json.dumps(GOOD_PROBE), ""))
    facts = M.preflight(exe)
    assert facts["mxc_version"] == "1.0.1+test" and facts["tier"] == "base-container"


# -- busybox-w32 ---------------------------------------------------------------------------------------------

def test_busybox_looks_for_the_arm64_build_first_on_an_arm_pc(monkeypatch):
    from openshell import busybox_env as B

    facts = pytest.importorskip("hermes_platform.host.facts")
    monkeypatch.setattr(facts, "native_arch", lambda: "arm64")
    assert B._candidate_names()[0] == "busybox64a.exe"
    monkeypatch.setattr(facts, "native_arch", lambda: "amd64")
    assert B._candidate_names()[0] == "busybox64u.exe"


def test_busybox_uses_the_plugins_reading_on_an_older_core(monkeypatch):
    from openshell import busybox_env as B

    monkeypatch.setitem(sys.modules, "hermes_platform.host.facts", None)  # import fails: no host facts
    monkeypatch.setattr(H, "windows_native_arch", lambda: "aarch64")
    assert B._candidate_names()[0] == "busybox64a.exe"
    monkeypatch.setattr(H, "windows_native_arch", lambda: "x86_64")
    assert B._candidate_names()[0] == "busybox64u.exe"
