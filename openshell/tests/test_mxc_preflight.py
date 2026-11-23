"""The MXC gate (launcher/mxc.py) the Windows OpenShell driver runs before anything is installed or started:
MXC 1.0 or newer, the base-container tier, deny paths and host loopback supported, no DACL augmentation.

Hermetic by default (wxc-exec is faked at the subprocess boundary). With OPENSHELL_WXC_EXEC_PATH set to an
MXC 1.0 wxc-exec on Windows, the last test runs the real gate (``--probe`` and a ``--dry-run``, never a
container).
"""
import base64
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from openshell.launcher import mxc as M
from openshell.launcher.driver import DriverUnavailable

PROBE_OK = {"tier": "base-container", "needsDaclAugmentation": False, "warnings": [],
            "probes": {"baseContainerApiPresent": True, "baseContainerSupportsDenyPaths": True,
                       "baseContainerSupportsIngressHostLoopbackAllow": True}}
UNSUPPORTED = ("Request error Configuration parse error: Unsupported contract version. Registered versions are: "
               "0.6.0-alpha, 0.7.0-alpha, 0.8.0-alpha, 0.9.0-alpha, 0.10.0-alpha")


@pytest.fixture
def fake_wxc(monkeypatch, tmp_path):
    """wxc-exec faked at the subprocess boundary; tweak ``state`` per test. Records every argv."""
    state = SimpleNamespace(version="1.0.0+3cddcbc2", probe=dict(PROBE_OK), dry_run=(0, "validation passed"), calls=[])

    def run(argv, **kwargs):
        state.calls.append(list(argv))
        if "--probe" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(state.probe), "")
        if "--dry-run" in argv:
            code, text = state.dry_run
            return subprocess.CompletedProcess(argv, code, text if code == 0 else "", "" if code == 0 else text)
        raise AssertionError(f"unexpected wxc-exec call {argv}")

    monkeypatch.setattr(M, "_on_windows", lambda: True)
    monkeypatch.setattr(M, "_file_version", lambda exe: state.version)
    monkeypatch.setattr(subprocess, "run", run)
    state.exe = tmp_path / "wxc-exec.exe"
    state.exe.write_bytes(b"")
    return state


def test_the_gate_accepts_mxc_1_0_on_a_base_container_host(fake_wxc):
    facts = M.preflight(fake_wxc.exe)
    assert facts["mxc_version"] == "1.0.0+3cddcbc2" and facts["schema"] == "1.0.0"
    assert facts["tier"] == "base-container" and facts["needs_dacl_augmentation"] is False
    dry = next(c for c in fake_wxc.calls if "--dry-run" in c)
    sent = json.loads(base64.b64decode(dry[dry.index("--config-base64") + 1]))
    assert sent["version"] == "1.0.0" and sent["fallback"] == {"allowDaclMutation": False}
    assert "--operation" not in dry


def test_the_gate_refuses_a_wxc_exec_older_than_mxc_1_0(fake_wxc):
    fake_wxc.version = "0.9.0+86fb3d2a"
    with pytest.raises(DriverUnavailable, match=r"MXC 0\.9\.0\+86fb3d2a, older than MXC 1\.0"):
        M.preflight(fake_wxc.exe)
    assert not any("--probe" in c for c in fake_wxc.calls)


def test_the_gate_refuses_a_build_that_rejects_the_1_0_0_contract(fake_wxc):
    # No version resource to go on: the dry run of a schema-1.0.0 request decides.
    fake_wxc.version, fake_wxc.dry_run = None, (1, UNSUPPORTED)
    with pytest.raises(DriverUnavailable, match=r"rejects MXC config version 1\.0\.0, so it predates MXC 1\.0"):
        M.preflight(fake_wxc.exe)


def test_the_gate_reports_any_other_dry_run_refusal(fake_wxc):
    fake_wxc.dry_run = (4294967295, '{"backend_error": "hostLoopback allow needs PSEC 1.1"}')
    with pytest.raises(DriverUnavailable, match=r"refused a schema-1\.0\.0 process-container request.*PSEC 1\.1"):
        M.preflight(fake_wxc.exe)


@pytest.mark.parametrize("value, shown", [(True, "needsDaclAugmentation true"), (None, "needsDaclAugmentation null"),
                                          ("missing", "needsDaclAugmentation missing")])
def test_the_gate_refuses_a_host_that_needs_dacl_augmentation(fake_wxc, value, shown):
    if value == "missing":
        fake_wxc.probe.pop("needsDaclAugmentation")
    else:
        fake_wxc.probe["needsDaclAugmentation"] = value
    with pytest.raises(DriverUnavailable, match=shown) as err:
        M.preflight(fake_wxc.exe)
    assert "rewriting host file permissions" in str(err.value)


def test_the_gate_demands_base_container_deny_and_loopback(fake_wxc):
    fake_wxc.probe["tier"] = "appcontainer"
    fake_wxc.probe["probes"]["baseContainerSupportsDenyPaths"] = False
    with pytest.raises(DriverUnavailable, match="containment tier is 'appcontainer'.*baseContainerSupportsDenyPaths"):
        M.preflight(fake_wxc.exe)


def test_the_gate_runs_on_windows_only(monkeypatch, tmp_path):
    monkeypatch.setattr(M, "_on_windows", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ran wxc-exec off Windows"))
    with pytest.raises(DriverUnavailable, match="Windows only"):
        M.preflight(tmp_path / "wxc-exec.exe")


def test_parse_version():
    assert M._parse_version("1.0.0+3cddcbc2") == (1, 0, 0) and M._parse_version("0.9.0") == (0, 9, 0)
    assert M._parse_version(None) is None and M._parse_version("dev") is None


@pytest.mark.skipif(sys.platform != "win32" or not os.environ.get("OPENSHELL_WXC_EXEC_PATH"),
                    reason="set OPENSHELL_WXC_EXEC_PATH to an MXC 1.0 wxc-exec to run against the real binary")
def test_the_gate_passes_with_a_real_wxc_exec():
    facts = M.preflight(os.environ["OPENSHELL_WXC_EXEC_PATH"])
    assert facts["schema"] == "1.0.0" and facts["needs_dacl_augmentation"] is False
    assert facts["tier"] == "base-container"
