"""The launcher runs as a windowless logon task on Windows. Every console program it starts must be
started without a console window, or each call opens a terminal window on the user's desktop."""
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from openshell.launcher import login_service, openshell_windows
from openshell.launcher.openshell_windows import CliGateway

pytestmark = pytest.mark.skipif(os.name != "nt", reason="console windows are a Windows behavior")


class _Cfg:
    cli = Path("C:/openshell/openshell.exe")
    config_home = Path("C:/openshell/xdg")
    gateway = "hermes-test"
    workspace = "default"


def test_cli_calls_open_no_console_window():
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    CliGateway(_Cfg(), run=fake_run).run("status")
    assert seen.get("creationflags", 0) & subprocess.CREATE_NO_WINDOW


def test_every_subprocess_call_in_windows_paths_hides_its_window():
    # A guard against new call sites: the Windows driver, the MXC gate and the host check pass the flag everywhere.
    root = Path(openshell_windows.__file__).parent
    for name in ("openshell_windows.py", "mxc.py", "compat.py"):
        text = (root / name).read_text(encoding="utf-8")
        for marker in ("subprocess.run(", "self._popen(cmd"):
            for chunk in text.split(marker)[1:]:
                assert "_NO_WINDOW" in chunk[:400], f"{name}: {marker} without _NO_WINDOW: {chunk[:120]!r}"


def test_the_signature_check_starts_no_program():
    # The installer asks Windows for each file's signature inside the launcher's own process (WinVerifyTrust
    # through ctypes): nothing is started, so there is no window to hide.
    from openshell.launcher import authenticode, openshell_install

    text = Path(authenticode.__file__).read_text(encoding="utf-8")
    for word in ("subprocess", "Popen", "os.system", "os.startfile", "powershell", "ShellExecute", "CreateProcess"):
        assert word not in text, f"authenticode.py mentions {word}"
    assert "WinVerifyTrust" in text and "_WTD_UI_NONE" in text
    installer = Path(openshell_install.__file__).read_text(encoding="utf-8")
    check = installer.split("def _check_publisher(")[1].split("\ndef ")[0]
    assert "authenticode.signature(" in check and "run(" not in check and "subprocess" not in check


def _service(tmp_path, bootstrap: str) -> tuple[Path, Path, Path]:
    """A login-service folder whose 'hermes_cli.main' is a stand-in that records the console it runs with."""
    fake = tmp_path / "fake" / "hermes_cli"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "main.py").write_text(
        "import ctypes, json, sys\n"
        "k32 = ctypes.windll.kernel32\n"
        "with open(sys.argv[1], 'w', encoding='utf-8') as fh:\n"
        "    json.dump({'console_cp': k32.GetConsoleCP(), 'console_hwnd': k32.GetConsoleWindow() or 0}, fh)\n",
        encoding="utf-8")
    folder = tmp_path / "service"
    folder.mkdir()
    out = tmp_path / "facts.json"
    (folder / login_service.BOOTSTRAP_FILE).write_text(bootstrap, encoding="utf-8")
    (folder / login_service.SERVICE_FILE).write_text(json.dumps({
        "env": {"PYTHONPATH": str(tmp_path / "fake")}, "cwd": str(tmp_path), "args": [str(out)],
        "log": str(tmp_path / "launcher.log")}), encoding="utf-8")
    return folder / login_service.BOOTSTRAP_FILE, folder / login_service.SERVICE_FILE, out


def test_the_windowless_launcher_shares_a_console_that_has_no_window(tmp_path):
    # The login task runs the bootstrap under pythonw (no console). Hermes code in the launcher starts console
    # programs without CREATE_NO_WINDOW (git, for one); each would open a Windows Terminal window unless the
    # launcher already has a console of its own, which they inherit. That console must have no window.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.is_file():
        pytest.skip("no pythonw.exe beside the test interpreter")
    boot, cfg, out = _service(tmp_path, login_service.BOOTSTRAP)
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONPATH"}
    subprocess.run([str(pythonw), str(boot), str(cfg)], env=env, timeout=120, check=False)
    facts = json.loads(out.read_text(encoding="utf-8"))
    assert facts["console_cp"], "the launcher runs without a console: every console program it starts opens a window"
    hwnd = facts["console_hwnd"]
    assert not hwnd or not ctypes.windll.user32.IsWindowVisible(hwnd), "the launcher's console has a visible window"
    assert "without a hidden console" not in (tmp_path / "launcher.log").read_text(encoding="utf-8")
