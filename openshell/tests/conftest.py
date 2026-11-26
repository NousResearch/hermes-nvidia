"""Point every Hermes path at a throwaway root before any test module imports Hermes.

The shell that runs these tests is often a Hermes terminal, which exports HERMES_HOME as the user's
real Hermes root. A test that writes a profile's .env or the launcher's spec would then rewrite the
user's own files, so the override is unconditional and checked before the first test runs.

Every test also runs on a host the compatibility check (launcher/compat.py) passes, so switch and route
tests don't depend on the host's Windows build, wxc-exec or Docker. Tests of the check itself are
marked ``host_check`` and get the real one.
"""

import importlib
import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

import no_real_apps as _real_apps
import no_service_manager as _service_manager

# Before any test module imports Hermes: imports, collection and session fixtures start no program either.
_real_apps.install()
_service_manager.install()

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="openshell-tests-root-")).resolve()
os.environ["HERMES_HOME"] = str(_TEST_ROOT)
_PLUGIN_DIR = Path(__file__).resolve().parent.parent
# dashboard/plugin_api.py imports the plugin's modules under this package name (its _PKG).
_ROUTER_PKG = "hermes_openshell_settings"


def pytest_configure(config):
    config.addinivalue_line("markers", "host_check: run the real host compatibility check (launcher/compat.py)")


def pytest_sessionstart(session):
    from hermes_constants import get_default_hermes_root, get_hermes_home

    for name, path in (("HERMES_HOME", get_hermes_home()), ("Hermes root", get_default_hermes_root())):
        if not Path(path).resolve().is_relative_to(_TEST_ROOT):
            raise RuntimeError(f"{name} resolves to {path}, outside the test root {_TEST_ROOT}; refusing to run")


def compat_modules() -> list:
    """Every copy of launcher/compat.py the tests reach: the package's own, and the one the dashboard
    router imports under its own package name."""
    if _ROUTER_PKG not in sys.modules:
        pkg = types.ModuleType(_ROUTER_PKG)
        pkg.__path__ = [str(_PLUGIN_DIR)]
        pkg.__package__ = _ROUTER_PKG
        sys.modules[_ROUTER_PKG] = pkg
    return [importlib.import_module("openshell.launcher.compat"),
            importlib.import_module(f"{_ROUTER_PKG}.launcher.compat")]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    yield
    if call.when == "call":  # the test already failed on the spot: the fixture below reports only a swallowed stop
        item.stopped_at_a_real_app = call.excinfo is not None and call.excinfo.errisinstance(_real_apps.StartedRealApp)
        item.stopped_at_the_service_manager = (call.excinfo is not None
                                               and call.excinfo.errisinstance(_service_manager.ReachedServiceManager))


@pytest.fixture(autouse=True)
def real_apps_guard(request, monkeypatch):
    """No test starts the user's browser or another program of theirs (``no_real_apps``): ``webbrowser.open``,
    ``open_new``, ``open_new_tab``, ``get`` and ``os.startfile`` record the call and stop the test, and a call the
    code under test swallowed fails the test here."""
    guard = _real_apps.Guard().install(monkeypatch.setattr)
    yield guard
    if guard.calls and not getattr(request.node, "stopped_at_a_real_app", False):
        pytest.fail(guard.report(), pytrace=False)


@pytest.fixture(autouse=True)
def service_manager_guard(request):
    """No test reaches the computer's service manager (``no_service_manager``): a call that is about to run
    ``schtasks``, ``systemctl``, ``loginctl``, ``launchctl`` or the login service's console helper is recorded and
    stops the test before the program starts, and a stop the code under test swallowed fails the test here. A test
    that gives the switch a manager of its own, or a manager a runner of its own, never gets that far."""
    guard = _service_manager.Guard()
    _service_manager.RUNNING.append(guard)
    try:
        yield guard
    finally:
        _service_manager.RUNNING.remove(guard)
    if guard.calls and not getattr(request.node, "stopped_at_the_service_manager", False):
        pytest.fail(guard.report(), pytrace=False)


@pytest.fixture(autouse=True)
def _no_download_from_another_computer(monkeypatch):
    """The installer's downloader fetches from this computer only: a test's own loopback server. A test that
    reaches it with any other address is stopped before a request is made."""
    import urllib.parse

    compat_modules()  # Registers the dashboard router's package name
    for name in ("openshell.launcher.openshell_install", f"{_ROUTER_PKG}.launcher.openshell_install"):
        module = importlib.import_module(name)

        def download(url, dest, *args, _real=module._download, **kwargs):
            host = urllib.parse.urlsplit(str(url)).hostname or ""
            if host not in ("127.0.0.1", "localhost", "::1"):
                raise AssertionError(f"a test must not download from another computer: {url}")
            return _real(url, dest, *args, **kwargs)

        monkeypatch.setattr(module, "_download", download)


COMPATIBLE = {"ok": True, "platform": "test", "code": "ok", "reason": None, "action": None, "detail": None,
              "facts": {}, "checked_at": 0.0}


@pytest.fixture(autouse=True)
def _compatible_host(request, monkeypatch):
    if request.node.get_closest_marker("host_check"):
        for mod in compat_modules():
            monkeypatch.setattr(mod, "_cache", {})
        return
    for mod in compat_modules():
        monkeypatch.setattr(mod, "check", lambda wxc_exec=None, *, refresh=False: dict(COMPATIBLE))


@pytest.fixture(autouse=True)
def _x64_windows_installs(request, monkeypatch):
    """The installer picks the Windows build for the machine's architecture; tests get the x64 build whatever PC
    runs them (Arm64 tests set ``openshell_install.windows_arch`` themselves)."""
    if request.node.get_closest_marker("host_check"):
        return
    compat_modules()  # registers the dashboard router's package name
    for name in ("openshell.launcher.openshell_install", f"{_ROUTER_PKG}.launcher.openshell_install"):
        monkeypatch.setattr(importlib.import_module(name), "windows_arch", lambda: "x86_64")
