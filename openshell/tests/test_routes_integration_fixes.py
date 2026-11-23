"""Two route contracts:

* ``events`` serves a stopped sandbox's saved audit log: the route asks the driver, which answers from
  its archive, or says NotSupported (409) where it kept none.
* The dashboard router (an unsandboxed profile's page) reports the capabilities of the driver the
  launcher would use: the OpenShell Windows driver on Windows.
"""
import asyncio
import importlib.util
import json
import types
from pathlib import Path

import pytest

from openshell.launcher import host_routes as HR
from openshell.launcher.driver import NotSupported, SandboxDriver
from openshell.launcher.layout import ProfileLayout
from openshell.launcher.proxy import parse_head

PLUGIN_DIR = Path(__file__).resolve().parent.parent
ARCHIVED = [{"time": 1700000000.0, "class": "NET", "action": "DENIED", "message": "example.com:443", "ocsf": True}]


class ArchiveDriver(SandboxDriver):
    """Audit events from a saved log whether or not the sandbox runs (like the Linux driver's archive)."""

    name = "fake-archive"
    capabilities_info = {"label": "Fake", "requests_supported": True, "credentials": "placeholders",
                         "host_loopback": "open", "audit_events": True}

    def __init__(self, archive=True):
        self.archive = archive
        self.calls = []

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return -1

    def stop(self, timeout=20.0):
        pass

    def policy(self):
        return {}

    def events(self, *, since=None, until=None, limit=200, classes=()):
        self.calls.append({"since": since, "limit": limit, "classes": classes})
        if not self.archive:
            raise NotSupported("the sandbox is not running")
        return [e for e in ARCHIVED if not classes or e["class"] in classes][-limit:]

    def proposals(self, status="pending"):
        raise AssertionError("never asked while stopped")


class StoppedSup:
    def __init__(self, driver, layout):
        self.driver, self.layout, self.state = driver, layout, "stopped"
        self.outer_port = 47999

    def running(self):
        return False


def _req(path):
    return parse_head(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())


def _routes(tmp_path, driver):
    root = tmp_path / "root"
    layout = ProfileLayout(name="work", home=root / "profiles" / "work", root=root)
    return HR.HostRoutes(StoppedSup(driver, layout), lambda: None)


def _get(routes, path):
    handler = routes.match("GET", path.split("?")[0])
    return asyncio.run(handler(_req(path), b""))


def test_events_serve_the_saved_audit_log_when_the_sandbox_is_stopped(tmp_path):
    driver = ArchiveDriver()
    code, payload, _ = _get(_routes(tmp_path, driver), "/api/plugins/openshell/events?class=NET&limit=50")
    assert code == 200 and payload["events"] == ARCHIVED
    assert driver.calls == [{"since": None, "limit": 50, "classes": ("NET",)}]


def test_events_without_a_saved_log_answer_409_from_the_driver(tmp_path):
    code, payload, _ = _get(_routes(tmp_path, ArchiveDriver(archive=False)), "/api/plugins/openshell/events")
    assert code == 409 and "not running" in payload["detail"]


def test_live_only_enforcer_routes_still_need_a_running_sandbox(tmp_path):
    code, payload, _ = _get(_routes(tmp_path, ArchiveDriver()), "/api/plugins/openshell/proposals")
    assert code == 409 and payload["detail"] == "The sandbox is not running."


# -- the dashboard router's capabilities --------------------------------------------------------

def _plugin_api():
    spec = importlib.util.spec_from_file_location("openshell_plugin_api_caps", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("spec", [{}, {"driver": "openshell"}])
def test_dashboard_capabilities_are_the_openshell_windows_drivers_on_windows(monkeypatch, spec):
    api = _plugin_api()
    monkeypatch.setattr(api, "os", types.SimpleNamespace(name="nt"))
    caps = api._capabilities(spec)
    assert caps["driver"] == "openshell" and caps["label"] == "OpenShell sandbox (Windows)"
    assert caps["credentials"] == "placeholders"
    assert caps["egress_allow_all"] is False and caps["audit_events"] is True


def test_dashboard_status_reports_the_openshell_windows_driver(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api = _plugin_api()
    monkeypatch.setattr(api, "os", types.SimpleNamespace(name="nt"))
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/openshell")
    st = TestClient(app).get("/api/plugins/openshell/status").json()
    assert st["driver"] == "openshell" and st["capabilities"]["label"] == "OpenShell sandbox (Windows)"
    assert json.dumps(st["capabilities"]).count("wxc") == 0
