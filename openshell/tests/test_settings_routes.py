"""Behaviour tests for the sandbox settings routes: the launcher's host routes and the dashboard router
the host ``hermes serve`` mounts for an unsandboxed profile.

Edits are validated on the host and saved to the host-only spec; a running sandbox keeps the policy it
started with (``applied``) until a restart, and the page reads both back. A fake driver stands in for
MXC: it serves ``/api/health`` on the inner port the supervisor picks, so start and restart run the
real supervisor code.

Run: PYTHONPATH="<hermes checkout>;<this repo>" <hermes python> -m pytest openshell/tests -q
"""
import asyncio
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


import pytest  # noqa: E402

from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher.driver import SandboxDriver  # noqa: E402
from openshell.launcher.host_routes import HostRoutes  # noqa: E402
from openshell.launcher.proxy import parse_head  # noqa: E402
from openshell.launcher.settings_view import endpoint_reach  # noqa: E402
from openshell.launcher.spec import load_spec, save_spec  # noqa: E402
from openshell.launcher.supervisor import Supervisor  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parent.parent
REQ = parse_head(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/api/health" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class FakeDriver(SandboxDriver):
    """Answers the supervisor's readiness probe on the inner port; records each launch request."""

    name = "fake"
    capabilities_info = {"label": "Fake", "requests_supported": False, "credentials": "environment",
                         "host_loopback": "open"}

    def __init__(self):
        self.server = None
        self.requests = []

    def preflight(self):
        return {}

    def start(self, request):
        port = int(request.argv[request.argv.index("--port") + 1])
        self.server = ThreadingHTTPServer(("127.0.0.1", port), _Health)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.requests.append(request)

    def exit_code(self):
        return None if self.server else -1

    def stop(self, timeout=20.0):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def policy(self):
        return {}


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A user home with credential folders, so refusals are tested against real directories."""
    home = tmp_path / "user"
    for rel in (".ssh", "AppData/Roaming/Microsoft/Credentials", "projects/app", "reference"):
        (home / rel).mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


def _layout(tmp_path, llm_url="http://127.0.0.1:5999/v1") -> L.ProfileLayout:
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text(f"model:\n  provider: custom\n  base_url: {llm_url}\n", encoding="utf-8")
    return L.ProfileLayout(name="work", home=home, root=root)


def _runtime(tmp: Path) -> L.Runtime:
    for d in ("code", "env", "base"):
        (tmp / d).mkdir(parents=True, exist_ok=True)
    return L.Runtime(python=tmp / "env" / "python.exe", code_dir=tmp / "code", env_dir=tmp / "env",
                     base_python=tmp / "base", store=None)


def _supervisor(tmp_path, layout, folders=()):
    spec = load_spec(layout)
    spec["folders"] = [{"path": str(p), "access": a} for p, a in folders]
    spec["busybox"] = None
    save_spec(layout, spec)
    driver = FakeDriver()
    sup = Supervisor(layout, _runtime(tmp_path), load_spec(layout), driver, outer_port=1)
    sup._busybox = lambda: None  # no shell in the fake sandbox
    return sup


def _call(routes, method, path, body=None):
    handler = routes.match(method, "/api/plugins/openshell/" + path)
    raw = b"" if body is None else json.dumps(body).encode()
    return asyncio.run(handler(REQ, raw)) if handler else (404, None, {})


def _saved_on_disk(layout):
    return load_spec(layout)


# --- folder and network validation (host-side, whatever the client checked) ------------------------

def test_put_folders_refuses_broad_and_credential_folders_and_leaves_the_spec(tmp_path, fake_home):
    layout = _layout(tmp_path)
    routes = HostRoutes(_supervisor(tmp_path, layout), lambda: None)
    before = layout.spec_path.read_bytes()
    drive_root = Path(fake_home.anchor)
    for bad in (fake_home, drive_root, fake_home.parent, layout.root, layout.home, fake_home / ".ssh",
                fake_home / "AppData" / "Roaming" / "Microsoft" / "Credentials", fake_home / "AppData",
                tmp_path / "missing", "relative/dir"):
        status, payload, _ = _call(routes, "PUT", "folders", {"folders": [{"path": str(bad), "access": "ro"}]})
        assert status == 422, (bad, payload)
        assert payload["detail"]
    assert layout.spec_path.read_bytes() == before
    status, payload, _ = _call(routes, "PUT", "folders", {"folders": [{"path": str(fake_home / "x"), "access": "admin"}]})
    assert status == 422


def test_folder_and_destination_checks_answer_without_saving(tmp_path, fake_home):
    layout = _layout(tmp_path)
    routes = HostRoutes(_supervisor(tmp_path, layout), lambda: None)
    status, payload, _ = _call(routes, "POST", "folders/check", {"path": str(fake_home / "projects" / "app"), "access": "rw"})
    assert status == 200 and payload == {"path": str((fake_home / "projects" / "app").resolve()), "access": "rw"}
    assert _saved_on_disk(layout)["folders"] == []
    status, payload, _ = _call(routes, "POST", "folders/check", {"path": str(fake_home), "access": "ro"})
    assert status == 422 and "home folder" in payload["detail"]
    status, payload, _ = _call(routes, "POST", "network/check", {"cidr": "203.0.113.9", "port": "443"})
    assert status == 200 and payload == {"cidr": "203.0.113.9/32", "port": 443}
    status, payload, _ = _call(routes, "POST", "network/check", {"cidr": "203.0.113.9", "port": 70000})
    assert status == 422 and "Port" in payload["detail"]
    assert _saved_on_disk(layout)["network"] == {"egress": "deny", "allow": []}


def test_put_network_normalizes_rules_and_refuses_bad_ones(tmp_path, fake_home):
    layout = _layout(tmp_path)
    routes = HostRoutes(_supervisor(tmp_path, layout), lambda: None)
    status, payload, _ = _call(routes, "PUT", "network", {"egress": "deny", "allow": [
        {"cidr": "192.0.2.10", "port": 5999}, {"cidr": "10.1.2.7/24", "port": "443"}, {"cidr": "192.0.2.10/32", "port": 5999}]})
    assert status == 200
    want = {"egress": "deny", "allow": [{"cidr": "192.0.2.10/32", "port": 5999}, {"cidr": "10.1.2.0/24", "port": 443}]}
    assert payload["network"] == want and _saved_on_disk(layout)["network"] == want
    for bad in ({"egress": "sometimes", "allow": []}, {"egress": "deny", "allow": [{"cidr": "example.com", "port": 443}]},
                {"egress": "deny", "allow": [{"cidr": "10.0.0.1", "port": 0}]},
                {"egress": "deny", "allow": [{"cidr": "10.0.0.1", "port": True}]}):
        status, _, _ = _call(routes, "PUT", "network", bad)
        assert status == 422, bad
    assert _saved_on_disk(layout)["network"] == want


def test_loopback_destinations_are_refused_where_every_loopback_port_is_reachable(tmp_path, fake_home):
    # FakeDriver reports host_loopback "open", as MXC does: a loopback rule would limit nothing.
    layout = _layout(tmp_path)
    routes = HostRoutes(_supervisor(tmp_path, layout), lambda: None)
    for cidr in ("127.0.0.1", "127.0.0.0/8", "::1"):
        status, payload, _ = _call(routes, "POST", "network/check", {"cidr": cidr, "port": 5999})
        assert status == 422 and "Loopback" in payload["detail"], cidr
        status, _, _ = _call(routes, "PUT", "network", {"egress": "deny", "allow": [{"cidr": cidr, "port": 5999}]})
        assert status == 422, cidr
    assert _saved_on_disk(layout)["network"] == {"egress": "deny", "allow": []}


# --- applied vs saved ----------------------------------------------------------------------------------

def test_saved_edits_pend_until_restart_and_status_reports_both(tmp_path, fake_home):
    projects, reference = fake_home / "projects" / "app", fake_home / "reference"
    layout = _layout(tmp_path)
    sup = _supervisor(tmp_path, layout, folders=[(projects.resolve(), "rw")])
    routes = HostRoutes(sup, lambda: None)

    async def scenario():
        await sup.start()
        try:
            st = sup.status()
            assert st["sandboxed"] and st["state"] == "running" and not st["restart_required"]
            assert st["applied"] == st["saved"]
            started = st["applied"]

            status, cfg, _ = await routes.match("PUT", "/api/plugins/openshell/folders")(REQ, json.dumps({"folders": [
                {"path": str(projects), "access": "rw"}, {"path": str(reference), "access": "ro"}]}).encode())
            assert status == 200 and cfg["restart_required"]
            st = sup.status()
            assert st["pending"] == {"folders": True, "network": False, "keys": False}
            assert st["applied"] == started and len(st["saved"]["folders"]) == 2

            # Putting the running policy back clears the pending flag: it is a diff, not a latch.
            await routes.match("PUT", "/api/plugins/openshell/folders")(REQ, json.dumps(
                {"folders": [{"path": str(projects), "access": "rw"}]}).encode())
            assert not sup.status()["restart_required"]

            await routes.match("PUT", "/api/plugins/openshell/network")(REQ, json.dumps(
                {"egress": "deny", "allow": [{"cidr": "192.0.2.10", "port": 5999}]}).encode())
            assert sup.status()["pending"]["network"]

            status, st, _ = await routes.match("POST", "/api/plugins/openshell/restart")(REQ, b"")
            assert status == 200 and st["state"] == "running" and not st["restart_required"]
            assert st["applied"]["network"]["allow"] == [{"cidr": "192.0.2.10/32", "port": 5999}]
            assert sup.driver.requests[-1].network == st["applied"]["network"]
        finally:
            await sup.stop()
        assert sup.status()["applied"] is None and not sup.status()["restart_required"]

    asyncio.run(scenario())


def test_config_carries_capabilities_and_model_endpoint_reach(tmp_path, fake_home):
    layout = _layout(tmp_path)
    routes = HostRoutes(_supervisor(tmp_path, layout), lambda: None)
    status, cfg, _ = _call(routes, "GET", "config")
    assert status == 200 and cfg["sandboxed"] and cfg["profile_folder"] == str(layout.home)
    assert cfg["capabilities"] == {"driver": "fake", "label": "Fake", "requests_supported": False,
                                   "credentials": "environment", "host_loopback": "open"}
    (endpoint,) = cfg["endpoints"]
    assert endpoint["url"] == "http://127.0.0.1:5999/v1" and endpoint["reach"] == "allowed"
    assert endpoint["via"] == "loopback"  # MXC host loopback is open whatever the egress rules say


@pytest.mark.parametrize("url, network, want", [
    ("https://10.1.2.3/v1", {"egress": "deny", "allow": []}, ("blocked", None)),
    ("https://10.1.2.3/v1", {"egress": "deny", "allow": [{"cidr": "10.1.2.0/24", "port": 443}]}, ("allowed", "rule")),
    ("https://10.1.2.3/v1", {"egress": "deny", "allow": [{"cidr": "10.1.2.0/24", "port": 8443}]}, ("blocked", None)),
    ("https://api.example.test/v1", {"egress": "deny", "allow": [{"cidr": "10.1.2.0/24", "port": 443}]}, ("allowed", "rule")),
    ("https://api.example.test/v1", {"egress": "allow", "allow": []}, ("allowed", "internet")),
    ("http://127.0.0.1:5999/v1", {"egress": "deny", "allow": []}, ("blocked", None)),
])
def test_endpoint_reach(url, network, want):
    resolve = {"api.example.test": ["10.1.2.9"]}.get
    assert endpoint_reach(url, network, {"host_loopback": "closed"}, lambda h: resolve(h) or []) == want


# --- keys: names only ------------------------------------------------------------------------------------

def test_keys_list_names_only_and_writes_flag_a_restart(tmp_path):
    from hermes_constants import get_hermes_home

    home = get_hermes_home()
    home.mkdir(parents=True, exist_ok=True)
    secret = "sk-test-" + "q" * 24
    (home / ".env").write_text(f"TEST_SETTINGS_KEY={secret}\n", encoding="utf-8")
    layout = L.ProfileLayout(name="default", home=home, root=home)
    sup = Supervisor(layout, _runtime(tmp_path), load_spec(layout), FakeDriver(), outer_port=1)
    sup.applied = {"folders": [], "network": {"egress": "deny", "allow": []}}  # as if running
    routes = HostRoutes(sup, lambda: None)
    status, payload, _ = _call(routes, "GET", "keys")
    assert status == 200 and {"name": "TEST_SETTINGS_KEY", "is_set": True} in payload["keys"]
    assert payload["credentials"] == "environment"
    assert secret not in json.dumps(payload) and "redacted_value" not in json.dumps(payload)
    status, payload, extra = _call(routes, "PUT", "keys", {"key": "TEST_OTHER_KEY", "value": "v-" + "z" * 20})
    assert status == 200 and payload == {"ok": True, "sandbox_restart_required": True, "sandbox": "after_restart"}
    assert extra.get("X-Hermes-Sandbox-Restart-Required") == "1"
    assert "TEST_OTHER_KEY=" in (home / ".env").read_text(encoding="utf-8")
    assert sup.status()["pending"]["keys"] and sup.status()["restart_required"]
    status, _, _ = _call(routes, "DELETE", "keys", {"key": "TEST_OTHER_KEY"})
    assert status == 200 and "TEST_OTHER_KEY=" not in (home / ".env").read_text(encoding="utf-8")


# --- the host backend's router for an unsandboxed profile -----------------------------------------------

def _plugin_api():
    spec = importlib.util.spec_from_file_location("openshell_plugin_api_under_test", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_dashboard_router_serves_the_saved_spec_for_an_unsandboxed_profile(fake_home):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hermes_constants import get_default_hermes_root

    app = FastAPI()
    app.include_router(_plugin_api().router, prefix="/api/plugins/openshell")
    client = TestClient(app)
    st = client.get("/api/plugins/openshell/status").json()
    assert st["sandboxed"] is False and st["state"] == "off" and st["applied"] is None
    assert client.put("/api/plugins/openshell/folders", json={"folders": [{"path": str(fake_home), "access": "ro"}]}).status_code == 422
    ok = client.put("/api/plugins/openshell/folders", json={"folders": [{"path": str(fake_home / "reference"), "access": "ro"}]})
    assert ok.status_code == 200 and ok.json()["folders"][0]["access"] == "ro" and not ok.json()["sandboxed"]
    saved = get_default_hermes_root() / "openshell" / st["profile"] / "spec.yaml"
    assert "reference" in saved.read_text(encoding="utf-8")
    net = client.put("/api/plugins/openshell/network", json={"egress": "allow", "allow": []})
    if st["capabilities"].get("egress_allow_all", True):
        assert net.status_code == 200 and net.json()["network"]["egress"] == "allow"
    else:  # OpenShell drivers have no all-internet egress: refused, never saved as a limit nobody enforces
        assert net.status_code == 422 and "egress: allow" not in saved.read_text(encoding="utf-8")
    assert client.get("/api/plugins/openshell/restart").status_code in (404, 405)  # nothing to restart here


def test_dashboard_router_lists_and_removes_hosts_saved_from_chat_cards(fake_home):
    """Unsandboxed, the Sandbox page's "Allowed from chat" shows hosts saved with Always allow (Allow grants
    end with the sandbox) and removes them from the stored policy."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from openshell.launcher import cards as C
    from openshell.launcher.layout import current_profile
    from openshell.launcher.spec import load_spec, network_policy, update_spec

    app = FastAPI()
    app.include_router(_plugin_api().router, prefix="/api/plugins/openshell")
    client = TestClient(app)
    assert client.get("/api/plugins/openshell/grants").json()["grants"] == []
    layout = current_profile()
    rule = C.host_rule("example.com", (80, 443))
    update_spec(layout, network={**network_policy(load_spec(layout)), "approved": {rule["name"]: rule}})
    [row] = client.get("/api/plugins/openshell/grants").json()["grants"]
    assert row["id"] == "network:always:example.com" and row["ports"] == [80, 443] and row["scope"] == "always"
    assert client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:allow:example.com"}).status_code == 404
    done = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": row["id"]})
    assert done.status_code == 200 and done.json()["grants"] == []
    assert "approved" not in network_policy(load_spec(layout))
