"""The Activity tab's backend (launcher/activity.py): the Windows audit collector, the merged timeline
(OpenShell audit, refused file accesses from Hermes's tool results, card decisions) and the OCSF export.

Run: PYTHONPATH="<hermes checkout>;<this repo>" <hermes python> -m pytest openshell/tests -q
"""
import asyncio
import importlib.util
import json
import sqlite3
import time
from pathlib import Path

import pytest

from openshell.launcher import activity as A
from openshell.launcher import layout as L
from openshell.launcher.driver import NotSupported, SandboxDriver
from openshell.launcher.host_routes import HostRoutes
from openshell.launcher.openshell_driver import parse_event
from openshell.launcher.proxy import parse_head

PY = r"C:\hermes\tools\python-3.14\python.exe"
T0 = 1_793_050_000.0


def line(t, msg):
    """One `openshell logs` line as the Windows driver parses it."""
    return parse_event({"time": t, "source": "sandbox", "level": "OCSF", "target": "ocsf", "message": msg, "fields": {}})


DENIED = f"NET:OPEN [MED] DENIED {PY}(0) -> api.github.com:443 [policy:- engine:opa] [reason:endpoint api.github.com:443 is not allowed by any policy]"
HTTP_L7 = f"HTTP:POST [INFO] ALLOWED {PY}(0) -> POST http://host.openshell.internal:8081/v1/chat/completions [policy:_provider_model engine:l7]"
HTTP_OPA = f"HTTP:POST [INFO] ALLOWED {PY}(0) -> POST http://host.openshell.internal:8081/v1/chat/completions [policy:_provider_model engine:opa]"
RELAY = "NET:OPEN [INFO] 127.0.0.1:54319/tcp"
LOADED = "CONFIG:LOADED [INFO] Policy reloaded successfully [policy_hash:abc] [hash:abc]"
NOISE_CONFIG = "CONFIG:ENABLED [INFO] TLS termination enabled: ephemeral CA generated"


class WinDriver(SandboxDriver):
    """Like the OpenShell Windows driver: audit events from the gateway's tail, nothing kept after stop."""

    name = "openshell"
    capabilities_info = {"label": "OpenShell sandbox (Windows)", "requests_supported": True,
                         "credentials": "placeholders", "host_loopback": "open", "audit_events": True,
                         "policy_revisions": True}

    def __init__(self):
        self.lines: list = []
        self.calls: list = []
        self._name = "hermes-work"
        self.running = True

    def preflight(self):
        return {}

    def start(self, request):
        pass

    def exit_code(self):
        return None if self.running else 0

    def stop(self, timeout=20.0):
        self.calls.append("stop")
        self.running = False

    def policy(self):
        return {}

    def events(self, *, since=None, until=None, limit=200, classes=()):
        if not self.running:
            raise NotSupported("the sandbox is not running")
        self.calls.append(("events", since))
        return [e for e in self.lines if since is None or e["time"] >= since][-limit:]


class LinuxDriver(WinDriver):
    """Like the Linux driver: it archives its own audit (``audit_records``)."""

    def audit_records(self, **kw):
        return []


class FakeSup:
    def __init__(self, layout, driver):
        self.layout, self.driver = layout, driver
        self.state = "running"
        self._started_at = T0

    def running(self):
        return self.state == "running" and self.driver.exit_code() is None


@pytest.fixture
def work_profile(tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = L.ProfileLayout(name="work", home=home, root=root)
    layout.state_dir.mkdir(parents=True)
    return layout


def make_db(home: Path, rows: list[tuple]):
    """A state.db with the columns activity.py reads. rows: (session, role, ts, content, tool_call_id,
    tool_name, tool_calls)."""
    con = sqlite3.connect(home / "state.db")
    con.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, started_at REAL, title TEXT)")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, role TEXT, content TEXT, "
                "tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL)")
    for sid, title in {(r[0], f"Chat {r[0]}") for r in rows}:
        con.execute("INSERT INTO sessions VALUES (?, 'desktop', ?, ?)", (sid, T0, title))
    for sid, role, ts, content, call_id, tool_name, tool_calls in rows:
        con.execute("INSERT INTO messages (session_id, role, content, tool_call_id, tool_calls, tool_name, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", (sid, role, content, call_id, tool_calls, tool_name, ts))
    con.commit()
    con.close()


def call(cid, name, args):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


# -- shorthand -> OCSF --------------------------------------------------------------------------------

def test_shorthand_converts_to_the_ocsf_class_openshell_uses():
    rec = A.ocsf_from_shorthand(line(T0, DENIED), "hermes-work")
    assert (rec["class_uid"], rec["activity_id"], rec["type_uid"]) == (4001, 1, 400101)
    assert (rec["action_id"], rec["disposition"], rec["status"]) == (2, "Blocked", "Failure")
    assert rec["dst_endpoint"] == {"domain": "api.github.com", "port": 443}
    assert rec["actor"]["process"]["name"] == PY
    assert rec["status_detail"] == "endpoint api.github.com:443 is not allowed by any policy"
    assert rec["firewall_rule"] == {"name": "-", "type": "opa"}
    assert rec["time"] == int(T0 * 1000) and rec["metadata"]["version"] == "1.8.0"
    assert rec["unmapped"]["shorthand"] == DENIED and rec["container"]["name"] == "hermes-work"

    http = A.ocsf_from_shorthand(line(T0, HTTP_L7), "hermes-work")
    assert (http["class_uid"], http["activity_id"], http["action"]) == (4002, 6, "Allowed")
    assert http["http_request"]["http_method"] == "POST"
    assert http["http_request"]["url"]["hostname"] == "host.openshell.internal"
    assert http["http_request"]["url"]["port"] == 8081 and http["http_request"]["url"]["path"] == "/v1/chat/completions"
    relay = A.ocsf_from_shorthand(line(T0, RELAY), "hermes-work")
    assert relay["dst_endpoint"] == {"ip": "127.0.0.1", "port": 54319} and "action_id" not in relay
    # the same line gives the same uid (dedupe across polls and launcher restarts)
    assert A.ocsf_from_shorthand(line(T0, DENIED), "x")["metadata"]["uid"] == rec["metadata"]["uid"]


# -- the collector ----------------------------------------------------------------------------------------

def test_collector_archives_new_events_once_and_survives_a_launcher_restart(work_profile):
    drv = WinDriver()
    drv.lines = [line(T0 + 1, RELAY), line(T0 + 2, DENIED)]
    sup = FakeSup(work_profile, drv)
    col = A.AuditCollector(sup, work_profile, clock=lambda: T0 + 5)
    assert col.collects
    col._open_run()
    assert col.poll() == 2
    assert col.poll() == 0  # the overlap re-reads, nothing is written twice
    drv.lines.append(line(T0 + 3, HTTP_L7))
    assert col.poll() == 1
    files = sorted((work_profile.state_dir / "audit").glob("ocsf-hermes-work-*.jsonl"))
    assert len(files) == 1
    assert [json.loads(x)["class_uid"] for x in files[0].read_text(encoding="utf-8").splitlines()] == [4001, 4001, 4002]
    # a new launcher re-reads the gateway's tail without duplicating it
    again = A.AuditCollector(FakeSup(work_profile, WinDriver()), work_profile, clock=lambda: T0 + 9)
    again._sup.driver.lines = list(drv.lines)
    again._open_run()
    assert again.poll() == 0


def test_stopping_the_sandbox_drains_the_tail_first_and_records_the_run(work_profile):
    drv = WinDriver()
    sup = FakeSup(work_profile, drv)
    clock = [T0 + 1]
    col = A.AuditCollector(sup, work_profile, clock=lambda: clock[0])
    col._open_run()
    drv.lines = [line(T0 + 2, DENIED)]  # arrives after the last regular poll
    clock[0] = T0 + 10
    drv.stop()  # what the supervisor calls (wrapped by the collector)
    assert drv.calls[-1] == "stop" and drv.calls[-2][0] == "events"  # polled before the sandbox went away
    assert len(A.network_rows(work_profile.state_dir, None, None)) == 1
    assert A.runs(work_profile.state_dir) == [{"start": T0, "end": T0 + 10, "sandbox": "hermes-work", "driver": "openshell"}]


def test_a_driver_that_archives_its_own_audit_is_not_polled(work_profile):
    drv = LinuxDriver()
    col = A.AuditCollector(FakeSup(work_profile, drv), work_profile, clock=lambda: T0 + 1)
    assert not col.collects
    col._open_run()
    assert col.poll() == 0 and not any(c for c in drv.calls if c != "stop")
    # its supervisor's full OCSF records (Linux archive) read the same way
    rec = {"class_uid": 4002, "activity_id": 3, "activity_name": "Get", "time": int((T0 + 2) * 1000),
           "action_id": 2, "action": "Denied", "http_request": {"http_method": "GET", "url": {
               "hostname": "example.com", "path": "/x", "port": 443}}, "dst_endpoint": {"domain": "example.com", "port": 443},
           "actor": {"process": {"name": "/usr/bin/curl", "pid": 9}}, "metadata": {"uid": "u-1"}}
    (work_profile.state_dir / "audit").mkdir()
    (work_profile.state_dir / "audit" / "ocsf-hermes-work-2026-10-26.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    rows = A.network_rows(work_profile.state_dir, None, None)
    assert [(r["title"], r["outcome"], r["program"]) for r in rows] == [("GET example.com/x", "denied", "curl")]


# -- the timeline -------------------------------------------------------------------------------------------

def seed(work_profile, *, folder):
    """One sandbox run with: a refused read, an allowed write, a blocked host carded and allowed, a denial."""
    runs = work_profile.state_dir / "activity" / "runs.jsonl"
    runs.parent.mkdir(parents=True, exist_ok=True)
    runs.write_text(json.dumps({"event": "start", "t": T0, "sandbox": "hermes-work", "driver": "openshell"}) + "\n"
                    + json.dumps({"event": "stop", "t": T0 + 100}) + "\n", encoding="utf-8")
    secret = folder / "outside" / "secret.txt"
    secret.parent.mkdir(parents=True)
    secret.write_text("x", encoding="utf-8")
    hello = folder / "projects" / "hello.txt"
    calls = json.dumps([call("c1", "terminal", {"command": f'cat "{secret.as_posix()}"'}),
                        call("c2", "write_file", {"path": str(hello), "content": "hi"})])
    make_db(work_profile.home, [
        ("chat-a", "user", T0 + 10, "read it and write hello", None, None, None),
        ("chat-a", "assistant", T0 + 11, "", None, None, calls),
        ("chat-a", "tool", T0 + 12, json.dumps({"output": f"cat: can't open '{secret.as_posix()}': Permission denied",
                                                 "exit_code": 1}), "c1", "terminal", None),
        ("chat-a", "tool", T0 + 13, json.dumps({"bytes_written": 2, "files_modified": [str(hello)]}), "c2", "write_file", None),
        ("chat-a", "assistant", T0 + 20, "done", None, None, None),
        # outside every run: an unsandboxed refusal is not the sandbox's
        ("chat-b", "user", T0 + 200, "again", None, None, None),
        ("chat-b", "assistant", T0 + 201, "", None, None, json.dumps([call("c3", "terminal", {"command": f'cat "{secret.as_posix()}"'})])),
        ("chat-b", "tool", T0 + 202, json.dumps({"output": f"cat: can't open '{secret.as_posix()}': Permission denied"}), "c3", "terminal", None),
    ])
    audit = work_profile.state_dir / "audit"
    audit.mkdir()
    recs = [A.ocsf_from_shorthand(line(t, m), "hermes-work") for t, m in
            [(T0 + 5, NOISE_CONFIG), (T0 + 10.5, HTTP_L7), (T0 + 10.6, HTTP_OPA), (T0 + 11, RELAY),
             (T0 + 14, DENIED.replace("api.github.com", "example.com")), (T0 + 40, LOADED), (T0 + 60, DENIED)]]
    (audit / "ocsf-hermes-work-2026-10-26.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    cards = [
        {"t": T0 + 15, "event": "raised", "request_id": "sandbox-card-1", "kind": "network", "chat": "chat-a",
         "host": "example.com", "port": 443, "binary": PY, "raised_at": T0 + 15, "proposal_id": "p1"},
        {"t": T0 + 30, "event": "answered", "request_id": "sandbox-card-1", "kind": "network", "chat": "chat-a",
         "choice": "allow", "answered_at": T0 + 30, "via": "response", "target": {"host": "example.com", "port": 443, "binary": PY}},
        {"t": T0 + 40, "event": "granted", "request_id": "sandbox-card-1", "kind": "network", "chat": "chat-a",
         "host": "example.com", "port": 443, "choice": "session"},
        {"t": T0 + 61, "event": "raised", "request_id": "sandbox-card-2", "kind": "network", "chat": "chat-a",
         "host": "api.github.com", "port": 443},
        {"t": T0 + 65, "event": "answered", "request_id": "sandbox-card-2", "kind": "network", "chat": "chat-a",
         "choice": "deny", "reason": "No.", "answered_at": T0 + 65, "target": {"host": "api.github.com", "port": 443}},
        {"t": T0 + 90, "event": "revoked", "kind": "network", "chat": "chat-a", "host": "example.com", "port": 443,
         "scope": "session", "why": "chat closed"},
    ]
    (work_profile.state_dir / "cards.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cards), encoding="utf-8")
    return secret, hello


def test_timeline_merges_network_files_and_decisions_newest_first(work_profile, tmp_path):
    secret, hello = seed(work_profile, folder=tmp_path / "f")
    view = A.query(work_profile, since=T0 - 10, until=T0 + 1000)
    rows = view["rows"]
    assert [r["t"] for r in rows] == sorted((r["t"] for r in rows), reverse=True)
    kinds = [(r["kind"], r["outcome"], r["title"]) for r in rows]
    # relay plumbing and startup chatter stay in the archive only; the two engines' copies are one row
    assert ("network", "allowed", "POST host.openshell.internal:8081/v1/chat/completions") in kinds
    assert sum(1 for k in kinds if k[2].startswith("POST host.openshell.internal")) == 1
    assert not any("127.0.0.1" in k[2] or "TLS termination" in k[2] for k in kinds)
    assert ("network", "denied", "example.com:443") in kinds and ("network", "info", "Policy reloaded successfully") in kinds
    assert ("files", "denied", str(Path(secret.as_posix()))) in kinds
    assert ("files", "allowed", str(hello)) in kinds
    assert sum(1 for k in kinds if k[0] == "files") == 2  # chat-b's refusal ran outside the sandbox
    dec = [r for r in rows if r["kind"] == "decisions"]
    assert [(d["label"], d["title"], d.get("status")) for d in dec] == [
        ("Access ended", "example.com:443", None), ("Denied", "api.github.com:443", None),
        ("Allowed", "example.com:443", "applied")]
    assert dec[1]["reason"] == "No." and dec[2]["program"] == "python.exe" and dec[2]["who"] == "you"
    assert [r["title"] for r in rows if r["kind"] == "lifecycle"] == ["Sandbox stopped", "Sandbox started"]
    # chats: file and decision rows carry theirs; a network row only when one chat's turn was running
    file_row = next(r for r in rows if r["kind"] == "files")
    assert file_row["chat"] == "chat-a" and file_row["chat_title"] == "Chat chat-a" and file_row["tool"]
    assert next(r for r in rows if r["title"] == "example.com:443" and r["kind"] == "network")["chat"] == "chat-a"
    assert next(r for r in rows if r["title"] == "api.github.com:443" and r["kind"] == "network")["chat"] is None
    assert "_record" not in json.dumps(view)


def test_filters_kinds_denied_only_and_window(work_profile, tmp_path):
    seed(work_profile, folder=tmp_path / "f")
    denied = A.query(work_profile, since=T0 - 10, until=T0 + 1000, denied_only=True)["rows"]
    assert denied and all(r["outcome"] == "denied" for r in denied)
    assert {r["kind"] for r in denied} == {"network", "files", "decisions"}
    files = A.query(work_profile, since=T0 - 10, until=T0 + 1000, kinds=("files",))["rows"]
    assert {r["kind"] for r in files} == {"files"}
    window = A.query(work_profile, since=T0 + 50, until=T0 + 70)["rows"]
    assert {r["t"] for r in window} <= set(range(int(T0 + 50), int(T0 + 71))) | {T0 + 60, T0 + 65}
    limited = A.query(work_profile, since=T0 - 10, until=T0 + 1000, limit=3)
    assert len(limited["rows"]) == 3 and limited["truncated"]


def test_export_is_ocsf_jsonl_with_hermes_rows_mapped(work_profile, tmp_path):
    seed(work_profile, folder=tmp_path / "f")
    out = A.export(work_profile, since=T0 - 10, until=T0 + 1000)
    recs = out["records"]
    assert out["filename"].startswith("sandbox-activity-work-") and out["filename"].endswith(".jsonl")
    assert [r["time"] for r in recs] == sorted(r["time"] for r in recs)  # oldest first
    for r in recs:
        json.dumps(r)
        assert {"class_uid", "category_uid", "activity_id", "type_uid", "time", "metadata"} <= set(r)
        assert r["type_uid"] == r["class_uid"] * 100 + r["activity_id"]
    by_class = {}
    for r in recs:
        by_class.setdefault(r["class_uid"], []).append(r)
    # network: OpenShell's records verbatim, both engines' copies of the collapsed row included
    assert len([r for r in by_class[4002] if "chat/completions" in r["message"]]) == 2
    f_denied = next(r for r in by_class[1001] if r["action_id"] == 2)
    assert f_denied["activity_name"] == "Read" and f_denied["file"]["name"] == "secret.txt"
    assert f_denied["unmapped"]["hermes"]["chat"] == "chat-a"
    assert f_denied["status_detail"].startswith("cat: can't open") and f_denied["status_detail"].endswith("Permission denied")
    f_write = next(r for r in by_class[1001] if r["action_id"] == 1)
    assert f_write["activity_name"] == "Update" and f_write["file"]["name"] == "hello.txt"
    names = [(r["activity_name"], r.get("action")) for r in by_class[3005]]
    assert names == [("Assign Privileges", "Allowed"), ("Deny", "Denied"), ("Revoke Privileges", None)]
    assert by_class[3005][0]["privileges"] == ["network:example.com:443"] and by_class[3005][0]["actor"]["user"]["name"]
    assert [r["activity_name"] for r in by_class[6002]] == ["Start", "Stop"]


def test_unreadable_or_missing_sources_give_an_empty_timeline(work_profile):
    view = A.query(work_profile)
    assert view["rows"] == [] and not any(s["kept"] for s in view["sources"].values())
    (work_profile.home / "state.db").write_bytes(b"not a database")
    (work_profile.state_dir / "activity").mkdir()
    (work_profile.state_dir / "activity" / "runs.jsonl").write_text('{"event": "start", "t": 1}\nnot json\n', encoding="utf-8")
    assert A.query(work_profile, since=0)["rows"][0]["title"] == "Sandbox started"


# -- routes ------------------------------------------------------------------------------------------------

def test_launcher_routes_answer_the_timeline_and_refuse_bad_filters(work_profile, tmp_path):
    seed(work_profile, folder=tmp_path / "f")
    drv = WinDriver()
    sup = FakeSup(work_profile, drv)
    col = A.AuditCollector(sup, work_profile)
    routes = HostRoutes(sup, lambda: None, extra_routes=col.routes())

    def get(path):
        req = parse_head(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        handler = routes.match("GET", req.path)
        return asyncio.run(handler(req, b""))

    status, payload, _ = get(f"/api/plugins/openshell/activity?since={T0 - 10}&until={T0 + 1000}&kinds=decisions")
    assert status == 200 and {r["kind"] for r in payload["rows"]} == {"decisions"}
    assert payload["collector"]["collects"] is True
    status, payload, _ = get("/api/plugins/openshell/activity?kinds=processes")
    assert status == 422
    status, payload, _ = get(f"/api/plugins/openshell/activity/export?since={T0 - 10}&until={T0 + 1000}&denied=1")
    assert status == 200 and payload["records"] and all(r.get("action_id") == 2 for r in payload["records"])


def test_dashboard_router_serves_saved_activity_after_the_switch_is_off():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    spec = importlib.util.spec_from_file_location(
        "openshell_plugin_api_activity", Path(__file__).resolve().parent.parent / "dashboard" / "plugin_api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    layout = L.current_profile()
    runs = layout.state_dir / "activity" / "runs.jsonl"
    runs.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    try:
        runs.write_text(json.dumps({"event": "start", "t": now - 50, "sandbox": "hermes-x"}) + "\n"
                        + json.dumps({"event": "stop", "t": now - 10}) + "\n", encoding="utf-8")
        app = FastAPI()
        app.include_router(mod.router, prefix="/api/plugins/openshell")
        client = TestClient(app)
        view = client.get("/api/plugins/openshell/activity").json()
        assert [r["title"] for r in view["rows"]] == ["Sandbox stopped", "Sandbox started"] and not view["running"]
        assert client.get("/api/plugins/openshell/activity?limit=0").status_code == 422
        exported = client.get("/api/plugins/openshell/activity/export").json()
        assert [r["class_uid"] for r in exported["records"]] == [6002, 6002]
    finally:
        runs.unlink(missing_ok=True)
