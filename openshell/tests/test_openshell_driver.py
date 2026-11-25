"""Behaviour tests for the OpenShell gateway driver and the host routes it enables (no gateway needed).

A fake gateway API stands in for the SDK and its stub: it keeps policy revisions, drafts (blocked
requests) and logs the way the gateway reports them, so approve / reject / rollback / live network
edits run the real driver and route code end to end. A fake ``forward`` serves ``/api/health`` on the
inner port the supervisor picks, so start and restart run the real supervisor too.

Run: PYTHONPATH="<hermes checkout>;<this repo>" <hermes python> -m pytest openshell/tests -q
"""
import asyncio
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest  # noqa: E402

from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher import openshell_driver as OD  # noqa: E402
from openshell.launcher import pins  # noqa: E402
from openshell.launcher import supervisor as S  # noqa: E402
from openshell.launcher.driver import DriverUnavailable, LaunchRequest  # noqa: E402
from openshell.launcher.host_routes import HostRoutes  # noqa: E402
from openshell.launcher.proxy import parse_head  # noqa: E402
from openshell.launcher.spec import allow_entry, load_spec, network_from_body, save_spec  # noqa: E402

SECRET = "sk-test-" + "s" * 32
DECOY = "decoy-" + "d" * 20
PY = "/opt/hermes/tools/python-*/bin/python3*"


def _req(target="/"):
    return parse_head(f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())


class FakeApi:
    """The gateway as the driver sees it: plain dicts, revisions, drafts, logs."""

    def __init__(self):
        self.calls = []
        self.sandboxes = {}
        self.providers = {}
        self.settings = {}
        self.revisions = {}
        self.drafts_by = {}
        self.log_lines = []

    def health(self):
        return "0.1.5"

    def create_sandbox(self, name, spec, labels):
        self.calls.append(("create", name, copy.deepcopy(spec)))
        self.sandboxes[name] = {"phase": "READY", "exit_code": None}
        self.revisions[name] = [{"version": 1, "status": "loaded", "policy": copy.deepcopy(spec["policy"])}]
        self.drafts_by.setdefault(name, [])

    def wait_ready(self, name, timeout):
        assert self.sandboxes[name]["phase"] == "READY"

    def sandbox_state(self, name):
        return self.sandboxes.get(name)

    def delete_sandbox(self, name, timeout):
        self.calls.append(("delete", name))
        self.sandboxes.pop(name, None)

    def upsert_provider(self, name, profile_id, credentials):
        self.providers[name] = {"type": profile_id, "credentials": dict(credentials)}
        return "created"

    stable_placeholders = True  # what the gateway answers when asked whether it keeps placeholders stable
    provider_states = {}  # provider name -> (state, reason) the sandbox reports; READY otherwise

    def supports_stable_placeholder(self):
        return self.stable_placeholders

    def update_provider(self, name, credentials, expires=None, clear=()):
        row = self.providers[name]
        row["credentials"].update(credentials)
        row.setdefault("expires", {}).update(expires or {})
        for env in clear:
            row["expires"].pop(env, None)
        self.calls.append(("provider update", name, sorted(credentials), dict(expires or {}), list(clear)))

    def delete_provider(self, name):
        self.providers.pop(name, None)
        self.calls.append(("provider delete", name))

    def provider_state(self, sandbox, provider):
        return self.provider_states.get(provider, ("READY", "UNSPECIFIED"))

    def set_setting(self, name, key, value):
        self.settings[(name, key)] = value

    def policy_status(self, name, version=0):
        revs = self.revisions[name]
        rev = revs[-1] if not version else next((r for r in revs if r["version"] == version), {"version": 0})
        return {**copy.deepcopy(rev), "active_version": revs[-1]["version"]}

    def list_policies(self, name):
        return [{k: v for k, v in r.items() if k != "policy"} for r in self.revisions[name]]

    def update_policy(self, name, policy, annotations):
        version = self.revisions[name][-1]["version"] + 1
        self.revisions[name].append({"version": version, "status": "loaded", "policy": copy.deepcopy(policy),
                                     "provenance": dict(annotations)})
        self.calls.append(("update", name, copy.deepcopy(policy), dict(annotations)))
        return {"version": version, "policy_hash": f"h{version}"}

    def drafts(self, name, status=""):
        return [copy.deepcopy(c) for c in self.drafts_by[name] if not status or c["status"] == status]

    def approve_draft(self, name, chunk_id, review_token):
        chunk = next(c for c in self.drafts_by[name] if c["id"] == chunk_id)
        assert review_token == chunk["review_token"]
        chunk["status"] = "approved"
        policy = copy.deepcopy(self.revisions[name][-1]["policy"])
        policy.setdefault("network_policies", {})[chunk["rule_name"]] = chunk["proposed_rule"]
        result = self.update_policy(name, policy, {"source": "draft"})
        return {"policy_version": result["version"], "policy_hash": result["policy_hash"]}

    def reject_draft(self, name, chunk_id, reason):
        chunk = next(c for c in self.drafts_by[name] if c["id"] == chunk_id)
        chunk["status"], chunk["rejection_reason"] = "rejected", reason

    def logs(self, name, *, since, lines, sources=("sandbox",)):
        return [l for l in self.log_lines if since is None or l["time"] >= since][-lines:]

    def block(self, name, chunk_id, host, port, binary):
        """What the gateway does when the sandbox's proxy denies a connection: draft a rule."""
        rule = {"name": f"allow_{host.replace('.', '_')}_{port}", "endpoints": [{"host": host, "port": port}],
                "binaries": [{"path": binary}]}
        self.drafts_by[name].append({"id": chunk_id, "status": "pending", "rule_name": rule["name"],
                                     "proposed_rule": rule, "binary": binary, "rationale": f"{binary} -> {host}:{port}",
                                     "hit_count": 1, "review_token": f"tok-{chunk_id}",
                                     "candidate_effective_policy": {"huge": True}})


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/api/health" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class FakeForward:
    """`openshell forward service` as a child process: serves the backend's health on the inner port."""

    def __init__(self, cmd, **kwargs):
        self.cmd, self.env, self.returncode = cmd, kwargs.get("env") or {}, None
        port = int(cmd[cmd.index("--local") + 1].rsplit(":", 1)[1])
        self.server = ThreadingHTTPServer(("127.0.0.1", port), _Health)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def poll(self):
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.server.shutdown()
            self.server.server_close()
            self.returncode = -15

    kill = terminate

    def wait(self, timeout=None):
        return self.returncode


class Recorder:
    def __init__(self, existing_profiles=()):
        self.argvs, self.popens = [], []
        self.existing = set(existing_profiles)

    def run(self, argv, **kwargs):
        self.argvs.append((list(argv), dict(kwargs.get("env") or {})))
        refused = "import" in argv and any(json.loads(Path(argv[argv.index("-f") + 1]).read_text())["id"] == p
                                           for p in self.existing)
        if "export" in argv:
            out = json.dumps({"id": argv[argv.index("export") + 1], "resource_version": 3})
        if "update" in argv:  # the gateway refuses an update without the current resource_version
            refused = json.loads(Path(argv[argv.index("-f") + 1]).read_text()).get("resource_version") != 3

        class Done:
            returncode, stdout, stderr = (1, "", "refused") if refused else (0, out if "export" in argv else "openshell 0.1.5\n", "")
        return Done()

    def popen(self, cmd, **kwargs):
        self.argvs.append((list(cmd), dict(kwargs.get("env") or {})))
        proc = FakeForward(cmd, **kwargs)
        self.popens.append(proc)
        return proc


def _cfg(tmp_path):
    cli = tmp_path / "bin" / "openshell"
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("#!/bin/sh\n")
    return OD.OpenShellConfig(gateway="hermes-gw", config_home=tmp_path / "xdg", cli=cli, image="hermes:test",
                              run_as=("1000", "1000"), container_cli=None)


def _layout(tmp_path):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("model:\n  provider: custom\n  base_url: http://127.0.0.1:18500/v1\n"
                                      "  key_env: LLAMA_API_KEY\n", encoding="utf-8")
    (home / ".env").write_text(f"LLAMA_API_KEY={SECRET}\nDECOY_TOKEN={DECOY}\n", encoding="utf-8")
    (home / "auth.json").write_text("{}", encoding="utf-8")
    return L.ProfileLayout(name="work", home=home, root=root)


def _runtime(tmp):
    """A venv-shaped host runtime: env/bin/python with pyvenv.cfg naming base/bin (the store Python)."""
    for d in ("code", "env/bin", "base/bin"):
        (tmp / d).mkdir(parents=True, exist_ok=True)
    (tmp / "base" / "bin" / "python3").write_text("", encoding="utf-8")
    (tmp / "env" / "bin" / "python").write_text("", encoding="utf-8")
    (tmp / "env" / "pyvenv.cfg").write_text(f"home = {tmp / 'base' / 'bin'}\n", encoding="utf-8")
    return L.Runtime(python=tmp / "env" / "bin" / "python", code_dir=tmp / "code", env_dir=tmp / "env",
                     base_python=tmp / "base" / "bin", store=None)


def _folders(tmp_path):
    work, ref = tmp_path / "folders" / "work", tmp_path / "folders" / "reference"
    work.mkdir(parents=True)
    ref.mkdir(parents=True)
    return [{"path": str(work), "access": "rw"}, {"path": str(ref), "access": "ro"}]


def _supervisor(tmp_path, monkeypatch, network=None):
    layout = _layout(tmp_path)
    spec = load_spec(layout)
    spec.update(driver="openshell", folders=_folders(tmp_path), network=network or {"egress": "deny", "allow": []})
    save_spec(layout, spec)
    pins.take(layout)  # as turn_on does: the keys' endpoints are the ones the profile has at switch-on
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"LLAMA_API_KEY": SECRET, "DECOY_TOKEN": DECOY})
    api, rec = FakeApi(), Recorder()
    driver = OD.OpenShellDriver(_cfg(tmp_path), api=api, run=rec.run, popen=rec.popen)
    sup = S.Supervisor(layout, _runtime(tmp_path), load_spec(layout), driver, outer_port=1)
    return sup, api, rec, layout


def _route(routes, method, path, body=None):
    target = "/api/plugins/openshell/" + path
    handler = routes.match(method, target.split("?", 1)[0])
    raw = b"" if body is None else json.dumps(body).encode()
    return asyncio.run(handler(_req(target), raw))


# --- pure translation ---------------------------------------------------------------------------------

def test_mounts_use_host_paths_mask_present_credentials_and_watch_absent_ones(tmp_path):
    layout, runtime, folders = _layout(tmp_path), _runtime(tmp_path), _folders(tmp_path)
    grants = L.profile_grants(layout, runtime, folders)
    req = LaunchRequest(sandbox_id="x", argv=[], cwd=tmp_path, env={}, grants=grants, network={}, log_path=tmp_path / "l",
                        config_dir=layout.state_dir, home=layout.home, folders=folders)
    plan = OD.plan_mounts(req, OD.ensure_masks(layout.state_dir))
    by_target = {m["target"]: m for m in plan.mounts}
    home = str(layout.home)
    assert by_target[home] == {"type": "bind", "source": home, "target": home, "read_only": False}
    assert by_target[folders[0]["path"]]["read_only"] is False and by_target[folders[1]["path"]]["read_only"] is True
    assert by_target[str(layout.home / "plugins")]["read_only"] is True  # plugin code never sandbox-writable
    env_mask, auth_mask = by_target[str(layout.home / ".env")], by_target[str(layout.home / "auth.json")]
    assert env_mask["read_only"] and Path(env_mask["source"]).read_text() == ""
    assert auth_mask["read_only"] and Path(auth_mask["source"]).read_text().strip() == "{}"
    assert str(layout.home / "mcp-tokens") in plan.unmasked_absent and str(layout.home / ".env") in plan.masked
    # Without a host runtime nothing of it is mounted; the launcher's box dirs never are.
    assert not any(t.startswith(str(tmp_path / "code")) or t.startswith(str(layout.state_dir)) for t in by_target)
    assert all(Path(m["source"]).exists() for m in plan.mounts)


def test_model_key_binds_to_its_endpoint_and_other_keys_stay_on_the_host(tmp_path):
    layout = _layout(tmp_path)
    pins.take(layout)
    routes, withheld = OD.credential_routes(layout.home, {"LLAMA_API_KEY": SECRET, "DECOY_TOKEN": DECOY},
                                            pins.route_pin(layout))
    (route,) = routes
    assert route["env"] == "LLAMA_API_KEY" and route["port"] == 18500
    assert route["host"] == "host.openshell.internal" and route["loopback_rewrite"]  # host model server
    assert withheld == ["DECOY_TOKEN"]
    assert (route["placement"], route["name"]) == ("bearer", None)
    profile = OD.provider_profile("hermes-work-llama-api-key", route, (PY,))
    assert profile["endpoints"] == [{"host": "host.openshell.internal", "port": 18500, "protocol": "rest",
                                     "access": "read-write", "enforcement": "enforce"}]
    assert profile["credentials"][0]["env_vars"] == ["LLAMA_API_KEY"] and SECRET not in json.dumps(profile)


def test_network_rules_round_trip_through_the_policy():
    network = {"egress": "deny", "allow": [{"host": "api.github.com", "port": 443},
                                           {"host": "example.com", "port": 443, "binary": "/usr/bin/curl"},
                                           {"cidr": "203.0.113.0/24", "port": 8443}],
               "approved": {"allow_pypi_org_443": {"name": "allow_pypi_org_443",
                                                   "endpoints": [{"host": "pypi.org", "port": 443}],
                                                   "binaries": [{"path": "/usr/bin/pip"}]}}}
    rules = OD.network_rules(network, (PY,))
    site = rules["hermes_site_api_github_com_443"]
    assert site["endpoints"] == [{"host": "api.github.com", "port": 443}] and site["binaries"] == [{"path": PY}]
    assert rules["hermes_addr_203_0_113_0_24_8443"]["endpoints"] == [{"port": 8443, "allowed_ips": ["203.0.113.0/24"]}]
    assert any(r["binaries"] == [{"path": "/usr/bin/curl"}] for r in rules.values())
    assert rules["allow_pypi_org_443"] == network["approved"]["allow_pypi_org_443"]
    back = OD.network_from_policy({"network_policies": rules}, (PY,))
    assert sorted(map(json.dumps, back["allow"])) == sorted(map(json.dumps, network["allow"]))
    assert back["approved"] == network["approved"]


def test_website_rules_are_validated_and_only_where_the_driver_filters_by_name():
    rules = ("host", "cidr")
    assert allow_entry({"host": "API.GitHub.com.", "port": "443"}, rules=rules) == {"host": "api.github.com", "port": 443}
    assert allow_entry({"host": "*.example.com", "port": 443}, rules=rules)["host"] == "*.example.com"
    for bad in ({"host": "*.com", "port": 443}, {"host": "localhost", "port": 80}, {"host": "10.0.0.1", "port": 80},
                {"host": "exa mple.com", "port": 443}, {"host": "example.com", "port": 443, "binary": "curl"}):
        with pytest.raises(L.LayoutError):
            allow_entry(bad, rules=rules)
    with pytest.raises(L.LayoutError, match="IP address only"):
        allow_entry({"host": "example.com", "port": 443})  # MXC: CIDR only
    with pytest.raises(L.LayoutError, match="never reachable"):
        allow_entry({"cidr": "127.0.0.1", "port": 18500}, host_loopback="closed", rules=rules)
    # a loopback NAME gets the answer a loopback address gets, whichever way the driver treats loopback
    for name in ("localhost", "LocalHost.", "db.localhost"):
        with pytest.raises(L.LayoutError, match="never reachable from this sandbox; reach host services as host.openshell.internal"):
            allow_entry({"host": name, "port": 8080}, host_loopback="closed", rules=rules)
        with pytest.raises(L.LayoutError, match="always reachable from this sandbox"):
            allow_entry({"host": name, "port": 8080}, host_loopback="open", rules=rules)
    with pytest.raises(L.LayoutError, match="Not a website hostname: localhost"):
        allow_entry({"host": "localhost", "port": 8080}, rules=rules)  # a driver that does not say: as before
    with pytest.raises(L.LayoutError, match="no rule for all internet"):
        network_from_body({"egress": "allow", "allow": []}, rules=rules, allow_all=False)


def test_the_page_is_told_the_driver_has_no_rule_for_all_internet_access(tmp_path, monkeypatch):
    """Both answers the Sandbox page reads while the sandbox is on say it, so the page offers no such choice."""
    sup, _api, _rec, _layout_ = _supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    for path in ("status", "config"):
        status, payload, _ = _route(routes, "GET", path)
        assert status == 200 and payload["capabilities"]["egress_allow_all"] is False, path


def test_ocsf_shorthand_lines_become_structured_events():
    event = OD.parse_event({"time": 5.0, "level": "OCSF", "source": "sandbox", "fields": {"dst_host": "example.com"},
                            "message": "NET:OPEN [MED] DENIED /usr/bin/curl(64) -> example.com:443 "
                                       "[policy:- engine:opa] [reason:no matching policy]"})
    assert (event["class"], event["activity"], event["severity"], event["action"]) == ("NET", "OPEN", "MED", "DENIED")
    assert event["detail"] == "/usr/bin/curl(64) -> example.com:443"
    assert event["context"] == {"policy": "-", "engine": "opa", "reason": "no matching policy"}
    assert not OD.parse_event({"level": "INFO", "message": "Starting sandbox"}).get("ocsf")
    # Nested context, as v0.1.2 logs a tunnel closed by a policy reload.
    closed = OD.parse_event({"time": 6.0, "level": "OCSF", "message":
                             "NET:OPEN [MED] DENIED host.openshell.internal:18500 [reason:L7 tunnel closed before inspection "
                             "because policy changed: policy generation is stale [captured_generation:5 current_generation:6]]"})
    assert closed["detail"] == "host.openshell.internal:18500"
    assert closed["context"] == {"reason": "L7 tunnel closed before inspection because policy changed: policy generation is stale",
                                 "captured_generation": "5", "current_generation": "6"}
    odd = OD.parse_event({"level": "OCSF", "message": "CONFIG:LOADED [INFO] Policy [v2] reloaded [policy_hash:ab] [unclosed"})
    assert odd["context"] == {"policy_hash": "ab"} and "[v2]" in odd["detail"] and "[unclosed" in odd["detail"]


def test_gateway_without_mtls_is_refused(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.gateway_dir.mkdir(parents=True)
    for meta in ({"gateway_endpoint": "http://127.0.0.1:8080", "auth_mode": "none"},
                 {"gateway_endpoint": "https://127.0.0.1:17680", "auth_mode": "mtls"}):  # no client cert on disk
        (cfg.gateway_dir / "metadata.json").write_text(json.dumps(meta))
        with pytest.raises(DriverUnavailable, match="mTLS"):
            OD.gateway_endpoint(cfg)
    (cfg.gateway_dir / "mtls").mkdir()
    for f in ("ca.crt", "tls.crt", "tls.key"):
        (cfg.gateway_dir / "mtls" / f).write_text("x")
    assert OD.gateway_endpoint(cfg)[0] == "127.0.0.1:17680"


# --- the driver through the real supervisor -------------------------------------------------------------

def test_start_hands_the_sandbox_placeholders_not_keys(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            assert sup.status()["state"] == "running" and sup.running()
            (_, name, spec), = [c for c in api.calls if c[0] == "create"]
            assert name == "hermes-work"
            dumped = json.dumps(spec)
            assert SECRET not in dumped and DECOY not in dumped  # no value in the spec the gateway stores
            (provider,) = api.providers  # one per key and set of addresses: <sandbox>-<variable>-<digest>
            assert provider.startswith("hermes-work-llama-api-key-") and spec["providers"] == [provider]
            assert api.providers[provider]["credentials"] == {"LLAMA_API_KEY": SECRET}
            for argv, env in rec.argvs:  # nor in any CLI argv or environment the driver built
                assert SECRET not in " ".join(argv) and SECRET not in json.dumps({k: v for k, v in env.items()
                                                                                  if k in ("XDG_CONFIG_HOME", "OPENSHELL_GATEWAY")})
            assert spec["environment"]["HERMES_HOME"] == str(layout.home)
            assert spec["command"][:4] == [str(tmp_path / "env" / "bin" / "python"), "-m", "hermes_cli.main", "serve"]
            assert spec["policy"]["process"] == {"run_as_user": "1000", "run_as_group": "1000"}
            assert str(layout.home) in spec["policy"]["filesystem"]["read_write"]
            assert spec["template"]["driver_config"]["docker"]["mounts"]
            assert api.settings[("hermes-work", "ocsf_json_enabled")] is True
            fwd = rec.popens[0].cmd
            assert fwd[1:3] == ["forward", "service"] and f"127.0.0.1:{sup._inner_port}" in fwd
            view = sup.policy()["enforced"]
            assert view["keys_withheld"] == ["DECOY_TOKEN"] and SECRET not in json.dumps(view)
        finally:
            await sup.stop()
        assert ("delete", "hermes-work") in api.calls and rec.popens[0].poll() is not None

    asyncio.run(scenario())


def test_relaunch_replaces_an_existing_provider_profile_by_id(tmp_path, monkeypatch):
    """A second launch finds the profile registered; `profile update` needs the ID and
    the current resource_version (from `profile export`)."""
    sup, api, _, layout = _supervisor(tmp_path, monkeypatch)
    pid = OD.provider_id("hermes-work", OD.key_declarations(
        OD.credential_routes(layout.home, {"LLAMA_API_KEY": SECRET}, pins.route_pin(layout))[0]), True)
    rec = Recorder(existing_profiles={pid})
    sup.driver._run = rec.run
    sup.driver._popen = rec.popen

    async def scenario():
        await sup.start()
        await sup.stop()

    asyncio.run(scenario())
    (update,) = [argv for argv, _ in rec.argvs if "update" in argv]
    assert update[-1] == pid and pid.startswith("hermes-work-llama-api-key-")
    assert update[update.index("-f") + 1].endswith("provider-profile-0.json")


def test_exit_code_follows_the_sandbox_and_a_dead_forward_is_restarted(tmp_path, monkeypatch):
    sup, api, rec, _ = _supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(OD, "_STATE_CHECK_INTERVAL", 0.0)
    monkeypatch.setattr(OD, "_FORWARD_RETRY", 0.0)

    async def scenario():
        await sup.start()
        try:
            rec.popens[0].terminate()
            assert sup.driver.exit_code() is None and len(rec.popens) == 2  # restarted, sandbox still up
            api.sandboxes["hermes-work"] = {"phase": "ERROR", "exit_code": None}
            assert sup.driver.exit_code() == 1
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_blocked_requests_list_reject_with_reason_and_approve_live(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)

    async def scenario():
        await sup.start()
        try:
            api.block("hermes-work", "c1", "example.com", 443, "/usr/bin/curl")
            api.block("hermes-work", "c2", "httpbin.org", 443, "/usr/bin/curl")
            status, payload, _ = await routes.match("GET", "/api/plugins/openshell/proposals")(_req("/api/plugins/openshell/proposals"), b"")
            assert status == 200 and [p["id"] for p in payload["proposals"]] == ["c1", "c2"]
            assert payload["proposals"][0]["endpoints"] == [{"host": "example.com", "port": 443}]
            assert "review_token" not in json.dumps(payload) and "candidate" not in json.dumps(payload)

            reject = routes.match("POST", "/api/plugins/openshell/proposals/c2/reject")
            assert (await reject(_req(), b"{}"))[0] == 422  # a reason is required
            status, payload, _ = await reject(_req(), json.dumps({"reason": "Not needed for this task."}).encode())
            assert status == 200 and api.drafts_by["hermes-work"][1]["rejection_reason"] == "Not needed for this task."

            approve = routes.match("POST", "/api/plugins/openshell/proposals/c1/approve")
            status, payload, _ = await approve(_req(), b"{}")
            assert status == 200 and payload["policy_version"] == 2 and payload["status"] == "loaded"
            assert "allow_example_com_443" in payload["network"]["approved"]
            # Live: same sandbox (one create), the spec follows the enforcer, nothing pends.
            assert [c[0] for c in api.calls].count("create") == 1
            assert "allow_example_com_443" in load_spec(layout)["network"]["approved"]
            assert not sup.status()["pending"]["network"]
            assert (await approve(_req(), b"{}"))[0] == 409  # already decided

            # A restart recreates the sandbox with the approved rule in its launch policy.
            await sup.restart()
            creates = [c for c in api.calls if c[0] == "create"]
            assert "allow_example_com_443" in creates[-1][2]["policy"]["network_policies"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_network_edits_apply_live_and_revisions_roll_back(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)

    async def scenario():
        await sup.start()
        try:
            put = routes.match("PUT", "/api/plugins/openshell/network")
            for bad in ({"egress": "allow", "allow": []}, {"egress": "deny", "allow": [{"cidr": "127.0.0.1", "port": 1}]}):
                assert (await put(_req(), json.dumps(bad).encode()))[0] == 422
            status, cfg, _ = await put(_req(), json.dumps({"egress": "deny", "allow": [{"host": "api.github.com", "port": 443}]}).encode())
            assert status == 200 and not cfg["restart_required"]
            (_, _, policy, ann), = [c for c in api.calls if c[0] == "update"]
            assert "hermes_site_api_github_com_443" in policy["network_policies"] and ann == {"hermes.change": "network"}
            assert policy["filesystem"] == api.revisions["hermes-work"][0]["policy"]["filesystem"]  # static part untouched
            assert sup.status()["applied"]["network"]["allow"] == [{"host": "api.github.com", "port": 443}]

            status, revs, _ = await routes.match("GET", "/api/plugins/openshell/policy/revisions")(_req(), b"")
            assert status == 200 and [r["version"] for r in revs["revisions"]] == [2, 1] and revs["active_version"] == 2
            status, rev1, _ = await routes.match("GET", "/api/plugins/openshell/policy/revisions/1")(_req(), b"")
            assert status == 200 and rev1["version"] == 1

            rollback = routes.match("POST", "/api/plugins/openshell/policy/rollback")
            assert (await rollback(_req(), b'{"version": "1"}'))[0] == 422
            status, payload, _ = await rollback(_req(), b'{"version": 1}')
            assert status == 200 and payload["policy_version"] == 3 and payload["restored"] == 1
            assert api.calls[-1][3] == {"hermes.change": "rollback", "hermes.rollback_of": "1"}
            assert payload["network"]["allow"] == [] and load_spec(layout)["network"]["allow"] == []
            assert not sup.status()["restart_required"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_events_route_filters_ocsf_by_class_and_time(tmp_path, monkeypatch):
    sup, api, rec, _ = _supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    api.log_lines = [
        {"time": 10.0, "level": "INFO", "message": "Starting sandbox", "source": "sandbox", "fields": {}},
        {"time": 11.0, "level": "OCSF", "message": "NET:OPEN [MED] DENIED /usr/bin/curl(9) -> example.com:443 [policy:- engine:opa]",
         "source": "sandbox", "fields": {}},
        {"time": 12.0, "level": "OCSF", "message": "CONFIG:LOADED [INFO] Policy reloaded successfully [policy_hash:ab]",
         "source": "sandbox", "fields": {}},
        {"time": 13.0, "level": "OCSF", "message": "HTTP:POST [INFO] ALLOWED POST http://host.openshell.internal:18500/v1/chat/completions "
                                                    "[policy:hermes-work-llama-api-key engine:opa]", "source": "sandbox", "fields": {}},
    ]

    async def scenario():
        await sup.start()
        try:
            target = "/api/plugins/openshell/events?since=11&class=NET,HTTP"
            status, payload, _ = await routes.match("GET", "/api/plugins/openshell/events")(_req(target), b"")
            assert status == 200 and [(e["class"], e["action"]) for e in payload["events"]] == [("NET", "DENIED"), ("HTTP", "ALLOWED")]
            bad = "/api/plugins/openshell/events?class=BOGUS"
            assert (await routes.match("GET", "/api/plugins/openshell/events")(_req(bad), b""))[0] == 422
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_enforcer_routes_answer_409_where_the_driver_has_no_such_feature_or_nothing_runs(tmp_path, monkeypatch):
    from test_settings_routes import FakeDriver

    layout = _layout(tmp_path)
    sup = S.Supervisor(layout, _runtime(tmp_path), load_spec(layout), FakeDriver(), outer_port=1)
    routes = HostRoutes(sup, lambda: None)
    for method, path in (("GET", "proposals"), ("GET", "policy/revisions"), ("GET", "events")):
        status, payload, _ = _route(routes, method, path)
        assert status == 409 and payload["supported"] is False
    sup2, *_ = _supervisor(tmp_path / "b", monkeypatch)
    status, payload, _ = _route(HostRoutes(sup2, lambda: None), "GET", "proposals")
    assert status == 409 and "not running" in payload["detail"]


def test_credential_stores_created_inside_the_sandbox_are_quarantined(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        (layout.home / "mcp-tokens").mkdir()  # as if the sandbox wrote a token store the host would trust
        (layout.home / "mcp-tokens" / "server.json").write_text("{}")
        await sup.stop()

    asyncio.run(scenario())
    assert not (layout.home / "mcp-tokens").exists()
    moved = list((layout.state_dir / "quarantine").glob("*/mcp-tokens/server.json"))
    assert len(moved) == 1 and (layout.home / ".env").read_text().startswith("LLAMA_API_KEY=")


def test_the_sandbox_gets_the_card_hook_channel_and_the_managed_scope(tmp_path, monkeypatch):
    """The driver builds the sandbox environment itself. Without the supervisor's card-hook folders the hook is not
    registered inside (no card resolves in its turn; a web tool's refusal raises no card at all); without the managed
    scope core's 30 s hook timeout applies and the profile's host-loopback model URL is dialled inside."""
    import hermes_yaml

    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [c for c in api.calls if c[0] == "create"]
            env = spec["environment"]
            for key in ("HERMES_SANDBOX_VERDICTS", "HERMES_SANDBOX_REQUESTS", "HERMES_SANDBOX_CARD_WAIT",
                        "HERMES_MANAGED_DIR"):
                assert env.get(key), key
            mounts = {m["target"]: m for m in spec["template"]["driver_config"]["docker"]["mounts"]}
            assert mounts[env["HERMES_SANDBOX_VERDICTS"]]["read_only"] is True
            assert mounts[env["HERMES_SANDBOX_REQUESTS"]]["read_only"] is False
            assert mounts[env["HERMES_MANAGED_DIR"]]["read_only"] is True
            doc = hermes_yaml.safe_load((Path(env["HERMES_MANAGED_DIR"]) / "config.yaml").read_text(encoding="utf-8"))
            assert doc["plugins"]["hook_callback_timeout"] >= 135
            assert doc["model"]["base_url"] == "http://host.openshell.internal:18500/v1"
            assert sup.policy()["enforced"]["model_overrides"] == {"model": {"base_url": doc["model"]["base_url"]}}
            assert "127.0.0.1:18500" in (layout.home / "config.yaml").read_text(encoding="utf-8")
        finally:
            await sup.stop()

    asyncio.run(scenario())
