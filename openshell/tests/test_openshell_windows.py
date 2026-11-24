"""The plugin's OpenShell driver on Windows (windows branch, MXC through the gateway), without a gateway.

A fake ``openshell`` CLI stands in at the subprocess boundary: it keeps sandboxes, provider profiles,
providers, policy revisions and advisor chunks, and answers in the formats the branch's CLI prints.
"""
import asyncio
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import hermes_yaml
from provider_status_output import status_output
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from openshell.launcher import pins
from openshell.launcher import supervisor as S
from openshell.launcher.driver import DriverUnavailable, LaunchRequest, ProposalChanged
from openshell.launcher.spec import load_spec, save_spec

SECRET = "sk-test-" + "w" * 32
DECOY = "decoy-" + "d" * 20
TOKEN = "inner-" + "t" * 30
RULES_TEXT = """Network Rules:  (version 1, 2 chunks)

  Chunk: 60c3fdd8-1b45-40ff-8605-d2b3fb08bf8a
  Status: pending
  Rule: allow_example_com_443
  Binary: C:\\store\\python-3.14\\python.exe
  Confidence: 65%
  Rationale: Allow C:\\store\\python-3.14\\python.exe to connect to example.com:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: de2ee0e13abc
  Endpoints: example.com:443 [L4]
  Binaries: C:\\store\\python-3.14\\python.exe

  Chunk: 5aabc6b7-8f0f-4620-84d9-bdd291d6bbf5
  Status: approved
  Rule: allow_postman_echo_com_443
  Binary: C:\\store\\python-3.14\\python.exe
  Endpoints: postman-echo.com:443 [L7 rest, access=read-only]
  Binaries: C:\\store\\python-3.14\\python.exe
  Hits: 2 (first seen 2026-10-26 16:27:51, last seen 2026-10-26 16:27:52)
"""
LOG_TEXT = """[1793049113.188] [sandbox] [INFO ] [openshell_supervisor] Starting sandbox supervision command=["x"]
[1793049113.317] [sandbox] [OCSF ] [ocsf] CONFIG:ENRICHED [INFO] Enriched policy with baseline filesystem paths for proxy mode
[1793049113.724] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED C:\\store\\python.exe(0) -> example.com:443 [policy:- engine:opa] [reason:endpoint example.com:443 is not allowed by any policy]
[1793049113.760] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED C:\\store\\python.exe(0) -> postman-echo.com:443 [policy:hermes_site_postman_echo_com_443 engine:opa]
[1793049113.785] [sandbox] [OCSF ] [ocsf] HTTP:GET [INFO] ALLOWED GET http://postman-echo.com:443/get
"""


class Done:
    def __init__(self, code, out="", err=""):
        self.returncode, self.stdout, self.stderr = code, out, err


class FakeCli:
    """The windows branch's CLI as the driver drives it. Records (argv, env) per call.

    *rejects_denied_paths*: a build without ``mxc-driver-config-denied-paths``, whose MXC driver refuses the field
    (``MxcSandboxConfig`` has ``deny_unknown_fields``; the gateway's ``invalid mxc driver_config`` error)."""

    def __init__(self, info_caps=("openshell.policy.ui.v1",), rejects_denied_paths=False, sandbox_exe=None):
        self.calls = []
        self.sandboxes = {}
        self.profiles = {}
        self.providers = {}
        self.expiries = {}  # provider name -> {variable: the expiry the CLI was given}
        self.provider_states = {}  # provider name -> (state, reason) the sandbox reports; READY otherwise
        self.refuses_stable = False  # a gateway that cannot keep a credential's placeholder stable
        self.revisions = {}
        self.rules = {}
        self.info_caps = info_caps
        self.rejects_denied_paths = rejects_denied_paths
        self.sandbox_exe = sandbox_exe  # the gateway's sandbox_binary_path, which its MXC driver grants itself
        self.driver_configs = {}
        self.policy_files = []
        # `policy set --wait`: the new revision loads at once (the default), only after this many `policy list`
        # calls (`--wait` gives up first: exit 124), or never (`load: "fail"`: the sandbox rejects it, exit 1)
        self.load = 0

    def __call__(self, argv, env=None, **kw):
        self.calls.append((list(argv), dict(env or {})))
        args = argv[1:]
        head = args[:2]
        if args == ["--version"]:
            return Done(0, "openshell 0.1.5-dev.32+g624f55b3c")
        if args == ["status"]:
            return Done(0, "Server Status\n\n  Status: Connected\n  Authentication: Authenticated (mTLS transport)")
        if head == ["gateway", "info"]:
            return Done(0, "Extensions:\n    mxc (compute-driver)\n      Capabilities: openshell.compute.contract, "
                           + ", ".join(self.info_caps))
        if head == ["sandbox", "get"]:
            box = self.sandboxes.get(args[2])
            return Done(0, json.dumps(box)) if box else Done(1, "", f"Error: sandbox '{args[2]}' not found")
        if head == ["sandbox", "create"]:
            name = args[args.index("--name") + 1]
            policy = hermes_yaml.safe_load(Path(args[args.index("--policy") + 1]).read_text(encoding="utf-8"))
            mxc = json.loads(args[args.index("--driver-config-json") + 1])["mxc"]
            if self.rejects_denied_paths and "denied_paths" in mxc:
                return Done(1, "", "Error:   x status: InvalidArgument, message: \"invalid mxc driver_config: unknown "
                                   "field `denied_paths`, expected `command` or `cwd`\"")
            # what the MXC driver (NVIDIA/OpenShell#5033) refuses: a denied path that equals or contains a grant
            fs = policy.get("filesystem_policy") or {}
            for denied in mxc.get("denied_paths") or []:
                for grant in (fs.get("read_only") or []) + (fs.get("read_write") or []) + \
                        ([str(self.sandbox_exe)] if self.sandbox_exe else []):
                    if W._inside(grant, denied):
                        return Done(1, "", f"Error: denied path {denied} contains filesystem grant {grant}")
            self.driver_configs[name] = mxc
            self.sandboxes[name] = {"name": name, "phase": "Ready", "exit_code": None}
            self.revisions[name] = [{"version": 1, "status": "loaded", "policy": policy}]
            self.rules.setdefault(name, RULES_TEXT)
            return Done(0, f"Created sandbox: {name}")
        if head == ["sandbox", "delete"]:
            self.sandboxes.pop(args[2], None)
            return Done(0, "deletion accepted")
        if args[:3] == ["provider", "profile", "import"]:
            data = json.loads(Path(args[args.index("--file") + 1]).read_text(encoding="utf-8"))
            if self.refuses_stable and any(c.get("stable_placeholder") for c in data["credentials"]):
                # what the CLI says after asking a gateway that cannot keep a placeholder stable
                return Done(1, "", "Error: gateway does not support stable_placeholder; upgrade the gateway "
                                   "before enabling it")
            if data["id"] in self.profiles:
                return Done(1, "", "already exists")
            self.profiles[data["id"]] = {**data, "resource_version": 3}
            return Done(0, "imported")
        if args[:3] == ["provider", "profile", "export"]:
            return Done(0, json.dumps(self.profiles[args[3]]))
        if args[:3] == ["provider", "profile", "update"]:
            data = json.loads(Path(args[args.index("--file") + 1]).read_text(encoding="utf-8"))
            assert data["resource_version"] == 3
            self.profiles[args[-1]] = data
            return Done(0, "updated")
        if head == ["provider", "create"]:
            name = args[args.index("--name") + 1]
            creds = [args[i + 1] for i, a in enumerate(args) if a == "--credential"]
            if name in self.providers:
                return Done(1, "", "already exists")
            self.providers[name] = {cred: env[cred] for cred in creds}
            return Done(0, "created")
        if head == ["provider", "update"]:
            creds = [args[i + 1] for i, a in enumerate(args) if a == "--credential"]
            self.providers.setdefault(args[2], {}).update({cred: env[cred] for cred in creds})
            self.expiries.setdefault(args[2], {}).update(
                dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "--credential-expires-at"))
            return Done(0, "updated")
        if head == ["provider", "delete"]:
            self.providers.pop(args[2], None)
            return Done(0, "deleted")
        if args[:3] == ["provider", "profile", "delete"]:
            self.profiles.pop(args[3], None)
            return Done(0, "deleted")
        if args[:3] == ["sandbox", "provider", "status"]:
            state, reason = self.provider_states.get(args[4], ("READY", "UNSPECIFIED"))
            return Done(0, status_output(args[3], args[4], state, reason))  # the form the real CLI prints
        if head == ["settings", "set"]:
            return Done(0, "ok")
        if head == ["policy", "list"]:
            for r in self.revisions[args[2]]:
                if r["status"] == "pending":
                    r["after"] -= 1
                    if r["after"] <= 0:
                        r["status"] = "loaded"
            revs = [{k: v for k, v in r.items() if k not in ("policy", "after")} for r in self.revisions[args[2]]]
            return Done(0, json.dumps({"revisions": revs[::-1], "next_page_token": ""}))
        if head == ["policy", "get"]:
            name = args[2]
            rev = int(args[args.index("--rev") + 1]) if "--rev" in args else 0
            pick = [r for r in self.revisions[name] if r["version"] == rev] if rev else [self.revisions[name][-1]]
            r = pick[0]
            return Done(0, json.dumps({"version": r["version"], "status": "effective", "policy": r["policy"]}))
        if head == ["policy", "set"]:
            name = args[2]
            policy = hermes_yaml.safe_load(Path(args[args.index("--policy") + 1]).read_text(encoding="utf-8"))
            self.policy_files.append(policy)
            version = len(self.revisions[name]) + 1
            submitted = f"✓ Policy version {version} submitted (hash: 0123456789ab)"
            if self.load == "fail":
                self.revisions[name].append({"version": version, "status": "failed", "policy": policy,
                                             "load_error": "invalid endpoint"})
                return Done(1, "", f"{submitted}\n✗ Policy version {version} failed to load: invalid endpoint")
            for r in self.revisions[name]:
                r["status"] = "superseded"
            if self.load:
                self.revisions[name].append({"version": version, "status": "pending", "policy": policy,
                                             "after": int(self.load)})
                return Done(124, "", f"{submitted}\n✗ Timeout waiting for policy version {version} to load")
            self.revisions[name].append({"version": version, "status": "loaded", "policy": policy})
            return Done(0, "", f"{submitted}\n✓ Policy version {version} loaded (active version: {version})")
        if head == ["rule", "get"]:
            return Done(0, self.rules[args[2]])
        if head == ["rule", "approve"]:
            name, chunk = args[-1], args[args.index("--chunk-id") + 1]
            if chunk not in self.rules[name]:
                return Done(1, "", "chunk changed")
            current = self.revisions[name][-1]["policy"]
            merged = {**current, "network_policies": {**current.get("network_policies", {}), "allow_example_com_443": {
                "name": "allow_example_com_443", "endpoints": [{"host": "example.com", "port": 443}],
                "binaries": [{"path": "C:/store/python-3.14/python.exe"}]}}}
            self.revisions[name].append({"version": len(self.revisions[name]) + 1, "status": "loaded", "policy": merged})
            self.rules[name] = self.rules[name].replace("Status: pending", "Status: approved", 1)
            return Done(0, "approved")
        if head == ["rule", "reject"]:
            self.rules[args[-1]] = self.rules[args[-1]].replace("Status: pending", "Status: rejected", 1)
            return Done(0, "rejected")
        if args[0] == "logs":
            return Done(0, LOG_TEXT)
        raise AssertionError(f"unexpected CLI call {args}")

    def argvs(self):
        return [a for a, _ in self.calls]


class Forward:
    """``openshell forward service``: serves /api/health on the launcher's inner port."""

    def __init__(self, argv, **kw):
        self.argv = argv
        port = int(argv[argv.index("--local") + 1].rsplit(":", 1)[1])

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.server.shutdown()
            self.server.server_close()
            self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    kill = terminate


def _tree(tmp_path, llm_port=8080):
    """A default-profile root (home == root), a venv whose leaf interpreter is a store Python, a
    gateway registration with mTLS, and busybox in its own folder."""
    root = tmp_path / "root"
    store = root / "tools" / "python-3.14"
    store.mkdir(parents=True)
    (store / "python.exe").write_bytes(b"")
    env_dir = root / "installs" / "key1" / "environments" / "env1"
    (env_dir / "venv" / "Scripts").mkdir(parents=True)
    (env_dir / "venv" / "Scripts" / "python.exe").write_bytes(b"")
    (env_dir / "venv" / "pyvenv.cfg").write_text(f"home = {store}\n", encoding="utf-8")
    (root / "installs" / "key1" / "environments" / "env-old").mkdir()
    (root / "installs" / "key1" / "facts.json").write_text("{}", encoding="utf-8")
    (root / "hermes-agent").mkdir()
    (root / ".env").write_text(f"TEST_MODEL_KEY={SECRET}\nOTHER_TOKEN={DECOY}\n", encoding="utf-8")
    (root / "auth.json").write_text("{}", encoding="utf-8")
    (root / "config.yaml").write_text(
        f"model:\n  default: m\n  provider: custom\n  base_url: http://127.0.0.1:{llm_port}/v1\n"
        "  key_env: TEST_MODEL_KEY\nterminal:\n  backend: local\n", encoding="utf-8")
    bb = tmp_path / "bb" / "busybox64u.exe"
    bb.parent.mkdir()
    bb.write_bytes(b"")
    gwdir = tmp_path / "xdg" / "openshell" / "gateways" / "hermes-oswin"
    (gwdir / "mtls").mkdir(parents=True)
    for f in ("ca.crt", "tls.crt", "tls.key"):
        (gwdir / "mtls" / f).write_text("x", encoding="utf-8")
    (gwdir / "metadata.json").write_text(json.dumps({"gateway_endpoint": "https://127.0.0.1:1", "auth_mode": "mtls"}),
                                         encoding="utf-8")
    cli = tmp_path / "openshell.exe"
    cli.write_bytes(b"")
    runtime = L.Runtime(python=env_dir / "venv" / "Scripts" / "python.exe", code_dir=root / "hermes-agent",
                        env_dir=env_dir, base_python=store, store=root / "tools", install_state=root / "installs" / "key1")
    layout = L.ProfileLayout(name="default", home=root, root=root)
    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=cli)
    return layout, runtime, cfg, bb


def _driver(cfg, fake, tmp_path, **kw):
    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=tmp_path / "wxc-exec.exe", gateway=W.CliGateway(cfg, run=fake),
                                      popen=Forward, **kw)
    driver.denied_paths_supported = True  # what a runtime pinned with mxc-driver-config-denied-paths records
    return driver


def test_network_answers_apply_live_only_on_a_build_whose_reload_keeps_streams(tmp_path):
    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe")
    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=None)
    assert driver.capabilities()["network_live_interrupts"] is True  # no managed runtime: the conservative answer
    assert W.OpenShellWindowsDriver.capabilities()["network_live_interrupts"] is True
    driver._adopt_runtime({"id": "openshell-windows-reload", "features": [W.RELOAD_FEATURE]})
    assert driver.capabilities()["network_live_interrupts"] is False
    driver._adopt_runtime({"id": "openshell-windows-no-reload"})
    assert driver.capabilities()["network_live_interrupts"] is True
    # a gateway the spec names says so itself (openshell.reload_keeps_streams)
    named = W.OpenShellWindowsDriver(cfg, wxc_exec=None, reload_keeps_streams=True)
    assert named.capabilities()["network_live_interrupts"] is False


def _supervisor(layout, runtime, driver, bb, network=None):
    spec = load_spec(layout)
    spec.update(busybox=str(bb), folders=[])
    if network:
        spec["network"] = network
    save_spec(layout, spec)
    pins.take(layout)  # as turn_on does: the keys' endpoints are the ones the profile has at switch-on
    return S.Supervisor(layout, runtime, load_spec(layout), driver, outer_port=1)


@pytest.fixture
def secrets_env(monkeypatch):
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": SECRET, "OTHER_TOKEN": DECOY})


def test_a_windows_sandbox_without_busybox_refuses_to_start(tmp_path, monkeypatch, secrets_env):
    # No busybox means no terminal.backend pin, and core refuses a withheld .env without one. The plugin installs
    # the shell itself where it has a pinned build for the PC (test_windows_programs_wiring.py); where it has
    # none, a PC with no copy named and none on PATH is refused here.
    from openshell import busybox_env
    from openshell.launcher import windows_programs

    layout, runtime, cfg, bb = _tree(tmp_path)
    sup = _supervisor(layout, runtime, _driver(cfg, FakeCli(), tmp_path), bb)
    sup.spec.pop("busybox", None)
    monkeypatch.delenv("OPENSHELL_BUSYBOX", raising=False)
    monkeypatch.setattr(windows_programs, "supported", lambda name: False)
    monkeypatch.setattr(busybox_env, "find_busybox", lambda: None)
    with pytest.raises(S.SandboxStartError, match="busybox-w32 was not found"):
        sup._launch_request()


def test_hermes_inside_is_given_an_install_state_folder_of_its_own(tmp_path, secrets_env):
    """The host's own interpreter runs inside, so the install's state folder is an ancestor of the environment the
    sandbox reads: Hermes inside sees it, can neither read nor lock it, and ends at start. The launcher names an
    empty folder in the sandbox's scratch instead (``HERMES_INSTALL_STATE_DIR``), which the sandbox may write."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    sup = _supervisor(layout, runtime, _driver(cfg, FakeCli(), tmp_path), bb)
    request, _ = sup._launch_request()
    folder = Path(request.env["HERMES_INSTALL_STATE_DIR"])
    assert folder == L.install_state_dir(layout) and folder.is_dir() and list(folder.iterdir()) == []
    assert layout.box in folder.parents and runtime.install_state not in (folder, *folder.parents)
    assert folder in request.grants.readwrite


def test_the_install_state_folder_is_empty_again_at_every_start(tmp_path, secrets_env):
    """Hermes inside takes its lock there and may write more. What an earlier sandbox left is never read."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    sup = _supervisor(layout, runtime, _driver(cfg, FakeCli(), tmp_path), bb)
    request, _ = sup._launch_request()
    folder = Path(request.env["HERMES_INSTALL_STATE_DIR"])
    (folder / "facts.json").write_text("{}", encoding="utf-8")
    (folder / "locks").mkdir()
    (folder / "locks" / "install.lock").write_text("", encoding="utf-8")
    again, _ = sup._launch_request()
    assert Path(again.env["HERMES_INSTALL_STATE_DIR"]) == folder and list(folder.iterdir()) == []


def test_a_sandbox_that_does_not_run_the_hosts_interpreter_is_named_no_install_state_folder(tmp_path, secrets_env):
    """A driver that builds the sandbox's file system itself (Linux) puts an empty folder over the state there."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    driver = _driver(cfg, FakeCli(), tmp_path)
    driver.uses_host_shell = False
    request, _ = _supervisor(layout, runtime, driver, bb)._launch_request()
    assert "HERMES_INSTALL_STATE_DIR" not in request.env and not L.install_state_dir(layout).exists()


def test_carve_keeps_every_grant_outside_the_deny_list(tmp_path):
    root = tmp_path / "root"
    state = root / "openshell" / "default"
    for d in (state / "box" / "tmp", state / "box" / "appdata", state / "managed", root / "openshell" / "work",
              root / "installs" / "key1" / "environments" / "env1", root / "installs" / "key1" / "environments" / "old"):
        d.mkdir(parents=True)
    for f in (state / "token", state / "spec.yaml", root / "installs" / "key1" / "facts.json"):
        f.write_text("x", encoding="utf-8")
    ro = [state / "managed", root / "installs" / "key1" / "environments" / "env1"]
    rw = [root, state / "box" / "tmp", state / "box" / "appdata"]
    deny, extra_ro, notes = W.carve_denials([root / "openshell", root / "installs" / "key1", root / ".env",
                                             tmp_path / "elsewhere"], ro, rw)
    keys = {os.path.normcase(str(p)) for p in deny}
    for grant in [*ro, *rw[1:]]:
        assert not any(W._inside(grant, d) for d in deny), grant
    for hidden in (state / "token", state / "spec.yaml", root / "openshell" / "work", root / ".env",
                   root / "installs" / "key1" / "facts.json", root / "installs" / "key1" / "environments" / "old"):
        assert os.path.normcase(str(hidden)) in keys, hidden
    # Intermediate directories inside the read & write root become read-only: nothing new appears there.
    assert {root / "openshell", state, state / "box", root / "installs" / "key1",
            root / "installs" / "key1" / "environments"} <= set(extra_ro)
    assert tmp_path / "elsewhere" in deny and not notes


def test_launch_policy_hides_credentials_names_native_binaries_and_enables_the_ui(tmp_path):
    layout, runtime, cfg, bb = _tree(tmp_path)
    grants = L.profile_grants(layout, runtime, [])
    network = {"egress": "deny", "allow": [{"host": "api.github.com", "port": 443}],
               "approved": {"allow_example_com_443": {"name": "allow_example_com_443",
                                                      "endpoints": [{"host": "example.com", "port": 443}],
                                                      "binaries": [{"path": "C:/store/python.exe"}]}}}
    policy, denied, notes = W.build_windows_policy(grants, network, [str(runtime.base_python / "python.exe")])
    fs = policy["filesystem_policy"]
    assert policy["ui"] == {"allow_graphical_ui": True, "clipboard": "none", "allow_input_injection": False}
    # The deny list is for driver_config.mxc.denied_paths: OpenShell's policy has no deny field.
    assert "deny" not in fs and set(fs) == {"include_workdir", "read_only", "read_write"}
    assert W.native(layout.home / ".env") in denied and W.native(layout.home / "auth.json") in denied
    assert W.native(layout.root / "installs" / "key1" / "facts.json") in denied
    for grant in fs["read_only"] + fs["read_write"]:
        assert not any(W._inside(grant, d) for d in denied), grant
    assert all(_native_form(p) for p in fs["read_only"] + fs["read_write"] + denied)
    rules = policy["network_policies"]
    assert rules["hermes_site_api_github_com_443"]["binaries"] == [{"path": W.native(runtime.base_python / "python.exe")}]
    assert rules["allow_example_com_443"]["binaries"] == [{"path": "C:\\store\\python.exe"}]


def _native_form(path: str) -> bool:
    """A path as the MXC driver must get it: native() leaves it unchanged (a drive path is backslash-only on every
    OS), and on Windows, where every path these tests build is a drive path, it has no forward slash at all. On Linux
    the tests' own tmp paths are POSIX and pass through native() as they are."""
    return path == W.native(path) and (os.name != "nt" or "/" not in path)


def _rule(name, *endpoints, binaries=("**",)):
    return {"name": name, "endpoints": [dict(e) for e in endpoints], "binaries": [{"path": b} for b in binaries]}


def test_plain_host_grants_are_tls_tunnels_to_the_site_and_overlaps_keep_termination(tmp_path):
    """A host grant from a card, a web tool grant and a page destination carry nothing that needs the proxy inside
    TLS: ``tls: skip`` (a raw tunnel, the site's own certificate; OpenShell otherwise terminates TLS on every allowed
    CONNECT with its own CA, which curl.exe/Schannel rejects). A provider endpoint and a rule OpenShell drafted keep
    termination, and so does a grant that overlaps them (OpenShell refuses overlapping endpoints that disagree on
    ``tls``)."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    grants = L.profile_grants(layout, runtime, [])
    network = {"egress": "deny", "allow": [{"host": "api.github.com", "port": 443}, {"host": "*.example.org", "port": 443}],
               "approved": {
                   "allowed_host_example_com": _rule("allowed_host_example_com", {"host": "example.com", "port": 80},
                                                     {"host": "example.com", "port": 443}),
                   "allowed_tool_web_extract": _rule("allowed_tool_web_extract", {"host": "mcp.exa.ai", "port": 443},
                                                     {"host": "search.parallel.ai", "port": 443}),
                   "allowed_host_www_example_org": _rule("allowed_host_www_example_org",
                                                         {"host": "www.example.org", "port": 443}),
                   "allowed_host_api_openai_com": _rule("allowed_host_api_openai_com", {"host": "api.openai.com", "port": 443}),
                   "allowed_host_pypi_org": _rule("allowed_host_pypi_org", {"host": "pypi.org", "port": 443}),
                   "allow_pypi_org_443": _rule("allow_pypi_org_443", {"host": "pypi.org", "port": 443, "protocol": "rest",
                                                                       "access": "read-only"}, binaries=("C:/py.exe",)),
               }}
    policy, _, _ = W.build_windows_policy(grants, network, [str(runtime.base_python / "python.exe")],
                                          reserved=[("api.openai.com", 443)])
    rules = policy["network_policies"]
    tls = {name: [ep.get("tls") for ep in rule["endpoints"]] for name, rule in rules.items()}
    assert tls["allowed_host_example_com"] == ["skip", "skip"]
    assert tls["allowed_tool_web_extract"] == ["skip", "skip"]
    assert tls["hermes_site_api_github_com_443"] == ["skip"]
    assert tls["hermes_site_example_org_443"] == ["skip"] and tls["allowed_host_www_example_org"] == ["skip"]
    assert tls["allowed_host_api_openai_com"] == [None]  # the provider's endpoint: placeholders need termination
    assert tls["allowed_host_pypi_org"] == [None] and tls["allow_pypi_org_443"] == [None]  # an L7 rule overlaps
    # idempotent (a policy read back and applied again), and a rule read back with skip may lose it again
    assert OD.passthrough(rules, [("api.openai.com", 443)]) == rules
    rules["allowed_host_api_openai_com"]["endpoints"][0]["tls"] = "skip"
    assert "tls" not in OD.passthrough(rules, [("api.openai.com", 443)])["allowed_host_api_openai_com"]["endpoints"][0]


def test_host_patterns_overlap_like_openshell():
    assert OD.hosts_overlap("example.com", "EXAMPLE.com") and not OD.hosts_overlap("example.com", "www.example.com")
    assert OD.hosts_overlap("*.example.com", "www.example.com") and not OD.hosts_overlap("*.example.com", "example.com")
    assert OD.hosts_overlap("**.example.com", "a.b.example.com") and not OD.hosts_overlap("*.example.com", "a.b.example.com")
    assert OD.hosts_overlap("", "example.com") and OD.hosts_overlap("*.a.com", "*.b.com")  # conservative


def test_live_network_updates_keep_grants_as_tunnels_except_on_provider_endpoints(tmp_path):
    layout, runtime, cfg, bb = _tree(tmp_path)
    driver = _driver(cfg, FakeCli(), tmp_path)
    driver._launch_policy = {"version": 1, "filesystem_policy": {}, "ui": dict(W.UI_POLICY)}
    driver._binaries = ["C:\\store\\python.exe"]
    driver._providers = [{"name": "p", "endpoint": "host.openshell.internal:8080"},
                         {"name": "q", "endpoint": "api.openai.com:443"}]
    driver.tls_tunnels = True
    sent = []
    driver._apply = lambda policy, label, **kw: sent.append(policy) or {"loaded": True}
    driver.apply_network({"egress": "deny", "approved": {
        "allowed_host_example_com": _rule("allowed_host_example_com", {"host": "example.com", "port": 443}),
        "allowed_host_api_openai_com": _rule("allowed_host_api_openai_com", {"host": "api.openai.com", "port": 443})}})
    rules = sent[0]["network_policies"]
    assert rules["allowed_host_example_com"]["endpoints"] == [{"host": "example.com", "port": 443, "tls": "skip"}]
    assert rules["allowed_host_api_openai_com"]["endpoints"] == [{"host": "api.openai.com", "port": 443}]


def test_node_in_the_sandbox_uses_the_proxy(tmp_path):
    """Node's fetch ignores HTTPS_PROXY unless NODE_USE_ENV_PROXY is set; a direct connection fails (EACCES)."""
    from types import SimpleNamespace

    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe")
    driver = _driver(cfg, FakeCli(), tmp_path)
    state = tmp_path / "state"
    env, _ = driver._sandbox_env(SimpleNamespace(env={"PATH": "C:\\x", "OPENSHELL_X": "1"}, home=str(tmp_path),
                                                 config_dir=state))
    assert env["NODE_USE_ENV_PROXY"] == "1" and "OPENSHELL_X" not in env
    # git verifies with OpenSSL against the sandbox's bundle (Schannel's strict revocation check has no route out)
    assert (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]) == ("1", "http.sslBackend", "openssl")
    env, _ = driver._sandbox_env(SimpleNamespace(env={"NODE_USE_ENV_PROXY": "0", "GIT_CONFIG_COUNT": "1",
                                                      "GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_VALUE_0": "J"},
                                                 home=str(tmp_path), config_dir=state))
    assert env["NODE_USE_ENV_PROXY"] == "0"  # the user's own setting wins
    assert env["GIT_CONFIG_COUNT"] == "2" and env["GIT_CONFIG_KEY_1"] == "http.sslBackend" and env["GIT_CONFIG_KEY_0"] == "user.name"
    env, _ = driver._sandbox_env(SimpleNamespace(env={"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.sslbackend",
                                                      "GIT_CONFIG_VALUE_0": "schannel"}, home=str(tmp_path),
                                                 config_dir=state))
    assert env["GIT_CONFIG_COUNT"] == "1" and env["GIT_CONFIG_VALUE_0"] == "schannel"


def test_start_registers_placeholders_and_keeps_secrets_out_of_every_argv(tmp_path, secrets_env):
    layout, runtime, cfg, bb = _tree(tmp_path, llm_port=8080)
    fake = FakeCli()
    driver = _driver(cfg, fake, tmp_path)
    sup = _supervisor(layout, runtime, driver, bb, network={"egress": "deny", "allow": [{"host": "api.github.com", "port": 443}]})

    async def scenario():
        await sup.start()
        try:
            assert sup.status()["state"] == "running" and sup.status()["driver"] == "openshell"
            for argv, env in fake.calls:
                assert SECRET not in " ".join(argv) and DECOY not in " ".join(argv) and TOKEN not in " ".join(argv)
                assert sup._inner_token not in " ".join(argv)
            create, env = next((a, e) for a, e in fake.calls if a[1:3] == ["sandbox", "create"])
            assert env["HERMES_DASHBOARD_SESSION_TOKEN"] == sup._inner_token  # --env-from, not argv
            assert "--env-from" in create and create[create.index("--env-from") + 1] == "HERMES_DASHBOARD_SESSION_TOKEN"
            pairs = [create[i + 1] for i, a in enumerate(create) if a == "--env"]
            assert not [p for p in pairs if p.upper().startswith("OPENSHELL_")]
            path = next(p for p in pairs if p.startswith("PATH="))
            assert path.split("=", 1)[1].split(os.pathsep)[0] == str(bb.parent)
            (provider,) = fake.providers  # <sandbox>-<variable>-<digest>
            assert provider.startswith("hermes-default-test-model-key-")
            assert create[create.index("--provider") + 1] == provider
            provider_env = next(e for a, e in fake.calls if a[1:3] == ["provider", "create"])
            assert provider_env["TEST_MODEL_KEY"] == SECRET and fake.providers[provider] == {"TEST_MODEL_KEY": SECRET}
            assert "OTHER_TOKEN" not in json.dumps(fake.providers)
            profile = fake.profiles[provider]
            assert profile["endpoints"][0]["host"] == "host.openshell.internal" and profile["endpoints"][0]["port"] == 8080
            assert profile["binaries"] == [W.native(runtime.base_python / "python.exe")]
            dc = json.loads(create[create.index("--driver-config-json") + 1])["mxc"]
            serve_port = int(dc["command"][dc["command"].index("--port") + 1])
            assert serve_port != sup._inner_port and "--isolated" in dc["command"]
            fwd = driver._forward.argv
            assert fwd[1:3] == ["forward", "service"] and fwd[fwd.index("--target-port") + 1] == str(serve_port)
            assert fwd[fwd.index("--local") + 1] == f"127.0.0.1:{sup._inner_port}"
            managed = hermes_yaml.safe_load((layout.state_dir / "managed" / "config.yaml").read_text(encoding="utf-8"))
            assert managed["terminal"]["backend"] == "busybox"
            assert managed["model"]["base_url"] == "http://host.openshell.internal:8080/v1"
            assert "127.0.0.1:8080" in (layout.home / "config.yaml").read_text(encoding="utf-8")  # profile untouched
            # Credential files are hidden through the MXC driver's own config, snake_case beside command and cwd;
            # the policy carries no deny list (OpenShell's policy has no such field).
            assert set(dc) == {"command", "cwd", "denied_paths"}
            assert W.native(layout.home / ".env") in dc["denied_paths"]
            assert W.native(layout.root / W.MARKER_NAME) in dc["denied_paths"]
            assert W.native(layout.token_path) in dc["denied_paths"]
            assert all(Path(p).is_absolute() and _native_form(p) for p in dc["denied_paths"])
            sent = fake.revisions["hermes-default"][0]["policy"]
            assert "deny" not in sent["filesystem_policy"]
            assert W.native(bb.parent) in sent["filesystem_policy"]["read_only"]
            view = driver.policy()
            assert view["keys_withheld"] == ["OTHER_TOKEN"] and SECRET not in json.dumps(view)
            assert view["active"]["version"] == 1
            assert view["denied_paths"] == dc["denied_paths"]  # the /policy route shows what is hidden
            assert "deny" not in view["launch_policy"]["filesystem_policy"]
            route = sup.policy()  # GET /api/plugins/openshell/policy
            assert str(layout.home / ".env") in route["grants"]["denied"]
            assert route["enforced"]["denied_paths"] == dc["denied_paths"]
        finally:
            await sup.stop()
        assert "hermes-default" not in fake.sandboxes and driver._forward is None

    asyncio.run(scenario())
    # A relaunch replaces the profile and provider in place (resource_version for the profile).
    driver2 = _driver(cfg, fake, tmp_path)
    sup2 = _supervisor(layout, runtime, driver2, bb)

    async def again():
        await sup2.start()
        await sup2.stop()

    asyncio.run(again())
    assert [a[1:4] for a in fake.argvs() if a[1:3] == ["provider", "profile"]][-2:] == [
        ["provider", "profile", "export"], ["provider", "profile", "update"]]
    assert any(a[1:3] == ["provider", "update"] for a in fake.argvs())


def test_preflight_refuses_hosts_and_gateways_that_cannot_enforce(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows driver")
    layout, runtime, cfg, bb = _tree(tmp_path)
    from openshell.launcher import mxc as M

    monkeypatch.setattr(M, "preflight", lambda exe: {"tier": "base-container", "needs_dacl_augmentation": False})
    ok = _driver(cfg, FakeCli(), tmp_path).preflight()
    assert ok["deny_list"] is True and ok["deny_via"] == "driver_config.mxc.denied_paths"
    assert ok["endpoint"] == "127.0.0.1:1"
    # A runtime pinned without mxc-driver-config-denied-paths: refused, whatever `gateway info` advertises.
    old = _driver(cfg, FakeCli(info_caps=("openshell.policy.filesystem.deny.v1",)), tmp_path)
    old._adopt_runtime({"runtime_id": "openshell-windows-without-deny",
                        "features": [W.RELOAD_FEATURE, W.TUNNEL_FEATURE]})
    with pytest.raises(DriverUnavailable, match="openshell-windows-without-deny cannot hide credential "
                                                "files: it lacks the feature mxc-driver-config-denied-paths"):
        old.preflight()
    # A gateway the spec names hides nothing unless the spec says its build takes the field.
    named = W.OpenShellWindowsDriver(cfg, wxc_exec=tmp_path / "wxc-exec.exe", gateway=W.CliGateway(cfg, run=FakeCli()))
    with pytest.raises(DriverUnavailable, match="openshell.mxc_denied_paths: true"):
        named.preflight()
    no_wxc = W.OpenShellWindowsDriver(cfg, wxc_exec=None, gateway=W.CliGateway(cfg, run=FakeCli()))
    with pytest.raises(DriverUnavailable, match="wxc-exec not found"):
        no_wxc.preflight()

    def dacl(exe):
        raise DriverUnavailable("wxc-exec --probe reports needsDaclAugmentation true")

    monkeypatch.setattr(M, "preflight", dacl)
    with pytest.raises(DriverUnavailable, match="needsDaclAugmentation"):
        _driver(cfg, FakeCli(), tmp_path).preflight()
    monkeypatch.setattr(M, "preflight", lambda exe: {})
    meta = cfg.gateway_dir / "metadata.json"
    meta.write_text(json.dumps({"gateway_endpoint": "http://127.0.0.1:1", "auth_mode": "none"}), encoding="utf-8")
    with pytest.raises(DriverUnavailable, match="must use mTLS"):
        _driver(cfg, FakeCli(), tmp_path).preflight()


def test_requests_live_network_revisions_and_events(tmp_path, secrets_env):
    layout, runtime, cfg, bb = _tree(tmp_path)
    fake = FakeCli()
    driver = _driver(cfg, fake, tmp_path)
    sup = _supervisor(layout, runtime, driver, bb)

    async def scenario():
        await sup.start()
        try:
            pending = driver.proposals()
            assert [p["id"] for p in pending if p["status"] == "pending"] == ["60c3fdd8-1b45-40ff-8605-d2b3fb08bf8a"]
            first = pending[0]
            assert first["endpoints"] == [{"host": "example.com", "port": 443, "detail": "L4"}]
            assert first["binary"].endswith("python.exe") and first["security_notes"] == "prover: no new findings"
            approved = next(p for p in pending if p["status"] == "approved")
            assert approved["hit_count"] == 2 and approved["first_seen"] == "2026-10-26 16:27:51"
            with pytest.raises(ProposalChanged):
                driver.approve("5aabc6b7-8f0f-4620-84d9-bdd291d6bbf5")
            result = driver.approve(first["id"])
            assert result["policy_version"] == 2 and result["status"] == "loaded"
            live = driver.current_network()
            # The gateway hands the approved rule back with forward slashes; the driver reads it natively.
            assert live["approved"]["allow_example_com_443"]["binaries"] == [{"path": "C:\\store\\python-3.14\\python.exe"}]
            out = driver.apply_network({"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}],
                                        "approved": live["approved"]})
            assert out["policy_version"] == 3
            sent = fake.policy_files[-1]
            assert set(sent["network_policies"]) == {"hermes_site_pypi_org_443", "allow_example_com_443"}
            assert sent["filesystem_policy"] == driver._launch_policy["filesystem_policy"]
            assert "deny" not in sent["filesystem_policy"]  # live updates never carry a deny list either
            assert all(_native_form(b["path"]) for r in sent["network_policies"].values() for b in r["binaries"])
            revs = driver.revisions()
            assert revs["active_version"] == 3 and [r["version"] for r in revs["revisions"]] == [3, 2, 1]
            back = driver.rollback(1)
            assert back["restored"] == 1 and back["policy_version"] == 4
            assert "network_policies" not in fake.policy_files[-1]
            assert "deny" not in fake.policy_files[-1]["filesystem_policy"]
            fake.rules["hermes-default"] = RULES_TEXT
            assert driver.reject(first["id"], "not needed") == {"rejected": first["id"], "reason": "not needed"}
            assert any(a[1:3] == ["rule", "reject"] and "not needed" in a for a in fake.argvs())
            events = driver.events(classes=("NET",))
            assert [e["action"] for e in events] == ["DENIED", "ALLOWED"]
            assert events[0]["context"]["reason"] == "endpoint example.com:443 is not allowed by any policy"
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_policy_update_reports_loaded_only_once_its_revision_loads(tmp_path, secrets_env, monkeypatch):
    """`policy set --wait` plus the revision list: ``loaded`` True only when the gateway lists the submitted
    revision as loaded; a load that outlasts the bounded wait is ``loaded: False`` (submitted, no error);
    a rejected revision raises with the sandbox's reason."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    fake = FakeCli()
    driver = _driver(cfg, fake, tmp_path)
    sup = _supervisor(layout, runtime, driver, bb)
    net = {"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]}

    async def scenario():
        await sup.start()
        try:
            out = driver.apply_network(net)
            assert out["loaded"] is True and out["policy_version"] == 2 and out["timed_out"] is False
            assert any(a[1:3] == ["policy", "set"] and "--wait" in a for a in fake.argvs())
            # loads two revision-list looks after --wait gave up: still within the bounded wait
            fake.load = 2
            out = driver._apply(json.loads(json.dumps(driver._launch_policy)), "network", load_timeout=5.0)
            assert out["loaded"] is True and out["policy_version"] == 3
            # never loads within the bound: reported, not raised; the version is the one the CLI printed
            fake.load = 10 ** 6
            out = driver._apply(json.loads(json.dumps(driver._launch_policy)), "network", load_timeout=0.5)
            assert out == {"policy_version": 4, "status": "pending", "loaded": False, "timed_out": True,
                           "waited": out["waited"]}
            assert driver.loaded(4) is None
            fake.revisions["hermes-default"][-1]["status"] = "loaded"
            assert driver.loaded(4) is True and driver.loaded(3) is True  # 3 superseded by a loaded later one
            fake.load = "fail"
            with pytest.raises(RuntimeError, match="rejected policy revision 5: invalid endpoint"):
                driver.apply_network(net)
            assert driver.loaded(5) is False
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_the_shipped_windows_pin_hides_credentials_and_lacks_the_stream_preserving_reload():
    from openshell.launcher import openshell_install as inst

    win = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))["windows"]
    assert win["id"] == "openshell-windows-0.1.9"
    assert W.RELOAD_FEATURE not in win["features"] and W.TUNNEL_FEATURE in win["features"]
    assert W.DENY_FEATURE == "mxc-driver-config-denied-paths" and W.DENY_FEATURE in win["features"]
    assert win["binaries"]["openshell.exe"] == "6ceb2c281e607b0dae48b58a04779c78e9747473db1f6006ba95b39326ae331d"
    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=Path("x"), cli=Path("openshell.exe"))
    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=None)
    assert driver.denied_paths_supported is False  # nothing adopted yet: refuse
    driver._adopt_runtime({"id": win["id"], "features": win["features"]})
    # no stream-preserving reload: card answers stop the turn, apply, and continue the chat
    assert driver.capabilities()["network_live_interrupts"] is True
    assert driver.tls_tunnels is True  # granted sites are TLS tunnels with their own certificate
    assert driver.denied_paths_supported is True  # credential files hidden via driver_config.mxc.denied_paths
    driver._providers = [{"endpoint": "api.openai.com:443"}]
    assert driver._provider_endpoints() == [("api.openai.com", 443)]
    driver._adopt_runtime({"id": "older", "features": [W.RELOAD_FEATURE]})
    assert driver.tls_tunnels is False and driver._provider_endpoints() is None
    assert driver.denied_paths_supported is False
    rules = {"allowed_host_example_com": {"endpoints": [{"host": "example.com", "port": 443, "tls": "skip"}]}}
    assert OD.passthrough(rules, None)["allowed_host_example_com"]["endpoints"] == [{"host": "example.com", "port": 443}]


@pytest.mark.parametrize("printed", ["openshell 0.1.8", "openshell 0.1.5-dev.39+ge451bb390", "openshell 0.0.1",
                                     "openshell 0.1.9", "openshell 99.0.0", "openshell (unknown)"])
def test_windows_behaviour_comes_from_the_pinned_features_never_from_the_number_the_cli_prints(
        tmp_path, monkeypatch, printed):
    # The Windows package is stamped with a release number whose source it does not share: the number must not
    # switch anything on or off.
    if os.name != "nt":
        pytest.skip("Windows driver")
    layout, runtime, cfg, bb = _tree(tmp_path)
    from openshell.launcher import mxc as M

    monkeypatch.setattr(M, "preflight", lambda exe: {"tier": "base-container", "needs_dacl_augmentation": False})

    class Cli(FakeCli):
        def __call__(self, argv, env=None, **kw):
            if argv[1:] == ["--version"]:
                self.calls.append((list(argv), dict(env or {})))
                return Done(0, printed)
            return super().__call__(argv, env=env, **kw)

    def facts(features):
        driver = W.OpenShellWindowsDriver(cfg, wxc_exec=tmp_path / "wxc-exec.exe", gateway=W.CliGateway(cfg, run=Cli()),
                                          popen=Forward)
        driver._adopt_runtime({"runtime_id": "openshell-windows-test", "features": features})
        return driver

    full = facts([W.RELOAD_FEATURE, W.TUNNEL_FEATURE, W.DENY_FEATURE])
    out = full.preflight()
    assert out["cli"] == printed and out["deny_list"] is True  # the number is reported, nothing more
    assert (full.reload_keeps_streams, full.tls_tunnels, full.denied_paths_supported) == (True, True, True)
    assert full.capabilities()["network_live_interrupts"] is False
    deny_only = facts([W.DENY_FEATURE])
    deny_only.preflight()  # the CLI has answered with its number: still only what the pin lists
    assert (deny_only.reload_keeps_streams, deny_only.tls_tunnels, deny_only.denied_paths_supported) == (False, False, True)
    assert deny_only.capabilities()["network_live_interrupts"] is True
    bare = facts([])
    assert (bare.reload_keeps_streams, bare.tls_tunnels, bare.denied_paths_supported) == (False, False, False)
    with pytest.raises(DriverUnavailable, match="lacks the feature mxc-driver-config-denied-paths"):
        bare.preflight()


def test_the_release_number_gate_is_the_linux_drivers_alone():
    # MIN_OPENSHELL compares release numbers of OpenShell's main line. Only the Linux driver may ask it.
    root = Path(W.__file__).parent
    for name in ("openshell_windows.py", "gateway_service.py", "openshell_install.py", "compat.py", "mxc.py",
                 "supervisor.py", "switch.py", "cards.py"):
        text = (root / name).read_text(encoding="utf-8")
        for word in ("MIN_OPENSHELL", "_require_version", "parse_version("):
            assert word not in text.replace("_parse_version(", ""), f"{name} reads OpenShell's release number ({word})"
    driver = (root / "openshell_driver.py").read_text(encoding="utf-8")
    assert driver.count("_require_version(") == 3  # its definition and the Linux preflight's two calls
    gate = driver.index('if os.name == "nt":\n            raise DriverUnavailable("the OpenShell gateway driver runs Linux')
    assert gate < driver.index('_require_version("the openshell CLI"')


def test_parse_rules_reads_empty_and_rejected_output():
    assert W.parse_rules("No network rules for sandbox 'x'") == []
    chunks = W.parse_rules(RULES_TEXT.replace("Status: pending", "Status: rejected\n  Reason: not needed", 1))
    assert chunks[0]["status"] == "rejected" and chunks[0]["rejection_reason"] == "not needed"


@pytest.mark.skipif(os.name != "nt", reason="the hook picks the Windows driver on Windows only")
def test_openshell_driver_from_spec_hands_out_the_windows_driver(tmp_path, monkeypatch):
    layout, runtime, cfg, bb = _tree(tmp_path)
    wxc = tmp_path / "wxc-exec.exe"
    wxc.write_bytes(b"")
    spec = {"wxc_exec": str(wxc), "openshell": {"gateway": "hermes-oswin", "config_home": str(tmp_path / "xdg"),
                                                "cli": str(cfg.cli)}}
    driver = OD.OpenShellDriver.from_spec(spec)
    assert isinstance(driver, W.OpenShellWindowsDriver) and driver.wxc_exec == wxc.resolve()
    assert driver.capabilities()["driver"] == "openshell" and driver.capabilities()["host_loopback"] == "open"
    assert driver.uses_host_shell
    # A named gateway hides credential files only when the spec says its build takes driver_config.mxc.denied_paths.
    assert driver.denied_paths_supported is False
    spec["openshell"]["mxc_denied_paths"] = True
    assert OD.OpenShellDriver.from_spec(spec).denied_paths_supported is True


def test_denied_paths_have_their_own_cap_outside_the_policy_count(tmp_path):
    rw = tmp_path / "rw"
    rw.mkdir()
    many_grants = [rw / f"g{i}" for i in range(200)]
    for g in many_grants:
        g.mkdir()
    # 200 grants + 100 hidden paths: fine, the deny list does not count against the policy's 256
    grants = L.Grants(readonly=[], readwrite=many_grants, denied=[rw / f"secret{i}" for i in range(100)])
    policy, denied, _ = W.build_windows_policy(grants, {"egress": "deny", "allow": []}, [])
    assert len(policy["filesystem_policy"]["read_write"]) == 200 and len(denied) == 100
    grants = L.Grants(readonly=[], readwrite=[rw], denied=[rw / f"secret{i}" for i in range(300)])
    with pytest.raises(DriverUnavailable, match="would hide 300 paths"):
        W.build_windows_policy(grants, {"egress": "deny", "allow": []}, [])


def test_start_refuses_a_runtime_without_the_deny_feature_before_creating_anything(tmp_path, secrets_env):
    layout, runtime, cfg, bb = _tree(tmp_path)
    fake = FakeCli()
    driver = _driver(cfg, fake, tmp_path)
    # an installed runtime whose recorded features lack the deny feature
    driver._adopt_runtime({"runtime_id": "openshell-windows-without-deny",
                           "features": [W.RELOAD_FEATURE, W.TUNNEL_FEATURE]})
    sup = _supervisor(layout, runtime, driver, bb)
    with pytest.raises(DriverUnavailable, match="cannot hide credential files: it lacks the feature "
                                                "mxc-driver-config-denied-paths"):
        asyncio.run(sup.start())
    assert fake.calls == []  # no lookup, no provider, no sandbox
    assert sup.status()["state"] == "failed" and "mxc-driver-config-denied-paths" in sup.status()["error"]


def test_a_build_whose_mxc_driver_rejects_denied_paths_fails_closed_with_a_clear_message(tmp_path, secrets_env):
    """A fresh install of an older build under a pin that lists the feature: its MXC driver refuses the unknown
    field at create (deny_unknown_fields), so nothing runs, and the launcher says why."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    fake = FakeCli(rejects_denied_paths=True)
    sup = _supervisor(layout, runtime, _driver(cfg, fake, tmp_path), bb)
    with pytest.raises(DriverUnavailable, match="does not take driver_config.mxc.denied_paths"):
        asyncio.run(sup.start())
    assert "hermes-default" not in fake.sandboxes


def test_a_stored_filesystem_policy_deny_is_honoured_as_denied_paths(tmp_path, secrets_env):
    """A deny list stored in spec.yaml (filesystem_policy.deny) is honoured: its paths are hidden
    through driver_config.mxc.denied_paths, the policy sent to OpenShell has no deny field, and the stored
    spec is left as it was. (A stored deny below a folder the sandbox could rename is refused instead:
    test_rename_safe.py.)"""
    from openshell.launcher import spec as SP

    layout, runtime, cfg, bb = _tree(tmp_path)
    private = layout.home / "private"
    private.mkdir()
    diary = private / "diary.txt"
    diary.write_text("x", encoding="utf-8")
    SP.set_policy(layout, {"version": 1, "filesystem_policy": {"read_write": [], "deny": [str(private)]}})
    fake = FakeCli()
    driver = _driver(cfg, fake, tmp_path)
    sup = _supervisor(layout, runtime, driver, bb)
    assert hermes_yaml.safe_load(layout.spec_path.read_text(encoding="utf-8"))["policy"]["filesystem_policy"]["deny"] \
        == [str(private)]

    async def scenario():
        await sup.start()
        try:
            dc = fake.driver_configs["hermes-default"]
            assert W.native(private) in dc["denied_paths"] and W.native(layout.home / ".env") in dc["denied_paths"]
            sent = fake.revisions["hermes-default"][0]["policy"]
            assert "deny" not in sent["filesystem_policy"]
            assert json.dumps(W.native(private))[1:-1] not in json.dumps(sent)
        finally:
            await sup.stop()

    asyncio.run(scenario())
    stored = hermes_yaml.safe_load(layout.spec_path.read_text(encoding="utf-8"))["policy"]["filesystem_policy"]
    assert stored["deny"] == [str(private)]  # spec.yaml unchanged: backward compatible both ways


def test_the_default_profile_deny_list_leaves_the_managed_sandbox_executable_granted(tmp_path, secrets_env):
    """The managed runtime is installed under <root>/openshell/runtime, inside the launcher state the default
    profile denies. The MXC driver grants openshell-windows-sandbox.exe to every sandbox itself and refuses a denied
    path that contains it, so the deny list is carved around it; the gateway's state, its CLI client key among it,
    stays hidden, and the executable is not added to the policy."""
    layout, runtime, cfg, bb = _tree(tmp_path)
    rt = layout.root / "openshell" / "runtime"
    bins = rt / "openshell-windows-test" / "bin"
    bins.mkdir(parents=True)
    for name in ("openshell.exe", "openshell-gateway.exe", "openshell-supervisor.exe", "openshell-windows-sandbox.exe"):
        (bins / name).write_bytes(b"")
    key = rt / "gateway" / "cli" / "openshell" / "gateways" / "hermes-oswin" / "mtls" / "tls.key"
    key.parent.mkdir(parents=True)
    key.write_text("x", encoding="utf-8")
    exe = bins / "openshell-windows-sandbox.exe"  # where gateway_service points sandbox_binary_path
    fake = FakeCli(sandbox_exe=exe)
    driver = _driver(cfg, fake, tmp_path)
    driver._adopt_runtime({"runtime_id": "openshell-windows-test", "features": [W.DENY_FEATURE],
                           "cli": bins / "openshell.exe"})
    sup = _supervisor(layout, runtime, driver, bb)

    async def scenario():
        await sup.start()
        try:
            denied = fake.driver_configs["hermes-default"]["denied_paths"]
            assert not any(W._inside(exe, d) for d in denied)
            assert any(W._inside(key, d) for d in denied)  # the gateway dir: the client key stays hidden
            assert W.native(bins / "openshell-gateway.exe") in denied
            fs = fake.revisions["hermes-default"][0]["policy"]["filesystem_policy"]
            assert W.native(exe) not in fs["read_only"] + fs["read_write"]
        finally:
            await sup.stop()

    asyncio.run(scenario())
