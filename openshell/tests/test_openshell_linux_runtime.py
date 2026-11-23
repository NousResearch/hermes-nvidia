"""Linux OpenShell path (v0.1.5): the host Hermes runtime mounted read-only into a small base image,
the version gate, and the OCSF JSON archive that outlives the sandbox. No gateway needed: the fakes
from test_openshell_driver stand in for the SDK, and fake container-CLI processes for `docker logs`.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher.driver import DriverUnavailable, LaunchRequest
from openshell.launcher.host_routes import HostRoutes

from test_openshell_driver import SECRET, _req, _supervisor  # noqa: E402


def _venv_runtime(root: Path, *, pm_generation: bool = False):
    """A Linux-install-shaped runtime: <root>/hermes-agent (code), <root>/tools/python/cpython/bin
    (store Python), and the venv either in-tree or as a PM generation under installs/."""
    code = root / "hermes-agent"
    prefix = root / "tools" / "python" / "cpython-3.14.3"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "lib" / "python3.14").mkdir(parents=True)
    (prefix / "bin" / "python3.14").write_text("", encoding="utf-8")
    (code / "hermes_cli").mkdir(parents=True)
    venv = root / "installs" / "k" / "environments" / "g1" / "venv" if pm_generation else code / ".venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("", encoding="utf-8")
    (venv / "pyvenv.cfg").write_text(f"home = {prefix / 'bin'}\nversion = 3.14.3\n", encoding="utf-8")
    return code, venv, prefix, root / "tools"


def _request(tmp_path, python, code, store=None, **kw):
    env = {"PYTHONPATH": str(code)}
    if store:
        env["HERMES_RUNTIME_DIR"] = str(store)
    return LaunchRequest(sandbox_id="x", argv=[str(python), "-m", "hermes_cli.main", "serve"], cwd=tmp_path, env=env,
                         grants=L.Grants(), network={}, log_path=tmp_path / "l", config_dir=tmp_path / "state", **kw)


# --- the host runtime ------------------------------------------------------------------------------------

def test_runtime_mounts_code_env_and_store_python_once(tmp_path):
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    rt = OD.host_runtime(_request(tmp_path, venv / "bin" / "python", code, store))
    # pyvenv.cfg names <prefix>/bin; the stdlib sits beside it, so the prefix is what must be visible.
    assert rt.prefix == prefix.resolve() and rt.env_dir == venv.resolve()
    # The venv is inside the code tree and the prefix inside the store: two mounts cover everything.
    assert rt.mount_paths() == [code.resolve(), store.resolve()]
    plan = OD.plan_mounts(_request(tmp_path, venv / "bin" / "python", code, store), OD.ensure_masks(tmp_path / "state"), rt)
    by_target = {m["target"]: m for m in plan.mounts}
    for p in (code, store):
        assert by_target[str(p.resolve())] == {"type": "bind", "source": str(p.resolve()), "target": str(p.resolve()),
                                               "read_only": True}
    assert plan.runtime == [str(code.resolve()), str(store.resolve())]
    assert set(plan.runtime) <= set(plan.read_only)  # Landlock read-only as well


def test_pm_generation_mounts_only_the_selected_environment_not_the_install_state(tmp_path):
    code, venv, prefix, store = _venv_runtime(tmp_path / "root", pm_generation=True)
    rt = OD.host_runtime(_request(tmp_path, venv / "bin" / "python", code, store))
    assert rt.env_dir == venv.parent.resolve()  # environments/<gen>: the venv and its editable snapshot
    mounts = rt.mount_paths()
    assert venv.parent.resolve() in mounts and (tmp_path / "root" / "installs" / "k").resolve() not in mounts
    assert not any(p == (tmp_path / "root" / "installs").resolve() for p in mounts)



def test_a_pm_environment_inside_the_denied_install_state_gets_an_empty_writable_stand_in(tmp_path):
    """Docker makes every missing parent of a mount target inside the container (root-owned, empty). For the PM
    generation that is installs/<key>: Hermes in the sandbox saw an install state it could not lock and exited
    ("install state is not writable by this user"), so no Linux sandbox started on a PM-managed install."""
    code, venv, prefix, store = _venv_runtime(tmp_path / "root", pm_generation=True)
    state = (tmp_path / "root" / "installs" / "k").resolve()
    (state / "facts.json").write_text("{}", encoding="utf-8")
    (state / ".install.lock").write_text("", encoding="utf-8")
    req = _request(tmp_path, venv / "bin" / "python", code, store)
    req.grants.denied.append(state)
    rt = OD.host_runtime(req)
    for _ in range(2):  # a relaunch starts from an empty stand-in again
        plan = OD.plan_mounts(req, OD.ensure_masks(tmp_path / "state"), rt)
        targets = [m["target"] for m in plan.mounts]
        shadow = next(m for m in plan.mounts if m["target"] == str(state))
        assert shadow["read_only"] is False and str(state) in plan.read_write and plan.shadowed == [str(state)]
        source = Path(shadow["source"])
        assert (tmp_path / "state" / "shadow") in source.parents
        # only the nested mount point, made beforehand: no facts.json, no lock, nothing of the real state
        assert sorted(p.relative_to(source).as_posix() for p in source.rglob("*")) == ["environments", "environments/g1"]
        (source / ".install.lock").write_text("", encoding="utf-8")  # what Hermes in the sandbox writes
        env_mount = next(m for m in plan.mounts if m["target"] == str(venv.parent.resolve()))
        assert env_mount["read_only"] is True and targets.index(str(state)) < targets.index(env_mount["target"])
    assert (state / "facts.json").is_file()  # the real install state is untouched


def test_an_in_tree_venv_needs_no_stand_in(tmp_path):
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    req = _request(tmp_path, venv / "bin" / "python", code, store)
    req.grants.denied.append((tmp_path / "root" / "installs" / "k").resolve())
    plan = OD.plan_mounts(req, OD.ensure_masks(tmp_path / "state"), OD.host_runtime(req))
    assert plan.shadowed == [] and not (tmp_path / "state" / "shadow").exists()


def test_a_host_loopback_model_is_pointed_at_the_gateway_alias_inside_through_managed_scope(tmp_path):
    """The Linux sandbox has its own loopback: the profile's base_url (127.0.0.1) must be overridden with
    host.openshell.internal in the managed scope the sandbox reads, and that scope must be mounted (read-only)."""
    import hermes_yaml

    from openshell.launcher.managed import write_managed_scope

    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  default: m\n  provider: custom\n  base_url: http://127.0.0.1:18530/v1\n"
                                      "  key_env: K\n", encoding="utf-8")
    managed = write_managed_scope(tmp_path / "state" / "managed", {"plugins": {"hook_callback_timeout": 135}})
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    req = _request(tmp_path, venv / "bin" / "python", code, store, home=home)
    req.env["HERMES_MANAGED_DIR"] = str(managed)
    assert OD.loopback_model_override(req) == {"model": {"base_url": "http://host.openshell.internal:18530/v1"}}
    doc = hermes_yaml.safe_load((managed / "config.yaml").read_text(encoding="utf-8"))
    assert doc["model"]["base_url"] == "http://host.openshell.internal:18530/v1"
    assert doc["plugins"]["hook_callback_timeout"] == 135  # the supervisor's pins are kept
    assert "127.0.0.1:18530" in (home / "config.yaml").read_text(encoding="utf-8")  # the profile is untouched
    plan = OD.plan_mounts(req, OD.ensure_masks(tmp_path / "state"), OD.host_runtime(req))
    mount = next(m for m in plan.mounts if m["target"] == str(managed))
    assert mount["read_only"] is True and str(managed) in plan.read_only
    # a remote model needs no override
    (home / "config.yaml").write_text("model:\n  base_url: https://api.example.com/v1\n", encoding="utf-8")
    assert OD.loopback_model_override(req) == {}

def test_runtime_without_a_store_still_mounts_the_python_prefix(tmp_path):
    code, venv, prefix, _ = _venv_runtime(tmp_path / "root")
    rt = OD.host_runtime(_request(tmp_path, venv / "bin" / "python", code))
    assert rt.mount_paths() == [code.resolve(), prefix.resolve()]


@pytest.mark.parametrize("case", ["no-venv", "relative", "no-home"])
def test_runtimes_the_sandbox_cannot_mount_are_refused(tmp_path, case):
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    if case == "no-venv":  # a bare interpreter, as a system Python would be
        req = _request(tmp_path, prefix / "bin" / "python3.14", code, store)
    elif case == "relative":
        req = _request(tmp_path, Path("python"), code, store)
    else:
        (venv / "pyvenv.cfg").write_text("version = 3.14.3\n", encoding="utf-8")
        req = _request(tmp_path, venv / "bin" / "python", code, store)
    with pytest.raises(DriverUnavailable):
        OD.host_runtime(req)


@pytest.mark.parametrize("path", ["/", "/usr", "/usr/lib/python3.12", "/etc/hermes", "/sandbox/x", "/opt/openshell/x"])
def test_system_tree_paths_are_never_runtime_mounts(path, monkeypatch):
    monkeypatch.setattr(Path, "is_dir", lambda self: True)
    with pytest.raises(DriverUnavailable, match="system tree"):
        OD._check_runtime_path(Path(path))
    if os.name != "nt":
        OD._check_runtime_path(Path("/opt/hermes"))  # a packaged install under /opt is fine


@pytest.mark.skipif(os.name == "nt", reason="symlinked store layout is a POSIX install shape")
def test_interpreter_link_that_leaves_the_runtime_is_refused(tmp_path):
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    outside = tmp_path / "elsewhere" / "bin"
    outside.mkdir(parents=True)
    (outside / "python3.14").write_text("", encoding="utf-8")
    (venv / "bin" / "python").unlink()
    (venv / "bin" / "python").symlink_to(outside / "python3.14")
    with pytest.raises(DriverUnavailable, match="outside its runtime"):
        OD.host_runtime(_request(tmp_path, venv / "bin" / "python", code, store))
    # uv's layout: venv python -> tools/python/cpython-3.14-.../bin/python3.14 through a minor-version
    # dir link, all inside the store: accepted, and the resolved file is what OpenShell sees.
    (tmp_path / "root" / "tools" / "python" / "cpython-3.14").symlink_to(prefix)
    (venv / "bin" / "python").unlink()
    (venv / "bin" / "python").symlink_to(tmp_path / "root" / "tools" / "python" / "cpython-3.14" / "bin" / "python3.14")
    rt = OD.host_runtime(_request(tmp_path, venv / "bin" / "python", code, store))
    assert rt.real_python == (prefix / "bin" / "python3.14").resolve()


# --- the driver through the real supervisor ------------------------------------------------------------

def test_start_runs_the_host_runtime_read_only_in_the_base_image(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)
    py = tmp_path / "env" / "bin" / "python"

    async def scenario():
        await sup.start()
        try:
            (_, _, spec), = [c for c in api.calls if c[0] == "create"]
            assert spec["template"]["image"] == "hermes:test"
            assert spec["command"] == [str(py), "-m", "hermes_cli.main", "serve", "--isolated", "--host", "127.0.0.1",
                                       "--port", "9119", "--skip-build"]
            env = spec["environment"]
            assert env["PYTHONPATH"] == str((tmp_path / "code").resolve()) and env["PYTHONDONTWRITEBYTECODE"] == "1"
            assert env["PATH"].split(os.pathsep)[0] == str(py.parent)
            mounts = {m["target"]: m for m in spec["template"]["driver_config"]["docker"]["mounts"]}
            for d in ("code", "env", "base"):
                p = str((tmp_path / d).resolve())
                assert mounts[p]["read_only"] is True and p in spec["policy"]["filesystem"]["read_only"]
            assert "/opt/hermes" not in spec["policy"]["filesystem"]["read_only"]
            # The executable OpenShell attributes connections to is the resolved interpreter.
            view = sup.policy()["enforced"]
            assert view["binaries"] == [str(py.resolve())]
            assert view["runtime"] == [str((tmp_path / d).resolve()) for d in ("code", "env", "base")] or \
                sorted(view["runtime"]) == sorted(str((tmp_path / d).resolve()) for d in ("code", "env", "base"))
            prof = json.loads((layout.state_dir / "provider-profile-0.json").read_text())
            assert prof["binaries"] == [str(py.resolve())] and SECRET not in json.dumps(prof)
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_live_network_rules_name_the_runtime_interpreter(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    py = str((tmp_path / "env" / "bin" / "python").resolve())

    async def scenario():
        await sup.start()
        try:
            put = routes.match("PUT", "/api/plugins/openshell/network")
            status, cfg, _ = await put(_req(), json.dumps({"egress": "deny", "allow": [{"host": "example.org", "port": 443}]}).encode())
            assert status == 200 and not cfg["restart_required"]
            (_, _, policy, _), = [c for c in api.calls if c[0] == "update"]
            assert policy["network_policies"]["hermes_site_example_org_443"]["binaries"] == [{"path": py}]
            assert sup.driver.current_network()["allow"] == [{"host": "example.org", "port": 443}]
        finally:
            await sup.stop()

    asyncio.run(scenario())


# --- version gate --------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,ok", [("openshell 0.1.5", True), ("openshell-gateway 0.1.6-pre.2", True),
                                     ("0.2.0", True), ("openshell 0.1.2", False), ("0.1.4", False), ("dev", False)])
def test_openshell_older_than_0_1_5_is_refused(text, ok):
    if ok:
        OD._require_version("x", text)
    else:
        with pytest.raises(DriverUnavailable, match="v0.1.5 or newer"):
            OD._require_version("x", text)


@pytest.mark.skipif(os.name == "nt", reason="the Linux driver's preflight refuses Windows first")
def test_preflight_refuses_an_old_gateway(tmp_path, monkeypatch):
    from test_openshell_driver import FakeApi, Recorder, _cfg

    cfg = _cfg(tmp_path)
    cfg.gateway_dir.mkdir(parents=True)
    (cfg.gateway_dir / "metadata.json").write_text(json.dumps({"gateway_endpoint": "https://127.0.0.1:17690",
                                                               "auth_mode": "mtls"}))
    (cfg.gateway_dir / "mtls").mkdir()
    for f in ("ca.crt", "tls.crt", "tls.key"):
        (cfg.gateway_dir / "mtls" / f).write_text("x")
    api = FakeApi()
    driver = OD.OpenShellDriver(cfg, api=api, run=Recorder().run)
    assert driver.preflight()["gateway_version"] == "0.1.5"
    api.health = lambda: "0.1.2"
    with pytest.raises(DriverUnavailable, match="0.1.5"):
        driver.preflight()


# --- the OCSF JSON archive -----------------------------------------------------------------------------

def _record(uid, t_ms, cls=4001, action="Denied", host="example.com", msg="CONNECT denied example.com:443"):
    return {"class_uid": cls, "class_name": "Network Activity", "activity_name": "Open", "action": action,
            "severity": "Medium", "time": t_ms, "message": msg, "dst_endpoint": {"domain": host, "port": 443},
            "actor": {"process": {"name": "curl", "file": {"path": "/usr/bin/curl"}}},
            "metadata": {"uid": uid, "product": {"name": "OpenShell Sandbox Supervisor", "version": "0.1.5"}}}


def test_ocsf_json_lines_are_picked_out_of_supervisor_stderr():
    rec = _record("u1", 1_791_000_000_000)
    line = f"2026-10-26T21:00:00.000Z OCSF-JSON {json.dumps(rec)}\n"
    assert OD.ocsf_json_record(line) == rec
    assert OD.ocsf_json_record("2026-10-26T21:00:00.000Z OCSF NET:OPEN [MED] DENIED curl -> example.com:443") is None
    assert OD.ocsf_json_record("2026-10-26T21:00:00.000Z OCSF-JSON {broken") is None
    ev = OD.ocsf_event(rec)
    assert (ev["class"], ev["activity"], ev["action"], ev["time"]) == ("NET", "OPEN", "DENIED", 1_791_000_000.0)
    assert ev["context"] == {"dst": "example.com:443", "binary": "/usr/bin/curl"} and ev["archived"]


class _FakeLogs:
    """`docker logs --follow <id>`: replays the container's stderr, then ends when it is removed."""

    def __init__(self, lines):
        self.stdout = iter(lines)
        self.returncode = None

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15


def test_archive_follows_the_supervisor_and_survives_it(tmp_path):
    a, b = _record("u1", 1_791_000_000_000), _record("u2", 1_791_000_001_000, cls=4002, action="Allowed", msg="POST allowed")
    lines = ["2026-10-26T21:00:00Z INFO starting\n", f"2026-10-26T21:00:00Z OCSF-JSON {json.dumps(a)}\n",
             "2026-10-26T21:00:00Z OCSF NET:OPEN [MED] DENIED ...\n", f"2026-10-26T21:00:01Z OCSF-JSON {json.dumps(b)}\n",
             f"2026-10-26T21:00:01Z OCSF-JSON {json.dumps(a)}\n"]  # a replayed record is not written twice
    calls = []
    containers = iter(["sup123\n", ""])  # found at start; gone after the stream ends (sandbox deleted)

    def run(argv, **kw):
        calls.append(argv)

        class Done:
            returncode, stdout = 0, next(containers, "")
        return Done()

    def popen(argv, **kw):
        calls.append(argv)
        return _FakeLogs(lines)

    arch = OD.AuditArchive(tmp_path / "audit", "hermes-work", "docker", run=run, popen=popen)
    arch.start()
    arch.stop(timeout=5)
    assert ["docker", "logs", "--follow", "sup123"] in calls
    assert any("label=openshell.ai/sandbox-name=hermes-work" in a for a in calls[0])
    assert any("label=openshell.ai/isolation-role=supervisor" in a for a in calls[0])
    files = OD.archive_files(tmp_path / "audit", "hermes-work")
    assert len(files) == 1 and files[0].name.startswith("ocsf-hermes-work-20")
    rows = [json.loads(x) for x in files[0].read_text().splitlines()]
    assert [r["metadata"]["uid"] for r in rows] == ["u1", "u2"] and arch.written == 2 and arch.error is None
    got = OD.read_archive(tmp_path / "audit", "hermes-work", classes=("HTTP",))
    assert [e["uid"] for e in got] == ["u2"]
    assert [e["uid"] for e in OD.read_archive(tmp_path / "audit", "hermes-work", until=1_791_000_000.5)] == ["u1"]


def test_archive_reports_a_missing_supervisor_instead_of_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(OD.AuditArchive, "LOCATE_TIMEOUT", 0.0)

    def run(argv, **kw):
        class Done:
            returncode, stdout = 0, ""
        return Done()

    arch = OD.AuditArchive(tmp_path / "audit", "hermes-work", "docker", run=run, popen=None)
    arch.start()
    arch.stop(timeout=5)
    assert "no supervisor container" in arch.error and arch.written == 0


def test_driver_keeps_the_archive_readable_after_stop(tmp_path, monkeypatch):
    sup, api, rec, layout = _supervisor(tmp_path, monkeypatch)
    sup.driver.cfg.container_cli = "docker"
    rec_line = json.dumps(_record("u9", 1_791_000_002_000))

    class Arch(OD.AuditArchive):
        def start(self):
            self.dir.mkdir(parents=True, exist_ok=True)
            self._write(json.loads(rec_line))

        def stop(self, timeout=15.0):
            pass

    monkeypatch.setattr(OD, "AuditArchive", Arch)

    async def scenario():
        await sup.start()
        assert sup.policy()["enforced"]["audit_archive"]["records_written"] == 1
        await sup.stop()

    asyncio.run(scenario())
    events = sup.driver.events(classes=("NET",))  # the sandbox is gone; the archive answers
    assert [e["uid"] for e in events] == ["u9"] and events[0]["action"] == "DENIED"
    assert (layout.state_dir / "audit").is_dir()


@pytest.mark.skipif(os.name == "nt", reason="a POSIX login shell")
def test_login_shells_inside_get_the_mounted_runtime_first_on_path(tmp_path):
    """Debian's /etc/profile resets PATH for every login shell, and the agent's terminal snapshots a login shell:
    the runtime the backend runs from (python, hermes) was missing from the agent's commands."""
    import shlex
    import subprocess

    code, venv, prefix, store = _venv_runtime(tmp_path / "root with space")
    req = _request(tmp_path, venv / "bin" / "python", code, store)
    plan = OD.plan_mounts(req, OD.ensure_masks(tmp_path / "state"), OD.host_runtime(req))
    mount = next(m for m in plan.mounts if m["target"] == OD.PROFILE_SNIPPET)
    assert mount["read_only"] is True and Path(mount["source"]).parent == tmp_path / "state" / "profile.d"
    out = subprocess.run(["sh", "-c", f". {shlex.quote(mount['source'])}; printf %s \"$PATH\""],
                         env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=True).stdout
    assert out.split(":")[0] == str(OD.host_runtime(req).python.parent)
    assert out.endswith(":/usr/bin:/bin")


def test_the_linux_sandbox_declares_policy_dns_and_passes_the_sandbox_ca_through_managed_scope(tmp_path):
    """Inside the sandbox every name resolves to 198.18.0.0/15 and execute_code scrubs the CA variables: the managed
    scope declares the block as a fake-IP range and passes the CA variables through, keeping the profile's own
    entries; the profile's config.yaml is untouched."""
    import hermes_yaml

    from openshell.launcher.managed import write_managed_scope

    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("terminal:\n  env_passthrough: [MY_TOKENLESS_VAR]\nsecurity:\n"
                                      "  fake_ip_ranges: 100.80.0.0/16\n", encoding="utf-8")
    managed = write_managed_scope(tmp_path / "state" / "managed", {"plugins": {"hook_callback_timeout": 135}})
    code, venv, prefix, store = _venv_runtime(tmp_path / "root")
    req = _request(tmp_path, venv / "bin" / "python", code, store, home=home)
    req.env["HERMES_MANAGED_DIR"] = str(managed)
    out = OD.sandbox_network_settings(req)
    doc = hermes_yaml.safe_load((managed / "config.yaml").read_text(encoding="utf-8"))
    assert doc["security"]["fake_ip_ranges"] == ["100.80.0.0/16", "198.18.0.0/15"] == out["security"]["fake_ip_ranges"]
    assert doc["terminal"]["env_passthrough"][0] == "MY_TOKENLESS_VAR"
    assert set(OD.SANDBOX_CA_ENV) <= set(doc["terminal"]["env_passthrough"])
    assert doc["plugins"]["hook_callback_timeout"] == 135
    assert "198.18" not in (home / "config.yaml").read_text(encoding="utf-8")
