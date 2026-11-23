"""OpenShell's own usage telemetry is off for every OpenShell program the plugin starts.

OpenShell sends anonymous usage telemetry unless ``OPENSHELL_TELEMETRY_ENABLED`` says otherwise (its README,
"Telemetry"); the gateway is the program that sends, and it hands the value on to each sandbox's supervisor. The
plugin builds the environment of everything it starts and drops inherited ``OPENSHELL_*`` values, so it sets the
switch itself, last. Nothing here starts OpenShell or talks to a network: fake runners record each environment,
and the gateway's bootstrap runs for real around a harmless child that prints what it was given.
"""
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import test_gateway_service as TG
import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import gateway_service as GS
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_install as inst
from openshell.launcher import openshell_windows as W
from openshell.launcher import supervisor as S

SWITCH = "OPENSHELL_TELEMETRY_ENABLED"
ENDPOINT = "OPENSHELL_TELEMETRY_ENDPOINT"


@pytest.fixture
def user_env(monkeypatch):
    """What the user's own shell (or an older setup) may export: telemetry on, and sent somewhere else."""
    monkeypatch.setenv(SWITCH, "true")
    monkeypatch.setenv(ENDPOINT, "http://127.0.0.1:9/events")


def _off(env) -> bool:
    return isinstance(env, dict) and env.get(SWITCH) == "false" and ENDPOINT not in env


def _ident(root, kind):
    return TG.make_ident(root, "openshell-v0.1.5", platform="windows" if kind == "mxc" else "linux")


# -- the gateway service ---------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["docker", "mxc"])
def test_the_gateway_service_runs_with_telemetry_off(tmp_path, kind):
    root = tmp_path / "hermes-root"
    root.mkdir()
    spec = GS.service_spec(kind, gw=GS.gateway_dir(root), port=17710, root=root, ident=_ident(root, kind))
    assert spec["env"][SWITCH] == "false"
    assert ENDPOINT not in spec["env"]


@pytest.mark.parametrize("kind", ["docker", "mxc"])
def test_the_bootstrap_hands_the_gateway_the_switch_whatever_the_login_environment_says(tmp_path, kind):
    """The real bootstrap around a child that prints its OPENSHELL_* variables: an inherited "on" and an
    inherited endpoint are gone, the service's own "off" is there."""
    root = tmp_path / "hermes-root"
    root.mkdir()
    spec = GS.service_spec(kind, gw=GS.gateway_dir(root), port=17710, root=root, ident=_ident(root, kind))
    script = ("import json, os; print('ENV=' + json.dumps({k: v for k, v in os.environ.items() "
              "if k.upper().startswith('OPENSHELL_TELEMETRY')}, sort_keys=True))")
    log = tmp_path / "logs" / "gateway.log"
    cfg = {"argv": [sys.executable, "-c", script], "env": spec["env"], "cwd": str(tmp_path), "log": str(log),
           "verify": {}}
    boot = TG.write_bootstrap(tmp_path, cfg)
    env = {**os.environ, SWITCH: "true", ENDPOINT: "http://127.0.0.1:9/events"}
    assert subprocess.run([sys.executable, str(boot)], timeout=120, env=env).returncode == 0
    line = next(l for l in log.read_text(encoding="utf-8").splitlines() if l.startswith("ENV="))
    assert json.loads(line[4:]) == {SWITCH: "false"}


@pytest.mark.parametrize("kind", ["docker", "mxc"])
def test_every_openshell_program_the_gateway_service_code_starts_has_telemetry_off(tmp_path, monkeypatch, user_env,
                                                                                    kind):
    """generate-certs, the CLI's registration, health and sandbox listing, status and removal: each call's
    environment, as handed to the process."""
    root = tmp_path / "hermes-root"
    root.mkdir()
    world = TG.World(monkeypatch, sandboxes=["hermes-leftover"])
    ident = _ident(root, kind)
    seen = []

    def run(cmd, **kw):
        seen.append((list(cmd), kw.get("env")))
        return world.run(cmd, **kw)

    monkeypatch.setattr(inst, "ensure_installed", lambda *a, **k: ident)
    extra = {"wxc_exec": tmp_path / "wxc-exec.exe"} if kind == "mxc" else {}
    GS.ensure_gateway(root, kind=kind, manager=world.manager, run=run, runtime=TG.Runtime(), base_image=False,
                      sleep=lambda s: None, timeout=5, **extra)
    GS.gateway_status(root, manager=world.manager, run=run, runtime=TG.Runtime())
    GS.remove_gateway(root, force=True, manager=world.manager, run=run, runtime=TG.Runtime())
    words = {" ".join(cmd[1:3]) for cmd, _ in seen}
    assert {"generate-certs --output-dir", "gateway add", "status", "sandbox list", "sandbox delete"} <= words
    assert [cmd[1:3] for cmd, env in seen if not _off(env)] == []


def test_the_gateway_clis_environment_cannot_be_given_another_answer(tmp_path, user_env):
    env = GS.cli_env(tmp_path / "gw", "hermes-x", extra={SWITCH: "true", "OPENSHELL_LOCAL_TLS_DIR": "pki"})
    assert env[SWITCH] == "false" and env["OPENSHELL_LOCAL_TLS_DIR"] == "pki" and ENDPOINT not in env


# -- a gateway service written by an older version of the plugin -----------------------------------------------

def _older_service(root, world, monkeypatch, ident, kind="docker"):
    """The gateway as a plugin without the switch left it: the same code with no telemetry setting writes the
    service's environment and records it in gateway.json; the service runs."""
    with monkeypatch.context() as older:
        older.setattr(GS, "TELEMETRY_OFF", {})
        TG.ensure(root, world, monkeypatch, ident, kind=kind)
    path = GS.gateway_dir(root) / "service" / GS.SERVICE_FILE
    assert SWITCH not in json.loads(path.read_text(encoding="utf-8"))["env"]
    world.calls.clear()
    return path


def test_an_older_gateway_service_is_rewritten_and_restarted_at_the_next_switch_on(tmp_path, monkeypatch):
    root = tmp_path / "hermes-root"
    root.mkdir()
    world = TG.World(monkeypatch)
    ident = TG.make_ident(root, "openshell-v0.1.5")
    path = _older_service(root, world, monkeypatch, ident)
    assert SWITCH not in json.loads(path.read_text(encoding="utf-8"))["env"]
    info = TG.ensure(root, world, monkeypatch, ident)  # what a launcher does before it creates its sandbox
    assert info["upgrade_pending"] is False
    assert json.loads(path.read_text(encoding="utf-8"))["env"][SWITCH] == "false"
    assert [c[0] for c in world.calls] == ["stop", "install", "start"]  # the running gateway had the old environment
    world.calls.clear()
    TG.ensure(root, world, monkeypatch, ident)
    assert world.calls == []  # current now: nothing restarts again


def test_gateway_status_says_what_the_service_is_set_to(tmp_path, monkeypatch):
    root = tmp_path / "hermes-root"
    root.mkdir()
    world = TG.World(monkeypatch)
    ident = TG.make_ident(root, "openshell-v0.1.5")
    path = _older_service(root, world, monkeypatch, ident)

    def status():
        return GS.gateway_status(root, manager=world.manager, run=world.run, runtime=TG.Runtime())["gateway"]

    assert status()["openshell_telemetry"] == "on"  # the older service file, as OpenShell reads it: unset is on
    TG.ensure(root, world, monkeypatch, ident)
    assert status()["openshell_telemetry"] == "off"
    for value, want in (("FALSE", "off"), (" 0 ", "off"), ("no", "off"), ("off", "off"), ("true", "on"), ("", "on")):
        svc = json.loads(path.read_text(encoding="utf-8"))
        svc["env"][SWITCH] = value
        path.write_text(json.dumps(svc), encoding="utf-8")
        assert GS.telemetry_setting(root) == want, value


def test_an_older_gateway_service_under_a_running_sandbox_is_rewritten_once_it_is_idle(tmp_path, monkeypatch):
    root = tmp_path / "hermes-root"
    root.mkdir()
    world = TG.World(monkeypatch, sandboxes=["hermes-other"])
    ident = TG.make_ident(root, "openshell-v0.1.5")
    path = _older_service(root, world, monkeypatch, ident)
    info = TG.ensure(root, world, monkeypatch, ident)
    assert info["upgrade_pending"] is True and world.calls == []  # never restarted under a running sandbox
    assert SWITCH not in json.loads(path.read_text(encoding="utf-8"))["env"]
    world.sandboxes.clear()
    info = TG.ensure(root, world, monkeypatch, ident)
    assert info["upgrade_pending"] is False and [c[0] for c in world.calls] == ["stop", "install", "start"]
    assert json.loads(path.read_text(encoding="utf-8"))["env"][SWITCH] == "false"


# -- the launcher's own CLI calls ------------------------------------------------------------------------------

def test_the_linux_drivers_cli_calls_and_its_forward_have_telemetry_off(tmp_path, monkeypatch, user_env):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)

    async def scenario():
        await sup.start()
        await sup.stop()

    asyncio.run(scenario())
    assert any("forward" in argv for argv, _ in rec.argvs) and any("import" in argv for argv, _ in rec.argvs)
    assert [argv[1:3] for argv, env in rec.argvs if not (env.get(SWITCH) == "false")] == []
    assert sup.driver._cli_env()[SWITCH] == "false"


def test_the_windows_drivers_cli_calls_and_its_forward_have_telemetry_off(tmp_path, monkeypatch, user_env):
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": WD.SECRET, "OTHER_TOKEN": WD.DECOY})
    fake = WD.FakeCli()
    forwards = []

    def popen(argv, **kw):
        forwards.append(kw.get("env"))
        return WD.Forward(argv, **kw)

    driver = W.OpenShellWindowsDriver(cfg, wxc_exec=tmp_path / "wxc-exec.exe", gateway=W.CliGateway(cfg, run=fake),
                                      popen=popen)
    driver.denied_paths_supported = True
    sup = WD._supervisor(layout, runtime, driver, bb)

    async def scenario():
        await sup.start()
        try:
            driver.apply_network({"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]})
            driver.proposals()
        finally:
            await sup.stop()

    asyncio.run(scenario())
    words = {" ".join(argv[1:3]) for argv, _ in fake.calls}
    assert {"sandbox create", "policy set", "sandbox delete"} <= words
    assert [argv[1:3] for argv, env in fake.calls if not _off(env)] == []
    assert forwards and all(_off(env) for env in forwards)
    # a provider key travels in the CLI's environment under its own name; a key named like the switch cannot turn it on
    assert W.CliGateway(cfg, run=fake).env({SWITCH: "true"})[SWITCH] == "false"
