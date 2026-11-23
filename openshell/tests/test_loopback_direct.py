"""Services on this computer and the sandbox's proxy variables (loopback_env.py).

Inside a Windows sandbox OpenShell sets the proxy variables with an empty NO_PROXY, and its proxy refuses loopback
addresses, so a program that follows the variables was refused for an address a direct connection reaches. The
launcher's Windows driver asks the plugin inside to list the loopback names in NO_PROXY; the Linux driver does not.
The client tests run real programs (Python's urllib, curl, Node) against a local service with the proxy variables
pointing at a stand-in proxy that refuses everything, as OpenShell's does for a loopback address.
"""
import asyncio
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading

import pytest

import openshell
import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell import loopback_env as E
from openshell.launcher import supervisor as S

NAMES = "127.0.0.1,localhost,::1"


def sandbox_environ(proxy_port: int = 3128, **extra) -> dict:
    """The variables OpenShell gives a Windows sandbox's programs: its proxy, and an empty NO_PROXY."""
    proxy = f"http://openshell:secret@127.0.0.1:{proxy_port}"
    env = {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "NO_PROXY": ""}
    if os.name != "nt":  # Windows names have one spelling; elsewhere OpenShell sets both
        env.update({"http_proxy": proxy, "https_proxy": proxy, "no_proxy": ""})
    return {**env, **extra}


# -- the plugin inside -------------------------------------------------------------------------------------

def test_the_loopback_names_are_the_ones_hermes_keeps_away_from_a_proxy():
    assert (E.LOOPBACK_ENV, E.DIRECT, E.LOOPBACK_HOSTS) == ("HERMES_SANDBOX_LOOPBACK", "direct",
                                                            ("127.0.0.1", "localhost", "::1"))
    core = pytest.importorskip("agent.proxy_bypass")  # Hermes's own list of what never goes through a proxy
    assert tuple(core.LOOPBACK_HOSTS) == E.LOOPBACK_HOSTS
    assert all(core.is_loopback_host(host) for host in E.LOOPBACK_HOSTS)  # nothing but loopback is ever named


def test_asked_by_the_launcher_the_plugin_lists_the_loopback_names_and_nothing_else():
    env = sandbox_environ(**{E.LOOPBACK_ENV: E.DIRECT})
    before = dict(env)
    assert E.apply(env) is True
    assert env["NO_PROXY"] == env["no_proxy"] == NAMES
    changed = {key for key in env if env[key] != before.get(key)}
    assert changed == {"NO_PROXY", "no_proxy"}  # the proxy itself stays where OpenShell put it
    assert E.apply(env) is True and env["NO_PROXY"] == env["no_proxy"] == NAMES  # once, however often it runs


def test_without_the_launchers_word_nothing_changes():
    for flag in ({}, {E.LOOPBACK_ENV: ""}, {E.LOOPBACK_ENV: "1"}, {E.LOOPBACK_ENV: "DIRECT"}, {E.LOOPBACK_ENV: "open"}):
        env = sandbox_environ(**flag)
        before = dict(env)
        assert E.apply(env) is False and env == before


def test_entries_already_there_stay_and_a_star_entry_is_left_alone():
    env = {"NO_PROXY": "corp.example.net, 127.0.0.1", "no_proxy": "*", E.LOOPBACK_ENV: E.DIRECT}
    assert E.apply(env) is True
    assert env["NO_PROXY"] == "corp.example.net,127.0.0.1,localhost,::1" and env["no_proxy"] == "*"


def test_the_plugin_applies_it_when_the_backend_loads_it(monkeypatch):
    class Ctx:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    for key, value in sandbox_environ().items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(E.LOOPBACK_ENV, raising=False)
    openshell.register(Ctx())
    assert os.environ["NO_PROXY"] == ""  # a host backend, a Linux sandbox: nothing asked for it
    monkeypatch.setenv(E.LOOPBACK_ENV, E.DIRECT)
    openshell.register(Ctx())
    assert os.environ["NO_PROXY"] == NAMES and os.environ.get("no_proxy", NAMES) == NAMES
    # what the backend starts from its terminal gets the same names (Hermes's own environment for commands)
    local = pytest.importorskip("tools.environments.local")
    run_env = local._make_run_env({})
    assert {value for key, value in run_env.items() if key.upper() == "NO_PROXY"} == {NAMES}
    assert run_env["HTTP_PROXY"] == sandbox_environ()["HTTP_PROXY"]


# -- the launcher: who asks ----------------------------------------------------------------------------------

def test_the_windows_driver_asks_for_it_and_sends_no_no_proxy_of_its_own(tmp_path, monkeypatch):
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TEST_MODEL_KEY": WD.SECRET})
    fake = WD.FakeCli()
    driver = WD._driver(cfg, fake, tmp_path)
    sup = WD._supervisor(layout, runtime, driver, bb)
    assert driver.capabilities()["host_loopback"] == "open"  # what the Sandbox page's sentence stands on

    async def scenario():
        await sup.start()
        try:
            create = next(argv for argv, env in fake.calls if argv[1:3] == ["sandbox", "create"])
            pairs = dict(create[i + 1].split("=", 1) for i, a in enumerate(create) if a == "--env")
            assert pairs[E.LOOPBACK_ENV] == E.DIRECT
            # OpenShell replaces these with its own values: asking for them here would only look like a setting
            assert not [key for key in pairs if key.upper() in ("NO_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")]
        finally:
            await sup.stop()

    asyncio.run(scenario())


def test_a_users_own_variable_cannot_turn_it_off_or_into_something_else(tmp_path):
    from types import SimpleNamespace

    from openshell.launcher import openshell_driver as OD

    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe")
    driver = WD._driver(cfg, WD.FakeCli(), tmp_path)
    env, _ = driver._sandbox_env(SimpleNamespace(env={"PATH": "C:\\x", E.LOOPBACK_ENV: "*"}, home=str(tmp_path),
                                                 config_dir=tmp_path / "state"))
    assert env[E.LOOPBACK_ENV] == E.DIRECT


def test_the_linux_driver_does_not_ask_for_it(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    assert sup.driver.capabilities()["host_loopback"] == "closed"  # its own loopback: the page makes no such claim

    async def scenario():
        await sup.start()
        try:
            env = [c for c in api.calls if c[0] == "create"][-1][2]["environment"]
            assert E.LOOPBACK_ENV not in env and not [key for key in env if "PROXY" in key.upper()]
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- real programs: refused through the proxy before, direct after ------------------------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    status = 200

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.server.seen.append(f"{self.command} {self.path}")
        body = b"denied" if self.status == 403 else b"ok"
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_CONNECT = _answer

    def log_message(self, *args):
        pass


class _Refusing(_Recorder):
    status = 403  # OpenShell's proxy on a loopback address: "not allowed by any policy"


@pytest.fixture
def stand_ins():
    """A service on this computer, and a proxy that refuses everything it is asked for."""
    servers = []
    for handler in (_Recorder, _Refusing):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.seen = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    yield servers
    for server in servers:
        server.shutdown()
        server.server_close()


def _client_env(proxy_port: int, direct: bool) -> dict:
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE")
           if key in os.environ}
    env.update(sandbox_environ(proxy_port, NODE_USE_ENV_PROXY="1"))
    if direct:
        env[E.LOOPBACK_ENV] = E.DIRECT
        assert E.apply(env)
    return env


_PYTHON = ("import sys, urllib.request, urllib.error\n"
           "try:\n"
           "    print(urllib.request.urlopen(urllib.request.Request(sys.argv[1], data=b'{}', method='POST'), "
           "timeout=20).status)\n"
           "except urllib.error.HTTPError as exc:\n"
           "    print(exc.code)\n")
_NODE = ("fetch(process.argv[1], {method: 'POST', body: '{}'}).then(r => console.log(r.status))"
         ".catch(e => console.log('failed ' + (e.cause && e.cause.code || e.message)))")


def _clients():
    yield "python", lambda url: [sys.executable, "-c", _PYTHON, url]
    curl = shutil.which("curl")
    if curl:
        yield "curl", lambda url: [curl, "-s", "-o", os.devnull, "-w", "%{http_code}", "--max-time", "20", "-X", "POST",
                                   "-d", "{}", url]
    node = shutil.which("node")
    if node:
        yield "node", lambda url: [node, "-e", _NODE, url]


def _ask(argv, env) -> str:
    done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
    return (done.stdout or "").strip() or f"exit {done.returncode}: {(done.stderr or '').strip()[-200:]}"


@pytest.mark.parametrize("name", ["python", "curl", "node"])
def test_a_program_that_follows_the_proxy_variables_reaches_a_local_service_directly(stand_ins, name):
    service, proxy = stand_ins
    argv = dict(_clients()).get(name)
    if argv is None:
        pytest.skip(f"{name} is not on PATH")
    target = f"127.0.0.1:{service.server_address[1]}"
    url = f"http://{target}/v1/telemetry"
    # as OpenShell starts it (the control): the request goes to the proxy, which refuses it
    answer = _ask(argv(url), _client_env(proxy.server_address[1], direct=False))
    if name == "node" and not proxy.seen:
        pytest.skip("this Node does not follow the proxy variables")  # an older Node: it was never refused
    assert answer == "403" or (name == "node" and answer.startswith("failed"))  # Node asks for a tunnel first
    assert service.seen == [] and len(proxy.seen) == 1 and target in proxy.seen[0]
    # with the loopback names listed: straight to the service, nothing more at the proxy
    assert _ask(argv(url), _client_env(proxy.server_address[1], direct=True)) == "200"
    assert service.seen == ["POST /v1/telemetry"] and len(proxy.seen) == 1


def test_localhost_by_name_goes_direct_too_and_every_other_name_still_goes_to_the_proxy(stand_ins):
    service, proxy = stand_ins
    port = service.server_address[1]
    env = _client_env(proxy.server_address[1], direct=True)
    python = dict(_clients())["python"]
    assert _ask(python(f"http://localhost:{port}/status"), env) == "200"
    assert service.seen == ["POST /status"] and proxy.seen == []
    for other in (f"http://service.example.net:{port}/x", f"http://host.openshell.internal:{port}/v1/chat",
                  f"http://127.0.0.1.example.net:{port}/x", f"http://10.0.0.7:{port}/x"):
        assert _ask(python(other), env) == "403"  # the proxy's answer: its policy still decides
    assert len(proxy.seen) == 4 and len(service.seen) == 1
    assert json.dumps(proxy.seen).count("example.net") == 2
