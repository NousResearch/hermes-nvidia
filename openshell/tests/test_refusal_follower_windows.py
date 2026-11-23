"""The Windows driver hears of refused connections as they happen (launcher/openshell_windows.py).

The launcher's look at OpenShell's records cost one CLI process per look on Windows, so nothing was copied into the
verdict file there and a program call that exited 0 was judged by its text alone. ``RefusalFollower`` follows the
gateway's own log file from a thread of the launcher (a look is the file's size; the file is opened only to read
what is new and closed again) and holds the refused connections of its sandbox in memory; ``recent_refusals`` hands
them to the launcher's feed, the same contract as the Docker driver's, and the sandbox's environment tells the hook
to look and for how long.

The lines below are a Windows gateway's log as recorded, colour escapes included (the store's folder shortened),
and records as ``openshell logs`` prints them.
"""
import asyncio
import calendar
import json
import os
import subprocess
import time
import types

import pytest

from openshell import sandbox_hook as H
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from test_cards import FakeDriver, _answer, _cards, _pump_requests, _setup, _turn_start, channel, harness  # noqa: F401

CURL = r"C:\Windows\System32\curl.exe"
# -- the gateway's log file, raw -------------------------------------------------------------------------------
CURL_HTTPS = b'\x1b[2m2026-11-22T03:47:43.947930Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:47:43.947Z OCSF NET:OPEN [MED] DENIED C:\\Windows\\System32\\curl.exe(0) -> example.com:443 [policy:- engine:opa] [reason:endpoint example.com:443 is not allowed by any policy] \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"'
CURL_HTTPS_JSON = b'\x1b[2m2026-11-22T03:47:43.948006Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:47:43.947Z OCSF-JSON {"class_uid":4001,"class_name":"Network Activity","category_uid":4,"category_name":"Network Activity","activity_id":1,"activity_name":"Open","type_uid":400101,"type_name":"Network Activity: Open","time":1795319263947,"dst_endpoint":{"domain":"example.com","port":443},"proxy_endpoint":{"ip":"127.0.0.1","port":3128},"actor":{"process":{"name":"C:\\\\Windows\\\\System32\\\\curl.exe","pid":0,"cmd_line":"-","parent_process":{"name":"-","pid":0}}},"firewall_rule":{"name":"-","type":"opa"},"action_id":2,"action":"Denied","disposition_id":2,"disposition":"Blocked","is_src_dst_assignment_known":true} \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"'
CURL_HTTP = b'\x1b[2m2026-11-22T03:51:18.252930Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:51:18.252Z OCSF HTTP:GET [MED] DENIED C:\\Windows\\System32\\curl.exe(0) -> GET http://example.com/probe-0 [policy:- engine:opa] [reason:endpoint example.com:80 is not allowed by any policy] \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"'
PYTHON_HTTPS = b'\x1b[2m2026-11-22T03:51:52.588743Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:51:52.588Z OCSF NET:OPEN [MED] DENIED C:\\store\\python-3.14.9+20261021-win32-x64\\python.exe(0) -> example.com:443 [policy:- engine:opa] [reason:endpoint example.com:443 is not allowed by any policy] \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"'
OTHER = (b'\x1b[2m2026-11-22T03:44:37.820729Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:44:37.820Z OCSF NET:OPEN [INFO] 127.0.0.1:47971 \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"',
         b'\x1b[2m2026-11-22T03:44:44.051628Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mopenshell_driver_mxc::driver\x1b[0m\x1b[2m:\x1b[0m 2026-11-22T03:44:44.051Z OCSF NET:CLOSE [INFO] 127.0.0.1:49634/tcp \x1b[3msandbox\x1b[0m\x1b[2m=\x1b[0mhermes-work \x1b[3mcomponent\x1b[0m\x1b[2m=\x1b[0m"supervisor"',
         b'\x1b[2m2026-11-22T03:44:30.414738Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2mopenshell_server\x1b[0m\x1b[2m:\x1b[0m OCSF JSONL audit log enabled (openshell-ocsf.<date>.log, daily rotation, keep 3) \x1b[3mocsf_jsonl_dir\x1b[0m\x1b[2m=\x1b[0mC:\\data\\openshell\\runtime\\gateway\\ocsf')
T_CURL_HTTPS = calendar.timegm((2026, 11, 22, 3, 47, 43)) + 0.947
BEFORE = T_CURL_HTTPS - 600.0         # a clock for followers that started before the recorded lines
# -- the same kind of record as ``openshell logs`` prints it -----------------------------------------------------
LOGS = {
    "curl refused": f"[1795218884.725] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED {CURL}(0) -> example.org:443 "
                    "[policy:- engine:opa] [reason:endpoint example.org:443 is not allowed by any policy]",
    "curl allowed": f"[1795218895.056] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED {CURL}(0) -> example.org:443 "
                    "[policy:allowed_host_example_org engine:opa]",
    "tunnel closed by a reload": "[1795222596.595] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED "
                                 "host.openshell.internal:47992 [policy:_provider_hermes_work_key engine:l7] "
                                 "[reason:L7 tunnel closed after policy reload [host:host.openshell.internal port:47992 "
                                 "captured_generation:2 current_generation:3]]",
    "alias refused": f"[1795155800.058] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED {CURL}(0) -> POST "
                     "http://host.openshell.internal:47994/v2/scrape [policy:- engine:opa]",
}


def test_a_refused_connection_is_read_from_the_gateways_log_line_escapes_and_all():
    assert b"\x1b[" in CURL_HTTPS and b"sandbox=hermes-work" not in CURL_HTTPS      # coloured, although a file
    assert W.relayed_refusal(CURL_HTTPS, "hermes-work") == {"time": T_CURL_HTTPS, "host": "example.com", "port": 443}
    assert T_CURL_HTTPS == 1795319263.947                                            # the record's own JSON time
    http = W.relayed_refusal(CURL_HTTP, "hermes-work")                               # a plain-http request: a URL
    assert http == {"time": 1795319478.252, "host": "example.com", "port": None}
    assert W.relayed_refusal(PYTHON_HTTPS, "hermes-work") == {"time": 1795319512.588, "host": "example.com", "port": 443}
    assert W.relayed_refusal(CURL_HTTPS + b"\r", "hermes-work")["host"] == "example.com"
    assert W.relayed_refusal(W._ANSI_RE.sub(b"", CURL_HTTPS), "hermes-work")["port"] == 443   # a log without colours
    # not kept: the JSON copy of the same record, another sandbox's line, and lines that are no refusal
    assert W.relayed_refusal(CURL_HTTPS_JSON, "hermes-work") is None
    assert W.relayed_refusal(CURL_HTTPS, "hermes-other") is None and W.relayed_refusal(CURL_HTTPS, "hermes-wor") is None
    for raw in (*OTHER, b"", b"[hermes-gateway-bootstrap] starting", CURL_HTTPS[:200]):
        assert W.relayed_refusal(raw, "hermes-work") is None, raw[:60]


def test_a_refused_connection_is_read_from_a_line_of_openshell_logs():
    row = lambda name: W.refusal_of(W.parse_log_lines(LOGS[name])[0])  # noqa: E731
    assert row("curl refused") == {"time": 1795218884.725, "host": "example.org", "port": 443}
    for name in ("curl allowed", "tunnel closed by a reload", "alias refused"):
        assert row(name) is None, name


def _until(cond, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.005)
    return False


def _append(path, *raws):
    with open(path, "ab") as fh:
        for raw in raws:
            fh.write(raw + b"\n")


def test_the_follower_reads_what_the_file_gains_from_its_start_on_and_never_holds_it_open(tmp_path, monkeypatch):
    log = tmp_path / "logs" / "gateway.log"
    log.parent.mkdir()
    _append(log, PYTHON_HTTPS)                                     # there before the sandbox: another run's
    follower = W.RefusalFollower(log, "hermes-work", clock=lambda: BEFORE)
    assert follower.look() == 0 and list(follower.recent) == []
    _append(log, OTHER[0], CURL_HTTPS, CURL_HTTPS_JSON, OTHER[2])
    assert follower.look() == 1                                    # one refusal: the JSON copy is not a second
    assert list(follower.recent) == [{"time": T_CURL_HTTPS, "host": "example.com", "port": 443}]
    with open(log, "ab") as fh:
        fh.write(CURL_HTTP[:150])                                  # half a line: the gateway is still writing it
    assert follower.look() == 0
    with open(log, "ab") as fh:
        fh.write(CURL_HTTP[150:] + b"\n")
    assert follower.look() == 1 and follower.recent[-1]["port"] is None
    assert follower.look() == 0                                    # nothing new: the file is not even opened
    with open(log, "ab") as fh:                                    # a whole line and the head of the next in one read
        fh.write(PYTHON_HTTPS + b"\n" + CURL_HTTPS[:120])
    assert follower.look() == 1 and follower.recent[-1]["time"] == 1795319512.588
    with open(log, "ab") as fh:
        fh.write(CURL_HTTPS[120:] + b"\n")
    assert follower.look() == 1 and follower.recent[-1] == {"time": T_CURL_HTTPS, "host": "example.com", "port": 443}
    # nothing holds the file: the gateway can rename it at its next start and remove it at its stop
    os.replace(log, log.with_name("gateway.log.1"))
    assert follower.look() == 0                                    # gone: no records yet, not an error
    _append(log, CURL_HTTPS)                                       # a new, shorter file: read from its start
    assert follower.look() == 1 and len(follower.recent) == 5
    os.remove(log)
    assert follower.look() == 0
    # a record older than the follower is another run's, even when the file is read from its start
    late = W.RefusalFollower(log, "hermes-work", clock=lambda: T_CURL_HTTPS + 3600.0)
    _append(log, CURL_HTTPS)
    assert late.look() == 0 and list(late.recent) == []
    assert follower.status()["bytes_read"] > 0 and follower.status()["running"] is False


def test_the_followers_thread_keeps_a_refusal_within_a_few_looks_and_starts_no_process(tmp_path, monkeypatch):
    log = tmp_path / "gateway.log"
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("the follower started a process"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("the follower started a process"))
    follower = W.RefusalFollower(log, "hermes-work", clock=lambda: BEFORE)     # no file yet: not an error
    follower.start()
    try:
        assert _until(lambda: follower.looks >= 2)
        began = time.monotonic()
        _append(log, CURL_HTTPS)
        assert _until(lambda: len(follower.recent) == 1)
        took = time.monotonic() - began
        assert took < 0.5, took                                    # as it happens (a look every 25 ms)
        assert follower.status()["running"] is True and W._FOLLOW_POLL <= 0.05
        print(f"the refusal was in memory {took * 1000:.0f} ms after its line was written")
    finally:
        follower.stop()
    assert not follower._thread.is_alive()                         # ended with the sandbox
    looks = follower.looks
    time.sleep(0.1)
    assert follower.looks == looks


def test_the_followers_memory_is_bounded(tmp_path):
    log = tmp_path / "gateway.log"
    follower = W.RefusalFollower(log, "hermes-work", clock=lambda: BEFORE)
    for i in range(W.RefusalFollower.RECENT + 40):
        _append(log, CURL_HTTPS.replace(b"example.com:443", b"h%d.example.org:443" % i))
    assert follower.look() == W.RefusalFollower.RECENT + 40
    assert len(follower.recent) == W.RefusalFollower.RECENT and follower.recent[-1]["host"] == "h295.example.org"


def test_the_windows_driver_offers_the_same_feed_as_the_docker_driver_and_tells_the_hook(tmp_path):
    recent = W.OpenShellWindowsDriver.recent_refusals
    log = tmp_path / "gateway.log"
    follower = W.RefusalFollower(log, "hermes-work", clock=lambda: BEFORE)
    _append(log, CURL_HTTPS, CURL_HTTP, OTHER[1], PYTHON_HTTPS)
    follower.look()
    driver = types.SimpleNamespace(_follower=follower)
    rows = recent(driver, 0.0)
    assert rows == [{"time": 1795319263.947, "host": "example.com", "port": 443},
                    {"time": 1795319478.252, "host": "example.com", "port": None},
                    {"time": 1795319512.588, "host": "example.com", "port": 443}]
    assert [r["time"] for r in recent(driver, 1795319400.0)] == [1795319478.252, 1795319512.588]
    rows[0]["host"] = "changed"
    assert recent(driver, 0.0)[0]["host"] == "example.com"                     # copies: the caller cannot edit the feed
    assert recent(types.SimpleNamespace(_follower=None), 0.0) == []            # before a start, after a stop
    assert set(rows[1]) == {"time", "host", "port"}                            # the Docker driver's row shape
    # the sandbox's environment: the hook looks only where verdicts are written, for this driver's own settle
    request = types.SimpleNamespace(env={H.VERDICTS_ENV: "C:/state/verdicts", "HERMES_HOME": "C:/h"},
                                    config_dir="C:/state", home="C:/h")
    stub = types.SimpleNamespace(_curl_home=lambda request, env: None, _managed_overrides=lambda request, env: None,
                                 _gateway_log=lambda: tmp_path / "logs" / "gateway.log")
    env, _ = W.OpenShellWindowsDriver._sandbox_env(stub, request)
    assert env[H.REFUSALS_ENV] == str(W.REFUSALS_SETTLE) and 0 < W.REFUSALS_SETTLE <= 0.5
    request.env.pop(H.VERDICTS_ENV)
    env, _ = W.OpenShellWindowsDriver._sandbox_env(stub, request)
    assert H.REFUSALS_ENV not in env
    assert float(str(OD.REFUSALS_SETTLE)) == OD.REFUSALS_SETTLE <= 0.5


def _driver(tmp_path, managed_root):
    cfg = types.SimpleNamespace(gateway_dir=tmp_path / "cli" / "openshell" / "gateways" / "hermes-x", managed_root=managed_root)
    driver = types.SimpleNamespace(cfg=cfg, _name="hermes-work", _follower=None)
    driver._stop_follower = lambda: W.OpenShellWindowsDriver._stop_follower(driver)
    driver._gateway_log = lambda: W.OpenShellWindowsDriver._gateway_log(driver)
    return driver


def test_the_driver_starts_the_follower_on_its_gateways_log_and_ends_it_with_the_sandbox(tmp_path):
    from openshell.launcher import gateway_service as GS

    root = tmp_path / "root"
    driver = _driver(tmp_path, root)
    W.OpenShellWindowsDriver._start_follower(driver)
    first = driver._follower
    # The file the gateway's own service writes (its definition's log), not the CLI's entry for the gateway.
    assert first.path == GS.gateway_log(root) == GS._definition(root, runtime=types.SimpleNamespace(
        python=tmp_path / "python.exe", code_dir=tmp_path)).log
    assert first.path == GS.gateway_dir(root) / "logs" / "gateway.log" and first.path != driver.cfg.gateway_dir / "logs" / "gateway.log"
    assert first.sandbox == "hermes-work" and first.status()["running"] is True
    W.OpenShellWindowsDriver._start_follower(driver)               # a restart: the old follower is ended first
    assert not first._thread.is_alive() and driver._follower is not first
    second = driver._follower
    W.OpenShellWindowsDriver._stop_follower(driver)
    assert not second._thread.is_alive() and driver._follower is None


def test_a_gateway_the_spec_names_has_no_log_to_follow_and_the_hook_is_not_told_to_look(tmp_path):
    """The launcher does not know where a gateway it did not start writes its log: no follower, and the sandbox's
    environment does not promise a feed, so the hook keeps its look at OpenShell's records for such a call."""
    driver = _driver(tmp_path, None)
    W.OpenShellWindowsDriver._start_follower(driver)
    assert driver._follower is None and W.OpenShellWindowsDriver.recent_refusals(driver, 0.0) == []
    request = types.SimpleNamespace(env={H.VERDICTS_ENV: "C:/state/verdicts", "HERMES_HOME": "C:/h"},
                                    config_dir="C:/state", home="C:/h")
    stub = types.SimpleNamespace(_curl_home=lambda request, env: None, _managed_overrides=lambda request, env: None,
                                 _gateway_log=driver._gateway_log)
    env, _ = W.OpenShellWindowsDriver._sandbox_env(stub, request)
    assert H.REFUSALS_ENV not in env


class FollowingDriver(FakeDriver):
    """The Windows driver's feed over the launcher's cards: ``recent_refusals`` from a follower of a log file; the
    one-shot log (``events``) stays empty."""
    recent_refusals = W.OpenShellWindowsDriver.recent_refusals

    def __init__(self, log):
        super().__init__()
        self._follower = W.RefusalFollower(log, "hermes-work")


def test_a_curl_that_exits_0_and_prints_nothing_is_held_on_its_card_from_the_followed_record(harness, channel,
                                                                                               monkeypatch, tmp_path):
    """``curl -s -o NUL https://example.com; echo done`` on Windows: exit 0, "done". The gateway's log gains the
    supervisor's line; the follower keeps it; the launcher's feed copies it to the verdict file; the hook finds it
    inside the driver's settle and the card holds the call."""
    log = tmp_path / "gateway.log"
    harness["sup"].driver = harness["driver"] = drv = FollowingDriver(log)
    monkeypatch.setenv(H.REFUSALS_ENV, str(W.REFUSALS_SETTLE))
    args, result = {"command": "curl -s -o NUL https://example.com; echo done"}, {"output": "done", "exit_code": 0}

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        started = time.time()
        drv._follower.start()
        await _turn_start(cards, conn)
        await asyncio.sleep(0.2)
        hook = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "terminal", args, json.dumps(result), session_id="chatA", status="ok",
            duration_ms=int((time.time() - started) * 1000)))
        await asyncio.sleep(0.05)                           # the hook has looked and found nothing yet
        refused = time.time() - 0.1                         # the supervisor refused curl just before the call ended
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(refused)) + (".%03dZ" % int(refused % 1 * 1000))
        _append(log, CURL_HTTPS.replace(b"2026-11-22T03:47:43.947Z", stamp.encode()))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == "example.com"
        [confirmed] = [r for r in cards._records if r.get("event") == "confirmed"]
        assert confirmed["how"] == "openshell records, one look (record feed)" and confirmed["refused"] == ["example.com"]
        await cards._from_client(conn, _answer(card, "deny"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["output"] == "done" and "The user denied network access to example.com" in out["sandbox"]
        drv._follower.stop()
        await cards.stop()

    asyncio.run(main())
