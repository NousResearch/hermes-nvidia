"""A program call that SUCCEEDED although a program in it was refused is held on its card, when OpenShell's records
already show the refusal (sandbox_hook.py, launcher/refusals.py, launcher/verdicts.py, launcher/cards.py,
launcher/openshell_driver.py).

Recorded on Windows: asked to try a site from curl, the model wrote ``curl -s https://<site>/ | head -c 2000``. The
proxy refused curl, curl printed nothing, and the pipeline exited 0: nothing in the result said anything had gone
wrong, the call returned at once, and the card came seconds later from OpenShell's draft, when the model was
already in its next step (once a model request had started). The recorded call is replayed below with a synthetic
host.

The rule: nothing waits. While a terminal / execute_code call is open, the launcher copies the refusals a driver
hears of as they happen (the Docker driver: the supervisor's own record stream) into the verdict file. When such a
call returns successfully and named a host, the hook reads that file once; only when it lists a host the call
named as refused inside the call does it relay those hosts, marked ``zero_wait``. The launcher looks at the
records once and raises the card, with the call held, for a host they show refused between the call's start and its
end. Never a card on a name alone; a record from before the call started never counts; a host every program may
already reach is skipped; every other successful call returns as it came. Where the launcher copies nothing (a
driver that does not follow the record stream: it does not set ``HERMES_SANDBOX_REFUSALS``), the hook opens no file.
"""
import asyncio
import json
import os
import time
import types

import pytest

from openshell import sandbox_hook as H
from openshell.launcher import cards as C
from openshell.launcher import openshell_driver as OD
from openshell.launcher import refusals as R
from openshell.launcher import verdicts as V
from test_cards import (FakeDriver, _answer, _cards, _chat_b, _interrupts, _pump_requests, _settle,  # noqa: F401
                        _setup, _steers, _turn_start, _until, channel, harness)
from test_openshell_driver import _supervisor

SITE = "shop.example.com"
SITE_RULE = "allowed_host_shop_example_com"
CURL = "/usr/bin/curl"
# The recorded call (synthetic host): a pipeline whose curl was refused. Exit 0, nothing printed.
PIPE = ({"command": f"curl -s -L https://{SITE}/ | head -c 2000"}, {"output": "", "exit_code": 0, "error": None})


class StreamDriver(FakeDriver):
    """A driver that hears of a refusal as it happens (the supervisor's own record stream), well before the
    gateway's log shows it: ``events`` stays empty here."""

    def __init__(self):
        super().__init__()
        self.stream: list = []

    def refuse(self, host, port=443, t=None):
        self.stream.append({"time": time.time() if t is None else t, "host": host, "port": port})

    def recent_refusals(self, since):
        self.calls.append(("recent_refusals", since))
        return [dict(row) for row in self.stream if row["time"] >= since]


class NoRecordsDriver(FakeDriver):
    """A driver that keeps no record of what it refused: no audit events, no drafts, no stream."""
    capabilities_info = {**FakeDriver.capabilities_info, "requests_supported": False, "audit_events": False}


@pytest.fixture
def drv(harness, monkeypatch):
    """The stream driver, and what it tells the hook through the sandbox's environment."""
    harness["sup"].driver = driver = StreamDriver()
    harness["driver"] = driver
    monkeypatch.setenv(H.REFUSALS_ENV, str(OD.REFUSALS_SETTLE))
    return driver


def _hook(tool, args, result, session="chatA", ran=0.2):
    """The hook on a worker thread, called the way core calls it for a call that succeeded after *ran* seconds."""
    text = result if isinstance(result, str) else json.dumps(result)
    return asyncio.to_thread(H.resolve, tool, args, text, session_id=session, status="ok",
                             duration_ms=int(ran * 1000))


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


def _request(rid, host=SITE, *, started, until=None, chat="chatA", **extra):
    """A zero-wait request as the hook writes it: the call ran from *started* to *until* (now when None)."""
    return {"id": rid, "kind": "network", "session_id": chat, "tool": "terminal", "strength": "candidate",
            "zero_wait": True, "t": started, "until": time.time() if until is None else until, "wait": 30.0,
            "hosts": [{"host": host, "port": 443, "source": "text"}], **extra}


def _looks(drv):
    return [c for c in drv.calls if c[0] in ("recent_refusals", "events")]


async def _refused_in_the_running_call(cards, conn, drv, host=SITE, live="live1"):
    """The agent's terminal call runs, the proxy refuses a program in it, and the launcher has copied the record
    to the verdict file. Returns the call's start."""
    started = time.time()
    await _turn_start(cards, conn, live=live)
    drv.refuse(host)
    assert await _until(lambda: host in cards.verdicts.refused)
    return started


def _request_files(cards):
    directory = cards._requests_dir
    return sorted(p.name for p in directory.iterdir()) if directory is not None and directory.is_dir() else []


# -- the recorded call, held at the tool boundary --------------------------------------------------------

def test_the_recorded_pipeline_that_exits_0_is_held_on_its_card_and_allow_tells_the_agent_to_retry(harness, channel,
                                                                                                    drv):
    """``curl -s -L https://<site>/ | head -c 2000`` returns exit 0 and nothing. OpenShell's record of the refused
    curl is already there, so the hook relays the site and the card is raised with the call held: the model gets
    no result, and so starts no request, until the user answers."""
    sup = harness["sup"]
    args, result = PIPE

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        started = await _refused_in_the_running_call(cards, conn, drv)
        hook = asyncio.ensure_future(_hook("terminal", args, result, ran=time.time() - started))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and card["params"]["kind"] == "network"
        [relayed] = _events(cards, "relayed")
        assert relayed["strength"] == "candidate" and [h["host"] for h in relayed["hosts"]] == [SITE]
        assert relayed["zero_wait"] is True
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["how"] == "openshell records, one look (record feed)" and confirmed["refused"] == [SITE]
        assert "waited" not in confirmed
        [raised] = _events(cards, "raised")
        assert raised["origin"] == "hook" and raised["turn_running"] is True
        await _settle(20)
        assert not hook.done() and _interrupts(conn) == []            # held: the agent has not moved on
        # OpenShell's draft for the same refusal is listed a moment later: it joins the card
        drv.add_chunk("d1", host=SITE, binary=CURL)
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1 and _interrupts(conn) == []
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["exit_code"] == 0 and out["output"] == ""          # the result itself is as it came
        assert out["sandbox"].startswith(f"[Sandbox] The sandbox blocked this call's connection to {SITE}. "
                                         f"The user allowed network access to {SITE}")
        assert "retry the request" in out["sandbox"]
        assert sup.applies == [[SITE_RULE]] and _interrupts(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_deny_reaches_the_held_successful_call_with_the_users_reason(harness, channel, drv):
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        started = await _refused_in_the_running_call(cards, conn, drv)
        hook = asyncio.ensure_future(_hook("terminal", *PIPE, ran=time.time() - started))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "deny", "Use the mirror instead."))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["exit_code"] == 0
        assert f"The user denied network access to {SITE}. Reason: Use the mirror instead." in out["sandbox"]
        assert harness["sup"].applies == []
        await cards.stop()

    asyncio.run(main())


def test_execute_code_that_succeeded_is_held_the_same_way(harness, channel, drv):
    """The code caught the error itself and printed nothing: status success."""
    code = ("import urllib.request\ntry:\n    urllib.request.urlopen('https://api.example.org/v1/items')\n"
            "except Exception:\n    pass")

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        started = time.time()
        await _turn_start(cards, conn, tool_name="execute_code")
        drv.refuse("api.example.org")
        assert await _until(lambda: "api.example.org" in cards.verdicts.refused)
        hook = asyncio.ensure_future(_hook("execute_code", {"code": code}, {"status": "success", "output": ""},
                                           ran=time.time() - started))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == "api.example.org"
        await _settle(20)
        assert not hook.done()
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "blocked this call's connection to api.example.org." in out["sandbox"]
        await cards.stop()

    asyncio.run(main())


def test_only_the_host_the_records_show_refused_is_relayed_and_carded(harness, channel, drv, monkeypatch):
    """The command names two sites and its output a third; one was refused. The hook relays that one only."""
    sent = []
    send = H._send
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or send(request))

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        started = time.time()
        await _turn_start(cards, conn)
        drv.refuse("b.example.org")
        assert await _until(lambda: "b.example.org" in cards.verdicts.refused)
        hook = asyncio.ensure_future(_hook(
            "terminal", {"command": "curl -s https://a.example.org/x | wc -c; curl -s https://b.example.org/y | wc -c"},
            {"output": "1256\n0\nsee https://docs.example.net/help", "exit_code": 0}, ran=time.time() - started))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == "b.example.org"
        [request] = sent
        assert request["zero_wait"] is True and request["strength"] == "candidate"
        assert request["hosts"] == [{"host": "b.example.org", "port": 443, "source": "text"}]
        assert started - 0.5 <= request["t"] <= request["until"] <= time.time()
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "connection to b.example.org." in out["sandbox"] and "a.example.org" not in out["sandbox"]
        await cards.stop()

    asyncio.run(main())


def test_a_second_chats_successful_call_raises_its_card_in_that_chat_only(harness, channel, drv):
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        await _turn_start(cards, conn)                    # chat A's turn runs a call too
        await _chat_b(cards, conn)
        started = await _refused_in_the_running_call(cards, conn, drv, live="liveB")
        hook = asyncio.ensure_future(_hook("terminal", *PIPE, session="chatB", ran=time.time() - started))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["session_id"] == "liveB" and cards.open[card["id"]]["chat"] == "chatB"
        await cards._from_client(conn, _answer(card, "deny"))
        assert "The user denied network access" in json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        await _settle()
        assert _steers(conn) == [] and _interrupts(conn) == []        # nothing reaches chat A
        await cards.stop()

    asyncio.run(main())


def test_a_card_openshells_draft_raised_first_is_the_one_the_successful_call_is_held_on(harness, channel, drv):
    """A longer command: the draft is listed while the call still runs and raises the card (which would pause the
    turn when the call ends). The call then returns with exit 0: it is held on that card, not released into a
    pause, and no second card is raised."""
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        started = await _refused_in_the_running_call(cards, conn, drv)
        drv.add_chunk("d1", host=SITE, binary=CURL)
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert _events(cards, "raised")[0]["origin"] == "proposal:tool"
        assert cards.status()["paused"]["chatA"]["state"] == "pending"
        hook = asyncio.ensure_future(_hook("terminal", *PIPE, ran=time.time() - started))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        await _settle(20)
        assert len(_cards(conn)) == 1 and not hook.done()
        assert "chatA" not in cards.status()["paused"] and _interrupts(conn) == []
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert f"The user allowed network access to {SITE}" in out["sandbox"]
        await cards.stop()

    asyncio.run(main())


# -- every other successful call returns as it came ------------------------------------------------------

def test_a_successful_call_whose_host_was_not_refused_returns_after_a_short_look_and_relays_nothing(harness, channel,
                                                                                                    drv):
    """Most successful commands that name a site reached it. The hook looks at the verdict file for as long as
    the driver says a record can trail the call's return, finds no refusal of that site in the call, and returns:
    no request to the launcher."""
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        await _refused_in_the_running_call(cards, conn, drv, host="other.example.net")   # another site's refusal
        args = {"command": f"curl -s -L https://{SITE}/ | head -c 2000"}
        result = json.dumps({"output": "<!doctype html><html><head><title>Shop</title>", "exit_code": 0})
        began = time.perf_counter()
        out = H.resolve("terminal", args, result, session_id="chatA", status="ok", duration_ms=150)
        took = time.perf_counter() - began
        assert out is None and OD.REFUSALS_SETTLE <= took < OD.REFUSALS_SETTLE + 0.25, took
        await _settle(20)
        assert _request_files(cards) == [] and _events(cards, "relayed") == [] and _cards(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_what_a_successful_call_costs(harness, channel, drv, monkeypatch):
    """The work added to a successful terminal call, measured apart from the bounded look for a late record
    (which only a call that names a host gets): reading the result for names, and one read of the verdict file.
    Each well under the "few milliseconds" a tool call may cost."""
    monkeypatch.setenv(H.REFUSALS_ENV, "0")
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        await _refused_in_the_running_call(cards, conn, drv, host="other.example.net")
        for i in range(12):                               # a verdict file as full as a long session leaves it
            cards.verdicts.target(V.net_key(f"h{i}.example.org"), kind="network", host=f"h{i}.example.org",
                                  status="allowed", scope="allow")
        await cards.stop()

    asyncio.run(main())
    page = "<html>" + "x" * 2000 + "</html>"
    listing = "\n".join(f"-rw-r--r-- 1 agent agent {i * 37} Jan  1 00:00 file{i}.txt" for i in range(400))
    calls = [("names a host", {"command": f"curl -s -L https://{SITE}/ | head -c 2000"}, {"output": page, "exit_code": 0}),
             ("names no host, 24 KB printed", {"command": "ls -l build"}, {"output": listing, "exit_code": 0}),
             ("names no host", {"command": "git status --short"}, {"output": "", "exit_code": 0})]
    rounds = 300
    for label, args, result in calls:
        text = json.dumps(result)
        began = time.perf_counter()
        assert H.resolve("terminal", args, text, session_id="chatA", status="ok", duration_ms=80) is None
        assert time.perf_counter() - began < 0.25, "a successful call waited"
        began = time.perf_counter()
        for _ in range(rounds):
            H.resolve("terminal", args, text, session_id="chatA", status="ok", duration_ms=80)
        whole = (time.perf_counter() - began) / rounds
        began = time.perf_counter()
        for _ in range(rounds):
            H.recorded_refusals(R.named_destinations("terminal", args, text, scan=R.NAMED_SCAN), time.time() - 0.08)
        added = (time.perf_counter() - began) / rounds
        assert added <= whole + 0.001 and whole < 0.005, (label, added, whole)
        print(f"successful terminal call, {label} ({len(text)} bytes): the hook takes {whole * 1e6:.0f} microseconds, "
              f"of which the new look {added * 1e6:.0f}")


def test_a_verdict_file_that_shows_nothing_returns_the_call_as_it_came(tmp_path, monkeypatch):
    """A file the launcher is replacing this instant, a file with no list, a broken list: the successful call's
    result returns as it came, after the bounded look and no longer."""
    monkeypatch.setenv(H.VERDICTS_ENV, str(tmp_path))
    monkeypatch.setenv(H.REFUSALS_ENV, "0.04")
    sent = []
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    named = [(SITE, 443, "text")]
    now = time.time()
    path = tmp_path / V.VERDICTS_FILE
    assert H.recorded_refusals(named, now - 1.0) == []                    # no file
    for body in ("{broken", "[1, 2]", json.dumps({"format": 1}), json.dumps({"refused": [SITE]}),
                 json.dumps({"refused": {SITE: "soon"}}), json.dumps({"refused": {SITE: True}}),
                 json.dumps({"refused": {"other.example.net": now}})):
        path.write_text(body, encoding="utf-8")
        assert H.recorded_refusals(named, now - 1.0) == [], body
        assert H.resolve("terminal", *[PIPE[0], json.dumps(PIPE[1])], status="ok", duration_ms=1000) is None
    path.write_text(json.dumps({"refused": {SITE: now - 0.5}}), encoding="utf-8")
    assert H.recorded_refusals(named, now - 1.0) == named
    assert H.recorded_refusals([], now - 1.0) == [] and sent == []
    # where the launcher copies no refusals (the driver did not say it does), a successful call opens no file at all
    monkeypatch.delenv(H.REFUSALS_ENV)
    with monkeypatch.context() as patch:
        patch.setattr(H.Path, "read_text", lambda *a, **k: pytest.fail("the hook opened a file nothing is copied to"))
        patch.setattr(H.Path, "stat", lambda *a, **k: pytest.fail("the hook looked at a file nothing is copied to"))
        assert H.resolve("terminal", PIPE[0], json.dumps(PIPE[1]), status="ok", duration_ms=1000) is None
    assert sent == []


# -- a record from before the call started never counts ---------------------------------------------------

def test_the_hook_does_not_relay_a_host_refused_before_its_call_started(harness, channel, drv, monkeypatch):
    """The site was refused five seconds ago, in an earlier call; this call, one second long, only names it."""
    sent = []
    send = H._send
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or send(request))

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        await _turn_start(cards, conn)
        cards.verdicts.note_refused({SITE: time.time() - 5.0})
        args = {"command": f"echo see https://{SITE}/docs"}
        result = json.dumps({"output": f"see https://{SITE}/docs", "exit_code": 0})
        assert H.resolve("terminal", args, result, session_id="chatA", status="ok", duration_ms=1000) is None
        assert sent == [] and _request_files(cards) == []
        # the same file, read for a call long enough to hold that refusal: relayed
        hook = asyncio.ensure_future(_hook("terminal", args, json.loads(result), ran=6.0))
        assert await _until(lambda: sent)
        assert sent[0]["zero_wait"] is True and [h["host"] for h in sent[0]["hosts"]] == [SITE]
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        assert await asyncio.wait_for(hook, 10) is None               # ... and the launcher's own look says no
        assert _cards(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_the_launcher_counts_only_a_record_inside_the_calls_own_time(harness, channel, drv):
    """One look at the records, for a call that ran from 3 s ago to 2 s ago. A refusal before it started, and one
    after it ended, are not this call's; one inside it is."""
    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool=False)
        now = time.time()
        drv.refuse(SITE, t=now - 8.0)                     # before the call started
        await cards.on_request(_request("z-before", started=now - 3.0, until=now - 2.0))
        drv.stream.clear()
        drv.refuse(SITE, t=now - 0.5)                     # after it ended
        await cards.on_request(_request("z-after", started=now - 3.0, until=now - 2.0))
        assert _cards(conn) == [] and cards.open == {}
        assert [r["refused"] for r in _events(cards, "confirmed")] == [[], []]
        assert {cards.verdicts.requests[r]["status"] for r in ("z-before", "z-after")} == {"refused"}
        assert "refused none of" in cards.verdicts.requests["z-before"]["detail"]
        drv.refuse(SITE, t=now - 2.5)                     # inside it
        await cards.on_request(_request("z-inside", started=now - 3.0, until=now - 2.0))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE
        assert cards.verdicts.requests["z-inside"]["status"] == "card"
        # a request that does not say when its call started has no time a record could lie in
        drv.refuse("late.example.org", t=now)
        await cards.on_request(_request("z-untimed", host="late.example.org", started=0.0))
        assert len(_cards(conn)) == 1 and cards.verdicts.requests["z-untimed"]["status"] == "refused"
        await cards.stop()

    asyncio.run(main())


# -- never a card on a name alone, and never a wait --------------------------------------------------------

def test_a_zero_wait_request_with_no_record_gets_no_card_and_its_answer_at_once(harness, channel, drv):
    """Whatever a request claims, the launcher raises nothing without a record, and it does not look twice: the
    answer is there in a fraction of the time a failed call's candidates are looked for."""
    assert C.CANDIDATE_WAIT >= 1.0                        # the real bound is in force here

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool=False)
        began = time.monotonic()
        await cards.on_request(_request("z1", started=time.time() - 1.0))
        took = time.monotonic() - began
        assert took < 0.5, took
        assert _cards(conn) == [] and cards.open == {} and len(_looks(drv)) == 1
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["refused"] == [] and confirmed["candidates"] == [SITE]
        assert cards.verdicts.requests["z1"]["status"] == "refused"
        # a forged request: its host marked as named by a refusal
        await cards.on_request(_request("z2", started=time.time() - 1.0,
                                        hosts=[{"host": SITE, "port": 443, "source": "refusal"}]))
        assert _cards(conn) == [] and cards.verdicts.requests["z2"]["status"] == "refused"
        await cards.stop()

    asyncio.run(main())


def test_a_driver_without_records_never_cards_a_successful_call(harness, channel):
    harness["sup"].driver = harness["driver"] = NoRecordsDriver()

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        assert cards._feed is None                        # nothing to copy from
        await cards.on_request(_request("z1", started=time.time() - 1.0))
        assert _cards(conn) == [] and cards.verdicts.requests["z1"]["status"] == "refused"
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["refused"] == [] and confirmed["how"].endswith("(None)")
        await cards.stop()

    asyncio.run(main())


def test_a_driver_with_audit_events_only_is_asked_once(harness, channel):
    """No stream: the one look is at the driver's audit events (and the hook would not have asked: nothing copies
    refusals to the verdict file here)."""
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        assert cards._feed is None and cards.verdicts.refused == {}
        now = time.time()
        drv.deny(SITE, binary=CURL, t=now - 8.0)
        await cards.on_request(_request("z-before", started=now - 3.0))
        assert _cards(conn) == [] and len(_looks(drv)) == 1
        drv.deny(SITE, binary=CURL, t=now - 1.0)
        await cards.on_request(_request("z-inside", started=now - 3.0))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and len(_looks(drv)) == 2
        assert _events(cards, "confirmed")[-1]["how"] == "openshell records, one look (audit events)"
        await cards.stop()

    asyncio.run(main())


def test_a_host_every_program_may_already_reach_is_skipped_without_a_look(harness, channel, drv):
    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool=False)
        now = cards._clock()
        cards.grants.append({"kind": "network", "scope": "allow", "host": SITE, "ports": [80, 443],
                             "rule_name": SITE_RULE, "rule": C.host_rule(SITE, (80, 443)),
                             "label": None, "chat": "chatA", "applied_at": now - 60.0, "answered_at": now - 61.0})
        drv.refuse(SITE, t=time.time() - 0.5)             # whatever the records say
        await cards.on_request(_request("z1", started=time.time() - 1.0))
        assert _cards(conn) == [] and _looks(drv) == [] and _events(cards, "confirmed") == []
        answer = cards.verdicts.requests["z1"]
        assert answer["status"] == "refused" and "already reach" in answer["detail"]
        await cards.stop()

    asyncio.run(main())


# -- the backstop is unchanged -----------------------------------------------------------------------------

def test_a_refusal_the_records_do_not_show_yet_is_carded_from_the_draft_and_pauses_the_turn(harness, channel, drv):
    """The record trails the call: the hook finds nothing and the result returns at once. OpenShell's draft then
    raises the card as before, and it pauses the turn."""
    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        assert H.resolve("terminal", PIPE[0], json.dumps(PIPE[1]), session_id="chatA", status="ok",
                         duration_ms=90) is None
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
            "type": "tool.complete", "session_id": "live1",
            "payload": {"name": "terminal", "tool_id": "t1", "result": json.dumps(PIPE[1])}}})
        assert _events(cards, "relayed") == [] and _cards(conn) == []
        drv.add_chunk("d1", host=SITE, binary=CURL)
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and _events(cards, "raised")[0]["origin"] == "proposal:tool"
        assert await _until(lambda: _interrupts(conn))
        assert _interrupts(conn)[0]["params"] == {"session_id": "live1", "resume": True}
        await cards.stop()

    asyncio.run(main())


# -- the launcher's copy of the records ----------------------------------------------------------------------

def test_refusals_are_copied_to_the_verdict_file_only_while_a_program_call_is_open(harness, channel, drv):
    path = channel.state_dir / "verdicts" / V.VERDICTS_FILE

    def on_file():
        try:
            return json.loads(path.read_text(encoding="utf-8")).get("refused")
        except (OSError, ValueError):
            return None

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        drv.refuse("early.example.org")                   # no call runs: nobody's
        await _settle(20)
        assert cards._feed is None and not cards.verdicts.refused and not on_file()
        await _turn_start(cards, conn, tool_name="web_extract")       # not a program call
        await _settle(20)
        assert cards._feed is None and not _looks(drv)
        drv.stream.clear()
        drv.refuse("old.example.org", t=time.time() - 5.0)            # before the call below starts
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
            "type": "tool.start", "session_id": "live1", "payload": {"name": "terminal", "tool_id": "t2"}}})
        assert cards._feed is not None and not cards._feed.done()
        began = time.time()
        drv.refuse(SITE)
        assert await _until(lambda: SITE in cards.verdicts.refused)
        assert time.time() - began < 1.0
        assert set(cards.verdicts.refused) == {SITE} and set(on_file()) == {SITE}
        assert abs(on_file()[SITE] - drv.stream[-1]["time"]) < 0.001
        # nothing new: the file is not written again
        writes = []
        write = cards.verdicts._write
        cards.verdicts._write = lambda: writes.append(1) or write()
        looks = len(_looks(drv))
        assert await _until(lambda: len(_looks(drv)) >= looks + 5)
        assert writes == []
        drv.refuse("b.example.org")
        assert await _until(lambda: "b.example.org" in cards.verdicts.refused)
        assert len(writes) == 1
        # the call ends: the copying stops
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
            "type": "tool.complete", "session_id": "live1",
            "payload": {"name": "terminal", "tool_id": "t2", "result": "ok"}}})
        assert await _until(lambda: cards._feed.done())
        looks = len(_looks(drv))
        drv.refuse("after.example.org")
        await _settle(20)
        assert len(_looks(drv)) == looks and "after.example.org" not in cards.verdicts.refused
        await cards.stop()

    asyncio.run(main())


def test_a_driver_that_does_not_hear_of_refusals_as_they_happen_copies_nothing(harness, channel):
    """The gateway's log tail trails a refusal by up to half a second and costs a call each look: it is no feed."""
    drv = harness["driver"]
    assert not os.environ.get(H.REFUSALS_ENV)

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        await _turn_start(cards, conn)
        drv.deny(SITE, binary=CURL)
        await _settle(30)
        assert cards._feed is None and cards.verdicts.refused == {} and _looks(drv) == []
        assert H.resolve("terminal", PIPE[0], json.dumps(PIPE[1]), session_id="chatA", status="ok",
                         duration_ms=90) is None
        assert _request_files(cards) == []
        # even a list that names the site (written by hand here) is not read: nothing told the hook to look
        cards.verdicts.note_refused({SITE: time.time()})
        assert H.resolve("terminal", PIPE[0], json.dumps(PIPE[1]), session_id="chatA", status="ok",
                         duration_ms=90) is None
        assert _request_files(cards) == [] and _events(cards, "relayed") == []
        await cards.stop()

    asyncio.run(main())


def test_the_verdict_file_keeps_the_newest_refusals_for_a_short_while(tmp_path):
    now = [1_800_000_000.0]
    verdicts = V.Verdicts(tmp_path, clock=lambda: now[0])
    path = tmp_path / V.VERDICTS_FILE
    assert verdicts.note_refused({}) is False and not path.exists()
    assert verdicts.note_refused({SITE: now[0] - 1.0}) is True
    assert json.loads(path.read_text(encoding="utf-8"))["refused"] == {SITE: now[0] - 1.0}
    stamp = path.stat().st_mtime_ns
    assert verdicts.note_refused({SITE: now[0] - 1.0}) is False       # known: not written again
    assert verdicts.note_refused({SITE: now[0] - 3.0}) is False       # older than what is known
    assert verdicts.note_refused({SITE: now[0] - 1.0 + V.REFUSED_STEP / 2}) is False   # a retry loop's next refusal
    assert path.stat().st_mtime_ns == stamp and verdicts.refused == {SITE: now[0] - 1.0}
    assert 0 < V.REFUSED_STEP < R.ZERO_WAIT_SKEW
    assert verdicts.note_refused({SITE: now[0] - 0.5, "b.example.org": now[0] - 0.2, 7: now[0],
                                  "c.example.org": "soon", "d.example.org": True}) is True
    assert verdicts.refused == {SITE: now[0] - 0.5, "b.example.org": now[0] - 0.2}
    # only the newest REFUSED_MAX, and none older than REFUSED_TTL
    verdicts.note_refused({f"h{i}.example.org": now[0] - 10.0 + i * 0.01 for i in range(V.REFUSED_MAX + 8)})
    assert len(verdicts.refused) == V.REFUSED_MAX and SITE in verdicts.refused
    assert "h0.example.org" not in verdicts.refused
    now[0] += V.REFUSED_TTL
    verdicts.note_refused({"new.example.org": now[0]})
    assert set(verdicts.refused) == {"new.example.org"}
    assert set(verdicts.snapshot()) >= {"requests", "targets", "refused"}
    verdicts.reset()
    assert verdicts.refused == {} and json.loads(path.read_text(encoding="utf-8"))["refused"] == {}


# -- what the hook relays, and what the launcher reads -------------------------------------------------------

def test_which_hosts_a_successful_call_names():
    named = R.named_destinations
    hosts = lambda *a, **k: [(h, p) for h, p, _ in named(*a, **k)]  # noqa: E731
    ok = {"output": "", "exit_code": 0}
    assert hosts("terminal", *PIPE) == [(SITE, 443)]
    assert {s for _, _, s in named("terminal", *PIPE)} == {R.SOURCE_TEXT}
    assert hosts("terminal", {"command": "wget -q example.org:8443/x.tgz || true"}, ok) == [("example.org", 8443)]
    assert hosts("terminal", {"command": "make test"}, {"output": "ok", "exit_code": 0}) == []
    # URLs the output shows come after the command's; addresses, loopback names and the gateway alias never count
    out = {"output": "moved: http://cdn.example.net/x\nsee http://127.0.0.1:8080/ https://host.openshell.internal/v1",
           "exit_code": 0}
    assert hosts("terminal", {"command": "curl -sL https://example.org/ | head"}, out) == [("example.org", 443),
                                                                                         ("cdn.example.net", 80)]
    assert hosts("execute_code", {"code": "get('https://api.example.org/v1')"},
                 {"status": "success", "output": ""}) == [("api.example.org", 443)]
    # other tools never
    assert named("web_extract", {"urls": [f"https://{SITE}/"]}, {"success": True}) == []
    assert named("read_file", {"path": f"https://{SITE}/"}, "text") == []
    # of a long printout only the start is read for names
    long = {"output": "x" * 300 + " https://far.example.org/", "exit_code": 0}
    assert hosts("terminal", {"command": "cat notes.txt"}, long) == [("far.example.org", 443)]
    assert hosts("terminal", {"command": "cat notes.txt"}, long, scan=200) == []
    assert R.candidate_destinations("terminal", *PIPE) == []          # a failed call's rule is as it was
    assert R.NAMED_SCAN >= 16384 and 0 < R.ZERO_WAIT_SKEW <= 0.5


def test_what_counts_as_refused_between_two_times():
    between = R.refused_between
    rows = [{"time": 100.0, "host": "a.example.org", "port": 443}, {"time": 105.0, "host": "A.Example.org", "port": 80},
            {"time": 111.0, "host": "b.example.org", "port": 443}, {"host": "c.example.org", "port": 443},
            {"time": True, "host": "d.example.org"}, {"time": 104.0, "host": "127.0.0.1", "port": 80}, "junk"]
    assert between(rows, 99.0, 110.0) == {"a.example.org": 105.0}
    assert between(rows, 101.0, 104.5) == {} and between(rows, 110.5, 120.0) == {"b.example.org": 111.0}
    assert between(rows, 0.0, float("inf")) == {"a.example.org": 105.0, "b.example.org": 111.0}
    assert between([], 0.0, 1.0) == {} and between(None, 0.0, 1.0) == {}
    # the driver's audit events (the gateway's shorthand), times in seconds or milliseconds
    events = [{"time": 1_800_000_000.0, "ocsf": True, "class": "NET", "action": "DENIED",
               "detail": f"{CURL}(0) -> {SITE}:443"},
              {"time": 1_800_000_002_000, "ocsf": True, "class": "NET", "action": "ALLOWED",
               "detail": f"{CURL}(0) -> open.example.org:443"},
              {"ocsf": True, "class": "NET", "action": "DENIED", "detail": f"{CURL}(0) -> untimed.example.org:443"}]
    assert between(events, 1_799_999_999.0, 1_800_000_010.0) == {SITE: 1_800_000_000.0}
    assert between(events, 1_800_000_001.0, 1_800_000_010.0) == {}


def test_the_launcher_reads_a_zero_wait_request():
    body = {"kind": "network", "strength": "candidate", "zero_wait": True, "tool": "terminal", "session_id": "chatA",
            "t": 10.0, "until": 12.5, "wait": 30, "hosts": [{"host": SITE, "port": 443, "source": "text"}]}
    request = V.parse_request("abc-1", json.dumps(body).encode())
    assert request["zero_wait"] is True and request["until"] == 12.5 and request["strength"] == "candidate"
    assert "zero_wait" not in V.parse_request("abc-2", json.dumps({**body, "zero_wait": "yes"}).encode())
    assert "zero_wait" not in V.parse_request("abc-3", json.dumps({**body, "zero_wait": False}).encode())
    # only a candidate request can be one: a refusal the result itself shows is looked for as before
    strong = V.parse_request("abc-4", json.dumps({**body, "strength": "strong"}).encode())
    assert strong["strength"] == "strong" and "zero_wait" not in strong and "until" not in strong
    assert V.parse_request("abc-5", json.dumps({**body, "until": "later"}).encode())["until"] == 0.0


# -- the Docker driver's record stream -----------------------------------------------------------------------

def _record(uid, t_ms, host=SITE, *, action="Denied", activity="Open", port=443, process=CURL, cls=4001,
            detail="transparent_tcp_policy_denied"):
    """An OCSF record as the supervisor writes it (the fields the launcher reads)."""
    record = {"class_uid": cls, "activity_name": activity, "time": t_ms, "severity": "Medium", "action": action,
              "status_detail": detail, "message": f"Transparent TCP denied before relay: endpoint {host}:{port}",
              "dst_endpoint": {"domain": host, **({"port": port} if port else {})},
              "metadata": {"uid": uid, "product": {"name": "OpenShell Sandbox Supervisor", "version": "0.1.6"}}}
    if process:
        record["actor"] = {"process": {"name": process, "pid": 0}}
    return record


def test_which_records_are_a_programs_refused_connection():
    row = OD.refusal_row
    assert row(_record("u1", 1_800_000_000_250)) == {"time": 1_800_000_000.25, "host": SITE, "port": 443}
    assert row(_record("u2", 1_800_000_000_250, host="Shop.Example.COM", action="Blocked", cls=4002))["host"] == SITE
    assert row(_record("u3", 1_800_000_000_250, action="Allowed")) is None
    # the name lookup OpenShell refuses first names no port and no program
    assert row(_record("u4", 1_800_000_000_250, activity="Refuse", port=None, process=None,
                       detail="policy_dns_ineligible")) is None
    # a tunnel closed because the policy changed is "Denied" too, and is no refusal of its host
    closed = _record("u5", 1_800_000_000_250, process=None, detail=None)
    closed["message"] = "L7 tunnel closed before inspection because policy changed"
    assert row(closed) is None
    assert row(_record("u6", 0)) is None and row(_record("u7", True)) is None
    assert row({**_record("u8", 1_800_000_000_250), "class_uid": 1007}) is None
    assert row({"class_uid": 4001, "action": "Denied", "time": 1_800_000_000_250, "dst_endpoint": "x"}) is None
    assert row({**_record("u9", 1_800_000_000_250), "dst_endpoint": {"ip": "198.51.100.7", "port": 443}}) is None


def test_the_archive_keeps_the_last_refusals_in_memory_and_the_driver_hands_them_out(tmp_path, monkeypatch):
    monkeypatch.setattr(OD.AuditArchive, "RECENT", 3)
    arch = OD.AuditArchive(tmp_path / "audit", "hermes-work", "docker", run=None, popen=None)
    arch.dir.mkdir(parents=True)
    base = 1_800_000_000_000
    arch._write(_record("u1", base, host="a.example.org"))
    arch._write(_record("u2", base + 1000, host="open.example.org", action="Allowed"))
    arch._write(_record("u3", base + 2000, host="b.example.org"))
    arch._write(_record("u3", base + 2000, host="b.example.org"))     # replayed by a re-follow: once
    assert arch.written == 3 and [r["host"] for r in arch.recent] == ["a.example.org", "b.example.org"]
    driver = types.SimpleNamespace(_audit=arch)
    recent = OD.OpenShellDriver.recent_refusals
    assert recent(driver, 0.0) == [{"time": base / 1000.0, "host": "a.example.org", "port": 443},
                                   {"time": base / 1000.0 + 2.0, "host": "b.example.org", "port": 443}]
    assert [r["host"] for r in recent(driver, base / 1000.0 + 1.0)] == ["b.example.org"]
    recent(driver, 0.0)[0]["host"] = "changed"                         # the caller's copy
    assert arch.recent[0]["host"] == "a.example.org"
    for i in range(4, 8):
        arch._write(_record(f"u{i}", base + i * 1000, host=f"h{i}.example.org"))
    assert [r["host"] for r in arch.recent] == ["h5.example.org", "h6.example.org", "h7.example.org"]
    assert recent(types.SimpleNamespace(_audit=None), 0.0) == []       # no archive (no container CLI)


def test_the_docker_driver_tells_the_hook_to_look_only_when_it_follows_the_record_stream(tmp_path, monkeypatch):
    """The sandbox's environment carries ``HERMES_SANDBOX_REFUSALS`` when the driver starts its follower of the
    supervisor's records (it has a container CLI), and not otherwise: then nothing is copied, and the hook of a
    successful call opens no file."""
    class Archive(OD.AuditArchive):
        def start(self):
            self.dir.mkdir(parents=True, exist_ok=True)

        def stop(self, timeout=15.0):
            pass

    monkeypatch.setattr(OD, "AuditArchive", Archive)

    def environment(container_cli, where):
        where.mkdir()
        sup, api, _rec, _layout = _supervisor(where, monkeypatch)
        sup.driver.cfg.container_cli = container_cli

        async def scenario():
            await sup.start()
            try:
                (_, _, spec), = [c for c in api.calls if c[0] == "create"]
                return spec["environment"], callable(getattr(sup.driver, "recent_refusals", None))
            finally:
                await sup.stop()

        return asyncio.run(scenario())

    env, feeds = environment("docker", tmp_path / "with-cli")
    assert env[H.REFUSALS_ENV] == str(OD.REFUSALS_SETTLE) and env.get(H.VERDICTS_ENV) and feeds
    env, _ = environment(None, tmp_path / "without-cli")
    assert H.REFUSALS_ENV not in env and env.get(H.VERDICTS_ENV)
