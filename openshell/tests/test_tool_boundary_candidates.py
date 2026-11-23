"""A failed program call that prints no refusal is still held on its card (sandbox_hook.py, launcher/refusals.py,
launcher/cards.py).

Recorded on Windows: the agent ran ``curl -s`` against a site the sandbox refuses. curl printed nothing of its
own (exit 7, "HTTP 000"), so the hook saw no refusal in the result, relayed nothing, and the call returned at
once. The card came two seconds later from OpenShell's draft, when the model was already in its next step: the
user clicked Allow, the agent finished its reply saying the site could not be reached, and the rule loaded after
the reply without a word. The two recorded calls are replayed below with a synthetic host.

The rule: a terminal / execute_code call that FAILED relays the hosts it named (URLs in its command or code and
in its output, a network client's bare host arguments) as candidates. The launcher raises the card, with the call
held as for any refusal, only for a candidate OpenShell's own records show refused; it looks for at most
``CANDIDATE_WAIT``. A host name alone never raises a card.
"""
import asyncio
import json
import time

import pytest

from openshell import sandbox_hook as H
from openshell.launcher import cards as C
from openshell.launcher import refusals as R
from openshell.launcher import verdicts as V
from test_cards import (CURLW, FakeDriver, WinDriver, _answer, _cards, _chat_b, _continuations,  # noqa: F401
                        _interrupted_turn_ends, _interrupts, _pump_requests, _settle, _setup, _steers, _turn_start,
                        _until, _win_driver, channel, harness)

ACK_WAIT = H.ACK_WAIT  # the hook's own bound on the launcher's answer (the ``channel`` fixture shortens it)
SITE = "shop.example.com"
SITE_RULE = "allowed_host_shop_example_com"
# The two recorded calls (synthetic host). core hands the hook the terminal tool's result as one JSON string.
CURL_1 = ({"command": 'curl -sL -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -o /tmp/page.html '
                      '-w "HTTP %{http_code}\\nfinal: %{url_effective}\\nsize: %{size_download} bytes\\n" '
                      f"https://{SITE}/"},
          {"output": f"HTTP 000\r\nfinal: https://{SITE}/\r\nsize: 0 bytes", "exit_code": 7, "error": None})
CURL_2 = ({"command": f"curl -sL --max-time 15 https://{SITE}/ "
                      '-w "\\n\\n---\\nHTTP: %{http_code}\\nsize: %{size_download} bytes\\n"'},
          {"output": "---\nHTTP: 000\nsize: 0 bytes", "exit_code": 7, "error": None,
           "exit_code_meaning": "Failed to connect to host"})


class CuttingWinDriver(WinDriver):
    """The recorded build: Windows, and a policy reload that closes open connections (an Allow loads once the
    answering turn has stopped)."""
    capabilities_info = {**WinDriver.capabilities_info, "network_live_interrupts": True}


class NoRecordsDriver(FakeDriver):
    """A driver that keeps no record of what it refused: no audit events, no drafts."""
    capabilities_info = {**FakeDriver.capabilities_info, "requests_supported": False, "audit_events": False}


def _driver(harness, cls):
    harness["sup"].driver = drv = cls()
    harness["driver"] = drv
    return drv


@pytest.fixture
def quick(monkeypatch):
    """The candidate check with a short bound, for tests that are not about the bound itself."""
    monkeypatch.setattr(C, "CANDIDATE_WAIT", 0.4)
    monkeypatch.setattr(C, "CANDIDATE_POLL", 0.05)


def _hook(tool, args, result, session="chatA", ran=0.0):
    """The hook on a worker thread, called the way core calls it for a failed call that took *ran* seconds."""
    text = result if isinstance(result, str) else json.dumps(result)
    return asyncio.to_thread(H.resolve, tool, args, text, session_id=session, status="error",
                             duration_ms=int(ran * 1000))


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


async def _tool_done(cards, conn, live="live1", name="terminal"):
    await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
        "type": "tool.complete", "session_id": live, "payload": {"name": name, "tool_id": "t1", "result": "x"}}})


# -- the recorded calls, held at the tool boundary -------------------------------------------------------

def test_the_recorded_silent_curl_is_held_on_its_card_and_allow_continues_the_reply_with_a_retry(harness, channel):
    """15:29:07 in the record: ``curl -sL ... https://<site>/`` returns exit 7 and "HTTP 000 / final: <url>". The
    hook relays the site as a candidate, OpenShell's denial record confirms it, and the card is raised with the
    call held. Allow stops the turn at that tool result, loads the rule and continues the reply with a retry."""
    drv = _driver(harness, CuttingWinDriver)
    sup = harness["sup"]
    args, result = CURL_1

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)                    # "can you try it from curl?": the terminal call runs
        drv.deny_line(SITE, binary=CURLW)                 # the proxy refuses curl.exe: OpenShell's audit record
        hook = asyncio.ensure_future(_hook("terminal", args, result))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and card["params"]["kind"] == "network"
        [relayed] = _events(cards, "relayed")
        assert relayed["strength"] == "candidate" and [h["host"] for h in relayed["hosts"]] == [SITE]
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["how"] == "openshell records" and confirmed["refused"] == [SITE]
        [raised] = _events(cards, "raised")
        assert raised["origin"] == "hook" and raised["turn_running"] is True
        await _settle(20)
        assert not hook.done()                            # held: the agent has not moved on
        # OpenShell's draft for the same refusal is listed two seconds later: it joins the card
        drv.add_chunk("d1", host=SITE, binary=CURLW)
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1 and _interrupts(conn) == []
        await cards._from_client(conn, _answer(card, "once"))         # Allow, while the turn runs
        [stop] = _interrupts(conn)
        assert stop["params"] == {"session_id": "live1", "resume": True}
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["exit_code"] == 7 and out["output"] == result["output"]
        assert out["sandbox"].startswith(f"[Sandbox] The sandbox blocked this call's connection to {SITE}. "
                                         f"The user allowed network access to {SITE}")
        assert H.STOP_NOW in out["sandbox"]
        await _tool_done(cards, conn)
        await _interrupted_turn_ends(cards, conn)
        assert await _until(lambda: sup.applies == [[SITE_RULE]])
        assert await _until(lambda: _continuations(conn))
        await _settle(20)
        [cont] = _continuations(conn)
        text = cont["params"]["text"]
        assert f"Network access to {SITE}" in text and "in place now" in text and text.endswith(C.CONTINUE_TAIL)
        assert _events(cards, "granted quietly") == []
        await cards.stop()

    asyncio.run(main())


def test_the_second_recorded_curl_names_its_site_only_in_the_command_and_deny_reaches_the_held_call(harness, channel):
    """15:30:14 in the record: the output is "---\\nHTTP: 000\\nsize: 0 bytes" (exit 7): only the command names the
    site. The call is held all the same, and a Deny comes back in its result."""
    drv = _driver(harness, CuttingWinDriver)
    args, result = CURL_2
    assert SITE not in json.dumps(result)
    assert not R.maybe_refused(json.dumps(result))        # nothing in the result reads as a refusal

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        drv.deny_line(SITE, binary=CURLW)
        hook = asyncio.ensure_future(_hook("terminal", args, result))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and not hook.done()
        await cards._from_client(conn, _answer(card, "deny", "Not from the terminal."))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["exit_code_meaning"] == "Failed to connect to host"
        assert out["sandbox"] == (f"[Sandbox] The sandbox blocked this call's connection to {SITE}. The user denied "
                                  f"network access to {SITE}. Reason: Not from the terminal. Don't retry it; continue "
                                  "without it or ask the user.")
        await _settle()
        assert _steers(conn) == [] and _interrupts(conn) == []        # the held call told the agent
        await cards.stop()

    asyncio.run(main())


def test_a_held_candidate_call_times_out_saying_the_user_has_not_answered(harness, channel, monkeypatch, quick):
    monkeypatch.setenv(H.WAIT_ENV, "1")
    drv = _driver(harness, CuttingWinDriver)

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        drv.deny_line(SITE, binary=CURLW)
        hook = asyncio.ensure_future(_hook("terminal", *CURL_2))
        await _pump_requests(cards, lambda: _cards(conn))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["sandbox"].startswith("[Sandbox] The sandbox refused this; a card in the chat asks the user for "
                                         f"network access to {SITE}, and the user has not answered.")
        assert len(cards.open) == 1                       # the card stays: an answer later still applies
        await cards.stop()

    asyncio.run(main())


def test_execute_code_that_failed_silently_is_held_the_same_way(harness, channel, quick):
    """A script that swallows its error: the code names the URL, the output says only that it failed."""
    drv = harness["driver"]
    code = f"import urllib.request\ntry:\n    urllib.request.urlopen('https://{SITE}/feed')\nexcept Exception:\n    raise SystemExit('fetch failed')"

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool_name="execute_code")
        drv.deny(SITE)
        hook = asyncio.ensure_future(_hook("execute_code", {"code": code},
                                           {"status": "error", "output": "", "error": "fetch failed"}))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "retry the request now" in out["sandbox"] and out["error"] == "fetch failed"
        await cards.stop()

    asyncio.run(main())


# -- never a card on a host name alone ------------------------------------------------------------------

def test_a_failed_call_that_was_refused_nothing_returns_unchanged_after_a_short_bounded_wait(harness, channel,
                                                                                             monkeypatch):
    """``curl -sf`` of a page that is not there: the command names a host and fails, and OpenShell refused nothing.
    No card; the result comes back as it was, within ``CANDIDATE_WAIT`` plus the two polls (the launcher's read of
    the request and the hook's read of the answer). Measured with the real constants."""
    monkeypatch.setattr(H, "ACK_WAIT", ACK_WAIT)
    assert C.CANDIDATE_WAIT + C.REQUEST_POLL + 1.0 < ACK_WAIT  # the hook is still listening when the answer comes

    async def main():
        cards, conn = await _setup(harness, request_poll=C.REQUEST_POLL)
        await _turn_start(cards, conn)
        began = time.monotonic()
        out = await _hook("terminal", {"command": "curl -sf https://example.org/missing"},
                          {"output": "", "exit_code": 22, "error": None})
        took = time.monotonic() - began
        assert out is None and _cards(conn) == [] and cards.open == {}
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["refused"] == [] and confirmed["candidates"] == ["example.org"]
        assert C.CANDIDATE_WAIT <= confirmed["waited"] < C.CANDIDATE_WAIT + 0.5
        assert took < C.CANDIDATE_WAIT + C.REQUEST_POLL + H.POLL + 0.75, took
        [answer] = cards.verdicts.requests.values()
        assert answer["status"] == "refused" and "refused none of example.org" in answer["detail"]
        print(f"refused nothing: the hook returned after {took:.2f} s (launcher looked {confirmed['waited']} s)")
        await cards.stop()

    asyncio.run(main())


def test_a_driver_without_records_never_cards_a_candidate(harness, channel):
    """No audit events and no drafts: nothing can confirm a candidate, so none is carded, whatever the request
    claims about where its host came from. The answer is immediate."""
    _driver(harness, NoRecordsDriver)

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        began = time.monotonic()
        hook = asyncio.ensure_future(_hook("terminal", *CURL_1))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        assert await asyncio.wait_for(hook, 10) is None and time.monotonic() - began < 1.5
        # a forged request: candidate strength, but its host marked as named by a refusal
        await cards.on_request({"id": "forged-1", "kind": "network", "session_id": "chatA", "tool": "terminal",
                                "strength": "candidate", "t": time.time(), "wait": 30.0,
                                "hosts": [{"host": SITE, "port": 443, "source": "refusal"}]})
        assert _cards(conn) == [] and cards.open == {}
        assert [r["refused"] for r in _events(cards, "confirmed")] == [[], []]
        assert {a["status"] for a in cards.verdicts.requests.values()} == {"refused"}
        await cards.stop()

    asyncio.run(main())


def test_only_the_candidate_openshell_refused_is_carded(harness, channel, quick):
    """The command names two sites and its output a third; OpenShell refused one of them."""
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        drv.deny("b.example.org")
        hook = asyncio.ensure_future(_hook(
            "terminal", {"command": "curl -s https://a.example.org/x && curl -s https://b.example.org/y"},
            {"output": "see https://docs.example.net/errors", "exit_code": 7}))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == "b.example.org"
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["candidates"] == ["a.example.org", "b.example.org", "docs.example.net"]
        assert confirmed["refused"] == ["b.example.org"]
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "connection to b.example.org." in out["sandbox"] and "a.example.org" not in out["sandbox"]
        await cards.stop()

    asyncio.run(main())


def test_a_candidate_every_program_may_already_reach_is_answered_without_a_wait(harness, channel):
    """The failed call named a site an Allow already opened to every program: it was not refused, and the launcher
    does not go looking (the real bound is in force here). Allowed only after the call started, it may have
    been refused a moment before the rule landed: that one is checked, and the hook says to retry."""
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        now = cards._clock()
        cards.grants.append({"kind": "network", "scope": "allow", "host": "example.org", "ports": [80, 443],
                             "rule_name": "allowed_host_example_org", "rule": C.host_rule("example.org", (80, 443)),
                             "label": None, "chat": "chatA", "applied_at": now - 60.0, "answered_at": now - 61.0})
        began = time.monotonic()
        hook = asyncio.ensure_future(_hook("terminal", {"command": "curl -sf https://example.org/missing"},
                                           {"output": "", "exit_code": 22}))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        assert await asyncio.wait_for(hook, 10) is None
        assert time.monotonic() - began < 1.5 and _events(cards, "confirmed") == []
        assert not [c for c in drv.calls if c[0] == "events"]         # the records were not even read
        [answer] = cards.verdicts.requests.values()
        assert answer["status"] == "refused" and "already reach" in answer["detail"]
        # the same call, started 5 s before a rule for its site landed, and refused then
        cards.grants[0]["applied_at"] = cards._clock()
        drv.deny("example.org", t=time.time() - 4.0)
        await cards.on_request({"id": "late-1", "kind": "network", "session_id": "chatA", "tool": "terminal",
                                "strength": "candidate", "t": time.time() - 5.0, "wait": 30.0,
                                "hosts": [{"host": "example.org", "port": 443, "source": "text"}]})
        assert cards.verdicts.requests["late-1"]["keys"] == ["net:example.org"]
        assert cards.verdicts.get("net:example.org")["status"] == "allowed" and _cards(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_a_failed_call_waits_on_the_card_openshell_drafted_for_another_host_it_reached(harness, channel, quick):
    """``curl -sL`` of an allowed site that redirects to a refused one: the command names only the first. OpenShell
    drafts a rule for curl.exe while the call is open, which raises the card; the failed call's request finds
    none of its own hosts refused and waits on that card instead of returning."""
    drv = _win_driver(harness)

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        drv.add_chunk("d1", host="www.example.org", binary=CURLW)
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert card["params"]["host"] == "www.example.org"
        assert _events(cards, "raised")[0]["origin"] == "proposal:tool"
        hook = asyncio.ensure_future(_hook("terminal", {"command": "curl -sL https://example.org/"},
                                           {"output": "", "exit_code": 7}, ran=3.0))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        [answer] = cards.verdicts.requests.values()
        assert answer["status"] == "card" and answer["keys"] == ["net:www.example.org"]
        await _settle(10)
        assert not hook.done() and _interrupts(conn) == []           # held by the hook; the turn is not stopped
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["sandbox"].startswith("[Sandbox] The sandbox blocked this call's connection to www.example.org. "
                                         "The user allowed network access to www.example.org")
        assert "retry the request now" in out["sandbox"]
        await _settle()
        assert _steers(conn) == [] and _interrupts(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_a_failed_call_does_not_wait_on_a_card_another_call_is_held_on(harness, channel, quick):
    """Two calls of one reply. The first printed a refusal and is held on its card. The second failed without one
    and named a site OpenShell refused nothing of: it returns as it was, and is not held on the first call's card
    (only a card from OpenShell's draft for a program of this chat can be an unnamed refusal of the call)."""
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        drv.deny(SITE)
        first = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "terminal", {"command": f"curl https://{SITE}/"},
            "curl: (56) CONNECT tunnel failed, response 403", session_id="chatA"))
        await _pump_requests(cards, lambda: _cards(conn))
        second = asyncio.ensure_future(_hook("terminal", {"command": "curl -sf https://example.org/missing"},
                                             {"output": "", "exit_code": 22}, ran=1.0))
        await _pump_requests(cards, lambda: len(cards.verdicts.requests) == 2)
        assert await asyncio.wait_for(second, 10) is None and not first.done()
        assert sorted(a["status"] for a in cards.verdicts.requests.values()) == ["card", "refused"]
        await cards._from_client(conn, _answer(_cards(conn)[0], "deny"))
        assert "The user denied network access" in await asyncio.wait_for(first, 10)
        await cards.stop()

    asyncio.run(main())


def test_a_second_chats_failed_call_raises_its_card_in_that_chat_only(harness, channel, quick):
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)                    # chat A's turn runs
        await _chat_b(cards, conn)
        await _turn_start(cards, conn, live="liveB")
        drv.deny(SITE)
        hook = asyncio.ensure_future(_hook("terminal", *CURL_2, session="chatB"))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["session_id"] == "liveB" and cards.open[card["id"]]["chat"] == "chatB"
        await cards._from_client(conn, _answer(card, "deny"))
        assert "The user denied network access" in json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        await _settle()
        assert _steers(conn) == [] and _interrupts(conn) == []        # nothing reaches chat A
        await cards.stop()

    asyncio.run(main())


# -- what the hook relays -------------------------------------------------------------------------------

def test_which_hosts_a_failed_call_names():
    named = R.candidate_destinations
    hosts = lambda *a, **k: [(h, p) for h, p, _ in named(*a, **k)]  # noqa: E731
    failed = {"output": "", "exit_code": 7}
    assert hosts("terminal", *CURL_1) == [(SITE, 443)] and hosts("terminal", *CURL_2) == [(SITE, 443)]
    assert {s for _, _, s in named("terminal", *CURL_1)} == {R.SOURCE_TEXT}
    # a network client's bare arguments, not its option values; other programs' arguments are files
    assert hosts("terminal", {"command": "curl -s -o page.html example.org/a"}, failed) == [("example.org", None)]
    assert hosts("terminal", {"command": "cd /tmp && wget -q example.org:8443/x.tgz"}, failed) == [("example.org", 8443)]
    assert hosts("terminal", {"command": "ssh git@example.org true"}, failed) == [("example.org", None)]
    assert hosts("terminal", {"command": "C:\\Windows\\System32\\curl.exe -s example.org"}, failed) == [("example.org", None)]
    assert hosts("terminal", {"command": "python build.py && cat notes.txt"}, {"output": "", "exit_code": 1}) == []
    # with a URL in the command, a client's bare arguments are its files
    assert hosts("terminal", {"command": "curl -s https://example.org/ report.html"}, failed) == [("example.org", 443)]
    # the output's URLs come after the command's; addresses, loopback names and the gateway alias never count
    out = {"output": "moved: http://cdn.example.net/x\nsee http://127.0.0.1:8080/ http://localhost/ "
                     "https://host.openshell.internal/v1", "exit_code": 22}
    assert hosts("terminal", {"command": "curl -sf https://example.org/"}, out) == [("example.org", 443),
                                                                                    ("cdn.example.net", 80)]
    # execute_code: URLs in the code; dotted names in code are not hosts
    code = "import requests, os.path\nr = requests.get('https://api.example.org/v1')\nr.raise_for_status()"
    assert hosts("execute_code", {"code": code}, {"status": "error", "error": "HTTPError"}) == [("api.example.org", 443)]
    many = " ".join(f"https://h{i}.example.org/" for i in range(9))
    assert len(hosts("terminal", {"command": f"curl -s {many}"}, failed)) == R.MAX_CANDIDATES


def test_only_a_program_call_that_clearly_failed_names_candidates():
    named = R.candidate_destinations
    args = {"command": f"curl -s https://{SITE}/"}
    assert named("terminal", args, {"output": "", "exit_code": 0}) == []
    assert named("terminal", args, {"output": "", "exit_code": 7}, status="ok") == []      # core's verdict
    assert named("terminal", args, {"output": ""}) == []                 # nothing says it failed
    assert named("terminal", args, "plain text that is not JSON") == []
    assert named("terminal", args, "plain text that is not JSON", status="error") != []
    assert named("execute_code", {"code": f"get('https://{SITE}/')"}, {"status": "success", "output": ""}) == []
    assert named("execute_code", {"code": f"get('https://{SITE}/')"}, {"status": "error", "output": ""}) != []
    # other tools never: a web tool reports its refused service itself, a file tool reaches no site
    assert named("web_extract", {"urls": [f"https://{SITE}/"]}, {"success": False, "error": "failed"}) == []
    assert named("read_file", {"path": f"https://{SITE}/"}, {"error": "File not found"}) == []
    failed = R.clearly_failed
    assert failed({"exit_code": 1}) and failed('{"success": false}') and failed({"error": "x"})
    assert failed({"status": "failed"}) and failed("anything", "error")
    assert not failed({"exit_code": 0}) and not failed({"exit_code": True}) and not failed("[1]")
    assert not failed({"exit_code": 1}, "ok")


def test_the_hook_relays_candidates_only_when_the_result_shows_no_refusal(monkeypatch):
    sent = []
    monkeypatch.setenv(H.WAIT_ENV, "0")
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    args = {"command": f"curl -s https://{SITE}/"}
    assert H.resolve("terminal", args, json.dumps({"output": "", "exit_code": 7}), status="error") is None
    [request] = sent
    assert request["kind"] == "network" and request["strength"] == "candidate" and request["tool"] == "terminal"
    assert request["hosts"] == [{"host": SITE, "port": 443, "source": "text"}]
    # refusal wording: the usual request, as before
    sent.clear()
    H.resolve("terminal", args, json.dumps({"output": "curl: (56) CONNECT tunnel failed, response 403",
                                            "exit_code": 56}), status="error")
    assert [r["strength"] for r in sent] == ["strong"]
    # a successful call, a failed one that names no host, and other tools relay nothing
    sent.clear()
    assert H.resolve("terminal", args, json.dumps({"output": "<html>", "exit_code": 0}), status="ok") is None
    assert H.resolve("terminal", {"command": "pytest -q"}, json.dumps({"output": "1 failed", "exit_code": 1}),
                     status="error") is None
    assert H.resolve("web_extract", {"urls": [f"https://{SITE}/"]}, json.dumps({"success": False, "error": "x"}),
                     status="error") is None
    assert sent == []


def test_a_failed_command_that_names_no_host_is_not_relayed_and_the_look_is_cheap(monkeypatch):
    """Most failed commands touch no network: a failing test run, a grep with no match, a script error. They name
    no host, so nothing is relayed and nothing waits. The extra look at such a result (for URLs) costs a fraction
    of a millisecond on a 16 KB printout, microseconds on a short one."""
    sent = []
    monkeypatch.setattr(H, "_send", lambda request: sent.append(request) or None)
    log = "\n".join(f"tests/test_mod{i}.py::test_case FAILED" for i in range(400))
    calls = [("terminal", {"command": "pytest -q tests"}, json.dumps({"output": log, "exit_code": 1})),
             ("terminal", {"command": "grep -rn needle src"}, json.dumps({"output": "", "exit_code": 1})),
             ("execute_code", {"code": "import json\njson.loads('{')"},
              json.dumps({"status": "error", "output": "", "error": "JSONDecodeError: Expecting property name"}))]
    rounds = 200
    for tool, args, result in calls:
        assert H.resolve(tool, args, result, status="error") is None
        began = time.perf_counter()
        for _ in range(rounds):
            assert R.candidate_destinations(tool, args, result, status="error") == []
        each = (time.perf_counter() - began) / rounds
        assert each < 0.002, each
        print(f"failed {tool} call naming no host, {len(result)} bytes: {each * 1e6:.0f} microseconds to look")
    assert sent == []


def test_the_launcher_reads_a_candidate_request():
    raw = json.dumps({"kind": "network", "strength": "candidate", "tool": "terminal", "session_id": "chatA",
                      "t": 1.0, "wait": 30, "hosts": [{"host": SITE, "port": 443, "source": "text"}]}).encode()
    request = V.parse_request("abc-1", raw)
    assert request["strength"] == "candidate" and request["hosts"] == [{"host": SITE, "port": 443, "source": "text"}]
    other = V.parse_request("abc-2", raw.replace(b'"candidate"', b'"made-up"'))
    assert other["strength"] == "strong"
