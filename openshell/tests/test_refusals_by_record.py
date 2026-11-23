"""Whether a program call was refused a site is read from OpenShell's records, not from what the call printed
(sandbox_hook.py, launcher/refusals.py, launcher/cards.py).

Recorded on Windows: after Deny on the Web extract card for a page, the model tried the page from the terminal with
``curl -sS --max-time 15 https://<site>; echo "---exit:$?"``. curl printed its refusal line, and the trailing
``echo`` made the call end with exit code 0. A successful call's output was never read, the driver there copied no
records for the hook, so nothing was relayed and no card came up: the user was never asked about the raw request.
The four recorded results are replayed below (the site is the one in the record; the traceback's frames are a
stock one with store paths, its last line and what follows it are as recorded).

The rule: a terminal / execute_code call that did not fail and named a host relays that host when OpenShell's
records show it refused inside the call. Where the launcher copies the records into the verdict file as they happen,
the hook looks there, for a moment after the call returned (as long as the driver says its feed can trail a
refusal; ``RECORD_SETTLE_SHOWN`` when the output shows a refusal's words): the call's text is not needed. Where it copies nothing, only an output that shows a
network refusal's words asks, and the launcher looks at the records as for any candidate. Never a card without a
record; a call that names no host is never held; a successful result of another tool that only holds such words and
names no host (a skill's text) is not relayed. A Deny on a web tool's card denies the tool, not the site it was
asked for: the agent's own request to that site asks with a card of its own.
"""
import asyncio
import json
import time

import pytest

from openshell import sandbox_hook as H
from openshell.launcher import cards as C
from openshell.launcher import refusals as R
from openshell.launcher import verdicts as V
from test_cards import (CURLW, EXA_ERR, EXTRACT_ARGS, FakeDriver, _answer, _cards, _interrupts,  # noqa: F401
                        _pump_requests, _settle, _setup, _turn_end, _turn_start, _until, _win_driver, channel,
                        harness)

SITE = "example.com"
SETTLE = 0.2          # what the driver of these tests says its feed can trail a refusal by (``REFUSALS_ENV``)
RULE = "allowed_host_example_com"
CURL = "/usr/bin/curl"
BODY = '{"error":"policy_denied","detail":"GET example.com:80/ not permitted by policy"}'
TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "<string>", line 1, in <module>\n'
    "    import urllib.request; print(urllib.request.urlopen('https://example.com', timeout=15).read().decode())\n"
    '  File "C:\\store\\python\\Lib\\urllib\\request.py", line 187, in urlopen\n'
    "    return opener.open(url, data, timeout)\n"
    '  File "C:\\store\\python\\Lib\\urllib\\request.py", line 487, in open\n'
    "    response = self._open(req, data)\n"
    '  File "C:\\store\\python\\Lib\\urllib\\request.py", line 1319, in do_open\n'
    "    h.request(req.get_method(), req.selector, req.data, headers,\n"
    '  File "C:\\store\\python\\Lib\\http\\client.py", line 1000, in _tunnel\n'
    '    raise OSError(f"Tunnel connection failed: {code} {message.strip()}")\n'
    "OSError: Tunnel connection failed: 403 Forbidden")
# The four recorded calls, in order. Each ended with exit code 0 because of the trailing ``echo``.
HTTPS_ECHO = ({"command": 'curl -sS --max-time 15 https://example.com; echo "---exit:$?"'},
              {"output": "curl: (7) CONNECT tunnel failed, response 403\r\n---exit:7", "exit_code": 0, "error": None})
HTTP_ECHO = ({"command": 'curl -sS --max-time 15 http://example.com; echo "---exit:$?"; env | grep -i proxy'},
             {"output": BODY + "---exit:0\nHTTPS_PROXY=http://127.0.0.1:3128", "exit_code": 0, "error": None})
AGAIN = ({"command": 'curl -sS --max-time 15 https://example.com; echo "---exit:$?"'},
         {"output": "curl: (7) CONNECT tunnel failed, response 403\r\n---exit:7", "exit_code": 0, "error": None})
PYTHON = ({"command": 'python -c "import urllib.request; print(urllib.request.urlopen(\'https://example.com\', '
                      'timeout=15).read().decode())" 2>&1; echo "---py-exit:$?"; curl -sS --max-time 15 '
                      'http://example.com; echo; echo "---http-exit:$?"'},
          {"output": TRACEBACK + "\n---py-exit:1\n" + BODY + "\n---http-exit:0", "exit_code": 0, "error": None})
RECORDED = [HTTPS_ECHO, HTTP_ECHO, AGAIN, PYTHON]
# The same site with nothing printed at all: no word of a refusal anywhere in the result.
SILENT = ({"command": "curl -s -o /dev/null https://example.com; echo done"},
          {"output": "done", "exit_code": 0, "error": None})
# Data that holds the proxy's words: a file's content, and a skill's text.
CAT = ({"command": "cat notes/refusals.txt"},
       {"output": "curl: (7) CONNECT tunnel failed, response 403\n" + BODY, "exit_code": 0, "error": None})
SKILL = ({"name": "sandbox-boundaries"},
         {"success": True, "name": "sandbox-boundaries", "content": (
             "# Testing a sandbox's boundaries\n\nA refused request answers 403 with the body " + BODY + ".\n"
             "curl prints `curl: (7) CONNECT tunnel failed, response 403`; Python raises `OSError: Tunnel "
             "connection failed: 403 Forbidden`. Writing outside a granted folder says Permission denied.\n")})


class StreamDriver(FakeDriver):
    """A driver that hears of a refusal as it happens (``recent_refusals``); its log (``events``) stays empty."""

    def __init__(self):
        super().__init__()
        self.stream: list = []

    def refuse(self, host, port=443, t=None):
        self.stream.append({"time": time.time() if t is None else t, "host": host, "port": port})

    def recent_refusals(self, since):
        return [dict(row) for row in self.stream if row["time"] >= since]


@pytest.fixture
def sent(monkeypatch):
    """What the hook would send, with nothing waited for (no launcher answers)."""
    out = []
    monkeypatch.setenv(H.WAIT_ENV, "0")
    monkeypatch.delenv(H.REFUSALS_ENV, raising=False)
    monkeypatch.setattr(H, "_send", lambda request: out.append(request) or None)
    return out


@pytest.fixture
def feed(tmp_path, monkeypatch, sent):
    """The verdict file of a launcher that copies OpenShell's records there, and the driver's word that it does."""
    monkeypatch.setenv(H.VERDICTS_ENV, str(tmp_path / "verdicts"))
    monkeypatch.setenv(H.REFUSALS_ENV, str(SETTLE))
    return V.Verdicts(tmp_path / "verdicts")


class Clock:
    """A clock the hook's sleeps move: how long a look lasted, without waiting for it."""

    def __init__(self, at=None):
        self.now, self.sleeps, self.at = 0.0, 0, at or {}

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps += 1
        self.now += seconds
        for due in [d for d in self.at if d <= self.now + 1e-9]:
            self.at.pop(due)()


def _ok(tool, args, result, ran=0.7, clock=None, **kw):
    clock = clock or Clock()
    text = result if isinstance(result, str) else json.dumps(result)
    return H.resolve(tool, args, text, session_id="chatA", status="ok", duration_ms=int(ran * 1000),
                     sleep=clock.sleep, clock=clock, **kw)


def _hook(tool, args, result, ran=0.7, status="ok"):
    """The hook on a worker thread, called the way core calls it."""
    text = result if isinstance(result, str) else json.dumps(result)
    return asyncio.to_thread(H.resolve, tool, args, text, session_id="chatA", status=status,
                             duration_ms=int(ran * 1000))


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


# -- what the functions say of the recorded results --------------------------------------------------------

def test_the_recorded_results_are_successful_calls_whose_text_is_never_read_as_a_refusal():
    for args, result in RECORDED:
        text = json.dumps(result)
        assert R.maybe_refused(text) and R.shows_network_refusal(text)
        assert not R.failed_result("terminal", text, "ok") and not R.clearly_failed(text, "ok")
        assert R.refused_destinations("terminal", args, text, status="ok") == ([], None)
        assert R.candidate_destinations("terminal", args, text, status="ok") == []
        assert R.refused_paths("terminal", args, text, status="ok") == []     # the traceback's paths are data
        [(host, port, source)] = R.named_destinations("terminal", args, text, scan=R.NAMED_SCAN)
        assert (host, source) == (SITE, "text") and port in (80, 443)
    assert not R.shows_network_refusal(json.dumps(SILENT[1])) and not R.maybe_refused(json.dumps(SILENT[1]))
    assert R.named_destinations("terminal", *CAT) == []                        # the file names no host


# -- a driver with no feed: the output's words ask, the launcher's records decide ---------------------------

@pytest.mark.parametrize("args,result", RECORDED, ids=["https-echo", "http-echo", "again", "python"])
def test_without_a_feed_each_recorded_call_asks_the_launcher_about_the_site_it_named(sent, args, result):
    clock = Clock()
    assert _ok("terminal", args, result, clock=clock) is None
    [request] = sent
    assert request["kind"] == "network" and request["strength"] == "candidate" and request["tool"] == "terminal"
    assert [h["host"] for h in request["hosts"]] == [SITE] and "zero_wait" not in request
    assert clock.sleeps == 0                                                   # the hook itself waited for nothing


def test_without_a_feed_execute_code_that_caught_its_refusal_asks_the_same_way(sent):
    code = ("import urllib.request\ntry:\n    urllib.request.urlopen('https://example.com')\n"
            "except Exception as exc:\n    print(exc)")
    result = {"status": "success", "output": "Tunnel connection failed: 403 Forbidden\n", "tool_calls_made": 0}
    assert _ok("execute_code", {"code": code}, result) is None
    [request] = sent
    assert request["strength"] == "candidate" and request["tool"] == "execute_code"
    assert request["hosts"] == [{"host": SITE, "port": 443, "source": "text"}]


def test_without_a_feed_a_successful_call_that_shows_no_refusal_or_names_no_host_is_not_relayed_or_held(sent):
    clock = Clock()
    assert _ok("terminal", *SILENT, clock=clock) is None                       # names the site, shows nothing
    assert _ok("terminal", *CAT, clock=clock) is None                          # shows the words, names no host
    assert _ok("terminal", {"command": "curl -s https://example.com/ | head"}, {"output": "<html>", "exit_code": 0},
               clock=clock) is None
    assert sent == [] and clock.sleeps == 0


def test_a_skills_text_that_holds_refusal_words_and_names_no_host_is_not_relayed_or_held(sent, feed):
    """Recorded: ``skill_view`` of a skill about sandbox boundaries, ``success: true``. Its words read as the
    proxy's refusal and name no host; the hook relayed a network request with no hosts and waited out the
    launcher's silence (``ACK_WAIT``)."""
    args, result = SKILL
    text = json.dumps(result)
    assert R.maybe_refused(text) and R.refused_destinations("skill_view", args, text, status="ok") == ([], "strong")
    clock = Clock()
    assert _ok("skill_view", args, result, clock=clock) is None
    assert sent == [] and clock.sleeps == 0


def test_refusal_words_that_name_no_host_are_still_relayed_for_a_failed_call_and_for_a_tool_with_services(sent):
    """Unchanged: pip's "Tunnel connection failed: 403" (the next card in the chat is its refusal), a web tool whose
    refused service comes back inside a successful-shaped result, and any other tool's failed result."""
    pip = {"output": "ERROR: Could not install packages due to an OSError: Tunnel connection failed: 403 Forbidden",
           "exit_code": 1}
    H.resolve("terminal", {"command": "pip install rich"}, json.dumps(pip), status="error")
    H.resolve("web_search", {"query": "weather"}, json.dumps(
        {"success": True, "results": [], "note": "Keyless search failed: [Errno 13] Permission denied"}), status="ok")
    H.resolve("mcp_fetch_get", {"id": 4}, json.dumps({"error": "Tunnel connection failed: 403 Forbidden"}),
              status="error")
    assert [(r["tool"], r["strength"], r["hosts"]) for r in sent] == [
        ("terminal", "strong", []), ("web_search", "strong", []), ("mcp_fetch_get", "strong", [])]


# -- a driver with a feed: the record decides, whatever the call printed --------------------------------------

@pytest.mark.parametrize("args,result", [*RECORDED, SILENT],
                         ids=["https-echo", "http-echo", "again", "python", "silent"])
def test_with_a_feed_a_call_that_exits_0_relays_the_site_the_records_show_refused_inside_it(sent, feed, args, result):
    began = time.time()
    feed.note_refused({SITE: began - 0.3})                                     # refused while the call ran
    clock = Clock()
    assert _ok("terminal", args, result, clock=clock) is None
    [request] = sent
    assert request["strength"] == "candidate" and request["zero_wait"] is True
    assert [h["host"] for h in request["hosts"]] == [SITE]
    assert began - 0.71 <= request["t"] <= time.time() - 0.69 and began <= request["until"] <= time.time()
    assert clock.sleeps == 0                                                   # the record was there: no wait


def test_with_a_feed_a_record_that_arrives_a_moment_after_the_call_returned_still_counts(sent, feed):
    """The refusal fell at the very end of the call: its record reaches the verdict file 0.1 s after the hook began
    to look. One read, as before, saw nothing."""
    clock = Clock(at={0.1: lambda: feed.note_refused({SITE: time.time() - 0.05})})
    assert _ok("terminal", *SILENT, clock=clock) is None
    [request] = sent
    assert request["zero_wait"] is True and [h["host"] for h in request["hosts"]] == [SITE]
    assert 0.1 <= clock.now < SETTLE


def test_with_a_feed_the_look_is_bounded_and_only_a_call_that_named_a_host_waits(sent, feed):
    quiet, shown, none = Clock(), Clock(), Clock()
    assert _ok("terminal", *SILENT, clock=quiet) is None                       # names a site; nothing recorded
    assert SETTLE <= quiet.now < SETTLE + 2 * R.RECORD_POLL
    assert _ok("terminal", *HTTPS_ECHO, clock=shown) is None                   # its output shows a refusal's words
    assert R.RECORD_SETTLE_SHOWN <= shown.now < R.RECORD_SETTLE_SHOWN + 2 * R.RECORD_POLL
    assert _ok("terminal", *CAT, clock=none) is None                           # the words, but no host: no look
    assert _ok("terminal", {"command": "pytest -q"}, {"output": "12 passed", "exit_code": 0}, clock=none) is None
    assert none.sleeps == 0 and none.now == 0.0
    assert sent == []                                                          # words alone never relay
    assert R.RECORD_SETTLE_SHOWN <= 3.0 and R.RECORD_SETTLE_MAX <= 5.0         # a few seconds at most
    print(f"no record: a call naming a host waited {quiet.now:.2f} s, {shown.now:.2f} s with a refusal shown")


def test_the_drivers_word_for_its_feed_is_how_long_the_hook_looks(monkeypatch):
    for raw, want in (("0.1", 0.1), ("0.5", 0.5), ("1", 1.0), ("0", 0.0), ("60", R.RECORD_SETTLE_MAX), ("-3", 0.0)):
        monkeypatch.setenv(H.REFUSALS_ENV, raw)
        assert H.feed_settle() == want, raw
    for raw in ("", "yes"):
        monkeypatch.setenv(H.REFUSALS_ENV, raw)
        assert H.feed_settle() is None, raw                                    # no feed: the hook opens no file
    monkeypatch.delenv(H.REFUSALS_ENV)
    assert H.feed_settle() is None


def test_with_a_feed_a_refusal_from_outside_the_calls_time_is_not_this_calls(sent, feed):
    now = time.time()
    feed.note_refused({SITE: now - 5.0})                                       # before a call that ran 0.7 s
    assert _ok("terminal", *HTTPS_ECHO) is None and sent == []
    feed.note_refused({"later.example.org": now + 5.0})                        # after it returned (another call's)
    assert _ok("terminal", {"command": "curl -s https://later.example.org/; echo done"}, SILENT[1]) is None
    assert sent == []
    hosts = [("a.example.org", 443, "text")]
    feed.note_refused({"a.example.org": now})
    assert H.recorded_refusals(hosts, now - 1.0, now + 1.0) == hosts
    assert H.recorded_refusals(hosts, now - 1.0, now - 0.5) == [] and H.recorded_refusals(hosts, now + 0.5) == []
    assert H.recorded_refusals(hosts, now - 1.0) == hosts                      # no later bound given


# -- end to end with the launcher ----------------------------------------------------------------------------

def test_the_recorded_curl_with_a_trailing_echo_gets_its_card_and_allow_applies(harness, channel):
    """No feed (the recorded driver). The call's output shows curl's refusal line, the site is relayed as a
    candidate, OpenShell's record of the refused curl confirms it, and the card is raised with the call held."""
    drv, sup = _win_driver(harness), harness["sup"]
    args, result = HTTPS_ECHO

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        drv.deny_line(SITE, binary=CURLW)                 # the proxy refused curl.exe: OpenShell's record
        began = time.monotonic()
        hook = asyncio.ensure_future(_hook("terminal", args, result))
        await _pump_requests(cards, lambda: _cards(conn))
        up = time.monotonic() - began
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE and card["params"]["kind"] == "network"
        [relayed] = _events(cards, "relayed")
        assert relayed["strength"] == "candidate" and "zero_wait" not in relayed
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["how"] == "openshell records" and confirmed["refused"] == [SITE]
        await _settle(20)
        assert not hook.done()                            # held: the agent has not moved on
        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["exit_code"] == 0 and out["output"] == result["output"]
        assert out["sandbox"].startswith(f"[Sandbox] The sandbox blocked this call's connection to {SITE}. "
                                         f"The user allowed network access to {SITE}")
        assert sup.applies == [[RULE]]
        print(f"record there at once: the card was up {up:.2f} s after the call returned")
        assert up < 1.0
        await cards.stop()

    asyncio.run(main())


def test_words_alone_raise_no_card_when_openshell_has_no_record_and_the_wait_is_bounded(harness, channel,
                                                                                        monkeypatch):
    """The same result with no record of a refusal (a script that only prints such a line): no card, and the
    result comes back as it was within ``CANDIDATE_WAIT`` plus the two polls. Measured with the real constants."""
    monkeypatch.setattr(H, "ACK_WAIT", 8.0)
    _win_driver(harness)
    script = ({"command": "python tools/show_error_samples.py https://example.com; echo done"}, HTTPS_ECHO[1])

    async def main():
        cards, conn = await _setup(harness, request_poll=C.REQUEST_POLL)
        await _turn_start(cards, conn)
        began = time.monotonic()
        out = await _hook("terminal", *script)
        took = time.monotonic() - began
        assert out is None and _cards(conn) == [] and cards.open == {}
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["refused"] == [] and confirmed["candidates"] == [SITE]
        assert took < C.CANDIDATE_WAIT + C.REQUEST_POLL + H.POLL + 0.75, took
        began = time.monotonic()
        assert await _hook("terminal", *CAT) is None      # names no host: not relayed, not held
        assert time.monotonic() - began < 0.2 and len(_events(cards, "relayed")) == 1
        print(f"no record: the call came back after {took:.2f} s; one that names no host at once")
        await cards.stop()

    asyncio.run(main())


def test_with_a_feed_the_silent_curl_followed_by_echo_is_held_on_its_card(harness, channel, monkeypatch):
    """``curl -s -o /dev/null URL; echo done``: exit 0 and "done". The refusal's record reaches the launcher's
    feed as the call returns; the hook's short look finds it in the verdict file and the card holds the call."""
    harness["sup"].driver = harness["driver"] = drv = StreamDriver()
    monkeypatch.setenv(H.REFUSALS_ENV, "0.5")
    args, result = SILENT

    async def main():
        cards, conn = await _setup(harness, feed_poll=0.005)
        cards._agent_calls.clear()
        started = time.time()
        await _turn_start(cards, conn)                    # the terminal call is open: the feed runs
        await asyncio.sleep(0.3)
        hook = asyncio.ensure_future(_hook("terminal", args, result, ran=time.time() - started))
        await asyncio.sleep(0.08)                         # the hook has looked and found nothing yet
        assert not hook.done() and _cards(conn) == []
        drv.refuse(SITE, t=time.time() - 0.1)             # the record of the refusal at the call's end arrives
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE
        [relayed] = _events(cards, "relayed")
        assert relayed["zero_wait"] is True and relayed["strength"] == "candidate"
        [confirmed] = _events(cards, "confirmed")
        assert confirmed["how"] == "openshell records, one look (record feed)" and confirmed["refused"] == [SITE]
        await cards._from_client(conn, _answer(card, "deny", "Not this one."))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["output"] == "done" and "The user denied network access to example.com" in out["sandbox"]
        await cards.stop()

    asyncio.run(main())


# -- Deny on the web tool's card, then the raw request to the same site -------------------------------------

def test_after_deny_on_web_extract_the_agents_curl_to_the_same_site_asks_with_its_own_card(harness, channel):
    """The recorded order. web_extract of the page is refused at its service; the card names the tool and keeps
    the page's site (``asked``). Deny. In the same turn the agent runs curl against the site: that is a request
    of its own, and the user is asked about it. Allow applies; a Deny on that card stands for the chat."""
    drv, sup = _win_driver(harness), harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn, tool_name="web_extract")
        drv.deny_line("mcp.exa.ai")
        first = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "web_extract", EXTRACT_ARGS, json.dumps(EXA_ERR), session_id="chatA"))
        await _pump_requests(cards, lambda: _cards(conn))
        [tool_card] = _cards(conn)
        assert tool_card["params"]["host"] == "tool:web_extract"
        assert SITE in next(iter(cards.open.values()))["asked"]                # the page's site is on the card
        await cards._from_client(conn, _answer(tool_card, "deny", "Not through that service."))
        assert "The user denied" in await asyncio.wait_for(first, 10)
        # the web tool stays denied for the chat, whichever service it tries next
        status, again = await cards.raise_host("search.parallel.ai", key="chatA", port=443, tool="web_extract")
        assert status == 200 and again["detail"] == "denied earlier in this chat"
        # the same turn: curl to the page's site, with the trailing echo
        drv.deny_line(SITE, binary=CURLW)
        curl = asyncio.ensure_future(_hook("terminal", *HTTPS_ECHO))
        await _pump_requests(cards, lambda: len(_cards(conn)) == 2)
        site_card = _cards(conn)[1]
        assert site_card["params"]["host"] == SITE and site_card["params"]["kind"] == "network"
        assert not curl.done()
        await cards._from_client(conn, _answer(site_card, "once"))
        out = json.loads(await asyncio.wait_for(curl, 10))
        assert f"The user allowed network access to {SITE}" in out["sandbox"] and sup.applies == [[RULE]]
        await cards.stop()

    asyncio.run(main())


def test_a_failed_curl_after_the_web_tools_deny_asks_too_and_its_own_deny_stands_for_the_chat(harness, channel):
    """The plain form (exit 7, the refusal read from the failed result). Before, the site a denied web tool card
    had been asked for was refused without a card until the user's next prompt."""
    drv = _win_driver(harness)
    failed = {"output": "curl: (7) CONNECT tunnel failed, response 403", "exit_code": 7, "error": None}
    args = {"command": "curl -sS --max-time 15 https://example.com"}

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn, tool_name="web_extract")
        status, card = await cards.raise_host("mcp.exa.ai", key="chatA", port=443, tool="web_extract", asked=[SITE])
        assert status == 200 and card["asked"] == [SITE]
        await cards._from_client(conn, _answer(_cards(conn)[0], "deny", "Not through that service."))
        await _settle(40)
        drv.deny_line(SITE, binary=CURLW)
        curl = asyncio.ensure_future(_hook("terminal", args, failed, status="error"))
        await _pump_requests(cards, lambda: len(_cards(conn)) == 2)
        site_card = _cards(conn)[1]
        assert site_card["params"]["host"] == SITE and not curl.done()
        await cards._from_client(conn, _answer(site_card, "deny", "Leave that site alone."))
        out = json.loads(await asyncio.wait_for(curl, 10))
        assert "The user denied network access to example.com. Reason: Leave that site alone." in out["sandbox"]
        # remembered for the chat: the next try, and one after the user's next prompt, get the reason and no card
        for prompt in (None, "try the curl again"):
            if prompt:
                await _turn_end(cards, conn)
                await _turn_start(cards, conn, text=prompt)
            drv.deny_line(SITE, binary=CURLW)
            retry = asyncio.ensure_future(_hook("terminal", *AGAIN))
            await _pump_requests(cards, lambda: len(cards.verdicts.requests) >= (2 if prompt is None else 3))
            out = json.loads(await asyncio.wait_for(retry, 10))
            assert "Reason: Leave that site alone." in out["sandbox"] and len(_cards(conn)) == 2
        await cards.stop()

    asyncio.run(main())
