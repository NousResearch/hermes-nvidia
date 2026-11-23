"""A draft OpenShell lists long after the refusal is still the agent's (launcher/cards.py, ``_draft_owner`` rule b).

Measured on Linux (WSL2, Docker driver, OpenShell v0.1.6): the supervisor reports refusals to the gateway every 10 s
there (the 2 s the plugin asks for reaches only the gateway it starts itself on Windows), so a draft was listed 4.3
to 9.1 s after the refused curl had returned, and up to 10.9 s in chats. A one-command turn has ended by then, and
the 5 s a call that "just ended" still counts for (``AGENT_TOOL_GRACE``) are over more often than not: 6 of 11
refusals that only the draft could show (``curl -s URL || echo failed``, a script that names no host) got no card
at all, only "draft not carded". Nothing asked the user and nothing was retried.

The draft carries OpenShell's own time for the refusal (``first_seen`` / ``last_seen``). When that time lies inside
one of the chat's terminal / execute_code calls, the draft is that call's however late it is listed, for calls that
ended at most ``AGENT_DRAFT_LATE`` ago. Everything else stays as it was: the backend's own fetches, drafts without
a usable time, refusals outside every call.
"""
import asyncio
import calendar
import json
import time

import pytest

from openshell.launcher import cards as C
from test_cards import (CURLW, PYW, WinDriver, _answer, _cards, _continuations, _interrupted_turn_ends,  # noqa: F401
                        _interrupts, _settle, _setup, _turn_start, _until, channel, harness)

SITE = "shop.example.com"
SITE_RULE = "allowed_host_shop_example_com"
ALLOWED = (f"The sandbox blocked {SITE} for a program you ran, and the user has now allowed it. Network access to "
           f"{SITE} (http and https, any program) is in place now, until the sandbox is switched off.")
LATE = 10.0  # seconds from the end of the call to the listing, as measured (4 to 11)


@pytest.fixture
def drv(harness):
    harness["sup"].driver = driver = WinDriver()  # a driver that names the backend's interpreter (rule b needs it)
    harness["driver"] = driver
    return driver


def _iso(t):
    """A time as the Linux gateway gives it (proto-JSON Timestamp)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e9):09d}Z"


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


async def _event(cards, conn, typ, live="live1", **payload):
    await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
        "type": typ, "session_id": live, "payload": payload}})


async def _call_ends(cards, conn, tool_id="t1"):
    """``curl -s URL || echo failed``: exit 0, nothing the hook could relay."""
    await _event(cards, conn, "tool.complete", name="terminal", tool_id=tool_id,
                 result=json.dumps({"output": "failed", "exit_code": 0, "error": None}))


def _age(cards, seconds, chat="chatA"):
    """Time passes: the chat's recorded calls are *seconds* older. Returns the spans (start, end) of its calls."""
    call = cards._agent_calls[chat]
    call["since"] -= seconds
    call["ended"] = call["ended"] - seconds if call["ended"] else call["ended"]
    call["spans"] = [(a - seconds, b - seconds) for a, b in call.get("spans") or []]
    return call["spans"]


async def _one_refused_call(harness, *, reply_ends=True):
    cards, conn = await _setup(harness)
    cards._agent_calls.clear()
    await _turn_start(cards, conn)
    await asyncio.sleep(0.05)                             # the refused curl runs
    await _call_ends(cards, conn)
    if reply_ends:
        await _event(cards, conn, "message.complete", text="The command printed `failed`.")
    return cards, conn


def test_a_draft_listed_ten_seconds_after_its_call_raises_the_card_and_allow_continues_the_reply(harness, drv):
    """The Linux run's step C: one command, the turn over 0.8 s later, the draft listed 5.6 s after the call."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _one_refused_call(harness)
        [(start, end)] = _age(cards, LATE)
        refused = _iso((start + end) / 2)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=refused, last_seen=refused)
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert card["params"]["host"] == SITE
        [raised] = _events(cards, "raised")
        assert raised["origin"] == "proposal:tool" and raised["turn_running"] is False
        assert _events(cards, "draft not carded") == [] and _interrupts(conn) == []
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        assert _continuations(conn)[0]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        assert sup.applies == [[SITE_RULE]] and _events(cards, "granted quietly") == []
        await cards.stop()

    asyncio.run(main())


def test_a_late_draft_while_the_model_is_still_thinking_pauses_the_running_turn(harness, drv):
    """A slow model: the call ended 10 s ago and the turn still runs (no call open) when the draft is listed."""
    async def main():
        cards, conn = await _one_refused_call(harness, reply_ends=False)
        [(start, end)] = _age(cards, LATE)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(start + 0.01), last_seen=_iso(start + 0.01))
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert _events(cards, "raised")[0]["turn_running"] is True
        assert [f["params"] for f in _interrupts(conn)] == [{"session_id": "live1", "resume": True}]
        await _interrupted_turn_ends(cards, conn)
        assert "chatA" in cards.status()["paused"]
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        assert _continuations(conn)[0]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        await cards.stop()

    asyncio.run(main())


def test_the_refused_call_is_found_among_the_calls_of_its_turn(harness, drv):
    """The refusal was in the first of three quick calls; the last one ended long ago too."""
    async def main():
        cards, conn = await _one_refused_call(harness, reply_ends=False)
        for tool_id in ("t2", "t3"):
            await asyncio.sleep(0.02)
            await _event(cards, conn, "tool.start", name="terminal", tool_id=tool_id)
            await asyncio.sleep(0.02)
            await _call_ends(cards, conn, tool_id)
        await _event(cards, conn, "message.complete", text="done")
        spans = _age(cards, LATE)
        assert len(spans) == 3
        first = _iso(sum(spans[0]) / 2)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=first, last_seen=first)
        await cards._on_proposals(drv.proposals("all"))
        assert [c["params"]["host"] for c in _cards(conn)] == [SITE]
        await cards.stop()

    asyncio.run(main())


@pytest.mark.parametrize("why, chunk, age", [
    ("no time on the draft", {}, LATE),
    ("a time without a zone", {"first_seen": "2026-11-10 17:08:05", "last_seen": "2026-11-10 17:08:05"}, LATE),
    ("refused after the call ended", {"after_end": 3.0}, LATE),
    ("refused before the call started", {"before_start": 3.0}, LATE),
    ("the call ended too long ago", {"inside": True}, C.AGENT_DRAFT_LATE + 5.0),
    ("the backend's own interpreter", {"inside": True, "binary": PYW}, LATE),
])
def test_a_late_draft_that_is_not_the_calls_stays_without_a_card(harness, drv, why, chunk, age):
    """As before the change: only OpenShell's own time for the refusal, inside a recent call, makes a late draft
    the agent's. Hermes's own fetches run as the backend's interpreter whatever the time says."""
    async def main():
        cards, conn = await _one_refused_call(harness)
        [(start, end)] = _age(cards, age)
        extra = dict(chunk)
        binary = extra.pop("binary", CURLW)
        when = None
        if extra.pop("inside", False):
            when = (start + end) / 2
        elif "after_end" in extra:
            when = end + C.AGENT_DRAFT_SKEW + extra.pop("after_end")
        elif "before_start" in extra:
            when = start - C.AGENT_DRAFT_SKEW - extra.pop("before_start")
        if when is not None:
            extra.update(first_seen=_iso(when), last_seen=_iso(when))
        drv.add_chunk("d1", host=SITE, binary=binary, **extra)
        await cards._on_proposals(drv.proposals("all"))
        await _settle(10)
        assert _cards(conn) == [] and _interrupts(conn) == [], why
        assert [e["draft"] for e in _events(cards, "draft not carded")] == ["d1"], why
        await cards.stop()

    asyncio.run(main())


def test_a_draft_listed_in_time_is_carded_as_before_whatever_its_time_says(harness, drv):
    """The listing-time test is unchanged: a call that ended within AGENT_TOOL_GRACE owns a draft listed after it
    started, with no time on the draft or with one outside the call (a clock that is off)."""
    async def main():
        cards, conn = await _one_refused_call(harness)
        off = _iso(time.time() - 3600.0)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=off, last_seen=off)
        await cards._on_proposals(drv.proposals("all"))
        assert [c["params"]["host"] for c in _cards(conn)] == [SITE]
        await cards.stop()

    asyncio.run(main())


def test_a_late_hit_on_a_card_left_open_pauses_the_turn_that_was_refused_again(harness, drv):
    """A card nobody answered stays open. A later turn runs the command again; OpenShell counts one more hit on the
    same draft and the launcher hears of it 10 s after that call: the turn, still running, pauses on the card."""
    async def main():
        cards, conn = await _one_refused_call(harness)
        [(start, end)] = _age(cards, LATE)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(start + 0.01), last_seen=_iso(start + 0.01))
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        assert _interrupts(conn) == []                    # that turn was over
        _age(cards, 60.0)                                 # a minute later: the user asks again
        await _turn_start(cards, conn)
        await asyncio.sleep(0.05)
        await _call_ends(cards, conn)
        spans = _age(cards, LATE)
        drv.chunks["d1"].update(hit_count=2, last_seen=_iso(sum(spans[-1]) / 2))
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1                     # the same card
        assert [f["params"] for f in _interrupts(conn)] == [{"session_id": "live1", "resume": True}]
        await _interrupted_turn_ends(cards, conn)
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        await cards.stop()

    asyncio.run(main())


def test_only_the_newest_hit_counts_for_a_card_left_open(harness, drv):
    """One more hit that fell outside every call of the chat (another program, later) pauses nothing."""
    async def main():
        cards, conn = await _one_refused_call(harness)
        [(start, end)] = _age(cards, LATE)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(start + 0.01), last_seen=_iso(start + 0.01))
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1
        drv.chunks["d1"].update(hit_count=2, last_seen=_iso(end + C.AGENT_DRAFT_SKEW + 4.0))
        await cards._on_proposals(drv.proposals("all"))
        await _settle(10)
        assert _interrupts(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_the_calls_remembered_per_chat_are_bounded(harness, drv):
    async def main():
        cards, conn = await _one_refused_call(harness, reply_ends=False)
        for n in range(C.AGENT_CALL_SPANS + 4):
            await _event(cards, conn, "tool.start", name="terminal", tool_id=f"x{n}")
            await _call_ends(cards, conn, f"x{n}")
        assert len(cards._agent_calls["chatA"]["spans"]) == C.AGENT_CALL_SPANS
        await cards.stop()

    asyncio.run(main())


@pytest.mark.parametrize("value, expected", [
    ("2026-11-10T22:05:21Z", calendar.timegm((2026, 11, 10, 22, 5, 21))),
    ("2026-11-10T22:05:21.250Z", calendar.timegm((2026, 11, 10, 22, 5, 21)) + 0.25),
    ("2026-11-10T22:05:21.123456789Z", calendar.timegm((2026, 11, 10, 22, 5, 21)) + 0.123456789),
    ("2026-11-10T17:05:21-05:00", calendar.timegm((2026, 11, 10, 22, 5, 21))),
    ("2026-11-10T23:35:21.5+0130", calendar.timegm((2026, 11, 10, 22, 5, 21)) + 0.5),
    ("2026-11-10 22:05:21 UTC", calendar.timegm((2026, 11, 10, 22, 5, 21))),
    (1794348321, 1794348321.0),
    (1794348321.5, 1794348321.5),
    (1794348321500, 1794348321.5),
])
def test_a_drafts_time_is_read_when_it_says_its_zone(value, expected):
    assert C._stamp(value) == pytest.approx(expected, abs=1e-6)


@pytest.mark.parametrize("value", [None, "", "2026-11-10 22:05:21", "2026-11-10T22:05:21", "3 minutes ago",
                                   "2026-13-40T22:05:21Z", True, 0, -5, {"seconds": 1}])
def test_a_time_without_a_zone_or_that_is_no_time_is_not_used(value):
    assert C._stamp(value) is None
