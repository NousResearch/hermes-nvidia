"""A draft OpenShell stamps again is not a new refusal (launcher/cards.py: ``_draft_news``, ``_draft_owner``).

Recorded on Linux (Docker driver, OpenShell v0.1.6 and v0.1.8): after every policy change the gateway evaluates
its pending drafts against the new policy and stores each one again, which sets the draft's ``last_seen`` to that
moment. The hit count does not change and ``first_seen`` never does. An Allow is such a policy change, and where a
tool call was held on the card it lands half a second after that call ended. The launcher read ``last_seen`` as
the time of a refusal, so every old draft nobody had been asked about (refusals outside any chat, minutes old)
looked as if it had been refused inside the call of the chat that had just answered: eight cards for unrelated
sites were raised in that chat. The first test replays that order of events with synthetic hosts.

The rule: a draft tells of a new refusal only in the listing that shows it for the first time (OpenShell's time
for it: ``first_seen``) or with a higher hit count than the listing before (``last_seen``, unless the same listing
shows it is a policy-change stamp). Any other listing of a draft says nothing new, whatever its times read, and
assigns it to no call. Everything a late draft was given before stays: a refusal inside a call is still that
call's when the draft is listed ten seconds later.
"""
import asyncio
import json
import time

import pytest

from openshell.launcher import cards as C
from test_cards import (CURLW, PYW, WinDriver, _answer, _cards, _chat_b, _continuations, _interrupted_turn_ends,  # noqa: F401
                        _interrupts, _settle, _setup, _turn_start, _until, channel, harness)

NEW = "shop.example.com"
NEW_RULE = "allowed_host_shop_example_com"
OLD = [f"mirror{n}.example.org" for n in range(8)]
SITE = "docs.example.net"


class CuttingDriver(WinDriver):
    """A build whose policy reload closes open connections, like the recorded one: an Allow loads once the
    answering turn has stopped. It names the backend's interpreter (rule b needs to tell it apart)."""
    capabilities_info = {**WinDriver.capabilities_info, "network_live_interrupts": True}


@pytest.fixture
def drv(harness):
    harness["sup"].driver = driver = CuttingDriver()
    harness["driver"] = driver
    return driver


class Clock:
    """The launcher's clock, moved forward by the test (the drafts' own times are written from it too)."""

    def __init__(self):
        self.ahead = 0.0

    def __call__(self):
        return time.time() + self.ahead

    def later(self, seconds):
        self.ahead += seconds


def _iso(t):
    """A time as the Linux gateway gives it (proto-JSON Timestamp)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e9):09d}Z"


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


def _hosts(conn):
    return [c["params"]["host"] for c in _cards(conn)]


async def _event(cards, conn, typ, live="live1", **payload):
    await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
        "type": typ, "session_id": live, "payload": payload}})


async def _call(cards, conn, clock, took, live="live1", name="terminal", tool_id="t1", output="", code=0):
    """One terminal / execute_code call that takes *took* seconds and returns exit *code*."""
    await _event(cards, conn, "tool.start", live, name=name, tool_id=tool_id)
    clock.later(took)
    await _event(cards, conn, "tool.complete", live, name=name, tool_id=tool_id,
                 result=json.dumps({"output": output, "exit_code": code, "error": None}))


def _candidate(rid, chat, tool, host, t):
    """The hook's request for a failed call that printed no refusal and named *host*."""
    return {"id": rid, "kind": "network", "session_id": chat, "tool": tool, "strength": "candidate", "t": t,
            "wait": 120.0, "hosts": [{"host": host, "port": 443, "source": "text"}]}


def _restamp(drv, clock, ids, at=None):
    """A policy change: OpenShell evaluates its pending drafts again, newest first, a few milliseconds apart, and
    stores each with ``last_seen`` = that moment. Hit counts and ``first_seen`` stay."""
    at = clock() if at is None else at
    for n, pid in enumerate(reversed(list(ids))):
        if drv.chunks[pid]["status"] == "pending":
            drv.chunks[pid]["last_seen"] = _iso(at + 0.012 * n)
    return at


def _old_drafts(drv, clock, n=8, ago=150.0, binary=CURLW):
    """Refusals made outside every chat (a command someone ran in the sandbox by hand), minutes ago."""
    for i in range(n):
        t = clock() - ago - 10.0 * i
        drv.add_chunk(f"old{i}", host=OLD[i], binary=binary, first_seen=_iso(t), last_seen=_iso(t))
    return [f"old{i}" for i in range(n)]


async def _start(harness, **kw):
    clock = Clock()
    cards, conn = await _setup(harness, clock=clock, **kw)
    cards._agent_calls.clear()
    return cards, conn, clock


# -- the recorded order of events ------------------------------------------------------------------------

def test_old_drafts_stamped_by_an_allow_raise_no_card_in_the_chat_that_answered(harness, drv):
    """The record: eight drafts 150 to 230 s old, first listed as a turn began (nobody's). Another chat's
    execute_code call is refused a new site and held on its card for 20 s; Allow; the turn stops, the rule is
    submitted half a second after the call ended and every pending draft is stamped with that moment. The reply
    continues, runs the call again, and five seconds after that call the launcher lists the drafts: they are
    still nobody's."""
    sup = harness["sup"]

    async def main():
        cards, conn, clock = await _start(harness)
        ids = _old_drafts(drv, clock)
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))                 # first listed, no call running
        assert _cards(conn) == [] and len(_events(cards, "draft not carded")) == 8
        # the call that is refused the new site, held on its card
        await _event(cards, conn, "tool.start", name="execute_code", tool_id="t1")
        started = clock()
        clock.later(0.4)
        drv.deny_line(NEW, binary=CURLW, t=clock())
        await cards.on_request(_candidate("rq1", "chatA", "execute_code", NEW, started))
        [card] = _cards(conn)
        assert card["params"]["host"] == NEW
        clock.later(20.0)
        await cards._from_client(conn, _answer(card, "once"))           # Allow: the turn stops at that tool result
        assert len(_interrupts(conn)) == 1
        await _event(cards, conn, "tool.complete", name="execute_code", tool_id="t1",
                     result=json.dumps({"status": "error", "output": "", "error": "fetch failed"}))
        await _interrupted_turn_ends(cards, conn)
        clock.later(0.55)
        assert await _until(lambda: sup.applies == [[NEW_RULE]])
        stamped = _restamp(drv, clock, ids)                             # the policy change
        [(_, ended)] = cards._agent_calls["chatA"]["spans"]
        assert 0.0 < stamped - ended < C.AGENT_DRAFT_SKEW               # as recorded: just after the held call
        await cards._on_proposals(drv.proposals("all"))
        assert _hosts(conn) == [NEW]
        # the reply continues and runs its call again, which now succeeds
        assert await _until(lambda: _continuations(conn))
        await _event(cards, conn, "message.start")
        clock.later(2.5)
        await _call(cards, conn, clock, 1.3, name="execute_code", tool_id="t2", output="STATUS 200")
        await cards._on_proposals(drv.proposals("all"))
        clock.later(C.AGENT_TOOL_GRACE + 0.3)                           # the listing that raised the eight cards
        await cards._on_proposals(drv.proposals("all"))
        await _settle(10)
        assert _hosts(conn) == [NEW]
        assert [e["host"] for e in _events(cards, "raised")] == [NEW]
        assert len(_interrupts(conn)) == 1                              # only the Allow's own
        await cards.stop()

    asyncio.run(main())


def test_five_policy_changes_in_a_row_never_raise_an_old_draft(harness, drv):
    """Every Allow in a chat stamps the old drafts again. However the stamp falls against that chat's calls
    (inside one that is still open, inside one that ended, just after it), no card is raised for them."""
    async def main():
        cards, conn, clock = await _start(harness)
        ids = _old_drafts(drv, clock, n=3)
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))
        assert len(_events(cards, "draft not carded")) == 3
        for round_, where in enumerate(["open", "inside", "after", "inside", "open"]):
            tool_id = f"t{round_}"
            await _event(cards, conn, "tool.start", name="terminal", tool_id=tool_id)
            clock.later(1.0)
            if where == "open":
                _restamp(drv, clock, ids)                               # while the call still runs
                await cards._on_proposals(drv.proposals("all"))
            inside = clock()
            clock.later(1.0)
            await _event(cards, conn, "tool.complete", name="terminal", tool_id=tool_id,
                         result=json.dumps({"output": "ok", "exit_code": 0, "error": None}))
            if where == "inside":
                _restamp(drv, clock, ids, at=inside)
            elif where == "after":
                _restamp(drv, clock, ids, at=clock() + 0.5)
            for wait in (0.5, C.AGENT_TOOL_GRACE, 4.0):                 # just ended, then late
                clock.later(wait)
                await cards._on_proposals(drv.proposals("all"))
            assert _cards(conn) == [] and _interrupts(conn) == [], (round_, where)
        assert len(_events(cards, "draft not carded")) == 3             # said once each
        await cards.stop()

    asyncio.run(main())


# -- what a draft's times mean ---------------------------------------------------------------------------

def test_a_draft_first_listed_late_belongs_to_the_call_its_first_refusal_fell_in_whatever_its_last_stamp_says(harness, drv):
    """Chat A's one-command turn was refused the site. Before the draft is listed, chat B's Allow of another site
    stamps it: ``last_seen`` now lies inside chat B's held call. ``first_seen`` is the refusal: chat A's card."""
    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _call(cards, conn, clock, 0.2, output="failed")           # chat A: curl -s URL || echo failed
        refused = clock() - 0.1
        await _event(cards, conn, "message.complete", text="It printed failed.")
        clock.later(2.0)
        await _chat_b(cards, conn)
        await _turn_start(cards, conn, live="liveB", tool=False)
        await _event(cards, conn, "tool.start", "liveB", name="terminal", tool_id="b1")
        clock.later(3.0)
        stamped = clock()                                               # chat B's Allow: the policy change
        clock.later(1.0)
        await _event(cards, conn, "tool.complete", "liveB", name="terminal", tool_id="b1",
                     result=json.dumps({"output": "ok", "exit_code": 0, "error": None}))
        await _event(cards, conn, "message.complete", "liveB", text="Done.")
        clock.later(C.AGENT_TOOL_GRACE + 1.0)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(refused), last_seen=_iso(stamped))
        await cards._on_proposals(drv.proposals("all"))
        assert [(e["host"], e["chat"]) for e in _events(cards, "raised")] == [(SITE, "chatA")]
        await cards.stop()

    asyncio.run(main())


def test_a_refusal_inside_an_earlier_chats_call_is_not_given_to_the_call_that_runs_when_it_is_listed(harness, drv):
    """OpenShell's own time for the refusal decides between two chats: chat A's call ended eight seconds ago with
    the refusal in it, chat B's call started after that and is still open when the draft is first listed."""
    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _call(cards, conn, clock, 0.2, output="failed")
        refused = clock() - 0.1
        await _event(cards, conn, "message.complete", text="It printed failed.")
        clock.later(5.0)
        await _chat_b(cards, conn)
        await _turn_start(cards, conn, live="liveB", tool=False)
        await _event(cards, conn, "tool.start", "liveB", name="terminal", tool_id="b1")
        clock.later(3.0)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(refused), last_seen=_iso(refused))
        await cards._on_proposals(drv.proposals("all"))
        assert [(e["host"], e["chat"]) for e in _events(cards, "raised")] == [(SITE, "chatA")]
        await cards.stop()

    asyncio.run(main())


def test_one_more_hit_on_an_old_draft_is_a_new_refusal_and_its_call_gets_the_card(harness, drv):
    """The other half of the rule: an old draft that was stamped several times is hit again by a one-command turn
    whose call exits 0. The hit count grows, ``last_seen`` is that refusal, and the draft is listed ten seconds
    later: that chat is asked."""
    async def main():
        cards, conn, clock = await _start(harness)
        [pid] = _old_drafts(drv, clock, n=1)
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))
        for _ in range(3):
            clock.later(4.0)
            _restamp(drv, clock, [pid])
            await cards._on_proposals(drv.proposals("all"))
        assert _cards(conn) == []
        await _call(cards, conn, clock, 0.2, output="failed")
        refused = clock() - 0.1
        await _event(cards, conn, "message.complete", text="It printed failed.")
        clock.later(10.0)
        drv.chunks[pid].update(hit_count=2, last_seen=_iso(refused))
        await cards._on_proposals(drv.proposals("all"))
        assert [(e["host"], e["chat"], e["origin"]) for e in _events(cards, "raised")] == [(OLD[0], "chatA", "proposal:tool")]
        await cards.stop()

    asyncio.run(main())


def test_a_hit_whose_stamp_sits_among_the_other_drafts_policy_stamps_is_given_to_no_call_by_that_time(harness, drv):
    """A draft is hit again somewhere else, and before the launcher lists it a policy change stamps every pending
    draft, this one included: its ``last_seen`` is the policy change, not the refusal. The listing shows that (the
    other drafts moved to the same moment with their hit counts unchanged), so the time is not used: no card in
    the chat whose held call the policy change fell into."""
    async def main():
        cards, conn, clock = await _start(harness)
        ids = _old_drafts(drv, clock, n=3)
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))
        await _call(cards, conn, clock, 20.0, output="ok")              # the chat's call, held on another card
        inside = clock() - 5.0
        await _event(cards, conn, "message.complete", text="Done.")
        clock.later(C.AGENT_TOOL_GRACE + 2.0)
        drv.chunks[ids[0]]["hit_count"] = 2                             # hit again, outside every call of this chat
        _restamp(drv, clock, ids, at=inside)                            # ... then stamped with the rest
        await cards._on_proposals(drv.proposals("all"))
        await _settle(10)
        assert _cards(conn) == [] and _interrupts(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_a_hit_seen_while_no_call_ran_is_not_given_to_a_call_that_starts_later_however_listings_arrive(harness, drv):
    """Listings are read on worker threads and can arrive out of order. An old draft is hit again while no call of
    any chat runs (a background process): nobody's. A call starts afterwards. Neither the same listing again nor
    an older one that arrives late, followed by the current one, makes that one hit a second new refusal."""
    async def main():
        cards, conn, clock = await _start(harness)
        [pid] = _old_drafts(drv, clock, n=1)
        await _turn_start(cards, conn, tool=False)
        before = drv.proposals("all")
        await cards._on_proposals(before)
        clock.later(20.0)
        drv.chunks[pid].update(hit_count=2, last_seen=_iso(clock() - 3.0))
        await cards._on_proposals(drv.proposals("all"))                 # the hit: no call runs, nobody's
        assert _cards(conn) == []
        clock.later(3.0)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t1")
        clock.later(1.0)
        await cards._on_proposals(drv.proposals("all"))                 # the same count again
        await cards._on_proposals(before)                               # an older listing, late
        await cards._on_proposals(drv.proposals("all"))                 # and the current one after it
        await _settle(10)
        assert _cards(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_of_two_calls_still_running_the_one_the_refusal_fell_in_gets_the_card(harness, drv):
    """Two chats each have a call open. The refusal happened before the second one started: the first chat's."""
    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="a1")
        clock.later(2.0)
        refused = clock()
        clock.later(4.0)
        await _chat_b(cards, conn)
        await _turn_start(cards, conn, live="liveB", tool=False)
        await _event(cards, conn, "tool.start", "liveB", name="terminal", tool_id="b1")
        clock.later(3.0)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(refused), last_seen=_iso(refused))
        await cards._on_proposals(drv.proposals("all"))
        assert [(e["host"], e["chat"]) for e in _events(cards, "raised")] == [(SITE, "chatA")]
        await cards.stop()

    asyncio.run(main())


# -- cards left open or decided ----------------------------------------------------------------------------

@pytest.mark.parametrize("left", ["unanswered", "denied"])
def test_a_card_left_open_or_denied_is_not_raised_again_nor_its_chat_paused_by_a_stamp(harness, drv, left):
    """Chat A was asked for the site and left the card unanswered, or denied it. Chat B allows another site five
    times; each change stamps what is still pending. Chat B is never asked for chat A's site, chat A gets no
    second card and its later turn is not paused."""
    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _call(cards, conn, clock, 0.2, output="failed")
        refused = clock() - 0.1
        await _event(cards, conn, "message.complete", text="It printed failed.")
        clock.later(8.0)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(refused), last_seen=_iso(refused))
        await cards._on_proposals(drv.proposals("all"))
        [card] = _cards(conn)
        if left == "denied":
            await cards._from_client(conn, _answer(card, "deny", "Not that site."))
            assert await _until(lambda: drv.chunks["d1"]["status"] == "rejected")
        await _chat_b(cards, conn)
        for round_ in range(5):
            await _turn_start(cards, conn, live="liveB", text=f"step {round_}", tool=False)
            await _event(cards, conn, "tool.start", "liveB", name="terminal", tool_id=f"b{round_}")
            clock.later(2.0)
            _restamp(drv, clock, ["d1"])
            await cards._on_proposals(drv.proposals("all"))
            clock.later(1.0)
            await _event(cards, conn, "tool.complete", "liveB", name="terminal", tool_id=f"b{round_}",
                         result=json.dumps({"output": "ok", "exit_code": 0, "error": None}))
            await _event(cards, conn, "message.complete", "liveB", text="Done.")
            for wait in (1.0, C.AGENT_TOOL_GRACE):
                clock.later(wait)
                await cards._on_proposals(drv.proposals("all"))
        # chat A again, a call that touches nothing: the stamp falls inside it
        await _turn_start(cards, conn, text="list the folder", tool=False)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t2")
        clock.later(1.0)
        _restamp(drv, clock, ["d1"])
        await cards._on_proposals(drv.proposals("all"))
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t2",
                     result=json.dumps({"output": "a.txt", "exit_code": 0, "error": None}))
        await _settle(10)
        assert _hosts(conn) == [SITE] and [e["chat"] for e in _events(cards, "raised")] == ["chatA"]
        assert _interrupts(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_an_old_second_draft_joins_a_card_left_open_without_pausing_the_turn_that_runs_now(harness, drv):
    """Two programs were refused the site long ago: one draft stayed nobody's, the other raised a card after its
    turn, left unanswered. In a later turn of that chat a call runs that touches neither. The old draft joins the
    open card (its answer decides both), but nothing was refused again: the turn is not paused."""
    async def main():
        cards, conn, clock = await _start(harness)
        t = clock() - 300.0
        drv.add_chunk("wget", host=SITE, binary="/usr/bin/wget", first_seen=_iso(t), last_seen=_iso(t))
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))                 # nobody's
        await _call(cards, conn, clock, 0.2, output="failed")
        refused = clock() - 0.1
        await _event(cards, conn, "message.complete", text="It printed failed.")
        clock.later(8.0)
        drv.add_chunk("curl", host=SITE, binary=CURLW, first_seen=_iso(refused), last_seen=_iso(refused))
        await cards._on_proposals(drv.proposals("all"))                 # (the old draft is read first: no card yet)
        assert _hosts(conn) == [SITE] and _interrupts(conn) == []
        assert cards._chunks["curl"].get("carded") and not cards._chunks["wget"].get("carded")
        clock.later(60.0)
        await _turn_start(cards, conn, text="list the folder", tool=False)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t2")
        clock.later(1.0)
        await cards._on_proposals(drv.proposals("all"))
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t2",
                     result=json.dumps({"output": "a.txt", "exit_code": 0, "error": None}))
        await _settle(10)
        assert cards._chunks["wget"].get("carded") == cards._chunks["curl"].get("carded")
        assert _hosts(conn) == [SITE] and _interrupts(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


# -- a failed call that only named the host ----------------------------------------------------------------

def test_an_old_draft_is_no_record_for_a_failed_call_that_only_named_its_host(harness, drv, monkeypatch):
    """A failed call names a host it never connected to (the command stopped before that). OpenShell still holds
    an old pending draft for that host. The call's hosts are candidates: only a refusal on record counts, and a
    draft the launcher listed long before the call is none. No card; the call is not held."""
    monkeypatch.setattr(C, "CANDIDATE_WAIT", 0.4)
    monkeypatch.setattr(C, "CANDIDATE_POLL", 0.05)

    async def main():
        cards, conn, clock = await _start(harness)
        [pid] = _old_drafts(drv, clock, n=1)
        await _turn_start(cards, conn, tool=False)
        await cards._on_proposals(drv.proposals("all"))
        clock.later(40.0)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t1")
        started = clock()
        clock.later(0.3)
        await cards.on_request(_candidate("rq1", "chatA", "terminal", OLD[0], started))
        await _settle(20)
        assert _cards(conn) == []
        assert cards.verdicts.requests["rq1"]["status"] == "refused"
        assert not cards._chunks[pid].get("carded")
        await cards.stop()

    asyncio.run(main())


def test_a_draft_first_listed_while_the_failed_call_waits_still_joins_its_request(harness, drv, monkeypatch):
    """Unchanged: the draft OpenShell makes for the refusal the hook relayed is that request's, as before."""
    monkeypatch.setattr(C, "CANDIDATE_WAIT", 0.4)
    monkeypatch.setattr(C, "CANDIDATE_POLL", 0.05)

    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t1")
        started = clock()
        clock.later(0.3)
        drv.add_chunk("d1", host=SITE, binary=CURLW, first_seen=_iso(clock()), last_seen=_iso(clock()))
        await cards.on_request(_candidate("rq1", "chatA", "terminal", SITE, started))
        assert _hosts(conn) == [SITE]
        assert cards.verdicts.requests["rq1"]["keys"] == [f"net:{SITE}"]
        await cards.stop()

    asyncio.run(main())


# -- a card that could not be shown ------------------------------------------------------------------------

@pytest.mark.parametrize("timed", [True, False])
def test_a_draft_whose_card_could_not_be_shown_is_asked_about_again_at_the_next_listing(harness, drv, timed):
    """The desktop is away when the draft of a call that still runs is first listed: no card can be shown. It is
    back at the next listing and the call is still open: the chat is asked then, once. With OpenShell's own times
    and without (a driver that gives none)."""
    async def main():
        cards, conn, clock = await _start(harness)
        await _turn_start(cards, conn, tool=False)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t1")
        clock.later(1.0)
        refused = clock() - 0.5
        times = {"first_seen": _iso(refused), "last_seen": _iso(refused)} if timed else {}
        drv.add_chunk("d1", host=SITE, binary=CURLW, **times)
        shown = list(cards._conns)
        cards._conns[:] = []                                            # no desktop connection
        await cards._on_proposals(drv.proposals("all"))
        assert _events(cards, "raised") == [] and not cards._chunks["d1"].get("carded")
        cards._conns[:] = shown
        clock.later(2.0)
        await cards._on_proposals(drv.proposals("all"))
        assert [(e["host"], e["chat"]) for e in _events(cards, "raised")] == [(SITE, "chatA")]
        await cards._on_proposals(drv.proposals("all"))
        assert _hosts(conn) == [SITE]
        await cards.stop()

    asyncio.run(main())


def test_drafts_nobody_was_asked_about_stay_so_when_the_desktop_was_away_at_their_first_listing(harness, drv):
    """Asking again is only for a draft that had a chat to ask. Old drafts first listed with no desktop connection
    and no call running are nobody's, and stay so when a policy change stamps them inside a later call."""
    async def main():
        cards, conn, clock = await _start(harness)
        ids = _old_drafts(drv, clock, n=3)
        await _turn_start(cards, conn, tool=False)
        shown = list(cards._conns)
        cards._conns[:] = []
        await cards._on_proposals(drv.proposals("all"))
        cards._conns[:] = shown
        clock.later(10.0)
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t1")
        clock.later(1.0)
        _restamp(drv, clock, ids)
        await cards._on_proposals(drv.proposals("all"))
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t1",
                     result=json.dumps({"output": "ok", "exit_code": 0, "error": None}))
        await _settle(10)
        assert _cards(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())
