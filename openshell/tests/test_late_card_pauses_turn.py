"""A card that arrives after its tool call still blocks the agent (launcher/cards.py).

Recorded on Windows: a refused ``curl -s`` returned at once (nothing in its result read as a refusal), and the
card came two seconds later from OpenShell's draft, while the model was in its next step. Nothing waited for the
answer: the user clicked Allow while the turn ran, the agent finished its reply saying the site could not be
reached, and the rule loaded afterwards with the log line "granted quietly". The same again one prompt later, with
the Allow given just after the turn ended.

A failed call that names its host is now held at the tool boundary (test_tool_boundary_candidates.py). This file
is the rule behind it, for a card that still comes late from OpenShell's draft (a refusal inside a call that
exited 0, or a call that names no host): the launcher pauses that chat's turn when it raises the card
(``session.interrupt`` with ``resume``, as for a grant), keeps the reply paused until the user answers or
``PAUSE_WAIT`` runs out, and continues it with the outcome. An answer given after the turn ended continues the
reply too. Drafts nothing asked about stay without a card.
"""
import asyncio
import json

import pytest

from openshell import sandbox_hook as H
from openshell.launcher import cards as C
from openshell.launcher.spec import load_spec, network_policy
from test_cards import (CURLW, PYW, WinDriver, _answer, _cards, _chat_b, _continuations,  # noqa: F401
                        _interrupted_turn_ends, _interrupts, _pump_requests, _settle, _setup, _turn_start, _until,
                        channel, harness)

SITE = "shop.example.com"
SITE_RULE = "allowed_host_shop_example_com"
OTHER = "cdn.example.net"
ALLOWED = (f"The sandbox blocked {SITE} for a program you ran, and the user has now allowed it. Network access to "
           f"{SITE} (http and https, any program) is in place now, until the sandbox is switched off.")
UNANSWERED = (f"The sandbox blocked {SITE} for a program you ran. A card in the chat asks the user to allow it, and "
              "the user has not answered. Tell the user what you need and why, then stop; if they allow it, the chat "
              "continues by itself.")


class CuttingWinDriver(WinDriver):
    """The recorded build: Windows, and a policy reload that closes open connections (an Allow loads once the
    answering turn has stopped)."""
    capabilities_info = {**WinDriver.capabilities_info, "network_live_interrupts": True}


@pytest.fixture(params=["reload cuts streams", "reload keeps streams"])
def drv(request, harness):
    """Both kinds of build: the recorded one, and one whose reload keeps open connections (an Allow loads at once)."""
    cls = CuttingWinDriver if request.param == "reload cuts streams" else WinDriver
    harness["sup"].driver = driver = cls()
    harness["driver"] = driver
    return driver


@pytest.fixture
def cutting(harness):
    harness["sup"].driver = driver = CuttingWinDriver()
    harness["driver"] = driver
    return driver


@pytest.fixture
def keeping(harness):
    harness["sup"].driver = driver = WinDriver()
    harness["driver"] = driver
    return driver


def _events(cards, name):
    return [r for r in cards._records if r.get("event") == name]


def _steered(conn):
    return [f["params"]["text"] for f in conn.upstream if f.get("method") == "session.steer"]


async def _event(cards, conn, typ, live="live1", **payload):
    await cards._from_sandbox(conn, {"jsonrpc": "2.0", "method": "event", "params": {
        "type": typ, "session_id": live, "payload": payload}})


async def _silent_call_ends(cards, conn, live="live1"):
    """The terminal call returns exit 7 with nothing that reads as a refusal (no hook request), and the model starts
    its next step."""
    await _event(cards, conn, "tool.complete", live, name="terminal", tool_id="t1",
                 result=json.dumps({"output": "HTTP 000\nsize: 0 bytes", "exit_code": 7, "error": None}))
    await _event(cards, conn, "message.delta", live, text="Curl couldn't connect")


async def _late_card(cards, conn, drv, host=SITE, pid="d1"):
    """OpenShell's draft for the refused connection is listed (two seconds after the call, in the record)."""
    drv.add_chunk(pid, host=host, binary=CURLW)
    await cards._on_proposals(drv.proposals("all"))
    card = _cards(conn)[-1]
    assert card["params"]["host"] == host
    return card


async def _paused_on_a_late_card(harness, drv, **kw):
    """A turn whose silent call ended, paused by the card OpenShell's draft raised, and stopped."""
    cards, conn = await _setup(harness, **kw)
    cards._agent_calls.clear()
    await _turn_start(cards, conn)
    await _silent_call_ends(cards, conn)
    card = await _late_card(cards, conn, drv)
    assert len(_interrupts(conn)) == 1
    await _interrupted_turn_ends(cards, conn)
    return cards, conn, card


# -- the recorded order of events ------------------------------------------------------------------------

def test_a_late_card_pauses_the_running_turn_and_allow_continues_the_reply_with_a_retry(harness, drv):
    """15:29:07-15:29:30 in the record: the call returned, the card was raised 1.9 s later with the turn running,
    Allow came 4 s after that. Now the launcher pauses the turn as it raises the card, nothing moves until the
    answer, and the Allow continues the reply."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)                    # "can you try it from curl?": the terminal call runs
        await _silent_call_ends(cards, conn)              # exit 7, no refusal wording: no hook request
        card = await _late_card(cards, conn, drv)
        [raised] = _events(cards, "raised")
        assert raised["origin"] == "proposal:tool" and raised["turn_running"] is True
        [stop] = _interrupts(conn)                        # paused by the launcher, as the card goes up
        assert stop["params"] == {"session_id": "live1", "resume": True} and stop["id"].startswith(C._CALL_PREFIX)
        [paused] = _events(cards, "paused")
        assert paused["chat"] == "chatA" and paused["hosts"] == [SITE] and paused["wait"] == C.PAUSE_WAIT
        assert cards.status()["paused"]["chatA"]["hosts"] == [SITE]
        await _interrupted_turn_ends(cards, conn)
        await _settle(60)
        assert _continuations(conn) == [] and _steered(conn) == [] and sup.applies == []   # waiting for the user
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: sup.applies == [[SITE_RULE]])
        assert await _until(lambda: _continuations(conn))
        await _settle(20)
        [cont] = _continuations(conn)
        assert cont["params"] == {"session_id": "live1", "display_kind": "hidden",
                                  "text": f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"}
        assert len(_interrupts(conn)) == 1 and _steered(conn) == []
        assert _events(cards, "granted quietly") == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_an_allow_given_after_the_turn_ended_continues_the_reply(harness, drv):
    """15:30:24 in the record: the Allow came 1.6 s after the turn had ended, and was "granted quietly". A card
    raised once the turn is over cannot pause it, but its Allow still continues the reply."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        await _event(cards, conn, "message.complete", text="I can't read it from curl either.")
        card = await _late_card(cards, conn, drv)         # listed just after the reply ended
        assert _events(cards, "raised")[0]["turn_running"] is False
        assert _interrupts(conn) == [] and cards.status()["paused"] == {}
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        [cont] = _continuations(conn)
        assert cont["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        assert sup.applies == [[SITE_RULE]] and _events(cards, "granted quietly") == []
        await cards.stop()

    asyncio.run(main())


# -- the three outcomes of a pause -----------------------------------------------------------------------

def test_a_deny_on_a_paused_reply_continues_it_with_the_reason_and_no_retry(harness, drv):
    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        await cards._from_client(conn, _answer(card, "deny", "Use the mirror instead."))
        assert await _until(lambda: _continuations(conn))
        await _settle(20)
        [cont] = _continuations(conn)
        assert cont["params"]["text"] == (f"[Sandbox] The user denied network access to {SITE}. Reason: Use the mirror "
                                          "instead. Continue without it, or ask the user.")
        assert harness["sup"].applies == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_a_pause_nobody_answers_ends_under_the_desktops_cap_and_says_so(harness, drv, monkeypatch):
    """The desktop shows a paused reply as continuing for 120 s, then as stopped. The pause ends before that: the
    reply continues with a note that the user has not answered, the card stays open, and an Allow given later
    continues the reply again."""
    assert C.PAUSE_WAIT + 20 <= 120  # the desktop's cap on a paused reply (its PAUSE_CAP_MS), with room to continue
    monkeypatch.setattr(C, "PAUSE_WAIT", 0.3)
    sup = harness["sup"]

    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        assert await _until(lambda: _continuations(conn))
        [cont] = _continuations(conn)
        assert cont["params"]["text"] == f"[Sandbox] {UNANSWERED}"          # no "retry what the sandbox refused"
        [ended] = _events(cards, "pause ended")
        assert ended["why"] == "no answer" and ended["hosts"] == [SITE]
        assert len(cards.open) == 1 and cards.status()["paused"] == {} and sup.applies == []
        await _event(cards, conn, "message.complete", text="I need access to the site; please allow it.")
        await cards._from_client(conn, _answer(card, "once"))               # the user answers after all
        assert await _until(lambda: len(_continuations(conn)) == 2)
        assert _continuations(conn)[1]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        assert sup.applies == [[SITE_RULE]] and len(_interrupts(conn)) == 1
        await cards.stop()

    asyncio.run(main())


def test_always_allow_on_a_paused_reply_is_saved_and_continues_it(harness, drv):
    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        await cards._from_client(conn, _answer(card, "always"))
        assert await _until(lambda: _continuations(conn))
        text = _continuations(conn)[0]["params"]["text"]
        assert "is in place now, saved to the sandbox's policy." in text and text.endswith(C.CONTINUE_TAIL)
        assert SITE_RULE in (network_policy(load_spec(harness["layout"])).get("approved") or {})
        await cards.stop()

    asyncio.run(main())


def test_one_continuation_carries_every_answer_of_a_pause(harness, drv):
    """The call was refused two sites: two cards, one pause. The reply stays paused until both are answered, then
    continues once with both outcomes."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        first = await _late_card(cards, conn, drv)
        second = await _late_card(cards, conn, drv, host=OTHER, pid="d2")
        assert len(_interrupts(conn)) == 1 and cards.status()["paused"]["chatA"]["hosts"] == [OTHER, SITE]
        await _interrupted_turn_ends(cards, conn)
        await cards._from_client(conn, _answer(first, "once"))
        assert await _until(lambda: harness["sup"].applies == [[SITE_RULE]])
        await _settle(60)
        assert _continuations(conn) == []                 # the second card is still open
        await cards._from_client(conn, _answer(second, "deny", "Not that one."))
        assert await _until(lambda: _continuations(conn))
        await _settle(40)
        [cont] = _continuations(conn)
        text = cont["params"]["text"]
        assert ALLOWED in text and f"The user denied network access to {OTHER}. Reason: Not that one." in text
        assert text.endswith(C.CONTINUE_TAIL)             # the granted site can be retried
        await cards.stop()

    asyncio.run(main())


def test_a_paused_reply_waits_for_an_allowed_rule_to_load_before_it_continues(harness, drv):
    """Two cards, Deny then Allow: the denial's note is ready at once, the grant's only when its rule has loaded
    (seconds, on a real sandbox). The reply continues once, after the load, with both."""
    sup = harness["sup"]
    sup.load_delay = 0.8

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        first = await _late_card(cards, conn, drv)
        second = await _late_card(cards, conn, drv, host=OTHER, pid="d2")
        await _interrupted_turn_ends(cards, conn)
        await cards._from_client(conn, _answer(second, "deny", "Not that one."))
        await cards._from_client(conn, _answer(first, "once"))
        await _settle(50)                                 # 0.5 s: both answered, the rule still loading
        assert _continuations(conn) == [] and sup.loaded_at == []
        assert await _until(lambda: _continuations(conn), n=250)
        await _settle(40)
        [cont] = _continuations(conn)
        assert ALLOWED in cont["params"]["text"] and "Reason: Not that one." in cont["params"]["text"]
        assert len(sup.loaded_at) == 1
        await cards.stop()

    asyncio.run(main())


def test_a_paused_reply_waits_for_an_allow_that_has_not_started_to_load(harness, keeping):
    """Deny on one card; later Allow on the other. For a moment every card is answered and no policy update runs
    yet (answers within the batch window share one). The reply does not continue with the denial alone then: it
    waits for the grant's note, and one continuation carries both."""
    async def main():
        cards, conn = await _setup(harness, batch_window=1.5)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        first = await _late_card(cards, conn, keeping)
        second = await _late_card(cards, conn, keeping, host=OTHER, pid="d2")
        await _interrupted_turn_ends(cards, conn)
        await cards._from_client(conn, _answer(second, "deny", "Not that one."))
        await _settle(40)                                 # the denial's note waits for the other card
        assert _continuations(conn) == []
        await cards._from_client(conn, _answer(first, "once"))
        await _settle(40)                                 # well inside the batch window: nothing loads yet
        assert harness["sup"].applies == [] and _continuations(conn) == []
        assert await _until(lambda: _continuations(conn), n=250)
        await _settle(40)
        [cont] = _continuations(conn)
        assert ALLOWED in cont["params"]["text"] and "Reason: Not that one." in cont["params"]["text"]
        assert _steered(conn) == []
        await cards.stop()

    asyncio.run(main())


# -- when the turn is paused -----------------------------------------------------------------------------

def test_a_card_raised_while_its_call_still_runs_pauses_the_turn_when_the_call_ends(harness, drv):
    """A long command refused early on: stopping the turn now would kill the command. The pause waits for the tool
    boundary."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)                    # the terminal call is still running
        await _late_card(cards, conn, drv)
        await _settle(20)
        assert _interrupts(conn) == [] and cards.status()["paused"]["chatA"]["state"] == "pending"
        await _silent_call_ends(cards, conn)
        assert await _until(lambda: _interrupts(conn))
        [stop] = _interrupts(conn)
        assert stop["params"] == {"session_id": "live1", "resume": True}
        assert cards.status()["paused"]["chatA"]["state"] in ("sent", "paused")
        await cards.stop()

    asyncio.run(main())


def test_the_pause_waits_for_the_last_call_of_a_batch(harness, drv):
    """The model asked for two calls in one step: the first ends and the second starts in the same breath. The
    pause does not stop the turn between them (that would kill the second command); it does when the second ends."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _late_card(cards, conn, drv)
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t1", result="x")
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t2")       # no pause between the frames
        await _settle(40)
        assert _interrupts(conn) == [] and cards.status()["paused"]["chatA"]["state"] == "pending"
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t2", result="y")
        assert await _until(lambda: len(_interrupts(conn)) == 1)
        await cards.stop()

    asyncio.run(main())


def test_an_answer_while_the_call_still_runs_is_steered_into_the_turn_where_the_reload_keeps_streams(harness, keeping):
    """Allowed (or denied) before the command has even finished: nothing to pause. The agent hears it in the
    running turn, and the turn is never stopped."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        first = await _late_card(cards, conn, keeping)
        second = await _late_card(cards, conn, keeping, host=OTHER, pid="d2")
        await cards._from_client(conn, _answer(first, "once"))
        assert await _until(lambda: _steered(conn))
        assert _steered(conn) == [f"[Sandbox] {ALLOWED}"]
        await cards._from_client(conn, _answer(second, "deny", "Not that one."))
        assert await _until(lambda: len(_steered(conn)) == 2)
        assert _steered(conn)[1].startswith(f"[Sandbox] The user denied network access to {OTHER}.")
        await _silent_call_ends(cards, conn)
        await _settle(40)
        assert _interrupts(conn) == [] and _continuations(conn) == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_an_allow_while_the_call_still_runs_stops_the_turn_when_the_call_ends_where_the_reload_cuts_streams(harness,
                                                                                                        cutting):
    """There the rule cannot load under a running turn. The command is not killed for it: the launcher stops the
    turn (once) when the call ends, loads the rule and continues the reply."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        card = await _late_card(cards, conn, cutting)
        await cards._from_client(conn, _answer(card, "once"))
        await _settle(40)
        assert _interrupts(conn) == [] and sup.applies == []          # the call still runs
        await _silent_call_ends(cards, conn)
        assert await _until(lambda: _interrupts(conn))
        assert [f["params"] for f in _interrupts(conn)] == [{"session_id": "live1", "resume": True}]
        assert sup.applies == []
        await _interrupted_turn_ends(cards, conn)
        assert await _until(lambda: _continuations(conn))
        await _settle(20)
        assert sup.applies == [[SITE_RULE]] and len(_interrupts(conn)) == 1
        assert _continuations(conn)[0]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        await cards.stop()

    asyncio.run(main())


def test_an_answer_that_races_the_stopping_turn_goes_out_as_the_continuation_not_a_steer(harness, drv):
    """The interrupt is on its way and the user has already clicked Allow: a steer would land in a turn that is
    ending, and a second interrupt would be one too many. The note waits for the turn to stop and continues the
    reply; where the reload cuts streams, the rule loads then too."""
    sup = harness["sup"]
    cuts = drv.capabilities()["network_live_interrupts"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        card = await _late_card(cards, conn, drv)
        assert len(_interrupts(conn)) == 1                # sent; the backend has not reported the turn stopped
        await cards._from_client(conn, _answer(card, "once"))
        await _settle(80)
        assert sup.applies == ([] if cuts else [[SITE_RULE]])
        assert _steered(conn) == [] and _continuations(conn) == [] and len(_interrupts(conn)) == 1
        await _interrupted_turn_ends(cards, conn)
        assert await _until(lambda: _continuations(conn))
        assert _continuations(conn)[0]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        assert sup.applies == [[SITE_RULE]] and _steered(conn) == [] and len(_interrupts(conn)) == 1
        await cards.stop()

    asyncio.run(main())


def test_a_card_left_open_pauses_the_turn_that_is_refused_the_same_site_again(harness, drv):
    """The card was raised after an earlier reply ended and never answered. In the next turn a program is refused
    the same site (OpenShell counts another hit on its draft): that turn pauses on the open card."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        await _event(cards, conn, "message.complete", text="It failed.")
        await _late_card(cards, conn, drv)
        assert _interrupts(conn) == []
        await _turn_start(cards, conn, text="try again")
        drv.chunks["d1"]["hit_count"] = 2
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1 and _interrupts(conn) == []          # one card; the call still runs
        await _silent_call_ends(cards, conn)
        assert await _until(lambda: len(_interrupts(conn)) == 1)
        assert cards.status()["paused"]["chatA"]["hosts"] == [SITE]
        await cards.stop()

    asyncio.run(main())


@pytest.mark.parametrize("choice", ["once", "deny"])
def test_a_call_that_slipped_in_while_the_turn_was_stopping_does_not_swallow_the_answer(harness, channel, keeping,
                                                                                        choice):
    """The interrupt went out as the model started another call; that call is refused the same site, says so, and
    its hook waits on the open card. Its result reaches a turn that then ends, so the answer must also continue
    the reply: a turn the launcher paused always gets its continuation."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        card = await _late_card(cards, conn, keeping)
        assert len(_interrupts(conn)) == 1
        await _event(cards, conn, "tool.start", name="terminal", tool_id="t2")
        keeping.deny_line(SITE, binary=CURLW)
        hook = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "terminal", {"command": f"curl -v https://{SITE}/"},
            "curl: (56) CONNECT tunnel failed, response 403", session_id="chatA"))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        assert len(_cards(conn)) == 1 and not hook.done()
        await cards._from_client(conn, _answer(card, choice, "Not now." if choice == "deny" else None))
        told = await asyncio.wait_for(hook, 10)
        assert ("retry the request now" if choice == "once" else "Reason: Not now.") in told
        await _event(cards, conn, "tool.complete", name="terminal", tool_id="t2", result=told)
        await _interrupted_turn_ends(cards, conn)
        assert await _until(lambda: _continuations(conn))
        await _settle(20)
        [cont] = _continuations(conn)
        text = cont["params"]["text"]
        if choice == "once":
            assert f"Network access to {SITE} (http and https, any program) is in place now" in text
            assert text.endswith(C.CONTINUE_TAIL)
        else:
            assert text == (f"[Sandbox] The user denied network access to {SITE}. Reason: Not now. Continue without "
                            "it, or ask the user.")
        assert len(_interrupts(conn)) == 1 and _steered(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_a_second_draft_for_a_card_left_open_pauses_the_turn_too(harness, drv):
    """As above, but OpenShell lists a new draft (the same site on another port) instead of another hit."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        await _event(cards, conn, "message.complete", text="It failed.")
        await _late_card(cards, conn, drv)
        await _turn_start(cards, conn, text="try again")
        await _silent_call_ends(cards, conn)
        drv.add_chunk("d2", host=SITE, port=80, binary=CURLW)
        await cards._on_proposals(drv.proposals("all"))
        assert len(_cards(conn)) == 1 and len(_interrupts(conn)) == 1
        assert cards.status()["paused"]["chatA"]["hosts"] == [SITE]
        await cards.stop()

    asyncio.run(main())


# -- who ends a pause ------------------------------------------------------------------------------------

def test_the_users_stop_ends_the_pause_and_a_later_allow_still_continues_the_reply(harness, drv, monkeypatch):
    monkeypatch.setattr(C, "PAUSE_WAIT", 0.3)

    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        await cards._from_client(conn, {"jsonrpc": "2.0", "id": 40, "method": "session.interrupt",
                                        "params": {"session_id": "live1"}})
        await _settle(80)                                 # past PAUSE_WAIT
        assert _continuations(conn) == [] and cards.status()["paused"] == {}
        assert [e["why"] for e in _events(cards, "pause ended")] == ["the user stopped the reply"]
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        assert _continuations(conn)[0]["params"]["text"] == f"[Sandbox] {ALLOWED} {C.CONTINUE_TAIL}"
        await cards.stop()

    asyncio.run(main())


def test_the_users_own_prompt_ends_the_pause_and_carries_the_note(harness, drv, monkeypatch):
    monkeypatch.setattr(C, "PAUSE_WAIT", 0.3)

    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        out = await cards._from_client(conn, {"jsonrpc": "2.0", "id": 41, "method": "prompt.submit",
                                              "params": {"session_id": "live1", "text": "never mind, use the docs"}})
        assert out["params"]["text"] == f"[Sandbox] {UNANSWERED}\n\nnever mind, use the docs"
        await _settle(80)
        assert _continuations(conn) == [] and cards.status()["paused"] == {} and len(cards.open) == 1
        await cards.stop()

    asyncio.run(main())


def test_a_card_decided_on_the_sandbox_page_ends_the_pause_with_that_outcome(harness, drv):
    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)
        drv.chunks["d1"]["status"] = "rejected"           # decided on the Sandbox page, not on the card
        await cards._on_proposals(drv.proposals("all"))
        assert cards.open == {}
        assert await _until(lambda: _continuations(conn))
        assert _continuations(conn)[0]["params"]["text"] == (
            f"[Sandbox] Network access to {SITE} was denied on the Sandbox page. Continue without it, or ask the user.")
        assert cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


def test_a_grant_that_cannot_be_put_in_force_still_continues_the_paused_reply(harness, drv):
    """Allow on a paused reply's card, and the policy update fails: the reply continues and says so (the grant
    is withdrawn), instead of staying paused."""
    sup = harness["sup"]

    async def main():
        cards, conn, card = await _paused_on_a_late_card(harness, drv)

        async def refuse(network):
            raise RuntimeError("the gateway refused the policy")

        sup.apply_network = refuse
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: _continuations(conn))
        text = _continuations(conn)[0]["params"]["text"]
        assert f"Network access to {SITE} could not be granted: the gateway refused the policy" in text
        assert cards.grants == [] and cards.status()["paused"] == {}
        await cards.stop()

    asyncio.run(main())


# -- what stays as it was --------------------------------------------------------------------------------

def test_a_draft_nothing_asked_about_raises_no_card_and_pauses_nothing(harness, drv):
    """Hermes's own fetches (the model catalog) run as the backend's interpreter, also right after a terminal call:
    no card, no pause, no message, as before."""
    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        drv.add_chunk("own", host="models.dev", binary=PYW)
        await cards._on_proposals(drv.proposals("all"))
        await _settle(20)
        assert _cards(conn) == [] and _interrupts(conn) == [] and cards.status()["paused"] == {}
        assert [e["draft"] for e in _events(cards, "draft not carded")] == ["own"]
        await cards.stop()

    asyncio.run(main())


def test_a_card_a_held_call_waits_on_does_not_pause_the_turn(harness, channel, keeping, monkeypatch):
    """The draft raised the card while the call ran; the call then failed, named another host, and its hook
    request waits on that card. The call is held, so nothing needs pausing when it returns."""
    monkeypatch.setattr(C, "CANDIDATE_WAIT", 0.4)
    monkeypatch.setattr(C, "CANDIDATE_POLL", 0.05)

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _turn_start(cards, conn)
        card = await _late_card(cards, conn, keeping, host="www.example.org")
        assert cards.status()["paused"]["chatA"]["state"] == "pending"
        hook = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "terminal", {"command": "curl -sL https://example.org/"},
            json.dumps({"output": "", "exit_code": 7}), session_id="chatA", status="error", duration_ms=3000))
        await _pump_requests(cards, lambda: cards.verdicts.requests)
        assert cards.status()["paused"] == {} and not hook.done()
        await cards._from_client(conn, _answer(card, "once"))
        assert "retry the request now" in json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        await _silent_call_ends(cards, conn)              # the held call returns: tool.complete
        await _settle(40)
        assert _interrupts(conn) == [] and _steered(conn) == [] and _continuations(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_a_card_raised_for_a_held_call_never_pauses(harness, channel, keeping):
    """The usual path: the hook relays the refusal, the card is raised with the call held. No pause at any point."""
    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn)
        keeping.deny_line(SITE, binary=CURLW)
        hook = asyncio.ensure_future(asyncio.to_thread(
            H.resolve, "terminal", {"command": f"curl https://{SITE}/"},
            "curl: (56) CONNECT tunnel failed, response 403", session_id="chatA"))
        await _pump_requests(cards, lambda: _cards(conn))
        keeping.add_chunk("d1", host=SITE, binary=CURLW)  # OpenShell's draft for it joins the card
        await cards._on_proposals(keeping.proposals("all"))
        await _settle(20)
        assert len(_cards(conn)) == 1 and _interrupts(conn) == [] and cards.status()["paused"] == {}
        await cards._from_client(conn, _answer(_cards(conn)[0], "once"))
        assert "retry the request now" in await asyncio.wait_for(hook, 10)
        await _silent_call_ends(cards, conn)
        await _settle(40)
        assert _interrupts(conn) == [] and _steered(conn) == [] and _continuations(conn) == []
        await cards.stop()

    asyncio.run(main())


def test_another_chats_turn_is_not_stopped_and_does_not_hold_the_paused_reply(harness, cutting):
    """Chat B runs a tool call while chat A's reply is paused on a card. B's turn is never interrupted, and A's
    Allow loads at once (a reload cuts only a streaming reply, and B streams none): A does not wait for B's turn
    to end."""
    sup = harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        cards._agent_calls.clear()
        await _chat_b(cards, conn)
        await _turn_start(cards, conn, live="liveB", tool_name="read_file")     # B: a tool call in flight
        await _turn_start(cards, conn)
        await _silent_call_ends(cards, conn)
        card = await _late_card(cards, conn, cutting)
        assert [f["params"]["session_id"] for f in _interrupts(conn)] == ["live1"]
        await _interrupted_turn_ends(cards, conn)
        await cards._from_client(conn, _answer(card, "once"))
        assert await _until(lambda: sup.applies == [[SITE_RULE]])
        assert await _until(lambda: _continuations(conn))
        [cont] = _continuations(conn)
        assert cont["params"]["session_id"] == "live1"
        assert [f["params"]["session_id"] for f in _interrupts(conn)] == ["live1"]
        await cards.stop()

    asyncio.run(main())
