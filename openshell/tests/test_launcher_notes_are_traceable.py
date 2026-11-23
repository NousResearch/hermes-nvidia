"""A note of the launcher's own (a sign-in that ended) can be followed in the card log: one line when it is queued
and why it waits, one when it goes out, one when the backend refuses the message that carried it (with the
backend's own words), and one when it never went out.
"""
import asyncio

import test_cards as TC
from openshell.launcher import cards as C
from test_cards import harness  # noqa: F401  (the fixture)

NOTE = ("The Nous Portal sign-in expired on this computer. Turn the sandbox off, sign in to Nous Portal, then turn "
        "it on again.")
LINE = "[Sandbox] " + NOTE


def _events(cards, *names):
    return [row for row in cards._records if row["event"] in names]


def _submit(rid, text="hello"):
    return {"jsonrpc": "2.0", "id": rid, "method": "prompt.submit", "params": {"session_id": "live1", "text": text}}


def test_a_note_with_no_chat_open_says_why_it_waits(tmp_path):
    cards = C.Cards(None, None, tmp_path / "cards.jsonl")
    asyncio.run(cards.note(NOTE))
    assert _events(cards, "noted") == [{"event": "noted", "chat": None, "text": LINE,
                                        "why": "no chat is open: it goes with the first message"}]


def test_a_note_for_an_idle_chat_is_followed_from_the_queue_to_the_message_that_takes_it(harness):  # noqa: F811
    async def main():
        cards, conn = await TC._setup(harness)
        await cards.note(NOTE)
        assert _events(cards, "noted") == [{"event": "noted", "chat": "chatA", "text": LINE,
                                            "why": "no reply runs in the chat: it goes with its next message"}]
        assert conn.upstream == [] and cards.notices == {"chatA": [LINE]}  # nothing is sent to a model that is idle
        first = await cards._from_client(conn, _submit(7))
        assert first["params"]["text"] == LINE + "\n\nhello"
        # the backend refuses that message and the desktop sends it again: the note goes with the second one
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "id": 7,
                                         "error": {"code": 4009, "message": "session busy " + "x" * 400, "data": {"k": 1}}})
        [kept] = _events(cards, "kept")
        assert kept["why"] == "submit refused" and kept["notes"] == [LINE]
        assert kept["error"] == {"code": 4009, "message": ("session busy " + "x" * 400)[:200]}
        second = await cards._from_client(conn, _submit(8))
        assert second["params"]["text"] == LINE + "\n\nhello"
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "id": 8, "result": {"status": "ok"}})
        assert [row["event"] for row in _events(cards, "noted", "delivered", "kept", "notes lost")] == \
            ["noted", "delivered", "kept", "delivered"]
        await cards.stop()
        assert _events(cards, "notes lost") == []  # it went out: nothing was lost

    asyncio.run(main())


def test_a_note_that_never_went_out_is_named_when_the_launcher_stops(harness):  # noqa: F811
    async def main():
        cards, _conn = await TC._setup(harness)
        await cards.note(NOTE)
        cards._unplaced_notes.append("A note no chat ever took.")
        await cards.stop()
        why = "the launcher stopped before the chat's next message"
        assert _events(cards, "notes lost") == [
            {"event": "notes lost", "chat": "chatA", "notes": [LINE], "why": why},
            {"event": "notes lost", "chat": None, "notes": ["[Sandbox] A note no chat ever took."], "why": why}]
        await cards.stop()
        assert len(_events(cards, "notes lost")) == 2  # said once

    asyncio.run(main())


def test_a_continuation_dropped_with_its_chat_is_named(harness):  # noqa: F811
    async def main():
        cards, conn = await TC._setup(harness)
        cards._continue_text["chatA"] = ["The user allowed read access to a folder."]
        await cards._from_client(conn, {"jsonrpc": "2.0", "id": 9, "method": "session.close", "params": {"session_id": "live1"}})
        assert _events(cards, "notes lost") == [{"event": "notes lost", "chat": "chatA",
                                                 "notes": ["[Sandbox] The user allowed read access to a folder."],
                                                 "why": "the chat was closed"}]
        await cards.stop()

    asyncio.run(main())
