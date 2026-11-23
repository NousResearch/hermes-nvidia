"""The reply an approval's restart stopped goes on whichever page the window shows (launcher/cards.py).

An Allow that restarts the sandbox (a folder, or a tool category that binds a sign-in) ends the desktop's
connection. A window that shows the chat resumes it on the new connection, and the launcher continues the
reply there. A window that shows another page (the Sandbox page, say) connects again and resumes nothing:
the launcher then resumes the chat on that connection itself, the way the desktop does when the chat is
opened, and continues the reply. With no window connected at all the reply cannot go on: the chat says so in
one line when it is next opened, the note for the agent rides on the user's next message, and the approval
stands, so the request raises no second card. The fakes are ``test_cards``'s.
"""
import asyncio
import json

import pytest

from test_cards import (FakeConn, _answer, _cards, _continuations, _pump_requests, _run_hook, _settle,  # noqa: F401
                        _setup, _turn_end, _turn_start, _until, channel, harness)
from test_tool_category_cards import FIRECRAWL, _refused_web_extract, signed_in  # noqa: F401

from openshell import sandbox_hook as H
from openshell.launcher import cards as C

NOTE = "Hermes's Web extract tool can reach its web services now, until the sandbox is switched off."


class Window(FakeConn):
    """A desktop connection made after the restart. Its backend answers the launcher's own calls the way
    Hermes does: ``session.resume`` of a stored chat gives it a live session (``refuse`` of them fail first)."""

    def __init__(self, cards, live="live2", refuse=0):
        super().__init__()
        self.cards, self.live, self.refuse = cards, live, refuse
        self.opened = cards._clock()

    async def to_upstream(self, data):
        await super().to_upstream(data)
        frame = self.upstream[-1]
        method, params = frame.get("method"), frame.get("params") or {}
        if method == "session.resume" and self.refuse:
            self.refuse -= 1
            reply = {"error": {"code": 5000, "message": "resume failed"}}
        elif method == "session.resume":
            reply = {"result": {"session_id": self.live, "resumed": params.get("session_id"),
                                "session_key": params.get("session_id"), "running": False, "messages": []}}
        elif method == "prompt.submit":
            reply = {"result": {"status": "streaming"}}
        elif method == "session.active_list":
            reply = {"result": {"sessions": []}}
        else:
            reply = {"result": {}}
        back = {"jsonrpc": "2.0", "id": frame.get("id"), **reply}
        asyncio.get_running_loop().call_soon(lambda: asyncio.ensure_future(self.cards._from_sandbox(self, back)))

    def sent(self, method):
        return [f for f in self.upstream if f.get("method") == method]


def _restart_drops_the_window(cards, sup, after=None):
    """As the launcher does it: the restart closes every desktop connection. *after* makes the connection the
    window comes back with (None: no window comes back)."""
    plain, made = sup.restart, []

    async def restart(note=None):
        for conn in list(cards._conns):
            cards._conns.remove(conn)
            cards._closed(conn)
        await plain(note)
        if after is not None:
            made.append(after())
            cards._conns.append(made[-1])

    sup.restart = restart
    return made


def _events(cards, *names):
    return [r["event"] for r in cards._records if r["event"] in names]


async def _allowed_web_extract(cards, conn, drv):
    hook = await _refused_web_extract(cards, conn, drv)
    [card] = _cards(conn)
    await cards._from_client(conn, _answer(card, "once"))
    await asyncio.wait_for(hook, 10)
    await _turn_end(cards, conn)


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(C, "RESUME_GRACE", 0.1, raising=False)
    monkeypatch.setattr(C, "RESUME_RETRY", 0.1, raising=False)


def test_a_tool_approvals_reply_continues_while_the_window_shows_another_page(signed_in, channel, quick):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]

    async def main():
        cards, conn = await _setup(signed_in)
        made = _restart_drops_the_window(cards, sup, after=lambda: Window(cards))
        await _allowed_web_extract(cards, conn, drv)
        assert len(sup.restarts) == 1 and sup.bound == {(FIRECRAWL, 443)}
        [window] = made
        assert await _until(lambda: window.sent("prompt.submit"))
        # the launcher resumed the chat on the window's connection, as the desktop does when a chat is opened
        [resume] = window.sent("session.resume")
        assert resume["params"] == {"session_id": "chatA", "cols": 96, "source": "desktop", "defer_history": True,
                                    "omit_messages": True}
        assert resume["id"].startswith("sandbox-call-")
        [cont] = window.sent("prompt.submit")
        assert cont["params"]["session_id"] == "live2" and cont["params"]["display_kind"] == "hidden"
        assert NOTE in cont["params"]["text"] and C.CONTINUE_TAIL in cont["params"]["text"]
        assert _events(cards, "resumed", "continued", "noted") == ["resumed", "continued"]
        [resumed] = [r for r in cards._records if r["event"] == "resumed"]
        assert resumed["chat"] == "chatA" and resumed["session_id"] == "live2"
        assert window.client == []  # the launcher's own calls and their answers never reach the desktop
        assert cards._chat_of("live2") == "chatA" and cards._chat_running("chatA")
        # the row settles with the restart, whatever the chat does
        [row] = cards.grants_view()["grants"]
        assert row["status"] == "active" and "restart" not in row
        # the user opens the chat again: the desktop's own resume joins the same session, and nothing is sent twice
        await cards._from_client(window, {"jsonrpc": "2.0", "id": 9, "method": "session.resume",
                                          "params": {"session_id": "chatA", "source": "desktop"}})
        await cards._from_sandbox(window, {"jsonrpc": "2.0", "id": 9, "result": {"session_id": "live2", "running": True}})
        await _settle(20)
        assert len(window.sent("prompt.submit")) == 1 and len(window.sent("session.resume")) == 1
        assert [f for f in window.client if f.get("method") == "event"] == []
        await cards.stop()

    asyncio.run(main())


def test_a_folder_approvals_reply_continues_while_the_window_shows_another_page(harness, channel, monkeypatch, quick):  # noqa: F811
    sup, outside = harness["sup"], harness["outside"]
    monkeypatch.setattr(H, "_visible_parent", lambda path: False)

    async def main():
        cards, conn = await _setup(harness)
        made = _restart_drops_the_window(cards, sup, after=lambda: Window(cards))
        await _turn_start(cards, conn, tool_name="read_file")
        secret = outside / "secret.txt"
        hook = asyncio.ensure_future(_run_hook("read_file", {"path": str(secret)},
                                               {"error": f"File not found: {secret}", "not_found": True}))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "once"))
        json.loads(await asyncio.wait_for(hook, 10))
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 1
        [window] = made
        assert await _until(lambda: window.sent("prompt.submit"))
        assert [f["params"]["session_id"] for f in window.sent("session.resume")] == ["chatA"]
        [cont] = window.sent("prompt.submit")
        assert cont["params"]["session_id"] == "live2" and "restarted with read access to" in cont["params"]["text"]
        assert _events(cards, "resumed", "continued", "noted") == ["resumed", "continued"]
        await cards.stop()

    asyncio.run(main())


def test_a_window_that_shows_the_chat_resumes_it_itself_and_the_launcher_sends_no_resume(signed_in, channel, monkeypatch):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]
    monkeypatch.setattr(C, "RESUME_GRACE", 2.0, raising=False)  # (the turn's end settles for 0.6 s first)

    async def main():
        cards, conn = await _setup(signed_in)
        made = _restart_drops_the_window(cards, sup, after=lambda: Window(cards, live="live7"))
        await _allowed_web_extract(cards, conn, drv)
        [window] = made
        await asyncio.sleep(0.1)  # the desktop resumes the chat it shows a moment after it is connected again
        await cards._from_client(window, {"jsonrpc": "2.0", "id": 5, "method": "session.resume",
                                          "params": {"session_id": "chatA", "source": "desktop", "profile": "work"}})
        await cards._from_sandbox(window, {"jsonrpc": "2.0", "id": 5, "result": {"session_id": "live7"}})
        assert await _until(lambda: window.sent("prompt.submit"))
        assert window.sent("session.resume") == []
        assert window.sent("prompt.submit")[0]["params"]["session_id"] == "live7"
        assert _events(cards, "resumed", "continued", "noted") == ["continued"]
        await cards.stop()

    asyncio.run(main())


def test_the_launchers_resume_names_the_profile_the_desktop_named_for_the_chat(signed_in, channel, quick):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]

    async def main():
        cards, conn = await _setup(signed_in)
        # the desktop had opened this chat with its own resume before
        await cards._from_client(conn, {"jsonrpc": "2.0", "id": 3, "method": "session.resume",
                                        "params": {"session_id": "chatA", "cols": 120, "source": "desktop",
                                                   "profile": "work", "defer_history": True, "omit_messages": True}})
        await cards._from_sandbox(conn, {"jsonrpc": "2.0", "id": 3, "result": {"session_id": "live1"}})
        made = _restart_drops_the_window(cards, sup, after=lambda: Window(cards))
        await _allowed_web_extract(cards, conn, drv)
        [window] = made
        assert await _until(lambda: window.sent("prompt.submit"))
        [resume] = window.sent("session.resume")
        assert resume["params"] == {"session_id": "chatA", "cols": 120, "source": "desktop", "profile": "work",
                                    "defer_history": True, "omit_messages": True}
        await cards.stop()

    asyncio.run(main())


def test_a_resume_the_backend_refuses_is_tried_again(signed_in, channel, quick):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]

    async def main():
        cards, conn = await _setup(signed_in)
        made = _restart_drops_the_window(cards, sup, after=lambda: Window(cards, refuse=2))
        await _allowed_web_extract(cards, conn, drv)
        [window] = made
        assert await _until(lambda: window.sent("prompt.submit"), n=300)
        assert len(window.sent("session.resume")) == 3 and len(window.sent("prompt.submit")) == 1
        assert _events(cards, "resume refused", "resumed", "continued", "noted") == [
            "resume refused", "resume refused", "resumed", "continued"]
        await cards.stop()

    asyncio.run(main())


def test_with_no_window_the_chat_says_so_when_it_is_opened_and_the_request_needs_no_new_card(signed_in, channel, monkeypatch, quick):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]
    monkeypatch.setattr(C, "CONTINUE_WAIT", 0.5, raising=False)
    monkeypatch.setattr(C, "STOPPED_LINE_DELAY", 0.05, raising=False)

    async def main():
        cards, conn = await _setup(signed_in)
        _restart_drops_the_window(cards, sup, after=None)  # the window was closed: nothing connects again
        await _allowed_web_extract(cards, conn, drv)
        assert await _until(lambda: _events(cards, "noted"), n=300)
        [noted] = [r for r in cards._records if r["event"] == "noted"]
        assert noted["why"] == "no window was connected" and noted["chat"] == "chatA"
        assert cards.notices["chatA"] == ["[Sandbox] " + NOTE]
        # the sandbox itself is as approved: the row is settled, and the tool raises no card
        [row] = cards.grants_view()["grants"]
        assert row["status"] == "active" and sup.bound == {(FIRECRAWL, 443)}

        # later a window opens the chat
        window = Window(cards)
        cards._conns.append(window)
        await cards._from_client(window, {"jsonrpc": "2.0", "id": 4, "method": "session.resume",
                                          "params": {"session_id": "chatA", "source": "desktop"}})
        await cards._from_sandbox(window, {"jsonrpc": "2.0", "id": 4, "result": {"session_id": "live2"}})
        assert await _until(lambda: [f for f in window.client if f.get("method") == "event"])
        [said] = [f for f in window.client if f.get("method") == "event"]
        assert said["params"] == {"type": "error", "session_id": "live2", "payload": {"message": C.STOPPED_LINE}}
        assert C.STOPPED_LINE == "This reply stopped when the sandbox restarted. Send your message again."
        assert window.sent("prompt.submit") == []  # nothing starts by itself this late
        assert _events(cards, "told") == ["told"]

        # opened once more: not said twice
        await cards._from_client(window, {"jsonrpc": "2.0", "id": 5, "method": "session.resume",
                                          "params": {"session_id": "chatA", "source": "desktop"}})
        await cards._from_sandbox(window, {"jsonrpc": "2.0", "id": 5, "result": {"session_id": "live2"}})
        await _settle(20)
        assert len([f for f in window.client if f.get("method") == "event"]) == 1

        # the user sends the request again: the agent is told what happened, and no card is raised
        out = await cards._from_client(window, {"jsonrpc": "2.0", "id": 6, "method": "prompt.submit",
                                                "params": {"session_id": "live2", "text": "read example.com"}})
        assert out["params"]["text"] == "[Sandbox] " + NOTE + "\n\nread example.com"
        status, _ = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 204 and _cards(window) == []
        await cards.stop()

    asyncio.run(main())


def test_a_kept_note_goes_with_its_approval_when_that_is_removed(signed_in, channel, monkeypatch, quick):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]
    monkeypatch.setattr(C, "CONTINUE_WAIT", 0.5, raising=False)
    monkeypatch.setattr(C, "STOPPED_LINE_DELAY", 0.05, raising=False)

    async def main():
        cards, conn = await _setup(signed_in)
        _restart_drops_the_window(cards, sup, after=None)
        await _allowed_web_extract(cards, conn, drv)
        assert await _until(lambda: _events(cards, "noted"), n=300)
        assert cards.notices["chatA"] == ["[Sandbox] " + NOTE]
        assert (await cards.remove_grant("network:allow:tool:web_extract"))[0] == 200
        assert "chatA" not in cards.notices  # the agent is not told of an approval that is gone
        [dropped] = [r for r in cards._records if r["event"] == "notes lost"]
        assert dropped["why"] == "the approval was removed" and dropped["notes"] == ["[Sandbox] " + NOTE]
        await cards.stop()

    asyncio.run(main())


def test_a_continuation_still_waiting_is_dropped_with_its_approval(signed_in, channel, monkeypatch):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]
    monkeypatch.setattr(C, "CONTINUE_WAIT", 30.0, raising=False)

    async def main():
        cards, conn = await _setup(signed_in)
        _restart_drops_the_window(cards, sup, after=None)
        await _allowed_web_extract(cards, conn, drv)
        assert cards._continue_text.get("chatA") == [NOTE]  # it waits for a window
        assert (await cards.remove_grant("network:allow:tool:web_extract"))[0] == 200
        assert not cards._continue_text.get("chatA") and "chatA" not in cards.notices
        window = Window(cards)
        cards._conns.append(window)
        await _settle(60)
        assert window.sent("prompt.submit") == [] and window.sent("session.resume") == []
        await cards.stop()

    asyncio.run(main())
