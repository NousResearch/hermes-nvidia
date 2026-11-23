"""The card of a tool category (launcher/cards.py, categories.py): the first time a tool of a category is used
its services open with one card, the existing tool card. Where the profile is signed in to Nous Portal the Allow
binds the sign-in to the category's host of the tool gateway, which a sandbox gets only at a start: the sandbox
restarts as for a folder and the reply continues. The fakes are ``test_cards``'s.
"""
import asyncio
import json

import pytest

import test_cards as TC
from test_cards import (EXTRACT_ARGS, TOOL_RULE, _answer, _cards, _continuations, _interrupts, _pump_requests,  # noqa: F401
                        _run_hook, _settle, _setup, _turn_end, _turn_start, channel, harness)

from openshell import sandbox_hook as H
from openshell.launcher import cards as C
from openshell.launcher.spec import load_spec, network_policy

FIRECRAWL = "firecrawl-gateway.nousresearch.com"
RING = ["mcp.exa.ai", "search.parallel.ai", "api.firecrawl.dev", "api.keenable.ai"]
# What Hermes's web tool reports when the sandbox refused its connect (Linux: the supervisor's answer is EACCES).
REFUSED = {"results": [{"url": "https://example.com", "title": "", "content": "", "error": "[Errno 13] Permission denied"}]}


def categories():
    from openshell.launcher import categories as module

    return module


class SignedInSup(TC.FakeSup):
    """A supervisor whose profile is signed in to Nous Portal: an approved tool category has the sign-in bound
    to its gateway hosts from the next start on, as ``Supervisor`` does it."""

    def __init__(self, layout, driver, grants=None):
        super().__init__(layout, driver, grants)
        self.bound: set = set()

    def approved_tools(self):
        return categories().granted(network_policy(self.spec).get("approved"), self.temporary.get("approved"))

    def tool_services(self, category_id):
        category = categories().by_id(category_id)
        return {"plain": list(category.keyless),
                "bound": [{"host": host, "port": port, "label": "Nous Portal"}
                          for host, port in categories().gateway_endpoints(category)]}

    def bound_hosts(self):
        return set(self.bound)

    async def restart(self, note=None):
        await super().restart(note)
        self.bound = {endpoint for cid in self.approved_tools()
                      for endpoint in categories().gateway_endpoints(categories().by_id(cid))}


@pytest.fixture
def signed_in(harness):  # noqa: F811
    harness["sup"] = SignedInSup(harness["layout"], harness["driver"], harness["sup"]._grants)
    return harness


async def _refused_web_extract(cards, conn, drv):
    """web_extract runs with the profile's web tools on the Nous gateway and is refused there."""
    await _turn_start(cards, conn, tool_name="web_extract")
    drv.deny(FIRECRAWL)
    hook = asyncio.ensure_future(_run_hook("web_extract", EXTRACT_ARGS, json.dumps(REFUSED)))
    await _pump_requests(cards, lambda: _cards(conn))
    return hook


def test_web_extract_on_the_gateway_asks_once_restarts_and_the_reply_continues(signed_in, channel):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]

    async def main():
        cards, conn = await _setup(signed_in)
        hook = await _refused_web_extract(cards, conn, drv)
        [card] = _cards(conn)
        p = card["params"]
        assert p["kind"] == "network" and p["label"] == "Web extract" and p["host"] == "tool:web_extract"
        assert p["description"] == "Allow Hermes's Web extract tool to reach its web services"
        assert p["risk"] == ("Hermes's web extract tool uses one of these services, whichever it picks: "
                             f"{FIRECRAWL}, {', '.join(RING)} (https). They fetch pages for it, so it can read any "
                             "public page.")
        assert "example.com" not in p["risk"].replace("api.firecrawl.dev", "")  # the page it was asked for is not a card
        [confirmed] = [e for e in cards._records if e.get("event") == "confirmed"]
        assert confirmed["refused"] == [FIRECRAWL] and confirmed["candidates"][:2] == ["example.com", FIRECRAWL]

        await cards._from_client(conn, _answer(card, "once"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "The sandbox restarts now to add it" in out["sandbox"] and "continues by itself" in out["sandbox"]
        assert next(iter(out)) == "sandbox" and H.STOP_NOW in out["sandbox"]
        assert sup.restarts == [] and sup.applies == []  # nothing while the turn runs, and no live rule
        assert [f["params"]["session_id"] for f in _interrupts(conn)] == ["live1"]  # the launcher stops the turn
        [row] = cards.grants_view()["grants"]
        assert row["status"] == "pending" and row["restart"] is True
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 1 and sup.applies == []
        assert sup.notes_seen[0]["label"] == "Restarting the sandbox to add Web extract"
        assert sup.notes_seen[0]["why"] == "tools" and sup.notes_seen[0]["reason"] is None
        rule = sup.restarts[0]["approved"][TOOL_RULE]
        assert [(e["host"], e["port"]) for e in rule["endpoints"]] == [(host, 443) for host in RING]
        assert sup.bound == {(FIRECRAWL, 443)} and sup.approved_tools() == {"web_extract"}
        assert network_policy(load_spec(signed_in["layout"])).get("approved") in (None, {})  # Allow is not saved
        [cont] = _continuations(conn)
        assert cont["params"]["display_kind"] == "hidden"
        assert "Hermes's Web extract tool can reach its web services now, until the sandbox is switched off." in cont["params"]["text"]

        # the second read: bound and granted, no card
        assert cards._host_allowed(FIRECRAWL, 443)[0] == "any"
        status, _ = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 204 and len(_cards(conn)) == 1
        # web_search falls back to the same host: covered, no card of its own for it
        status, _ = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_search")
        assert status == 204 and len(_cards(conn)) == 1

        [row] = cards.grants_view()["grants"]
        assert row["id"] == "network:allow:tool:web_extract" and row["label"] == "Web extract"
        assert row["target"] == f"{FIRECRAWL}, {', '.join(RING)}" and row["ports"] == [443]
        assert row["status"] == "active" and "restart" not in row and row["bound"] is True
        assert row["note"] == "Reads any public page through these services."

        # removed on the page: one restart without it, and the next read asks again
        assert (await cards.remove_grant(row["id"]))[0] == 200
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 2 and sup.restarts[1]["approved"] == {}
        assert sup.notes_seen[1]["label"] == "Restarting the sandbox to remove Web extract"
        assert sup.bound == set() and cards.grants_view()["grants"] == []
        drv.deny(FIRECRAWL)
        status, again = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 200 and again["host"] == "tool:web_extract" and len(_cards(conn)) == 2
        await cards.stop()

    asyncio.run(main())


def test_deny_makes_the_tool_fail_with_a_sentence_to_act_on_and_opens_nothing(signed_in, channel):  # noqa: F811
    drv, sup = signed_in["driver"], signed_in["sup"]

    async def main():
        cards, conn = await _setup(signed_in)
        hook = await _refused_web_extract(cards, conn, drv)
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "deny"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert out["sandbox"] == (
            "[Sandbox] The user denied Hermes's Web extract tool to reach its web services "
            f"({FIRECRAWL}, {', '.join(RING)}). Reason: {C.DEFAULT_DENY_REASON} Don't retry it; continue without it "
            "or ask the user.")
        await _turn_end(cards, conn)
        assert sup.restarts == [] and sup.applies == [] and sup.bound == set() and _interrupts(conn) == []
        assert cards.grants_view()["grants"] == [] and sup.approved_tools() == set()
        # asked again in the same chat: the same answer at once, no second card
        status, payload = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 200 and payload["detail"] == "denied earlier in this chat" and len(_cards(conn)) == 1
        await cards.stop()

    asyncio.run(main())


def test_always_allow_saves_the_category_and_the_row_lists_every_host_it_opens(signed_in, channel):  # noqa: F811
    drv, sup, layout = signed_in["driver"], signed_in["sup"], signed_in["layout"]

    async def main():
        cards, conn = await _setup(signed_in)
        hook = await _refused_web_extract(cards, conn, drv)
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "always"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "and saved it to the sandbox's policy" in out["sandbox"] and "The sandbox restarts now" in out["sandbox"]
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 1 and sup.bound == {(FIRECRAWL, 443)}
        saved = network_policy(load_spec(layout))["approved"]
        assert list(saved) == [TOOL_RULE] and categories().granted(saved) == {"web_extract"}
        [row] = cards.grants_view()["grants"]
        assert row["id"] == "network:always:tool:web_extract" and row["label"] == "Web extract" and row["scope"] == "always"
        assert row["target"] == f"{FIRECRAWL}, {', '.join(RING)}" and row["status"] == "active"
        assert row["note"] == "Reads any public page through these services."
        assert (await cards.remove_grant(row["id"]))[0] == 200
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 2 and sup.bound == set()
        assert sup.notes_seen[1]["label"] == "Restarting the sandbox to remove Web extract"
        assert "approved" not in network_policy(load_spec(layout))
        await cards.stop()

    asyncio.run(main())


def test_an_image_tool_gets_its_own_card_and_a_saved_approval_without_a_policy_rule(signed_in, channel):  # noqa: F811
    drv, sup, layout = signed_in["driver"], signed_in["sup"], signed_in["layout"]
    fal, krea = "fal-queue-gateway.nousresearch.com", "krea-gateway.nousresearch.com"

    async def main():
        cards, conn = await _setup(signed_in)
        await _turn_start(cards, conn, tool_name="image_generate")
        drv.deny(fal)
        failed = {"success": False, "error": "Image generation failed: [Errno 13] Permission denied"}
        hook = asyncio.ensure_future(_run_hook("image_generate", {"prompt": "a lighthouse"}, json.dumps(failed)))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        p = card["params"]
        assert p["label"] == "Image generation" and p["host"] == "tool:image_gen"
        assert p["description"] == "Allow Hermes's Image generation tool to reach its services"
        assert p["risk"] == (f"Hermes's image generation tool uses one of these services, whichever it picks: "
                             f"{fal}, {krea} (https).")
        await cards._from_client(conn, _answer(card, "always"))
        out = json.loads(await asyncio.wait_for(hook, 10))
        assert "The user allowed Hermes's Image generation tool to reach its web services" in out["sandbox"]
        await _turn_end(cards, conn)
        assert len(sup.restarts) == 1 and sup.notes_seen[0]["label"] == "Restarting the sandbox to add Image generation"
        assert sup.bound == {(fal, 443), (krea, 443)}
        rule = network_policy(load_spec(layout))["approved"]["allowed_tool_image_gen"]
        assert rule["endpoints"] == [], "a credentialed service became a rule any program may use"
        [row] = cards.grants_view()["grants"]
        assert row["label"] == "Image generation" and row["target"] == f"{fal}, {krea}" and "note" not in row
        assert row["ports"] == [443]
        # the web tools were not opened by it
        drv.deny(FIRECRAWL)
        status, other = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 200 and other["host"] == "tool:web_extract"
        await cards.stop()

    asyncio.run(main())


def test_a_refused_gateway_host_names_its_category_without_a_tool_name(signed_in):
    drv = signed_in["driver"]

    async def main():
        cards, conn = await _setup(signed_in)
        await _turn_start(cards, conn, tool_name="terminal")
        status, card = await cards.raise_host("browser-use-gateway.nousresearch.com", key="chatA", port=443)
        assert status == 200 and card["host"] == "tool:browser" and card["label"] == "Browser"
        [shown] = _cards(conn)
        assert shown["params"]["risk"] == ("Hermes's browser tool uses this service: browser-use-gateway.nousresearch.com "
                                           "(https). It runs a browser for the tool, which can open any public page.")
        # a host of the gateway no category names is a website like any other: its own site card, never a category's
        status, site = await cards.raise_host("tool-gateway.nousresearch.com", key="chatA", port=443)
        assert status == 200 and site["host"] == "tool-gateway.nousresearch.com" and not site.get("tool")
        # a web tool's name does not turn another category's host into its own
        status, speech = await cards.raise_host("openai-audio-gateway.nousresearch.com", key="chatA", port=443,
                                                tool="web_extract")
        assert status == 200 and speech["host"] == "tool:speech"
        await cards.stop()

    asyncio.run(main())


def test_an_approval_saved_before_the_sign_in_covers_the_gateway_once_it_is_bound(signed_in):
    """A 'Web extract' approval saved while the tool used the services without a key keeps working after a
    Portal sign-in moves the tool to the gateway: the next start binds the sign-in there, and nothing asks."""
    sup, layout = signed_in["sup"], signed_in["layout"]
    from openshell.launcher.spec import update_spec

    net = network_policy(load_spec(layout))
    sup.set_spec(update_spec(layout, network={**net, "approved": {TOOL_RULE: C.tool_rule("web_extract", RING)}}))
    sup.bound = {(FIRECRAWL, 443)}  # what the supervisor binds at the start for a saved approval

    async def main():
        cards, conn = await _setup(signed_in)
        await _turn_start(cards, conn, tool_name="web_extract")
        status, _ = await cards.raise_host(FIRECRAWL, key="chatA", port=443, tool="web_extract")
        assert status == 204 and _cards(conn) == []
        status, _ = await cards.raise_host("mcp.exa.ai", key="chatA", port=443, tool="web_extract")
        assert status == 204 and _cards(conn) == []
        [row] = cards.grants_view()["grants"]
        assert row["target"] == f"{FIRECRAWL}, {', '.join(RING)}"
        await cards.stop()

    asyncio.run(main())


def test_without_a_sign_in_the_card_opens_the_same_services_live_as_before(harness, channel):  # noqa: F811
    """The regression: a profile that is not signed in gets the card it got, and its Allow applies at once."""
    drv, sup = harness["driver"], harness["sup"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool_name="web_extract")
        drv.deny("mcp.exa.ai")
        hook = asyncio.ensure_future(_run_hook("web_extract", EXTRACT_ARGS, json.dumps(TC.EXA_ERR)))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["risk"] == (
            f"Hermes's web extract tool uses one of these services, whichever it picks: {', '.join(RING)} (https). "
            "They fetch pages for it, so it can read any public page.")
        await cards._from_client(conn, _answer(card, "once"))
        note = json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        assert "call web_extract again now with the same arguments" in note
        assert sup.applies == [[TOOL_RULE]] and sup.restarts == [] and _interrupts(conn) == []
        [row] = cards.grants_view()["grants"]
        assert row["target"] == ", ".join(RING) and "restart" not in row and "bound" not in row
        await cards.stop()

    asyncio.run(main())


def test_an_allow_whose_addresses_are_bound_already_applies_at_once(signed_in, channel):  # noqa: F811
    """Another category's approval bound the host both web tools share: this Allow has nothing to bind, so the
    sandbox is not restarted for it."""
    drv, sup = signed_in["driver"], signed_in["sup"]
    sup.bound = {(FIRECRAWL, 443)}

    async def main():
        cards, conn = await _setup(signed_in)
        await _turn_start(cards, conn, tool_name="web_extract")
        drv.deny("mcp.exa.ai")
        hook = asyncio.ensure_future(_run_hook("web_extract", EXTRACT_ARGS, json.dumps(TC.EXA_ERR)))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        await cards._from_client(conn, _answer(card, "once"))
        note = json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        assert "call web_extract again now with the same arguments" in note
        assert sup.restarts == [] and _interrupts(conn) == [] and len(sup.applies) == 1
        await cards.stop()

    asyncio.run(main())


def test_the_web_search_card_says_that_its_services_fetch_pages_too(harness, channel):  # noqa: F811
    drv = harness["driver"]

    async def main():
        cards, conn = await _setup(harness)
        await _turn_start(cards, conn, tool_name="web_search")
        drv.deny("mcp.exa.ai")
        hook = asyncio.ensure_future(_run_hook("web_search", {"query": "lab"}, json.dumps(TC.EXA_ERR)))
        await _pump_requests(cards, lambda: _cards(conn))
        [card] = _cards(conn)
        assert card["params"]["description"] == "Allow Hermes's Web search tool to reach its web services"
        assert card["params"]["risk"] == (
            f"Hermes's web search tool uses one of these services, whichever it picks: {', '.join(RING)} (https). "
            "They also fetch pages, so the agent can read any public page.")
        await cards._from_client(conn, _answer(card, "always"))
        assert "call web_search again now" in json.loads(await asyncio.wait_for(hook, 10))["sandbox"]
        [row] = cards.grants_view()["grants"]
        assert row["label"] == "Web search" and row["note"] == "Reads any public page through these services."
        await cards.stop()

    asyncio.run(main())


def test_the_hook_names_the_tool_that_asked_when_it_says_what_to_retry():
    base = {"kind": "network", "status": "allowed", "scope": "allow", "label": "Image generation",
            "hosts": ["fal-queue-gateway.nousresearch.com"]}
    assert "call image_generate again now" in H.note_for({**base, "tool": "image_gen", "name": "image_generate"})
    assert "retry the request now" in H.note_for({**base, "tool": "remote_terminal", "name": ""})
    assert "call web_extract again now" in H.note_for({**base, "tool": "web_extract"})  # a verdict of an older launcher
