"""Tool categories (launcher/categories.py): at switch-on a sign-in or a key opens what the profile's model needs
and nothing a tool needs; a tool category's services are bound once the user approved the category.

The sign-in engine runs Hermes's own code over the launcher's host-only copy, against loopback issuers
(signin_issuers.py); the supervisor runs over the fake gateway of ``test_openshell_driver``. Every token is made up.
"""
import asyncio
import json

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402,F401
import signin_issuers  # noqa: E402
from signin_home import world  # noqa: E402,F401
from test_standins_wiring import _supervisor  # noqa: E402

from openshell.launcher import activity as A  # noqa: E402
from openshell.launcher import openshell_driver as OD  # noqa: E402
from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import signins  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402
from openshell.launcher.spec import load_spec, network_policy, update_spec  # noqa: E402

INFERENCE = "inference-api.nousresearch.com"
FIRECRAWL = "firecrawl-gateway.nousresearch.com"
PERPLEXITY = "perplexity-gateway.nousresearch.com"
GATEWAYS = ("browser-use", "connector", "fal-queue", "firecrawl", "krea", "modal", "openai-audio", "perplexity", "tool")
WEB_KEYS = {"TAVILY_API_KEY": "tvly-" + "t" * 20, "BRAVE_SEARCH_API_KEY": "BSA" + "b" * 20,
            "PERPLEXITY_API_KEY": "pplx-" + "p" * 20, "KEENABLE_API_KEY": "kn-" + "k" * 20}


def categories():
    from openshell.launcher import categories as module

    return module


def signed_in(world):  # noqa: F811
    world.config({"model": {"provider": "nous", "default": "a-model"}})
    world.sign_in("nous")
    world.take_copy()


def hosts_of(decl) -> list:
    return [endpoint.host for endpoint in decl.endpoints]


class Sink(signin_issuers.Sink):
    """A driver's sink that takes a credential declared again: what it holds for an id is the last declaration,
    as the driver's own does (the next sandbox start registers that one)."""

    def declare(self, decl, value, expires_at):
        self.declared.pop(decl.id, None)
        return super().declare(decl, value, expires_at)


# -- 1. at switch-on only the model is open -------------------------------------------------------------------

def test_a_nous_sign_in_is_bound_to_the_inference_host_and_to_nothing_a_tool_uses(world):  # noqa: F811
    signed_in(world)
    (declared,) = world.engine().declare()
    assert hosts_of(declared) == [INFERENCE]
    held = hosts_of(world.sink.declared[declared.id]["decl"])
    assert held == [INFERENCE]
    for vendor in GATEWAYS:
        assert f"{vendor}-gateway.nousresearch.com" not in held
    assert "portal.nousresearch.com" not in held


def test_a_web_service_key_is_not_bound_before_its_category_is_approved():
    found = OD.discover_routes(None, WEB_KEYS, {"present": True, "models": [], "allowed": []})
    assert found.routes == [], "a tool's key opened its service's host at switch-on"
    assert {row["env"]: row["categories"] for row in found.on_approval} == {
        "TAVILY_API_KEY": ["web_search", "web_extract"], "KEENABLE_API_KEY": ["web_search", "web_extract"],
        "PERPLEXITY_API_KEY": ["web_search", "web_extract"], "BRAVE_SEARCH_API_KEY": ["web_search"]}
    assert sorted(found.withheld) == sorted(WEB_KEYS)
    # without a pin, as with one
    assert OD.discover_routes(None, WEB_KEYS, None).routes == []


def test_an_approved_category_binds_the_keys_its_tools_use_and_no_other():
    search = OD.discover_routes(None, WEB_KEYS, {"tools": ["web_search"]})
    assert sorted((r["env"], r["host"]) for r in search.routes) == [
        ("BRAVE_SEARCH_API_KEY", "api.search.brave.com"), ("KEENABLE_API_KEY", "api.keenable.ai"),
        ("PERPLEXITY_API_KEY", "api.perplexity.ai"), ("TAVILY_API_KEY", "api.tavily.com")]
    extract = OD.discover_routes(None, WEB_KEYS, {"tools": ["web_extract"]})
    assert sorted(r["env"] for r in extract.routes) == ["KEENABLE_API_KEY", "PERPLEXITY_API_KEY", "TAVILY_API_KEY"]
    assert [row["env"] for row in extract.on_approval] == ["BRAVE_SEARCH_API_KEY"]
    assert OD.discover_routes(None, WEB_KEYS, {"tools": ["image_gen", "browser"]}).routes == []


# -- 2. the table ---------------------------------------------------------------------------------------------

def test_a_tool_belongs_to_one_category_by_its_name():
    C = categories()
    assert {name: C.of_tool(name).id for name in (
        "web_search", "web_extract", "web_crawl", "browser_exec", "browser_cdp", "browser_navigate", "image_generate",
        "video_generate", "text_to_speech", "manage_connections", "connectors__mail__send")} == {
        "web_search": "web_search", "web_extract": "web_extract", "web_crawl": "web_extract", "browser_exec": "browser",
        "browser_cdp": "browser", "browser_navigate": "browser", "image_generate": "image_gen",
        "video_generate": "video_gen", "text_to_speech": "speech", "manage_connections": "connected_apps",
        "connectors__mail__send": "connected_apps"}
    for name in ("terminal", "read_file", "execute_code", "", None, "web"):
        assert C.of_tool(name) is None
    assert [c.label for c in C.CATEGORIES] == ["Web search", "Web extract", "Browser", "Image generation",
                                               "Video generation", "Speech", "Connected apps", "Remote terminal"]


def test_a_gateway_host_belongs_to_the_category_that_asks_for_it_first():
    C = categories()
    by_vendor = {vendor: getattr(C.of_gateway(f"{vendor}-gateway.nousresearch.com", 443), "id", None) for vendor in GATEWAYS}
    assert by_vendor == {"browser-use": "browser", "connector": "connected_apps", "fal-queue": "image_gen",
                         "firecrawl": "web_extract", "krea": "image_gen", "modal": "remote_terminal",
                         "openai-audio": "speech", "perplexity": "web_search", "tool": None}
    assert C.of_gateway("example.com", 443) is None and C.of_gateway("api.firecrawl.dev", 443) is None
    assert C.of_gateway(FIRECRAWL, 8443) is None  # another port is another address
    assert C.gateway_endpoints(C.by_id("web_search")) == [(PERPLEXITY, 443), (FIRECRAWL, 443)]
    assert C.gateway_endpoints(C.by_id("video_gen")) == [("fal-queue-gateway.nousresearch.com", 443)]
    assert C.use_label(FIRECRAWL, 443) == "Web extract" and C.use_label(INFERENCE, 443) is None
    assert C.use_label("api.tavily.com", 443, "TAVILY_API_KEY") == "Web search and Web extract"


def test_a_host_two_categories_share_is_named_for_the_approval_that_opened_it():
    C = categories()
    assert C.use_label(FIRECRAWL, 443, approved={"web_search"}) == "Web search"
    assert C.use_label(FIRECRAWL, 443, approved={"web_extract", "image_gen"}) == "Web extract"
    assert C.use_label(FIRECRAWL, 443, approved={"web_search", "web_extract"}) == "Web search and Web extract"
    assert C.use_label(PERPLEXITY, 443, approved={"web_search", "web_extract"}) == "Web search"
    assert C.use_label(INFERENCE, 443, approved={"web_search"}) is None
    assert C.use_label("api.tavily.com", 443, "TAVILY_API_KEY", approved={"web_extract"}) == "Web extract"
    # a search's services fetch pages too, and its card says so; a media tool's do not
    assert C.by_id("web_search").reach == "They also fetch pages, so the agent can read any public page."
    assert C.by_id("web_extract").reach == "They fetch pages for it, so it can read any public page."
    assert C.by_id("image_gen").reach == "" and C.by_id("speech").reach == ""


def test_the_gateway_addresses_are_the_ones_hermes_builds(monkeypatch):
    pytest.importorskip("tools.managed_tool_gateway")
    C = categories()
    monkeypatch.setenv("FIRECRAWL_GATEWAY_URL", "https://localhost:18443")
    monkeypatch.setenv("TOOL_GATEWAY_DOMAIN", "gateway.example.test")
    assert C.gateway_endpoints(C.by_id("web_extract")) == [("localhost", 18443)]
    assert C.gateway_endpoints(C.by_id("browser")) == [("browser-use-gateway.gateway.example.test", 443)]
    assert C.of_gateway("localhost", 18443).id == "web_extract"
    monkeypatch.setenv("TOOL_GATEWAY_SCHEME", "gopher")  # Hermes refuses it: the names of the default domain
    monkeypatch.delenv("FIRECRAWL_GATEWAY_URL")
    assert C.gateway_endpoints(C.by_id("web_extract")) == [(FIRECRAWL, 443)]


def test_a_saved_approval_is_the_rule_named_after_its_category():
    C = categories()
    saved = {"allowed_tool_web_extract": {"endpoints": []}, "allowed_host_example_com": {}, "allowed_tool_nothing": {}}
    assert C.granted(saved, None, {"allowed_tool_image_gen": {}}) == {"web_extract", "image_gen"}
    assert C.granted(None) == set() and C.of_rule("allowed_tool_browser").label == "Browser"


# -- 4. the binding follows the approvals ----------------------------------------------------------------------

def test_an_approval_binds_its_gateway_hosts_from_the_next_start_and_its_removal_unbinds_them(world):  # noqa: F811
    signed_in(world)
    approved: set = set()
    world.sink = Sink(world.clock)
    engine = signins.SignIns(world.copy, world.sink, clock=world.clock, sleep=world.clock.sleep,
                             approved=lambda: set(approved))
    (declared,) = engine.declare()
    first_env = declared.env
    assert hosts_of(declared) == [INFERENCE] and engine.rebind() == []
    assert engine.tool_hosts("web_extract") == [{"host": FIRECRAWL, "port": 443, "label": "Nous Portal"}]
    assert engine.tool_hosts("nothing") == []

    approved.add("web_extract")
    assert engine.rebind() == [declared.id]
    held = world.sink.declared[declared.id]
    assert hosts_of(held["decl"]) == [INFERENCE, FIRECRAWL]
    assert held["decl"].expires is True and held["decl"].placement == "bearer"
    assert world.issuers.valid("nous", world.sink.values[declared.id][0]), "the value handed over is not the current one"
    assert engine.rebind() == [], "declared again with nothing changed"
    (row,) = engine.status()
    assert row["hosts"] == [{"host": INFERENCE, "port": 443, "use": "model"},
                            {"host": FIRECRAWL, "port": 443, "use": "web_extract"}]

    approved.add("web_search")  # its second vendor is web_extract's: one address, bound once
    assert engine.rebind() == [declared.id]
    assert hosts_of(world.sink.declared[declared.id]["decl"]) == [INFERENCE, PERPLEXITY, FIRECRAWL]

    approved.clear()
    assert engine.rebind() == [declared.id]
    assert hosts_of(world.sink.declared[declared.id]["decl"]) == [INFERENCE]
    assert world.sink.declared[declared.id]["decl"].id == declared.id and first_env == declared.env
    assert world.issuers.refreshes("nous") == [], "binding anew renewed the sign-in"


def test_an_approval_saved_before_the_switch_is_bound_at_the_first_start(world):  # noqa: F811
    signed_in(world)
    engine = signins.SignIns(world.copy, world.sink, clock=world.clock, sleep=world.clock.sleep,
                             approved=lambda: {"image_gen", "no_such_category"})
    (declared,) = engine.declare()
    assert hosts_of(declared) == [INFERENCE, "fal-queue-gateway.nousresearch.com", "krea-gateway.nousresearch.com"]


def test_only_a_sign_in_hermes_tools_use_is_bound_for_a_category(world):  # noqa: F811
    world.config({"model": {"provider": "openai-codex", "default": "a-model"}})
    world.sign_in("openai-codex")
    world.take_copy()
    engine = signins.SignIns(world.copy, world.sink, clock=world.clock, sleep=world.clock.sleep,
                             approved=lambda: {"web_extract", "browser"})
    (declared,) = engine.declare()
    assert hosts_of(declared) == ["chatgpt.com"] and engine.rebind() == [] and engine.tool_hosts("web_extract") == []


def test_an_approval_that_cannot_be_read_binds_only_the_model(world):  # noqa: F811
    signed_in(world)

    def broken():
        raise OSError("the saved policy could not be read")

    (declared,) = signins.SignIns(world.copy, world.sink, clock=world.clock, sleep=world.clock.sleep,
                                  approved=broken).declare()
    assert hosts_of(declared) == [INFERENCE]


def _on(world, tmp_path, monkeypatch):  # noqa: F811
    """A supervisor over the fake gateway for the world's profile, signed in to Nous Portal, with a web
    service's key, and an engine that reads the supervisor's approvals."""
    world.config({"model": {"provider": "nous", "default": "m"}})
    world.sign_in("nous")
    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    sup, api, _rec, layout = _supervisor(tmp_path, monkeypatch, layout)
    from openshell.launcher import supervisor as S

    monkeypatch.setattr(S, "_profile_secrets", lambda _layout: {"TAVILY_API_KEY": WEB_KEYS["TAVILY_API_KEY"]})
    sup.signins = signins.SignIns(P.pin_dir(layout), sup.driver, clock=world.clock, sleep=world.clock.sleep,
                                  on_change=lambda names: P.follow_copy(layout), approved=sup.approved_tools)
    return sup, api, layout


def _bound(sup) -> dict:
    return {row["label"].split(" (")[0]: row["endpoints"] for row in sup.driver.registered_providers()}


def test_a_restart_after_an_approval_starts_bound_to_the_category_and_one_after_its_removal_does_not(world, tmp_path, monkeypatch):  # noqa: F811
    sup, api, layout = _on(world, tmp_path, monkeypatch)
    rule = {"name": "allowed_tool_web_extract", "endpoints": [{"host": "mcp.exa.ai", "port": 443}],
            "binaries": [{"path": "**"}]}

    async def scenario():
        await sup.start()
        try:
            assert _bound(sup) == {"Nous Portal": [f"{INFERENCE}:443"]}, "something a tool uses was open at switch-on"
            assert sup.bound_hosts() == {(INFERENCE, 443)} and sup.approved_tools() == set()
            assert sup.tool_services("web_extract") == {
                "plain": ["mcp.exa.ai", "search.parallel.ai", "api.firecrawl.dev", "api.keenable.ai"],
                "bound": [{"host": FIRECRAWL, "port": 443, "label": "Nous Portal"},
                          {"host": "api.tavily.com", "port": 443, "label": "Tavily"}]}
            first = {name for name in api.providers}
            status = sup.status()
            assert status["opened"] == [{"host": INFERENCE, "port": 443, "reason": "Model \u00b7 Nous Portal",
                                          "rule": status["opened"][0]["rule"]}]
            rows = {row["id"]: row for row in status["providers"]}
            assert rows["sign_in:nous"]["detail"] == (
                f"Works in the sandbox. Stays signed in on this computer and is used only at {INFERENCE}.")
            assert rows["key:TAVILY_API_KEY"]["detail"] == (
                "Used in the sandbox once Web search or Web extract is allowed in a chat. The key stays on this computer.")

            sup.temporary["approved"] = {rule["name"]: rule}  # Allow on the card (cards.py keeps it here)
            assert sup.approved_tools() == {"web_extract"} and sup.bound_hosts() == {(INFERENCE, 443)}
            await sup.restart()
            assert _bound(sup) == {"Nous Portal": [f"{INFERENCE}:443", f"{FIRECRAWL}:443"], "Tavily": ["api.tavily.com:443"]}
            assert not first & set(api.providers), "the provider bound to the old addresses was kept"
            status = sup.status()
            assert [(row["host"], row["reason"]) for row in status["opened"]] == [
                (INFERENCE, "Model \u00b7 Nous Portal"), (FIRECRAWL, "Web extract \u00b7 Nous Portal"),
                ("api.tavily.com", "Web extract \u00b7 Tavily")]  # named for the approval that opened it
            rows = {row["id"]: row for row in status["providers"]}
            assert rows["sign_in:nous"]["detail"].endswith(f"is used only at {INFERENCE} and {FIRECRAWL}.")
            assert rows["key:TAVILY_API_KEY"]["detail"] == (
                "Works in the sandbox. The key stays on this computer and is used only at api.tavily.com.")
            template = json.loads((layout.state_dir / "standin" / "template.json").read_text(encoding="utf-8"))
            assert "nous" in template["files"]["auth.json"]["providers"], "the stand-in of the restart lost the row"

            sup.temporary["approved"] = {}  # the grant removed on the page
            await sup.restart()
            assert _bound(sup) == {"Nous Portal": [f"{INFERENCE}:443"]}
            assert [row["host"] for row in sup.status()["opened"]] == [INFERENCE]
            assert world.issuers.refreshes("nous") == [], "binding anew renewed the sign-in"
        finally:
            sup.switching_off = True
            await sup.stop()

    asyncio.run(scenario())


def test_a_saved_approval_is_bound_at_switch_on_and_listed_before_it(world, tmp_path, monkeypatch):  # noqa: F811
    sup, api, layout = _on(world, tmp_path, monkeypatch)
    net = network_policy(load_spec(layout))
    saved = {"allowed_tool_web_search": {"name": "allowed_tool_web_search", "endpoints": [], "binaries": [{"path": "**"}]}}
    sup.set_spec(update_spec(layout, network={**net, "approved": saved}))
    assert SV.saved_tools(layout) == {"web_search"}

    async def scenario():
        await sup.start()
        try:
            assert _bound(sup) == {"Nous Portal": [f"{INFERENCE}:443", f"{PERPLEXITY}:443", f"{FIRECRAWL}:443"],
                                   "Tavily": ["api.tavily.com:443"]}
            # the rule that stands for the approval has no endpoints: it is no rule of the sandbox's policy
            assert "allowed_tool_web_search" not in OD.network_rules(network_policy(sup.spec), ("/py",))
        finally:
            sup.switching_off = True
            await sup.stop()

    asyncio.run(scenario())


# -- 5. the page says what is open ------------------------------------------------------------------------------

def test_a_sign_in_row_names_every_address_the_sign_in_is_used_at():
    facts = [{"id": "sign_in:nous", "label": "Nous Portal", "kind": "sign_in", "state": "ready", "reason": "signed_in",
              "hosts": [{"host": INFERENCE, "port": 443, "use": "model"}, {"host": FIRECRAWL, "port": 443, "use": "web_extract"}]},
             {"id": "sign_in:openai-codex", "label": "OpenAI Codex", "kind": "sign_in", "state": "ready",
              "reason": "signed_in_shared", "hosts": [{"host": "chatgpt.com", "port": 443, "use": "model"}]},
             {"id": "sign_in:xai-oauth", "label": "xAI", "kind": "sign_in", "state": "ready", "reason": "signed_in"}]
    rows = {row["id"]: row["detail"] for row in SV.page_rows(facts)}
    assert rows["sign_in:nous"] == ("Works in the sandbox. Stays signed in on this computer and is used only at "
                                    f"{INFERENCE} and {FIRECRAWL}.")
    assert rows["sign_in:openai-codex"] == ("Works in the sandbox with the default profile's sign-in. Stays signed in "
                                            "on this computer and is used only at chatgpt.com.")
    assert rows["sign_in:xai-oauth"] == "Works in the sandbox. Stays signed in on this computer."  # a row without hosts


def test_the_rows_of_a_profile_that_is_off_say_where_its_sign_in_will_be_used(world):  # noqa: F811
    world.config({"model": {"provider": "nous", "default": "m"}})
    world.sign_in("nous")
    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    SV.forget_providers()
    rows = {row["id"]: row for row in R.host_rows(layout)}
    assert rows["sign_in:nous"]["detail"] == (
        f"Works in the sandbox. Stays signed in on this computer and is used only at {INFERENCE}.")
    net = network_policy(load_spec(layout))
    update_spec(layout, network={**net, "approved": {"allowed_tool_browser": {"name": "allowed_tool_browser", "endpoints": []}}})
    SV.forget_providers()
    rows = {row["id"]: row for row in R.host_rows(layout)}
    assert rows["sign_in:nous"]["detail"].endswith(f"is used only at {INFERENCE} and browser-use-gateway.nousresearch.com.")


def test_a_key_that_waits_for_an_approval_says_so():
    waiting = [{"label": "Tavily", "env": "TAVILY_API_KEY", "host": "api.tavily.com", "port": 443,
                "categories": ["web_search", "web_extract"]},
               {"label": "Brave Search", "env": "BRAVE_SEARCH_API_KEY", "host": "api.search.brave.com", "port": 443,
                "categories": ["web_search"]}]
    rows, routed = SV.key_rows_of([], {}, facts=True, on_approval=waiting)
    assert routed == set() and [row["state"] for row in rows] == ["ready", "ready"]
    assert rows[0]["detail"] == ("Used in the sandbox once Web search or Web extract is allowed in a chat. The key "
                                 "stays on this computer.")
    assert rows[1]["detail"] == "Used in the sandbox once Web search is allowed in a chat. The key stays on this computer."
    assert "used only at" not in rows[0]["detail"] and rows[0]["hosts"] == []
    # the launcher's rows are worded again from their facts: the same sentence
    assert [row["detail"] for row in SV.page_rows(rows)] == [row["detail"] for row in rows]


def test_the_destinations_a_page_lists_include_what_a_sign_in_keeps_open(tmp_path):
    layout = ProfileLayout(name="work", home=tmp_path / "root" / "profiles" / "work", root=tmp_path / "root")
    layout.home.mkdir(parents=True)
    opened = [{"host": INFERENCE, "port": 443, "reason": "Model \u00b7 Nous Portal", "rule": "_provider_x"}]
    payload = SV.config_payload(layout, load_spec(layout), {}, sandboxed=True, restart_required=False, opened=opened)
    assert payload["opened"] == opened and payload["builtin"] == []
    assert SV.config_payload(layout, load_spec(layout), {}, sandboxed=True, restart_required=False)["opened"] == []


def test_a_gateway_request_on_the_activity_tab_carries_its_category():
    row = {"kind": "network", "rule": "_provider_hermes-work-x", "host": FIRECRAWL, "port": 443}
    assert A._tool_use(row) == "Web extract"
    assert A._tool_use({**row, "host": INFERENCE}) is None, "the model's host is the model's"
    assert A._tool_use({**row, "host": "api.tavily.com"}) == "Web search and Web extract"
    assert A._tool_use({**row, "rule": "allowed_host_x"}) is None and A._tool_use({**row, "host": None}) is None
