"""What a profile's saved approvals mean for the Sandbox page's routes (dashboard/plugin_api.py, launcher/spec.py,
host_routes.py, supervisor.py, activity.py).

* A tool category saved with "Always allow" is listed under "Allowed from chat" while the sandbox is off, and can
  be removed there: nothing runs, so nothing restarts.
* A network edit beside a saved approval works: the page sends the internet setting and the destinations, and a
  body that hands the approvals back as the config answer gave them is taken by their names.
* A host a sign-in is still bound to while its approval is on the way out is named for what opened it.
* The Activity row a removal leaves is named as the category is everywhere else.
"""
import asyncio
import json
import time
from types import SimpleNamespace

import pytest

from test_settings_routes import _call, _layout, _plugin_api, _supervisor, fake_home  # noqa: F401

from openshell.launcher import activity, cards as C, categories, settings_view
from openshell.launcher.host_routes import HostRoutes
from openshell.launcher.layout import LayoutError, current_profile
from openshell.launcher.spec import load_spec, network_from_body, network_policy, update_spec
from openshell.launcher.supervisor import Supervisor

FIRECRAWL = "firecrawl-gateway.nousresearch.com"
INFERENCE = "inference-api.nousresearch.com"
RING = ["mcp.exa.ai", "search.parallel.ai", "api.firecrawl.dev", "api.keenable.ai"]
WIKI = C.host_rule("www.wikipedia.org", (80, 443))
EXTRACT = C.tool_rule("web_extract", RING)
POSTMAN = {"host": "postman-echo.com", "port": 443}


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(_plugin_api().router, prefix="/api/plugins/openshell")
    return TestClient(app)


def _save(layout, *rules, allow=()):
    net = {**network_policy(load_spec(layout)), "allow": list(allow), "approved": {r["name"]: r for r in rules}}
    if not rules:
        net.pop("approved")
    update_spec(layout, network=net)


# -- a saved tool approval while the sandbox is off ---------------------------------------------------------

def test_a_saved_tool_approval_is_listed_while_the_sandbox_is_off(fake_home):  # noqa: F811
    client, layout = _client(), current_profile()
    _save(layout, WIKI, EXTRACT)
    try:
        site, tool = client.get("/api/plugins/openshell/grants").json()["grants"]
        assert site["id"] == "network:always:www.wikipedia.org" and site["target"] == "www.wikipedia.org"
        assert tool == {"id": "network:always:tool:web_extract", "kind": "network", "label": "Web extract",
                        "target": ", ".join(RING), "ports": [443], "scope": "always", "status": "active",
                        "rule_name": "allowed_tool_web_extract",
                        "note": "Reads any public page through these services."}
    finally:
        _save(layout)


def test_the_row_names_the_address_a_sign_in_would_be_used_at_first(fake_home, monkeypatch):  # noqa: F811
    client, layout = _client(), current_profile()
    _save(layout, EXTRACT)
    router_view = __import__("sys").modules["hermes_openshell_settings.launcher.settings_view"]
    monkeypatch.setattr(router_view, "tool_uses", lambda layout: {"web_extract": [FIRECRAWL]})
    try:
        [tool] = client.get("/api/plugins/openshell/grants").json()["grants"]
        assert tool["target"] == ", ".join([FIRECRAWL, *RING]) and tool["bound"] is True
    finally:
        _save(layout)


def test_it_is_removed_there_and_only_it(fake_home):  # noqa: F811
    client, layout = _client(), current_profile()
    _save(layout, WIKI, EXTRACT)
    try:
        gone = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:tool:web_search"})
        assert gone.status_code == 404  # not approved
        done = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:tool:web_extract"})
        assert done.status_code == 200
        assert [row["id"] for row in done.json()["grants"]] == ["network:always:www.wikipedia.org"]
        assert list(network_policy(load_spec(layout))["approved"]) == [WIKI["name"]]
        assert settings_view.saved_tools(layout) == set()  # the next switch-on binds no sign-in for it
        again = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:tool:web_extract"})
        assert again.status_code == 404
    finally:
        _save(layout)


def test_what_a_sign_in_would_be_used_at_comes_from_the_providers_the_page_already_read(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    _save(layout, EXTRACT)
    monkeypatch.setattr(settings_view, "_reported", lambda layout: [{
        "provider": "nous", "label": "Nous Portal", "kind": "sign_in", "state": "works", "reason": "signed_in",
        "used_by": ["model"], "hosts": [{"host": INFERENCE, "port": 443, "use": "model"},
                                        {"host": FIRECRAWL, "port": 443, "use": "web_extract"}]}])
    settings_view.forget_providers(layout)
    assert settings_view.tool_uses(layout) == {"web_extract": [FIRECRAWL]}
    [row] = settings_view.saved_grants(layout)
    assert row["target"] == ", ".join([FIRECRAWL, *RING]) and row["bound"] is True and row["label"] == "Web extract"
    # a sign-in that went away since: the row names the services the rule holds
    monkeypatch.setattr(settings_view, "_reported", lambda layout: [])
    settings_view.forget_providers(layout)
    [row] = settings_view.saved_grants(layout)
    assert row["target"] == ", ".join(RING) and "bound" not in row


# -- a network edit beside a saved approval ------------------------------------------------------------------

def test_the_body_the_config_answer_gave_back_is_taken_by_the_names_of_its_approvals():
    saved = {WIKI["name"]: WIKI, EXTRACT["name"]: EXTRACT}
    forged = {WIKI["name"]: {**WIKI, "endpoints": [{"host": "anywhere.example", "port": 443}]}}
    out = network_from_body({"egress": "deny", "allow": [], "approved": forged}, approved=saved)
    assert out["approved"] == {WIKI["name"]: WIKI}  # by name: a rule's content is never taken from the body
    assert network_from_body({"egress": "deny", "allow": []}, approved=saved)["approved"] == saved
    assert network_from_body({"egress": "deny", "allow": [], "approved": [EXTRACT["name"]]},
                             approved=saved)["approved"] == {EXTRACT["name"]: EXTRACT}
    with pytest.raises(LayoutError, match="No approved rule named 'nobody'"):
        network_from_body({"egress": "deny", "allow": [], "approved": {"nobody": {}}}, approved=saved)
    with pytest.raises(LayoutError, match="approved must be a list of rule names to keep."):
        network_from_body({"egress": "deny", "allow": [], "approved": "all"}, approved=saved)


@pytest.mark.parametrize("hands_back", [False, True], ids=["the page's edit", "the config answer handed back"])
def test_a_destination_is_removed_and_added_beside_a_saved_approval_while_on(tmp_path, fake_home, hands_back):  # noqa: F811
    layout = _layout(tmp_path)
    sup = _supervisor(tmp_path, layout)
    _save(layout, WIKI, allow=[POSTMAN])
    sup.set_spec(load_spec(layout))
    routes = HostRoutes(sup, lambda: None)
    status, config, _ = _call(routes, "GET", "config")
    assert status == 200 and config["network"]["allow"] == [POSTMAN] and WIKI["name"] in config["network"]["approved"]
    body = lambda allow: ({**config["network"], "allow": allow} if hands_back  # noqa: E731
                          else {"egress": config["network"]["egress"], "allow": allow})
    status, after, _ = _call(routes, "PUT", "network", body([]))
    assert status == 200, after
    assert after["network"]["allow"] == [] and after["network"]["approved"] == {WIKI["name"]: WIKI}
    added = {"cidr": "203.0.113.0/24", "port": 443}  # (the test's driver filters by address)
    status, after, _ = _call(routes, "PUT", "network", body([added]))
    assert status == 200, after
    assert after["network"]["allow"] == [added]
    assert network_policy(load_spec(layout))["approved"] == {WIKI["name"]: WIKI}


@pytest.mark.parametrize("hands_back", [False, True], ids=["the page's edit", "the config answer handed back"])
def test_a_destination_is_removed_and_added_beside_a_saved_approval_while_off(fake_home, hands_back):  # noqa: F811
    client, layout = _client(), current_profile()
    _save(layout, WIKI, allow=[POSTMAN])
    try:
        config = client.get("/api/plugins/openshell/config").json()
        assert config["network"]["allow"] == [POSTMAN] and WIKI["name"] in config["network"]["approved"]
        body = lambda allow: ({**config["network"], "allow": allow} if hands_back  # noqa: E731
                              else {"egress": config["network"]["egress"], "allow": allow})
        done = client.put("/api/plugins/openshell/network", json=body([]))
        assert done.status_code == 200, done.text
        assert done.json()["network"]["allow"] == [] and done.json()["network"]["approved"] == {WIKI["name"]: WIKI}
        done = client.put("/api/plugins/openshell/network", json=body([{"host": "example.org", "port": 443}]))
        assert done.status_code == 200, done.text
        assert network_policy(load_spec(layout))["approved"] == {WIKI["name"]: WIKI}
    finally:
        _save(layout)


# -- a host on its way out, the restart the launcher makes itself, the Activity row ----------------------------

def test_a_host_whose_approval_is_gone_is_named_for_what_opened_it_not_for_every_category():
    assert categories.use_label(FIRECRAWL, 443, approved=set()) == "Web extract"
    assert categories.use_label(FIRECRAWL, 443, approved=set(), was="Web search") == "Web search"
    assert categories.use_label(FIRECRAWL, 443, approved={"web_search"}, was="Web extract") == "Web search"
    assert categories.use_label("api.tavily.com", 443, "TAVILY_API_KEY", approved=set()) == "Web search"
    assert categories.use_label(INFERENCE, 443, approved=set(), was="Web extract") is None  # the model's


def test_the_page_keeps_that_name_until_the_restart_takes_the_address_away():
    approved = {"web_search"}
    driver = SimpleNamespace(registered_providers=lambda: [{
        "name": "p1", "label": "Nous Portal", "env": "HERMES_CRED_NOUS_AGENT_KEY",
        "endpoints": [f"{INFERENCE}:443", f"{FIRECRAWL}:443"]}])
    sup = SimpleNamespace(driver=driver, applied={}, approved_tools=lambda: set(approved), _opened_for={})
    reasons = lambda: [row["reason"] for row in Supervisor.opened_hosts(sup)]  # noqa: E731
    assert reasons() == ["Model \u00b7 Nous Portal", "Web search \u00b7 Nous Portal"]
    approved.clear()  # removed on the page; the sandbox that runs is still bound until it has restarted
    assert reasons() == ["Model \u00b7 Nous Portal", "Web search \u00b7 Nous Portal"]


def test_the_status_says_when_the_launcher_restarts_by_itself(tmp_path):
    layout = _layout(tmp_path)
    sup = _supervisor(tmp_path, layout)
    assert sup.status()["restart_queued"] is False
    cards = C.Cards(sup, layout, cards=True)

    async def main():
        cards.start()
        assert sup.status()["restart_queued"] is False
        cards._pending_restart.append({"tool_remove": "Web extract", "scope": "allow"})
        assert sup.status()["restart_queued"] is True
        cards._pending_restart.clear()
        assert sup.status()["restart_queued"] is False
        await cards.stop()

    asyncio.run(main())


def test_the_activity_row_of_a_removed_tool_approval_is_named_as_the_category(tmp_path):
    now = time.time()
    log = tmp_path / activity.CARDS_FILE
    entries = [
        {"t": now - 3, "event": "removed", "kind": "network", "host": "tool:web_extract", "label": "Web extract", "scope": "allow"},
        {"t": now - 2, "event": "removed", "kind": "network", "host": "tool:image_gen", "scope": "always"},  # an older line
        {"t": now - 1, "event": "removed", "kind": "network", "host": "example.com", "scope": "allow"}]
    log.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    rows = activity.decision_rows(tmp_path, None, None)
    assert [row["title"] for row in rows] == ["Web extract", "Image generation", "example.com"]
    assert all(row["choice"] == "ended" and row["who"] == "you" for row in rows)


def test_a_removal_is_logged_with_the_categorys_name(tmp_path):
    layout = _layout(tmp_path)
    sup = _supervisor(tmp_path, layout)
    cards = C.Cards(sup, layout, cards=True)
    cards.grants.append({"kind": "network", "scope": "allow", "host": "tool:web_extract", "tool": "web_extract",
                         "hosts": RING, "ports": [443], "label": "Web extract", "rule_name": EXTRACT["name"],
                         "rule": EXTRACT, "chat": "chatA", "applied_at": 1.0, "answered_at": 1.0})

    async def main():
        assert (await cards.remove_grant("network:allow:tool:web_extract"))[0] == 200

    asyncio.run(main())
    [removed] = [e for e in cards.history if e["event"] == "removed"]
    assert removed["host"] == "tool:web_extract" and removed["label"] == "Web extract"
