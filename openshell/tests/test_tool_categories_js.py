"""Tool categories on the Sandbox page (desktop/plugin.js, run in Node through tests/js/switch_harness.mjs).

Every host a sign-in or a key keeps open is a destination the page lists and its header counts. A tool
category's grant says what its services let the agent reach beyond the hosts it lists, and says that it waits
for a restart when it does. A request a sign-in was used for carries its category on the Activity tab.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

INFERENCE = "inference-api.nousresearch.com"
FIRECRAWL = "firecrawl-gateway.nousresearch.com"


def _categories(run):  # noqa: F811
    found = run["categories"]
    assert "error" not in found, found.get("error")
    return found


def test_the_header_counts_what_a_sign_in_keeps_open_with_the_users_own(run):  # noqa: F811
    summary = _categories(run)["summary"]
    assert summary["own"] == ["1 folder", "Internet blocked", "1 allowed destination"]
    assert summary["opened"] == ["1 folder", "Internet blocked", "3 allowed destinations"]
    assert summary["onlyOpened"] == ["1 folder", "Internet blocked", "1 allowed destination"]
    # with what the launcher keeps open by itself; a launcher that sends neither list counts none
    assert summary["withBuiltin"] == ["1 folder", "Internet blocked", "4 allowed destinations"]
    assert summary["neither"] == 0


def test_the_network_section_lists_them_with_what_each_is_for(run):  # noqa: F811
    assert _categories(run)["destinations"] == [
        {"title": "telemetry.nousresearch.com", "note": "Usage data this profile shares with Nous", "removable": False},
        {"title": INFERENCE, "note": "Model \u00b7 Nous Portal", "removable": False},
        {"title": FIRECRAWL, "note": "Web extract \u00b7 Nous Portal", "removable": False}]


def test_a_category_grant_says_what_it_reaches_and_when_it_waits_for_a_restart(run):  # noqa: F811
    found = _categories(run)
    extract, image, site = found["grants"]
    assert extract == {"title": "Web extract", "sub": f"{FIRECRAWL}, mcp.exa.ai \u00b7 https",
                       "note": "Reads any public page through these services.", "tip": None, "removable": True}
    assert image["title"] == "Image generation" and image["note"] is None
    assert image["sub"] == "fal-queue-gateway.nousresearch.com \u00b7 https \u00b7 any program"  # no credential said
    assert image["tip"] == found["tips"]["restart"] == "The sandbox restarts to add it when the current turn ends."
    assert site["tip"] == found["tips"]["applying"] and site["note"] is None  # a site's grant applies as before
    assert found["removeDialog"] == [{
        "title": found["removeDialog"][0]["title"], "target": f"{FIRECRAWL}, mcp.exa.ai",
        "body": "The sandbox can no longer reach it; the agent is asked again next time."}]
    assert "Web extract" in found["removeDialog"][0]["title"]


def test_a_gateway_request_carries_its_category_and_a_models_request_says_model(run):  # noqa: F811
    activity = _categories(run)["activity"]
    assert activity["gateway"] == "python3.14 \u00b7 Web extract"
    assert activity["model"] == "python3.14 \u00b7 Model"
    assert activity["site"] == "curl"  # a category is only said for a request a credential's rule let through
