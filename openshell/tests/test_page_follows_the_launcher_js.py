"""The Sandbox page follows the launcher (desktop/plugin.js, run in Node through tests/js/switch_harness.mjs).

What the launcher changes by itself (a card answered in a chat, a removal, a restart, a sign-in renewed) shows
on the open page within its normal poll, whether the window has focus, is covered or is minimized. An edit of
the network sends the internet setting and the destinations only. The restart bar asks for a restart only
when the user has one to make. A tool's services wrap at the commas.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

FIRECRAWL = "firecrawl-gateway.nousresearch.com"


def _follows(run):  # noqa: F811
    found = run["follows"]
    assert "error" not in found, found.get("error")
    return found


def test_every_poll_of_the_page_goes_on_in_a_hidden_or_unfocused_window(run):  # noqa: F811
    polls = _follows(run)["polls"]
    assert [poll["part"] for poll in polls] == ["status", "config", "keys", "grants", "activity", "revisions"]
    for poll in polls:
        assert poll["whileHidden"] is True, poll       # the tick is not skipped while the document is hidden
        assert poll["whenShownAgain"] == "always", poll  # and a window shown again reads at once
    assert {poll["part"]: poll["every"] for poll in polls} == {
        "status": 3000, "config": 5000, "keys": 5000, "grants": 3000, "activity": 3000, "revisions": 5000}


def test_a_polled_read_that_gets_no_answer_ends_so_the_next_one_goes_out(run):  # noqa: F811
    reads = _follows(run)["reads"]
    assert [read["path"] for read in reads] == ["/status", "/config", "/keys", "/grants", "/activity", "/policy/revisions"]
    assert all(read["timeoutMs"] == 15000 for read in reads), reads


def test_the_chip_keeps_the_desktops_rule_and_reads_when_the_window_is_shown(run):  # noqa: F811
    assert _follows(run)["chip"] == [{"part": "status", "whileHidden": False, "whenShownAgain": "always"}]


def test_a_change_the_launcher_made_is_read_again_with_the_status_that_shows_it(run):  # noqa: F811
    reread = _follows(run)["reread"]
    parts = ["config", "grants", "keys"]
    assert reread["firstSight"] == [] and reread["nothingNew"] == [] and reread["otherProfileFirstSight"] == []
    for change in ("restartBegan", "restartEnded", "cardAnswered", "savedByACard", "folderGranted", "renewal"):
        assert reread[change] == parts, change
    assert _follows(run)["alone"] == {name: parts for name in (
        "opened", "restartQueued", "restartRequired", "provider", "state", "allowedFromChat", "folderFromChat",
        "savedFromChat", "savedFolder")}
    assert _follows(run)["wired"] == 1  # the page asks with the status it draws
    assert _follows(run)["wiredReads"] == parts


def test_a_network_edit_never_sends_the_saved_approvals_back(run):  # noqa: F811
    removed, added, internet = _follows(run)["networkEdits"]
    assert removed == {"path": "/network", "method": "PUT", "body": {"egress": "deny", "allow": []}}
    assert added == {"path": "/network", "method": "PUT", "body": {
        "egress": "deny", "allow": [{"host": "postman-echo.com", "port": 443}, {"host": "example.org", "port": 443}]}}
    assert internet == {"path": "/network", "method": "PUT", "body": {
        "egress": "allow", "allow": [{"host": "postman-echo.com", "port": 443}]}}


def test_the_restart_bar_is_for_a_restart_the_user_has_to_make(run):  # noqa: F811
    bar = _follows(run)["bar"]
    assert bar["usersOwn"] == "Changes apply after restart. | Restart"
    assert bar["usersRestartRuns"] == "Changes apply after restart. | Restart"  # the button shows it running
    assert bar["launcherWillRestart"] is None and bar["launcherRestarts"] is None and bar["nothing"] is None


def test_a_tools_services_wrap_at_the_commas_on_the_row_and_in_the_dialog(run):  # noqa: F811
    found = _follows(run)
    tool, site = found["rows"]
    assert tool["sub"] == f"{FIRECRAWL}, mcp.exa.ai, search.parallel.ai \u00b7 https" and tool["oneLine"] is False
    assert tool["pieces"] == [f"{FIRECRAWL},", "mcp.exa.ai,", "search.parallel.ai \u00b7 https"] and tool["whole"] is True
    assert site == {"sub": "http and https \u00b7 any program", "oneLine": True, "pieces": [], "whole": True}
    assert found["dialog"] == {"text": f"{FIRECRAWL}, mcp.exa.ai, search.parallel.ai", "breaksInsideNames": False,
                               "pieces": [f"{FIRECRAWL},", "mcp.exa.ai,", "search.parallel.ai"]}
    assert found["pathDialog"] == {"pieces": 0, "text": "D:\\work\\a folder, with a comma"}


def test_the_activity_row_of_a_removal_says_removed(run):  # noqa: F811
    assert _follows(run)["activity"] == {"removedByTheUser": "Removed", "endedByItself": "Ended"}


def test_the_models_address_is_on_the_page_once(run):  # noqa: F811
    model = _follows(run)["model"]
    assert model["on"] == ["Internet access", "localhost", "postman-echo.com"]
    assert model["off"] == ["Internet access", "Model", "postman-echo.com"]
    assert model["internetAllowed"] == ["Internet access", "Model"]
    # a model whose address no key or sign-in is used at keeps its fixed row
    assert model["portal"] == ["Internet access", "Fallback", "inference-api.nousresearch.com", FIRECRAWL,
                               "postman-echo.com"]
    assert model["count"] == ["1 folder", "Internet blocked", "2 allowed destinations"]
