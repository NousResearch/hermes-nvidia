"""What the Sandbox page says by itself (desktop/plugin.js, run in Node through tests/js/switch_harness.mjs).

A sign-in that ends while the sandbox is on is said once, wherever the user is: the status-bar chip raises one
notice with the provider's name and the row's own sentence, the words the Sandbox page shows. A key saved while
the sandbox is on gets one line for what that means there. Whatever refuses the switch uses one notice, so a
second refusal replaces the first.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

EXPIRED = "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
LAPSED = "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is."
NOTICE = "openshell:sign-in:work:sign_in:nous"


def _says(run):  # noqa: F811
    says = run["says"]
    assert "error" not in says, says.get("error")
    return says


def _told(message, notice=NOTICE):
    return {"id": notice, "kind": "error", "title": "Nous Portal", "message": message, "timed": False}


def test_a_sign_in_that_ended_is_said_once_with_the_rows_own_sentence(run):  # noqa: F811
    steps = _says(run)["expired"]
    assert steps["fine"] == []
    assert steps["expired"] == [_told(EXPIRED)]  # the provider's name, what happened and what to do; it stays up
    assert steps["nextPoll"] == []  # once, not at every poll
    # a poll without an answer, or a launcher that sends no rows, neither says it again nor forgets it was said
    assert steps["noAnswer"] == [] and steps["afterNoAnswer"] == []
    assert steps["olderLauncher"] == [] and steps["afterOlderLauncher"] == []
    assert steps["otherProfile"] == [_told(EXPIRED, "openshell:sign-in:play:sign_in:nous")]
    assert steps["junk"] == []  # a row without a name and a sentence says nothing


def test_a_renewed_sign_in_takes_its_notice_back_and_a_later_end_is_said_again(run):  # noqa: F811
    steps = _says(run)["expired"]
    # the same notice, replaced by a line that goes away by itself
    assert steps["renewed"] == [{"id": NOTICE, "kind": "info", "title": "Nous Portal", "message": "Sign-in renewed.", "timed": True}]
    assert steps["renewedNextPoll"] == []
    assert steps["lapsed"] == [_told(LAPSED)]
    assert steps["thenExpired"] == [_told(EXPIRED)]  # another sentence for the same sign-in is said, in the same notice
    # switched off: nothing is said, and the next session starts over
    assert steps["switchedOff"] == [] and steps["onAgainFine"] == []
    assert steps["expiredAgain"] == [_told(EXPIRED)]


def test_the_status_bar_chip_is_what_tells(run):  # noqa: F811
    chip = _says(run)["chip"]
    assert chip["fine"]["notes"] == []
    assert chip["expired"]["notes"] == [EXPIRED]
    assert chip["again"]["notes"] == []  # drawn again (another poll, another page): not said twice
    assert chip["expired"]["effects"] == chip["fine"]["effects"] >= 2


def test_a_saved_key_gets_one_line_for_what_it_means_in_the_sandbox(run):  # noqa: F811
    key = _says(run)["key"]
    sent = [["/keys", "PUT", {"key": "OPENROUTER_API_KEY", "value": "made-up-value"}]]

    def line(text):
        return [{"id": None, "kind": "info", "title": None, "message": text, "timed": False}]

    assert key["inUse"] == {"calls": sent, "notes": line("Saved. In use in the sandbox now."), "result": "saved"}
    assert key["afterRestart"]["notes"] == line("Saved. Used in the sandbox after a restart.")
    assert key["notUsed"]["notes"] == line("Saved. Not used in the sandbox: no model in this profile names it.")
    # a profile that is off, a launcher that does not say, a word this page does not know: the save, no line
    for case in ("off", "olderLauncher", "unknownWord"):
        assert key[case] == {"calls": sent, "notes": [], "result": "saved"}, case
    # a refusal stays the dialog's own error
    assert key["refused"] == {"calls": sent, "notes": [], "result": "failed: Invalid key name."}
    # the dialog's Save button is that save
    assert key["dialog"] == {"steps": [["/keys", "PUT", {"key": "OPENROUTER_API_KEY", "value": ""}], "closed"],
                             "notes": ["Saved. In use in the sandbox now."]}
    assert sorted(key["copy"]) == ["after_restart", "in_use", "not_used"]
    assert all(text.startswith("Saved. ") and len(text) < 80 for text in key["copy"].values())


def test_a_second_refusal_of_the_switch_replaces_the_first(run):  # noqa: F811
    refusals = _says(run)["refusals"]
    assert [r["message"] for r in refusals] == [
        "A key is written in config.yaml.",
        "This profile's model uses GitHub Copilot ACP, which isn't available in the sandbox.",
        "A reason from the rows."]
    assert {r["id"] for r in refusals} == {"openshell:switch"}
