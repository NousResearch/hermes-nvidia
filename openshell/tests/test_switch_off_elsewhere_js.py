"""The desktop half when the launcher of a profile it shows as on stops answering (desktop/plugin.js, run in Node
through tests/js/switch_harness.mjs), the card's buttons, and the review rows' layout.

Seen with the desktop app: after ``hermes -p work sandbox off`` in a terminal an open desktop window kept the switch on with
"Backend offline" for minutes, a click on the switch did nothing, and then a raw "connect ECONNREFUSED
127.0.0.1:47972" toast appeared. The page's calls all go to the launcher while the profile is routed there; the
route was given back only by the page's own switch-off.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

NOT_ANSWERING = "The sandbox isn't answering."
OFF_ELSEWHERE = "The sandbox was turned off outside this window."
CLEAR = {"clear": ["plugin", "profile"], "plugin": "openshell", "profile": "work", "switching": None}


def _of(log, key):
    return [entry for entry in log if key in entry]


def test_a_switch_off_made_elsewhere_gives_the_route_back_within_one_poll(run):  # noqa: F811
    """The launcher's last answer said it was switching off and the next poll got no answer: the page asks the
    desktop to route the profile to this computer again (the call its own switch-off makes, without a launcher to
    stop first), once, and shows this computer's status the moment it has it."""
    done = run["lost"]["elsewhere"]
    assert done["lost"] == {"off": True} and done["asked"] is True
    assert done["again"] is False and done["later"] is False  # one dialog, not one per poll (or per chip and page)
    log = done["log"]
    assert log[0] == CLEAR and len(_of(log, "clear")) == 1  # no beforeApply: there is no launcher to stop
    assert log[1]["rest"] == "/status"
    [seed] = _of(log, "seed")
    assert seed["seed"] == ["openshell", "work", "status"] and seed["value"]["sandboxed"] is False
    assert log.index(seed) < log.index(_of(log, "invalidate")[0])
    assert not _of(log, "notify") and not _of(log, "fetch")


def test_a_no_in_the_dialog_is_not_asked_again_and_the_page_keeps_a_button(run):  # noqa: F811
    done = run["lost"]["declined"]
    assert done["asked"] is True and done["later"] is False and len(_of(done["log"], "clear")) == 1
    assert not _of(done["log"], "seed") and not _of(done["log"], "notify")
    bar = run["lost"]["bars"]["elsewhere"]
    assert bar["texts"] == [OFF_ELSEWHERE, "Switch back to run this profile on this computer again.", "Switch back"]
    assert bar["buttons"] == [{"text": "Switch back", "disabled": False}]
    assert run["lost"]["declinedClick"][0] == CLEAR  # the button asks again


def test_a_launcher_that_just_stops_answering_is_said_in_plain_words_with_what_to_do(run):  # noqa: F811
    """A crash: the profile may still be marked, and a launcher its login service restarts must find its window.
    Nothing is asked by itself; the page says so and offers the way out instead of a dead switch."""
    done = run["lost"]["crash"]
    assert done["lost"] == {"off": False} and done["asked"] is False and done["log"] == []
    bar = run["lost"]["crashBar"]
    assert bar["role"] == "status"
    assert bar["texts"] == [NOT_ANSWERING, 'If it doesn\'t come back, run "hermes -p work sandbox off" in a terminal, '
                            "then switch back.", "Switch back"]
    assert run["lost"]["bars"]["crashDefault"][1].startswith('If it doesn\'t come back, run "hermes sandbox off"')
    # The button gives the route back; this computer's backend then says the profile is still switched on.
    click = run["lost"]["crashClick"]
    assert click[0] == CLEAR
    [seed] = _of(click, "seed")
    assert seed["value"]["switch"]["marked"] is True and seed["value"]["sandboxed"] is False
    still = run["lost"]["stillOn"]
    assert still["marked"] is True and still["bar"] == [run["lost"]["copy"]["stillOn"]] and still["noBar"] is None
    assert still["whileSwitching"] is False and still["sandboxed"] is False and still["unmarked"] is False
    assert run["lost"]["copy"]["stillOn"] == ("The sandbox is still switched on for this profile, but it isn't "
                                              'running. Run "hermes -p work sandbox off" in a terminal.')
    assert '"hermes sandbox off"' in run["lost"]["copy"]["stillOnDefault"]


def test_the_switch_is_never_a_dead_control(run):  # noqa: F811
    switches = run["lost"]["switches"]
    assert switches["elsewhere"] == {"checked": False, "disabled": True, "tip": OFF_ELSEWHERE, "label": "Off"}
    assert switches["crash"] == {"checked": True, "disabled": True, "tip": NOT_ANSWERING, "label": "On"}
    assert switches["stillMarked"]["disabled"] is True and switches["stillMarked"]["tip"] == run["lost"]["copy"]["stillOn"]
    assert switches["plainOff"] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}
    assert run["lost"]["header"] == {"elsewhere": ["Sandbox", "work", "Not sandboxed"],
                                     "crash": ["Sandbox", "work", "Not answering"]}


def test_only_a_poll_without_an_answer_for_a_sandboxed_profile_counts(run):  # noqa: F811
    views = run["lost"]["views"]
    assert views["back"] is None  # the launcher answers again: nothing is lost
    assert views["restarting"] is None  # an HTTP answer (503 while the sandbox restarts) is an answer
    assert views["neverOn"] is None and views["noData"] is None
    assert views["fetchFailed"] == {"off": True}


def test_this_windows_own_switch_and_a_desktop_that_cannot_switch_are_left_alone(run):  # noqa: F811
    assert run["lost"]["mine"] == {"asked": False, "log": []}
    assert run["lost"]["noSdk"] == {"asked": False, "bar": []}  # no call to make: the notice has no button


def test_the_page_and_the_chip_follow_together_and_ask_once(run):  # noqa: F811
    page, chip = run["lost"]["page"], run["lost"]["chip"]
    assert page["elsewhere"] == {"lostBar": [{"off": True}], "cardView": [True], "headerLost": [{"off": True}], "clears": 1}
    assert page["crash"] == {"lostBar": [{"off": False}], "cardView": [True], "headerLost": [{"off": False}], "clears": 0}
    # The chip is in the status bar whatever page is open: it follows too, and goes when the sandbox is off.
    assert chip["elsewhere"] == {"shown": False, "clears": 1}
    assert chip["crash"] == {"shown": True, "tip": "Sandbox: Not answering", "clears": 0}
    assert chip["on"] == {"shown": True, "tip": "Sandbox: Running"}


def test_no_toast_ever_carries_the_transports_words(run):  # noqa: F811
    click = run["lost"]["deadClick"]  # a click on the switch with the launcher gone
    assert _of(click, "notify") == [{"notify": NOT_ANSWERING}]
    words = run["lost"]["words"]
    for raw, shown in words.items():
        if raw.startswith(("409", "500", "Only")):
            continue
        assert shown == NOT_ANSWERING, raw
        assert "ECONN" not in shown and "127.0.0.1" not in shown and "fetch" not in shown
    assert words['409: {"detail": "1 change needs an answer."}'] == "1 change needs an answer."  # the backend's words
    assert words["500: boom"] == "boom" and words["Only loopback URLs"] == "Only loopback URLs"


def test_a_switch_back_the_desktop_cannot_make_is_said_in_the_pages_words(run):  # noqa: F811
    done = run["lost"]["failedBack"]
    assert done["result"] is False
    assert _of(done["log"], "notify") == [{"notify": NOT_ANSWERING}] and not _of(done["log"], "seed")


def test_the_copy_is_terse_and_in_sentence_case(run):  # noqa: F811
    copy = run["lost"]["copy"]
    for key in ("notAnswering", "lostState", "lostHelp", "offElsewhere", "offElsewhereHelp", "switchBack", "stillOn"):
        text = copy[key]
        assert text[0].isupper() and text == text.strip() and len(text) <= 130, key
        for sentence in text.replace('"', "").split(". "):  # sentence case: one capital, at the start
            assert not any(word.istitle() for word in sentence.split()[1:] if word.isalpha()), key
        assert "!" not in text and "please" not in text.lower() and "error" not in text.lower(), key
    assert copy["stuckOff"] == 'Couldn\'t finish turning off: x. Run "hermes -p work sandbox off".'


# -- the card offers only what can happen ---------------------------------------------------------------

def test_a_card_of_always_reverted_rows_has_no_buttons(run):  # noqa: F811
    """Nothing in such a card can be kept or needs an answer, and the plain switch works: no "Keep and turn
    off", one line that says when the rows are put back."""
    on, off = run["buttons"]["fixedOnlyOn"], run["buttons"]["fixedOnlyOff"]
    assert on["buttons"] == [] and off["buttons"] == []
    assert on["texts"][-1] == "Put back when the sandbox restarts or turns off."
    assert off["texts"][-1] == "Put back when the sandbox turns on."
    assert on["rows"][0]["badge"] == {"text": "Always reverted", "tip": None}
    assert run["buttons"]["fixedOnlySwitch"] == {"disabled": False, "tip": None}  # the switch turns it off
    mixed = run["buttons"]["mixed"]  # one row that takes an answer: both buttons, as before
    assert [b["text"] for b in mixed["buttons"]] == ["Revert and turn off", "Keep and turn off"]
    assert "Put back when the sandbox restarts or turns off." not in mixed["texts"]


def test_the_no_copy_badge_says_what_revert_will_do_with_the_row(run):  # noqa: F811
    tips = run["buttons"]["copy"]["tips"]
    leave, hold = run["buttons"]["noCopyLeave"], run["buttons"]["noCopyHold"]
    assert leave["rows"][0]["badge"] == {"text": "No copy kept", "tip": tips["leave"]}
    assert hold["rows"][0]["badge"] == {"text": "No copy kept", "tip": tips["hold"]}
    assert run["buttons"]["noCopyOlderLauncher"]["rows"][0]["badge"]["tip"] == tips["hold"]  # as that launcher does
    assert tips["leave"] == "No earlier copy was kept. Revert leaves it as the sandbox changed it."
    assert "removes" in tips["hold"]
    assert len(leave["buttons"]) == 2  # the row takes an answer


# -- the review rows use the width they have -------------------------------------------------------------

def test_review_rows_have_no_empty_columns(run):  # noqa: F811
    """The settings rows keep a 9.5rem access column and an action column; the review, kept and "also changed"
    rows have neither, and cut their names and details at the middle of the row with a quarter of it empty."""
    layout = run["layout"]
    assert layout["cardRowsPlain"] and all(layout["cardRowsPlain"])
    assert layout["keptRowsPlain"] and all(layout["keptRowsPlain"])
    assert layout["alsoRowsPlain"] and all(layout["alsoRowsPlain"])
    assert layout["plain"]["columns"] == "minmax(0, 1fr) auto" and layout["plain"]["cells"] == 2
    assert layout["plain"]["noteTitle"] == "new, runs when the script is imported"  # the whole detail on hover
    assert layout["full"]["columns"] == "minmax(0, 1fr) auto 9.5rem 1.75rem"  # the other lists are as they were
