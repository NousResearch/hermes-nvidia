"""The Sandbox page's switch while the sandbox is down (desktop/plugin.js, run in Node through
tests/js/switch_harness.mjs, a document that is shown).

Seen with the desktop app after the sandbox's gateway had ended: the page said "Backend offline", then "On" and
"Not answering"; a message was not sent; a click on the switch brought no confirm dialog. The launcher had no
turn left to answer anything then. With a launcher that answers, the page is in one of three states, and in each
the user has a way to turn the sandbox off:

* ``failed`` (the launcher answers, the sandbox is gone, its sentence is in the header): the switch asks the
  desktop to confirm and the launcher turns off. A chat that was left waiting on the sandbox does not hold it.
* the launcher answers while the desktop's own bar says the backend is offline: the same.
* nothing answers at all: the switch is held with the reason, and the notice's "Switch back" asks the desktop.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

SENTENCE = "The sandbox's gateway stopped. Turn the sandbox off, then on again."
OFF_URL = "http://127.0.0.1:47972/api/plugins/openshell/switch/off"
BUSY_TIP = "Available when the current turn finishes."


def _of(log, key):
    return [entry for entry in log if key in entry]


def _turned_off(log):
    """The steps of a switch-off, in order: the list is read, a ticket is taken, the desktop asks, and only then
    the launcher's own route is called with the ticket."""
    steps = [next(iter(entry)) for entry in log if set(entry) & {"rest", "clear", "fetch"}]
    assert steps[:4] == ["rest", "rest", "clear", "fetch"], steps
    assert [entry["rest"] for entry in _of(log, "rest")][:2] == ["/handback", "/switch/ticket"]
    [clear] = _of(log, "clear")
    assert clear["clear"] == ["beforeApply", "plugin", "profile"] and clear["switching"] is None  # the dialog first
    [fetch] = _of(log, "fetch")
    assert fetch == {"fetch": OFF_URL, "body": {"ticket": "t-1"}}
    assert not _of(log, "notify")
    return True


def test_the_failed_state_shows_the_launchers_sentence(run):  # noqa: F811
    down = run["down"]
    assert "error" not in down, down.get("error")
    assert down["header"] == {"label": SENTENCE, "tone": "bad"}


def test_in_the_failed_state_the_switch_asks_and_turns_off(run):  # noqa: F811
    failed = run["down"]["failed"]
    assert failed["switch"] == {"checked": True, "disabled": False, "tip": None}
    assert _turned_off(failed["log"])


def test_a_chat_left_waiting_on_a_sandbox_that_is_gone_does_not_hold_the_switch(run):  # noqa: F811
    """A message sent to a sandbox that is gone is never answered, so "a reply is running" never ends: the
    switch was disabled with "Available when the current turn finishes." and a click did nothing."""
    for case in ("failedBusy", "exitedBusy"):
        seen = run["down"][case]
        assert seen["switch"] == {"checked": True, "disabled": False, "tip": None}, case
        assert _turned_off(seen["log"]), case
    card = run["down"]["cardBusy"]
    assert [b["disabled"] for b in card["failed"]] == [False, False]
    assert [b["disabled"] for b in card["running"]] == [True, True]


def test_a_reply_that_does_run_still_makes_the_switch_wait(run):  # noqa: F811
    running = run["down"]["runningBusy"]
    assert running["switch"] == {"checked": True, "disabled": True, "tip": BUSY_TIP}
    assert not _of(running["log"], "clear") and not _of(running["log"], "fetch")


def test_with_the_desktops_bar_on_offline_the_switch_works_as_long_as_the_launcher_answers(run):  # noqa: F811
    """The page does not read the desktop's status bar. A list that cannot be read never keeps the switch from
    turning off."""
    offline = run["down"]["offline"]
    assert offline["switch"] == {"checked": True, "disabled": False, "tip": None}
    assert _turned_off(offline["log"])


def test_when_nothing_answers_the_switch_is_held_and_the_notice_asks(run):  # noqa: F811
    lost = run["down"]["lost"]
    assert lost["view"] == {"off": False}
    assert lost["switch"]["checked"] is True and lost["switch"]["disabled"] is True
    assert lost["switch"]["tip"] == "The sandbox isn't answering."
    assert lost["bar"]["buttons"] == [{"text": "Switch back", "disabled": False}]
    assert 'run "hermes -p work sandbox off" in a terminal' in " ".join(lost["bar"]["texts"])
    [clear] = _of(run["down"]["lostClick"], "clear")  # the desktop's own confirm
    assert clear["clear"] == ["plugin", "profile"] and clear["profile"] == "work"
