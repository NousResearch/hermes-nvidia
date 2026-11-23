"""The Sandbox page after "Switch back" from a launcher that never said it was turning off (desktop/plugin.js, run
in Node through tests/js/switch_harness.mjs).

Seen with the desktop app: the launcher's process was gone, the page said so with its notice, and after "Switch
back" it read "On", "Running", with a switch that looked usable and did nothing, while the status bar said the
backend was offline. The profile was still switched on for the sandbox, and the desktop does not run such a
profile on this computer: every call of the page failed in the desktop itself, so the page kept drawing the
launcher's last answer, which nobody reported any more.

The switch-back does not turn the sandbox off: nothing the page can reach could stop a sandbox the launcher left
behind, and the profile's marker may only go once that is known. The page says what it knows and what to run.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

CLEAR = {"clear": ["plugin", "profile"], "plugin": "openshell", "profile": "work", "switching": None}
NOT_ANSWERING = "The sandbox isn't answering."
LEFT_ON = ("The sandbox is still switched on for this profile, but this window isn't connected to it. "
           'Run "hermes -p work sandbox off" in a terminal.')
TICKET = "Error invoking remote method 'hermes:api': Error: Gateway ticket bootstrap failed"


def _of(log, key):
    return [entry for entry in log if key in entry]


def test_the_page_stops_showing_the_launchers_last_answer_once_the_route_is_given_back(run):  # noqa: F811
    left = run["left"]
    assert "error" not in left, left.get("error")
    for case in ("refused", "noRoute"):  # the two ways the desktop says "this profile runs through a plugin"
        view = left[case]
        assert view["header"] == ["Sandbox", "work", "Not connected"], case  # not "Running" and its details
        assert view["switch"] == {"checked": True, "disabled": True, "tip": LEFT_ON, "label": "On"}
        assert view["bar"] == [{"role": "status", "texts": [LEFT_ON], "buttons": 0}]
        assert view["lostBar"] == [None]  # no second "Switch back"
        assert view["card"] == [True]  # no review card nobody could answer
        assert view["chip"] == {"shown": True, "tip": "Sandbox: Not connected"}


def test_one_look_at_this_computer_then_the_status_poll_brings_the_answer(run):  # noqa: F811
    """The switch-back asks the desktop once, looks once at this computer's backend, and leaves the rest to the
    page's own poll: no minute and a half of the old picture."""
    log = run["left"]["click"]
    assert log[0] == CLEAR and len(_of(log, "clear")) == 1
    assert len(_of(log, "rest")) == 1 and log[1]["rest"] == "/status"
    assert not _of(log, "seed") and not _of(log, "notify") and not _of(log, "fetch")
    assert _of(log, "invalidate")


def test_while_this_computer_has_not_said_anything_the_page_claims_nothing(run):  # noqa: F811
    """After "sandbox off" in a terminal this computer's backend can take a while to serve the profile again.
    Until it says something the page knows only that nobody answers."""
    for case in ("slow", "pending"):
        view = run["left"][case]
        assert view["header"] == ["Sandbox", "work", "Not answering"], case
        assert view["switch"] == {"checked": True, "disabled": True, "tip": NOT_ANSWERING, "label": "On"}
        assert view["bar"] == [{"role": "status", "texts": [NOT_ANSWERING], "buttons": 0}]
        assert view["lostBar"] == [None] and view["chip"]["tip"] == "Sandbox: Not answering"


def test_the_first_answer_after_the_switch_back_is_shown_as_it_is(run):  # noqa: F811
    left = run["left"]
    off = left["answeredOff"]  # the sandbox was turned off in a terminal meanwhile
    assert off["header"][:3] == ["Sandbox", "work", "Not sandboxed"] and off["bar"] == []
    assert off["switch"] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}
    assert off["chip"]["shown"] is False
    marked = left["answeredMarked"]  # a backend on this computer that reports the profile as still switched on
    assert marked["bar"] == [] and marked["stillOnBar"] == [True] and marked["switch"]["disabled"] is True
    again = left["answeredOn"]  # routed to a launcher again: its state and its details line are back
    assert again["header"][:3] == ["Sandbox", "work", "Running"] and again["bar"] == []
    assert "OpenShell sandbox" in again["header"]
    assert again["switch"]["checked"] is True and again["chip"]["tip"] == "Sandbox: Running"


def test_a_look_that_is_answered_is_shown(run):  # noqa: F811
    """A backend on this computer that does answer for such a profile says the rest, as before."""
    done = run["left"]["lookAnswered"]
    [seed] = _of(done["log"], "seed")
    assert seed["value"]["switch"]["marked"] is True and len(_of(done["log"], "rest")) == 1
    view = done["view"]
    assert view["bar"] == [] and view["stillOnBar"] == [True]
    assert view["header"][:3] == ["Sandbox", "work", "Not sandboxed"]


def test_a_switch_off_made_elsewhere_is_followed_as_before(run):  # noqa: F811
    """The launcher said it was turning off: the page waits for this computer's status, also past a first
    refusal, and shows it. Nothing here is the notice of a profile that is still switched on."""
    after = run["left"]["afterOffElsewhere"]
    assert after["log"][0] == CLEAR and len(_of(after["log"], "rest")) == 2
    [seed] = _of(after["log"], "seed")
    assert seed["value"]["sandboxed"] is False
    assert after["view"]["bar"] == [] and after["view"]["header"][2] != "Not connected"
    assert "Not connected" not in run["left"]["otherProfile"]


def test_the_desktops_refusal_is_never_shown_as_raw_text(run):  # noqa: F811
    words = run["left"]["words"]
    assert len(words) == 2 and set(words.values()) == {NOT_ANSWERING}
    copy = run["left"]["copy"]
    assert copy["leftState"] == "Not connected" and copy["leftOn"] == LEFT_ON
    assert '"hermes sandbox off"' in copy["leftOnDefault"]
    assert TICKET in words
