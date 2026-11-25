"""The Sandbox page's switch and header (desktop/plugin.js) against stand-ins for the desktop SDK, run in
Node (tests/js/switch_harness.mjs): the confirm-first switch (``prepare`` and ``purpose``,
feature-detected, start-then-ask as fallback), the status seeded before the switch state clears (no
"Off · Not sandboxed" frame), and the header's one name per state."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN_JS = HERE.parent / "desktop" / "plugin.js"
PURPOSE = "Runs this profile in a sandbox that limits the files and websites it can reach."


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH")
    work = tmp_path_factory.mktemp("js")
    done = subprocess.run([node, str(HERE / "js" / "switch_harness.mjs"), str(PLUGIN_JS), str(work)],
                          capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _steps(log, key):
    return [e for e in log if key in e]


def test_the_desktop_asks_first_and_prepare_starts_the_sandbox(run):
    log = run["askFirst"]
    first = log[0]
    assert first["set"] == ["plugin", "prepare", "profile", "purpose"]  # no url/token: nothing started yet
    assert first["purpose"] == PURPOSE and len(PURPOSE) <= 160
    assert first["switching"] is None  # the page shows no "Starting" while the dialog is open
    assert log[1] == {"rest": "/switch/on", "switching": {"profile": "work", "to": "on"}}
    assert log[2] == {"prepared": {"url": "http://127.0.0.1:47972", "token": "tok"}}
    [seed] = _steps(log, "seed")
    assert seed["value"]["sandboxed"] is True and seed["switching"] == {"profile": "work", "to": "on"}
    assert log.index(seed) < log.index(_steps(log, "invalidate")[0])
    assert not _steps(log, "fetch")  # nothing to undo


def test_cancel_starts_nothing(run):
    log = run["cancel"]
    assert not _steps(log, "rest") and not _steps(log, "fetch") and not _steps(log, "seed")


def test_an_address_the_desktop_refuses_is_undone_with_the_ticket(run):
    log = run["refused"]
    [undo] = _steps(log, "fetch")
    assert undo == {"fetch": "http://127.0.0.1:47972/api/plugins/openshell/switch/off", "body": {"ticket": "undo-1"}}
    assert {"notify": "Only loopback URLs"} in log
    [seed] = _steps(log, "seed")
    assert seed["value"]["sandboxed"] is False and seed["switching"] is not None


def test_an_older_desktop_keeps_the_old_order_with_the_purpose(run):
    log = run["legacy"]
    assert log[0]["rest"] == "/switch/on"
    assert log[1]["set"] == ["plugin", "profile", "purpose", "token", "url"]
    assert _steps(log, "fetch")[0]["body"] == {"ticket": "undo-1"}  # cancelled: undone


def test_off_says_stopping_only_after_the_user_confirms(run):
    log = run["off"]
    [clear] = _steps(log, "clear")
    assert clear["switching"] is None  # the dialog is open: nothing stops yet, the header stays "On"
    assert log.index(clear) < log.index(_steps(log, "fetch")[0])  # the launcher stops after the confirm
    cancel = run["offCancel"]
    # the list read (nothing needs an answer here), the ticket, the dialog, the ticket dropped
    assert [e["switching"] for e in cancel if "rest" in e or "clear" in e] == [None, None, None, None]
    assert [e["rest"] for e in _steps(cancel, "rest")] == ["/handback", "/switch/ticket", "/switch/ticket"]
    assert {"rest": "/switch/ticket", "switching": None} in cancel  # the ticket is dropped (DELETE)
    assert not _steps(cancel, "fetch") and not _steps(cancel, "seed")


def test_off_seeds_the_final_status_before_the_switch_state_clears(run):
    log = run["off"]
    [seed] = _steps(log, "seed")
    assert seed["value"]["sandboxed"] is False and seed["switching"] == {"profile": "work", "to": "off"}
    assert _steps(log, "invalidate")[0]["switching"] is None


def test_the_header_uses_the_desktops_words(run):
    copy = run["copy"]
    assert copy["turningOn"] == copy["starting"] == "Starting sandbox…"
    assert copy["turningOff"] == copy["stopping"] == copy["switchingOff"] == "Stopping sandbox…"
    assert copy["restarting"] == "Restarting sandbox…"
    assert copy["folder"] == "Restarting the sandbox to add outside…"
    assert copy["running"] == "Running" and copy["off"] == "Not sandboxed"


# -- host compatibility (launcher/compat.py): the bar and the switch ------------------------------------

UPDATE = "Needs the September 2026 Windows update. This PC has Windows 11 25H2, build 26200.9278."


def test_an_incompatible_host_shows_one_reason_one_action_and_check_again(run):
    bar = run["compat"]["update"]
    assert bar["role"] == "status"
    assert bar["texts"] == [UPDATE, "Install it in Settings > Windows Update, then check again.", "Check again"]
    # Windows Update is an ms-settings: link the desktop's openExternal refuses: text only, no dead button
    assert bar["buttons"] == [{"text": "Check again", "disabled": False, "variant": None}]


def test_a_web_action_gets_its_own_button_through_the_desktops_os_door(run):
    docker = run["compat"]["docker"]
    assert docker["texts"] == ["Needs Docker.", "Install Docker Engine, then check again.", "Install Docker", "Check again"]
    assert [b["text"] for b in docker["buttons"]] == ["Install Docker", "Check again"]
    assert docker["opened"] == ["https://docs.docker.com/engine/install/"]
    # a desktop without ctx.os: the text stays, the button goes
    assert [b["text"] for b in run["compat"]["dockerNoOs"]["buttons"]] == ["Check again"]


def test_a_compatible_host_or_a_running_sandbox_shows_no_bar(run):
    compat = run["compat"]
    assert compat["okBar"] is None and compat["sandboxedBar"] is None and compat["problemWhileOn"] is None


def test_the_switch_is_disabled_with_the_reason_on_an_incompatible_host(run):
    assert run["compat"]["switchBlocked"] == {"disabled": True, "tip": UPDATE, "label": "Can't turn on"}
    assert run["compat"]["switchFine"] == {"disabled": False, "tip": None, "label": "Off"}


# -- the launcher's built-in destination on the Sandbox page (launcher/usage_data.py) ----------------------

USAGE_ROW = {"title": "telemetry.nousresearch.com", "note": "Usage data this profile shares with Nous", "mono": True,
             "port": "Port 443", "removable": False}
PYPI_ROW = {"title": "pypi.org", "note": None, "mono": True, "port": "Port 443", "removable": True}


def test_the_usage_data_destination_is_listed_first_with_its_reason_and_no_remove_button(run):
    builtin = run["builtin"]
    assert builtin["both"] == [USAGE_ROW, PYPI_ROW]
    assert builtin["note"] == {"text": ["Usage data this profile shares with Nous"], "className": None}  # a sentence


def test_an_edit_of_the_users_destinations_never_sends_the_built_in_one(run):
    assert run["builtin"]["edit"] == [["/network", "PUT", {"egress": "deny", "allow": []}]]


def test_without_shared_usage_data_the_list_is_the_users_own(run):
    builtin = run["builtin"]
    assert builtin["olderLauncher"] == [PYPI_ROW]  # a launcher that sends no "builtin" key
    assert builtin["onlyBuiltin"]["rows"] == [USAGE_ROW] and "None" not in builtin["onlyBuiltin"]["texts"]
    assert builtin["nothing"] == {"rows": [], "texts": ["None"]}


# -- the header's count of allowed destinations ---------------------------------------------------------------

def test_the_header_counts_every_destination_the_page_lists(run):
    count = run["headerCount"]
    assert count["both"] == {"parts": ["Internet blocked", "2 allowed destinations"], "rows": 2}
    assert count["onlyBuiltin"] == {"parts": ["Internet blocked", "1 allowed destination"], "rows": 1}
    assert count["twoAndBuiltin"] == {"parts": ["Internet blocked", "3 allowed destinations"], "rows": 3}
    assert count["onlyOwn"] == {"parts": ["Internet blocked", "1 allowed destination"], "rows": 1}


def test_the_header_count_without_built_in_destinations_is_the_users_own(run):
    count = run["headerCount"]
    assert count["olderLauncher"] == {"parts": ["Internet blocked", "1 allowed destination"], "rows": 1}  # no key sent
    assert count["nothing"] == {"parts": ["Internet blocked"], "rows": 0}
    assert count["internetAllowed"] == ["Internet allowed"]  # no list on the page, no count in the header


# -- the withheld-key bar (launcher/pins.py: a model endpoint changed inside the sandbox) ----------------------

CHANGED = "Model endpoint changed in the sandbox. Key withheld."


def test_a_withheld_key_shows_one_bar_with_the_pair_and_allow_and_dismiss(run):
    bar = run["endpointBar"]["one"]
    assert bar["role"] == "status"
    assert bar["texts"] == [CHANGED, "OTHER_API_KEY -> 127.0.0.1:18923", "Allow", "Dismiss"]
    assert bar["buttons"] == [{"text": "Allow", "disabled": False, "variant": None},
                              {"text": "Dismiss", "disabled": False, "variant": "outline"}]


def test_allow_posts_each_withheld_pair_to_the_launchers_host_route(run):
    bar = run["endpointBar"]
    pair = {"env": "OTHER_API_KEY", "host": "127.0.0.1", "port": 18923}
    assert bar["allowSent"] == [["/endpoints/allow", "POST", pair]]
    assert bar["two"]["texts"][:3] == ["Model endpoints changed in the sandbox. Keys withheld.",
                                       "OTHER_API_KEY -> 127.0.0.1:18923", "SPARE_API_KEY -> models.example.com:443"]
    assert bar["two"]["sent"] == [["/endpoints/allow", "POST", pair],
                                  ["/endpoints/allow", "POST", {"env": "SPARE_API_KEY", "host": "models.example.com", "port": 443}]]
    assert bar["allowFailed"] == [{"notify": "No withheld key for this endpoint."}]  # a refusal is a toast


def test_no_bar_without_withheld_keys_or_outside_a_sandbox(run):
    bar = run["endpointBar"]
    assert bar["none"] is None and bar["olderLauncher"] is None and bar["notSandboxed"] is None


def test_dismiss_hides_the_bar_until_the_list_changes(run):
    dismiss = run["endpointBar"]["dismiss"]
    assert dismiss["before"] == "" and dismiss["shownAfter"] == 0
    assert dismiss["otherList"] == 2 and dismiss["otherProfile"] == 1


def test_a_sandbox_switched_on_without_pins_is_asked_to_turn_off_and_on_with_nothing_to_allow(run):
    bar = run["endpointBar"]["unpinned"]
    assert bar["texts"] == ["Turn the sandbox off and on to finish updating. Keys for these endpoints are withheld until then.",
                            "OTHER_API_KEY -> 127.0.0.1:18923", "Dismiss"]
    assert [b["text"] for b in bar["buttons"]] == ["Dismiss"]


def test_check_again_shows_the_fresh_answer_at_once(run):
    log = run["recheck"]
    assert log[0] == {"rest": "/switch/check", "method": "POST"}
    assert log[1]["seed"] == ["openshell", "work", "status"] and log[1]["value"]["switch"]["host"]["ok"] is True
    assert run["recheckFailed"] == [{"notify": "boom"}]


# -- the hand-back card (launcher/handback.py: what the sandbox changed among the files that run here) -------

OFF_URL = "http://127.0.0.1:47972/api/plugins/openshell/switch/off"
BUSY_TIP = "Available when the current turn finishes."
NO_COPY_TIP = "Reverting removes the sandbox's version. The earlier one can't be restored."
SHOWN = ["cfg:hooks_auto_accept", "cfg:mcp_servers.injected", "file:plugins/p1/__init__.py", "env:.op.env"]


def _rests(log):
    return [e["rest"] for e in _steps(log, "rest")]


def _notes(log):
    return [{k: v for k, v in e.items()} for e in _steps(log, "notify")]


def test_the_card_lists_each_change_as_the_launcher_gives_it_with_two_buttons(run):
    card = run["handback"]["card"]
    assert card["texts"][:2] == ["Changed in the sandbox", "These run on this computer once the sandbox is off."]
    assert [(r["label"], r["name"], r["detail"]) for r in card["rows"]] == [
        ("Shell hooks", "hooks_auto_accept", "turned on"),
        ("MCP server", "injected", "new, runs /bin/sh -c id"),
        ("Plugin file", "plugins/p1/__init__.py", "changed"),
        ("Env file", ".op.env", "created")]
    assert all(r["mono"] for r in card["rows"])
    # explicit buttons, the safe one first and primary
    assert card["buttons"] == [{"text": "Revert and turn off", "disabled": False, "variant": None},
                               {"text": "Keep and turn off", "disabled": False, "variant": "outline"}]
    assert card["also"] == 1


def test_no_card_and_nothing_blocked_without_rows(run):
    hb = run["handback"]
    free = {"disabled": False, "tip": None}
    assert hb["noRows"] == {"card": None, "switch": free}
    # only text the agent reads and ordinary settings changed: nothing is shown and nothing blocks
    assert hb["onlyOther"] == {"card": None, "switch": free}
    assert hb["noView"] == {"card": None, "closed": None, "switch": free}  # the list not read yet, or no baseline
    assert hb["notSandboxed"] is None


def test_rows_that_are_always_reverted_or_have_no_copy_say_so(run):
    badges = [r["badge"] for r in run["handback"]["card"]["rows"]]
    assert badges == [None, None, {"text": "No copy kept", "tip": NO_COPY_TIP}, {"text": "Always reverted", "tip": None}]


def test_the_other_changes_are_one_line_with_show(run):
    also = run["handback"]["also"]
    assert also["closed"]["texts"] == ["Also changed: 2 skills, 1 memory, SOUL.md, 2 other settings.", "Show"]
    assert also["closed"]["rows"] == [] and also["closed"]["buttons"] == ["Show"]
    assert also["open"]["buttons"] == ["Hide"]
    assert also["open"]["rows"] == [["SOUL.md", "changed", "Context file"], ["memories/MEMORY.md", "changed", "Memory"],
                                    ["skills/new-one/SKILL.md", "new", "Skill"], ["skills/writing/SKILL.md", "changed", "Skill"],
                                    ["display.skin", None, ""], ["mcp_servers_note", None, ""]]
    assert also["cut"] == ["50 more"]
    assert also["one"][0] == "Also changed: 1 skill, 1 other setting."
    assert also["none"] is None  # no line when nothing else changed


def test_folders_the_listing_did_not_finish_are_named(run):
    assert run["handback"]["incomplete"] == ["Not fully checked: skills."]
    assert run["handback"]["incompleteNone"] == []


def test_the_switch_waits_for_an_answer_while_rows_need_one(run):
    hb = run["handback"]
    assert hb["switchDisabled"] == {"disabled": True, "tip": "Changes need an answer first."}
    assert hb["copy"]["first"] == "Changes need an answer first."
    assert hb["switchFixedOnly"] == {"disabled": False, "tip": None}  # rows that are always reverted ask nothing
    assert hb["switchOff"] == {"disabled": False, "tip": None}  # a profile that is off with nothing left to review


def test_revert_and_turn_off_sends_the_answer_with_the_ticket(run):
    log = run["handback"]["revert"]
    assert _rests(log)[0] == "/switch/ticket" and "/handback/answer" not in _rests(log) and "/handback" not in _rests(log)
    [clear] = _steps(log, "clear")
    [fetch] = _steps(log, "fetch")
    assert log.index(clear) < log.index(fetch)  # the desktop's own confirm still comes first
    assert fetch == {"fetch": OFF_URL, "body": {"ticket": "t-1", "handback": "revert"}}
    assert _notes(log) == [{"notify": "Reverted 3 changes.", "kind": "info"}]
    assert _notes(run["handback"]["revertOne"]) == [{"notify": "Reverted 1 change.", "kind": "info"}]


def test_keep_and_turn_off_records_what_was_shown_then_turns_off(run):
    log = run["handback"]["keep"]
    [answer] = _steps(log, "answer")
    assert answer == {"method": "POST", "answer": {
        "answer": "keep", "rows": SHOWN[:3],  # a row that is always reverted takes no answer
        "seen": {row: f"state-of-{row}" for row in SHOWN}}}
    assert _rests(log)[:2] == ["/handback/answer", "/switch/ticket"]
    [fetch] = _steps(log, "fetch")
    assert fetch["body"] == {"ticket": "t-1", "handback": "keep"}
    assert _notes(log) == []  # what was reverted was on the list, marked as always reverted


def test_keep_says_when_a_change_made_after_the_list_was_reverted(run):
    assert _notes(run["handback"]["keepLate"]) == [
        {"notify": "1 change made after the list was shown was reverted.", "kind": "info"}]
    assert _notes(run["handback"]["keepLateTwo"]) == [
        {"notify": "2 changes made after the list was shown were reverted.", "kind": "info"}]


def test_a_keep_that_was_not_recorded_turns_nothing_off(run):
    log = run["handback"]["keepNotRecorded"]
    assert _rests(log) == ["/handback/answer"] and not _steps(log, "fetch") and not _steps(log, "clear")
    assert _notes(log) == [{"notify": "RuntimeError: boom"}]  # else the launcher would revert what was to be kept


def test_cancel_in_the_desktops_confirm_changes_nothing(run):
    log = run["handback"]["cancel"]
    assert not _steps(log, "fetch") and not _steps(log, "seed") and not _notes(log)
    assert _rests(log) == ["/switch/ticket", "/switch/ticket"]  # taken, then dropped
    assert run["handback"]["cancelCard"] is True


def test_a_plain_turn_off_that_finds_changes_shows_the_card_instead(run):
    log = run["handback"]["foundAtTheClick"]
    assert _rests(log) == ["/handback"]  # no ticket taken
    assert not _steps(log, "clear") and not _steps(log, "fetch") and not _notes(log)  # no dialog, nothing stops
    [seed] = _steps(log, "seed")
    assert seed["seed"] == ["openshell", "work", "handback"] and seed["value"]["unanswered"] == 2


def test_a_plain_turn_off_with_nothing_to_answer_turns_off(run):
    hb = run["handback"]
    log = hb["plainOnlyOther"]
    assert _rests(log)[:2] == ["/handback", "/switch/ticket"]
    assert _steps(log, "fetch") == [{"fetch": OFF_URL, "body": {"ticket": "t-1"}}] and _notes(log) == []
    assert [e["seed"][2] for e in _steps(log, "seed")] == ["status"]
    # rows that are always reverted are reverted without a question, and the page says so afterwards
    assert _notes(hb["plainFixedReverted"]) == [{"notify": "Reverted 1 change.", "kind": "info"}]
    # a list that cannot be read never keeps the switch from turning off
    assert _steps(hb["plainListFails"], "fetch") == [{"fetch": OFF_URL, "body": {"ticket": "t-1"}}]


def test_a_change_made_between_the_list_and_the_click_asks_again(run):
    log = run["handback"]["late409"]
    assert _notes(log) == [{"notify": "The sandbox changed more settings. Review them and turn off again."}]
    assert run["handback"]["copy"]["late"] == _notes(log)[0]["notify"]
    assert not any("hermes -p" in n["notify"] for n in _notes(log))  # not the "run sandbox off" advice


def test_a_revert_the_launcher_could_not_finish_is_shown_in_its_words(run):
    stuck = ("Couldn't revert 1 change: hooks_auto_accept. The sandbox is stopped. Close any app using this profile's "
             "files, then turn off again.")
    assert _notes(run["handback"]["incomplete409"]) == [{"notify": stuck}]
    # any other failure keeps the advice it had
    assert _notes(run["handback"]["other500"]) == [
        {"notify": "Couldn't finish turning off: The sandbox didn't turn off: boom Run \"hermes -p work sandbox off\"."}]


def test_a_review_that_could_not_run_is_said_once_the_sandbox_is_off(run):
    log = run["handback"]["reviewFailed"]
    assert _notes(log) == [{"notify": "Couldn't review the sandbox's changes. The sandbox is off.", "kind": "warning"}]
    [seed] = [e for e in _steps(log, "seed") if e["seed"][2] == "status"]
    assert seed["value"]["sandboxed"] is False  # it did turn off
    assert _notes(run["handback"]["keptWithProblem"]) == [
        {"notify": "Couldn't revert 1 change: scripts/late.sh.", "kind": "warning"}]


def test_the_buttons_and_the_switch_wait_for_a_running_turn(run):
    busy = run["handback"]["busy"]
    assert [b["disabled"] for b in busy["buttons"]] == [True, True] and busy["tips"] == [BUSY_TIP, BUSY_TIP]
    assert busy["switch"] == {"disabled": True, "tip": BUSY_TIP}


# -- the last session's changes, reviewed before the sandbox turns on again (launcher/switch.py previous_session) --

ON_BUTTONS = [{"text": "Revert and turn on", "disabled": False, "variant": None},
              {"text": "Keep and turn on", "disabled": False, "variant": "outline"}]
STARTED = {"prepared": {"url": "http://127.0.0.1:47972", "token": "tok"}}


def _asked(bodies):
    """What each switch-on request sent, apart from how long the host route may hold it: a number of seconds
    that keeps every request short."""
    assert all(isinstance(body.get("wait"), (int, float)) and 0 < body["wait"] <= 25 for body in bodies)
    return [{key: value for key, value in body.items() if key != "wait"} for body in bodies]


def test_a_profile_that_is_off_shows_the_last_sessions_changes_with_buttons_that_turn_on(run):
    review = run["review"]
    assert review["card"]["texts"] == ["Changed in the sandbox", "From the last sandbox session. These run on this computer now."]
    assert review["card"]["rows"] == ["hooks_auto_accept", "injected", "plugins/p1/__init__.py", ".op.env"]
    assert review["card"]["buttons"] == ON_BUTTONS and review["card"]["also"] == 1
    assert review["copy"]["captionOff"] == review["card"]["texts"][1]


def test_the_switch_waits_for_the_answer_before_it_turns_on(run):
    review = run["review"]
    assert review["switch"] == {"disabled": True, "tip": "Changes need an answer first."}
    assert review["switchNoRows"] == {"disabled": False, "tip": None} and review["noRowsCard"] is None


def test_the_list_is_shown_for_an_off_profile_only_while_the_host_says_it_is_open(run):
    assert run["review"]["view"] == {"open": True, "stale": True, "whileOn": True, "noStatus": True}


def test_where_the_switch_cannot_turn_on_neither_can_the_cards_buttons(run):
    blocked = run["review"]["blocked"]
    assert [b["disabled"] for b in blocked["buttons"]] == [True, True] and blocked["tips"] == ["Needs Docker.", "Needs Docker."]


def test_revert_and_turn_on_sends_the_answer_with_the_switch_on(run):
    done = run["review"]["revert"]
    log = done["log"]
    assert _asked(done["bodies"]) == [{"handback": "revert"}]
    assert log[0]["set"] == ["plugin", "prepare", "profile", "purpose"] and log[0]["switching"] is None  # the confirm first
    assert _rests(log)[0] == "/switch/on" and "/handback" not in _rests(log) and STARTED in log
    assert _notes(log) == [{"notify": "Reverted 3 changes.", "kind": "info"}]
    [seed] = _steps(log, "seed")
    assert seed["value"]["sandboxed"] is True


def test_keep_and_turn_on_sends_the_rows_as_they_were_shown(run):
    done = run["review"]["keep"]
    assert _asked(done["bodies"]) == [{"handback": "keep", "seen": {row: f"state-of-{row}" for row in SHOWN}}]
    # only what was reverted although it was not on the list is said
    assert _notes(done["log"]) == [{"notify": "1 change made after the list was shown was reverted.", "kind": "info"}]
    assert _notes(run["review"]["keepNothingLate"]["log"]) == []


def test_cancel_in_the_confirm_answers_nothing_and_starts_nothing(run):
    done = run["review"]["cancel"]
    assert done["bodies"] == [] and not _steps(done["log"], "rest") and not _steps(done["log"], "notify")


def test_a_switch_on_the_host_refuses_for_the_answer_says_so_and_starts_nothing(run):
    for name, body in (("refused", {"handback": "keep", "seen": {row: f"state-of-{row}" for row in SHOWN}}), ("plainRefused", {})):
        done = run["review"][name]
        assert _asked(done["bodies"]) == [body]
        assert _notes(done["log"]) == [{"notify": "Changes need an answer first."}]  # not the bare 409 text
        assert not _steps(done["log"], "fetch") and not _steps(done["log"], "prepared")
        assert _steps(done["log"], "invalidate")  # the page reads the list again: the card shows


# -- the Network list while a key is withheld -------------------------------------------------------------------

LOOPBACK_TIP = "Services on this computer are always reachable from the sandbox."
WITHHELD = {"text": "Key withheld", "tip": "The sandbox can reach this endpoint. It doesn't get the key until you allow it."}


def test_an_endpoint_whose_key_is_withheld_says_so_instead_of_allowed(run):
    rows = run["withheldRow"]
    assert rows["one"] == [
        {"title": "Model", "sub": "http://127.0.0.1:47970/v1", "text": "Allowed", "tip": LOOPBACK_TIP},
        {"title": "Fallback model", "sub": "http://127.0.0.1:47986/v1", **WITHHELD}]
    assert rows["copy"] == {"state": WITHHELD["text"], "tip": WITHHELD["tip"]}
    assert rows["https"] == [{"title": "Model", "sub": "https://models.example.com/v1", **WITHHELD}]  # the default port


def test_other_endpoints_keep_their_state(run):
    rows = run["withheldRow"]
    allowed = [{"title": "Model", "sub": "http://127.0.0.1:47970/v1", "text": "Allowed", "tip": LOOPBACK_TIP},
               {"title": "Fallback model", "sub": "http://127.0.0.1:47986/v1", "text": "Allowed", "tip": LOOPBACK_TIP}]
    assert rows["none"] == allowed and rows["olderLauncher"] == allowed
    assert [r["text"] for r in rows["otherPort"]] == ["Allowed"] and [r["text"] for r in rows["otherLabel"]] == ["Allowed"]
    assert [r["text"] for r in rows["otherHost"]] == ["Allowed"]
    assert [r["text"] for r in rows["blocked"]] == ["Blocked"]  # unreachable is still the first thing to say


# -- the list follows the status the page polls; what was kept is named afterwards -------------------------------

LIST_KEY = ["openshell", "work", "handback"]


def test_the_list_is_read_again_when_the_statuss_stamp_changes(run):
    follow = run["follow"]
    assert follow["first"] == {"did": True, "read": [LIST_KEY]}  # the page opened: the list is read, cached or not
    assert follow["changed"] == {"did": True, "read": [LIST_KEY]}
    assert follow["olderLauncher"] == {"did": False, "read": []}  # no stamp: read once, as before
    assert follow["notWanted"] == {"did": False, "read": []}  # a profile that is off with nothing to review


def test_the_page_follows_the_stamp_with_the_status_poll_and_no_timer_of_its_own(run):
    follow = run["follow"]
    on, later = follow["pageOn"], follow["pageOnLater"]
    assert on["listQuery"] == {"enabled": True, "refetchInterval": False} and on["timers"] == 0
    assert on["deps"] == ["work", "s1", True] and on["read"] == [LIST_KEY]
    assert later["deps"] == ["work", "s2", True]  # the next status carries another stamp: the effect runs again
    assert on["card"] == 1
    off = follow["pageOff"]
    assert off["listQuery"] == {"enabled": False, "refetchInterval": False} and off["read"] == []
    assert follow["pageOffOpen"]["listQuery"]["enabled"] is True and follow["pageOffOpen"]["read"] == [LIST_KEY]
    older = follow["pageOlderLauncher"]
    assert older["listQuery"]["enabled"] is True and older["deps"] == ["work", None, True] and older["read"] == []
    assert follow["wanted"] == {"on": True, "off": False, "offOpen": True, "offKept": True, "none": False}


def test_what_was_kept_is_one_line_with_a_way_to_see_it(run):
    kept = run["kept"]
    assert kept["none"] is None  # nothing kept: no line
    assert kept["one"]["texts"][0] == "Kept from the sandbox: 1 item" and kept["one"]["buttons"] == ["Show"]
    assert kept["two"]["texts"][0] == "Kept from the sandbox: 2 items" and kept["two"]["rows"] == []
    assert kept["twoOpen"]["buttons"] == ["Hide"]
    assert kept["twoOpen"]["rows"] == [
        {"title": "command", "note": "new, runs print-keys", "label": "Secret source"},
        {"title": "injected-job", "note": "new, runs scripts/cron-injected.sh", "label": "Cron job"}]
    assert kept["beforeTheList"]["rows"] == []  # the count comes with the status, the items with the list
    assert kept["copy"] == {"one": "Kept from the sandbox: 1 item", "three": "Kept from the sandbox: 3 items"}


def test_the_page_lists_what_was_kept_for_a_profile_that_is_off_too(run):
    page = run["follow"]["pageOffKept"]
    assert page["listQuery"]["enabled"] is True and page["card"] == 1  # the card renders nothing without rows
    assert page["keptLine"]["count"] == 2 and [i["id"] for i in page["keptLine"]["items"]] == ["cfg:secrets.command", "cron:bbbbbbbbbbbb"]


# -- a switch-on asked for in short requests: the page asks again until the final answer --------------------------

STARTING = {"profile": "work", "to": "on"}


def _asks(log):
    return [e for e in _steps(log, "rest") if e["rest"] == "/switch/on"]


def test_a_slow_start_is_asked_for_again_until_the_final_answer_and_then_routed(run):
    assert "error" not in run["waited"], run["waited"].get("error")
    slow = run["waited"]["slow"]
    log = slow["log"]
    assert len(_asks(log)) == 3 and _asked(slow["bodies"]) == [{}, {}, {}]
    assert slow["bodies"][0] == slow["bodies"][1] == slow["bodies"][2]  # the same request each time
    assert all(e["switching"] == STARTING for e in _asks(log))  # "Starting sandbox…" for the whole wait
    [prepared] = _steps(log, "prepared")
    assert prepared == STARTED and log.index(prepared) > log.index(_asks(log)[-1])  # routed by the final answer only
    [seed] = _steps(log, "seed")
    assert seed["value"]["sandboxed"] is True and seed["switching"] == STARTING
    assert not _steps(log, "fetch") and not _steps(log, "notify") and slow["switching"] is None


def test_a_backend_that_answers_once_with_the_address_still_switches_on(run):
    once = run["waited"]["answersAtOnce"]
    assert len(_asks(once["log"])) == 1 and _asked(once["bodies"]) == [{}]
    assert STARTED in once["log"] and _steps(once["log"], "seed")[0]["value"]["sandboxed"] is True
    assert not _steps(once["log"], "fetch") and not _steps(once["log"], "notify")


def test_a_start_that_fails_while_the_page_waits_shows_the_error_and_leaves_the_switch_off(run):
    failed = run["waited"]["failsLater"]
    log = failed["log"]
    assert len(_asks(log)) == 2  # the error ends the asking
    assert _steps(log, "notify") == [{"notify": "The sandbox didn't start within 240 seconds."}]
    # nothing was routed, and the page holds nothing to undo: the host route undid what it had started
    assert not _steps(log, "prepared") and not _steps(log, "fetch") and not _steps(log, "seed")
    assert failed["switching"] is None and _steps(log, "invalidate")


def test_an_older_desktop_waits_for_the_final_answer_before_it_asks(run):
    log = run["waited"]["olderDesktop"]["log"]
    assert len(_asks(log)) == 2
    [asked] = _steps(log, "set")
    assert asked["set"] == ["plugin", "profile", "purpose", "token", "url"] and log.index(asked) > log.index(_asks(log)[-1])


def test_an_address_the_desktop_refuses_after_the_wait_is_undone_with_the_ticket(run):
    log = run["waited"]["refusedAfterTheWait"]["log"]
    assert len(_asks(log)) == 2
    assert _steps(log, "fetch") == [{"fetch": OFF_URL, "body": {"ticket": "undo-1"}}]
    assert {"notify": "Only loopback URLs"} in log
