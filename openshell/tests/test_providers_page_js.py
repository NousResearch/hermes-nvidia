"""The providers on the Sandbox page (desktop/plugin.js, run in Node through tests/js/switch_harness.mjs).

Before the switch the page lists the profile's providers, one row each, with the backend's sentence for what each
will do in the sandbox. A key written in config.yaml, and a model whose provider cannot work in the sandbox or
needs a sign-in first, keep the switch from turning on: the switch and the "turn on" buttons are disabled with
the reason, a bar above the tabs says it, and for a key in config.yaml the bar and the row offer "Move to .env",
which asks before anything is written. While the sandbox is on the same rows come with the launcher's status, and
a sign-in that expired is named in a bar with what to do. A row shows a name, a state and a sentence, never a
value.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

WORKS_KEY = "Works in the sandbox. The key stays on this computer and is used only at openrouter.ai."
SIGNED_IN = "Works in the sandbox. Stays signed in on this computer."
INLINE = "Written in config.yaml, where the sandbox could read it. Move it to .env first."
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."
TWO_KEYS = "Keys are written in config.yaml, where the sandbox could read them. Move them to .env first."
MODEL_GONE = "This profile's model uses GitHub Copilot ACP, which isn't available in the sandbox."
MODEL_NEEDS = "This profile's model uses OpenAI Codex, which needs a sign-in first."
GONE = "Not available in the sandbox: GitHub Copilot ACP signs in through its own program."
EXPIRED = "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
MODEL = {"text": "Model", "variant": "muted"}
MODEL_TIP = "This profile's model uses this provider."
MOVE = {"text": "Move to .env", "disabled": False, "variant": "outline"}
CANT_MOVE = "This version can't move keys. Take the key out of config.yaml and save it in .env yourself."
ALL_IDS = ["config:model.api_key", "key:OPENROUTER_API_KEY"]


def _providers(run):  # noqa: F811
    providers = run["providers"]
    assert "error" not in providers, providers.get("error")
    return providers


def test_the_rows_come_from_the_host_route_while_off_and_from_the_launchers_status_while_on(run):  # noqa: F811
    views = _providers(run)["views"]
    assert views["off"] == {"known": True, "on": False, "rows": ["key:OPENROUTER_API_KEY", "sign_in:nous"], "block": None}
    assert views["offBlocked"] == {"known": True, "on": False, "rows": ALL_IDS, "block": "key_in_config"}
    assert views["offNoRows"] == {"known": True, "on": False, "rows": [], "block": None}
    # While on, the host route's rows and its reason are not the launcher's: neither is shown.
    assert views["on"] == {"known": True, "on": True, "rows": ["key:OPENROUTER_API_KEY", "nous:agent_key"], "block": None}
    # A backend that sends no rows (an older launcher, an older host route, a config still on its way).
    for case in ("offOlderBackend", "offNoConfigYet"):
        assert views[case] == {"known": False, "on": False, "rows": [], "block": None}, case
    assert views["onOlderLauncher"] == {"known": False, "on": True, "rows": [], "block": None}
    assert views["junkRows"]["rows"] == ["key:OPENROUTER_API_KEY"]


def test_each_state_of_a_row_is_drawn_with_its_name_its_badge_and_the_backends_sentence(run):  # noqa: F811
    section = _providers(run)["section"]
    assert section["off"]["title"] == "Providers"
    rows = {(row["title"], row["note"]): row for row in section["off"]["rows"]}
    assert len(rows) == 9 and all(row["plain"] for row in rows.values())  # the sentence gets the row's width
    assert rows[("Key in config.yaml", INLINE)] == {
        "title": "Key in config.yaml", "plain": True, "code": [{"text": "model.api_key", "mono": True}],
        "badges": [{"text": "In config.yaml", "variant": "warn"}], "tips": [], "note": INLINE, "buttons": []}
    assert rows[("OpenRouter", WORKS_KEY)] == {
        "title": "OpenRouter", "plain": True, "code": [{"text": "OPENROUTER_API_KEY", "mono": True}],
        "badges": [MODEL], "tips": [MODEL_TIP], "note": WORKS_KEY, "buttons": []}
    assert rows[("Nous Portal", SIGNED_IN)] == {
        "title": "Nous Portal", "plain": True, "code": [], "badges": [], "tips": [], "note": SIGNED_IN, "buttons": []}
    assert rows[("OpenAI Codex", "Not signed in. Sign in to OpenAI Codex first.")]["badges"] == [
        MODEL, {"text": "Sign in first", "variant": "warn"}]
    assert rows[("GitHub Copilot ACP", GONE)]["badges"] == [MODEL, {"text": "Not available", "variant": "muted"}]
    no_key = rows[("DeepSeek", "No key found: DEEPSEEK_API_KEY is not set in this profile's .env.")]
    assert no_key["badges"] == [{"text": "No key", "variant": "muted"}] and no_key["code"][0]["text"] == "DEEPSEEK_API_KEY"
    assert rows[("Nous Portal", EXPIRED)]["badges"] == [MODEL, {"text": "Sign-in expired", "variant": "destructive"}]
    withheld = rows[("OPENAI_API_KEY", "Model endpoint changed in the sandbox. Key withheld.")]
    assert withheld["badges"] == [{"text": "Key withheld", "variant": "warn"}] and withheld["code"] == []  # the name once
    # A state this page does not know: the backend's sentence, no badge, and no move whatever the row carries.
    odd = rows[("Some provider", "A state this page does not know.")]
    assert odd["badges"] == [] and odd["buttons"] == [] and odd["code"] == [{"text": "some.place", "mono": True}]
    # No row offers anything: nothing to replace, remove or reveal, and one key is moved by the bar's button.
    assert [row["buttons"] for row in section["off"]["rows"]] == [[], [], [], [], [], [], [], [], []]


def test_while_the_sandbox_is_on_no_row_offers_the_move(run):  # noqa: F811
    section = _providers(run)["section"]
    assert [row["title"] for row in section["on"]["rows"]] == [row["title"] for row in section["off"]["rows"]]
    assert all(row["buttons"] == [] for row in section["on"]["rows"])
    assert section["pending"] == []  # one key: the bar's button is the one (it waits while another edit is on its way)


def test_a_profile_without_providers_says_so_and_a_backend_without_rows_shows_no_list(run):  # noqa: F811
    section = _providers(run)["section"]
    assert section["empty"] == {"title": "Providers", "texts": ["No providers set up."], "rows": 0}
    assert section["unknownOff"] is None and section["unknownOn"] is None and section["noView"] is None


def test_the_bar_says_why_the_switch_does_not_turn_on_and_offers_the_move_for_keys_only(run):  # noqa: F811
    bar = _providers(run)["bar"]
    button = [{"text": "Move to .env", "disabled": False}]
    assert bar["inline"] == {"role": "status", "buttons": button,
                             "texts": [ONE_KEY, "model.api_key moves to .env as CUSTOM_API_KEY", "Move to .env"]}
    assert bar["inlineTwo"] == {"role": "status", "buttons": button, "texts": [
        TWO_KEYS, "model.api_key moves to .env as CUSTOM_API_KEY",
        "providers.spare.api_key moves to .env as SPARE_API_KEY", "Move to .env"]}
    assert bar["modelGone"] == {"role": "status", "texts": [MODEL_GONE, GONE], "buttons": []}
    assert bar["modelNeeds"] == {"role": "status", "buttons": [],
                                 "texts": [MODEL_NEEDS, "Not signed in. Sign in to OpenAI Codex first."]}
    assert bar["offFine"] is None and bar["launcherGone"] is None


def test_while_on_the_bar_names_an_expired_sign_in_with_what_to_do_and_nothing_else(run):  # noqa: F811
    bar = _providers(run)["bar"]
    assert bar["onExpired"] == {"role": "status", "buttons": [], "texts": ["Nous Portal", "Sign-in expired", EXPIRED]}
    # The sentence is the row's: a token that was only late is not told to sign in again.
    assert bar["onLapsed"]["texts"] == [
        "Nous Portal", "Sign-in expired", "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is.",
        "OpenAI Codex", "Sign-in expired", "Sign-in expired. Turn the sandbox off, sign in to OpenAI Codex, then turn it on."]
    assert bar["onFine"] is None  # a withheld key has its own bar, as before
    assert bar["onIgnoresTheHostBlock"] is None


def test_the_switch_is_disabled_with_the_reason_and_never_while_the_sandbox_is_on(run):  # noqa: F811
    switch = _providers(run)["switch"]
    for case, reason in (("inline", ONE_KEY), ("modelGone", MODEL_GONE), ("modelNeeds", MODEL_NEEDS)):
        assert switch[case] == {"checked": False, "disabled": True, "tip": reason, "label": "Can't turn on"}, case
    for case in ("fine", "noProviders", "olderBackend"):
        assert switch[case] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}, case
    # What this computer cannot do comes first; the last session's answer comes after the key.
    assert switch["hostProblemFirst"]["tip"].startswith("Needs the ") and "Windows update" in switch["hostProblemFirst"]["tip"]
    assert switch["beforeTheLastSessionsAnswer"]["tip"] == ONE_KEY
    # A sandbox that is on can always be turned off.
    assert switch["onIsNeverHeld"] == {"checked": True, "disabled": False, "tip": None, "label": "On"}
    assert switch["headerHandsItOn"] == [True]


def test_the_cards_turn_on_buttons_are_held_for_the_same_reason(run):  # noqa: F811
    switch = _providers(run)["switch"]
    assert switch["cardBlocked"] == {"tips": [ONE_KEY], "buttons": [
        {"text": "Revert and turn on", "disabled": True}, {"text": "Keep and turn on", "disabled": True}]}
    assert switch["cardFine"] == {"tips": [], "buttons": [
        {"text": "Revert and turn on", "disabled": False}, {"text": "Keep and turn on", "disabled": False}]}


def test_a_held_turn_on_starts_nothing_and_says_why(run):  # noqa: F811
    providers = _providers(run)
    # No call to the host route, no question from the desktop, no launcher: the reason, once.
    assert providers["heldTurnOn"] == [{"notify": ONE_KEY}]
    assert providers["heldCardClick"] == [{"notify": MODEL_GONE}]
    assert providers["heldSwitchClick"] == [{"notify": MODEL_NEEDS}]
    assert providers["freeTurnOn"] == ["asked", "started"]  # without a reason the switch turns on as before


def test_a_refusal_of_the_host_route_is_shown_in_its_own_words(run):  # noqa: F811
    """The page's rows can be seconds old, and the host route refuses for the same reasons: its sentence is the
    toast, the switch is free again, the rows are read again and nothing was left started."""
    refused = _providers(run)["refused"]
    for case, reason in (("inline", ONE_KEY), ("withCode", MODEL_GONE), ("olderDesktop", MODEL_NEEDS)):
        assert refused[case] == {"notes": [reason], "fetches": 0, "switching": None, "reread": True}, case
    assert refused["remote"] == [ONE_KEY]  # never the transport's "Error invoking remote method ... 409: {...}"


def test_the_move_asks_first_and_sends_only_the_paths(run):  # noqa: F811
    move = _providers(run)["move"]
    assert move["afterClick"] == {"asked": 1, "sent": 0, "notes": 0}  # a click writes nothing
    assert move["barDialog"] == {
        "kind": "confirm", "title": "Move 2 keys to .env?", "confirmLabel": "Move", "destructive": False,
        "body": "Takes each key out of config.yaml and saves it in this profile's .env. config.yaml then refers to each by name.",
        "target": "model.api_key -> CUSTOM_API_KEY, providers.spare.api_key -> SPARE_API_KEY"}
    assert move["twoMoved"]["sent"] == [["/providers/move", "POST", {"keys": ["model.api_key", "providers.spare.api_key"]}]]
    assert move["twoMoved"]["notes"] == [{"notify": "Moved 2 keys to .env: CUSTOM_API_KEY, SPARE_API_KEY.", "kind": "info"}]
    # A row's own button moves that key only.
    assert move["rowDialog"] == {
        "kind": "confirm", "title": "Move this key to .env?", "confirmLabel": "Move", "destructive": False,
        "body": "Takes the key out of config.yaml and saves it in this profile's .env. config.yaml then refers to it by name.",
        "target": "providers.spare.api_key -> SPARE_API_KEY"}
    assert move["oneMoved"]["sent"] == [["/providers/move", "POST", {"keys": ["providers.spare.api_key"]}]]
    assert move["oneMoved"]["notes"] == [{"notify": "Moved providers.spare.api_key to .env as SPARE_API_KEY.", "kind": "info"}]


def test_what_the_move_did_not_do_is_said_in_plain_words(run):  # noqa: F811
    move = _providers(run)["move"]
    assert move["partly"] == [{"kind": "warning", "notify": (
        "Moved model.api_key to .env as CUSTOM_API_KEY. Still in config.yaml: providers.spare.api_key.")}]
    assert move["refused"] == [{"notify": "Couldn't move model.api_key to .env: Permission denied"}]
    assert move["whileOn"] == [{"notify": "Turn the sandbox off for this profile first."}]
    # A backend without the route answers with the web server's two words: the page says what that means.
    assert move["noRoute"] == [{"notify": CANT_MOVE}] and move["noMethod"] == [{"notify": CANT_MOVE}]
    assert move["oddAnswer"] == []  # an answer that names nothing is not turned into a claim


def test_the_page_follows_each_answer_a_moved_key_frees_the_switch_and_an_expiry_comes_and_goes(run):  # noqa: F811
    live = _providers(run)["live"]
    assert live["beforeMove"]["switch"] == {"checked": False, "disabled": True, "tip": ONE_KEY, "label": "Can't turn on"}
    assert live["beforeMove"]["states"] == [["Key in config.yaml", "In config.yaml", 0], ["Nous Portal", "", 0]]
    assert live["afterMove"]["switch"] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}
    assert live["afterMove"]["bar"] is None and live["afterMove"]["states"] == [["Model", "Model", 0], ["Nous Portal", "", 0]]
    assert live["needsSignIn"]["switch"]["tip"] == MODEL_NEEDS and live["needsSignIn"]["bar"]["texts"][0] == MODEL_NEEDS
    assert live["signedIn"]["switch"]["disabled"] is False and live["signedIn"]["bar"] is None
    assert live["ready"] == live["renewed"] == {"bar": None, "states": [["Nous Portal", "Model", SIGNED_IN]]}
    assert live["expired"]["bar"]["texts"] == ["Nous Portal", "Sign-in expired", EXPIRED]
    assert live["expired"]["states"] == [["Nous Portal", "Model+Sign-in expired", EXPIRED]]


def test_the_page_puts_the_bar_above_the_tabs_and_the_rows_above_the_keys(run):  # noqa: F811
    page = _providers(run)["page"]
    order = page["off"]["order"]
    assert order.index("CompatBar") < order.index("ProvidersBar") < order.index("EndpointBar") < order.index("PageTabs")
    assert order.index("GrantsSection") < order.index("ProvidersSection") == order.index("KeysSection") - 1
    view = {"known": True, "on": False, "rows": ALL_IDS, "block": "key_in_config"}
    assert page["off"]["bar"] == page["off"]["section"] == page["off"]["header"] == page["off"]["card"] == [view]
    on = {"known": True, "on": True, "rows": ["key:OPENROUTER_API_KEY", "nous:agent_key"], "block": None}
    assert page["on"]["bar"] == page["on"]["section"] == page["on"]["header"] == [on]
    assert page["on"]["order"] == order and page["on"]["endpointBar"] == 1  # the withheld-key bar is where it was
    # While the launcher is gone its last rows are not shown as the state of anything.
    gone = page["launcherGone"]
    assert gone["bar"] == gone["section"] == gone["header"] == gone["card"] == ["none"]


def test_the_words(run):  # noqa: F811
    copy = _providers(run)["copy"]
    assert copy["providers"] == "Providers" and copy["noProviders"] == "No providers set up."
    assert copy["mainModel"] == "Model" and copy["mainModelTip"] == MODEL_TIP
    assert copy["providerState"] == {"needs_sign_in": "Sign in first", "expired": "Sign-in expired",
                                     "unavailable": "Not available", "withheld": "Key withheld",
                                     "key_in_config": "In config.yaml", "no_key": "No key"}
    assert copy["moveToEnv"] == "Move to .env" and copy["move"] == "Move"
    assert copy["moveTitle"] == ["Move this key to .env?", "Move 3 keys to .env?"]
    assert copy["moveUnavailable"] == CANT_MOVE
    # One word for it everywhere: no row, bar or caption says "placeholder".
    assert copy["credentials"]["placeholders"] == ("Values stay on this computer. A key the sandbox can use works only at "
                                                   "its own address.")
    assert "placeholder" not in str(run["providers"]).lower().replace("'placeholders':", "")
