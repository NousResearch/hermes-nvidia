"""What a look at the Sandbox page found (desktop/plugin.js, run in Node through tests/js/switch_harness.mjs).

A switch that cannot be turned on does not look like a plain Off switch: it is disabled, which is the desktop's
own dimmed look, its tip says why, and the word beside it says that it will not turn on. A file that cannot be
read holds it like anything else and the rows stay. The bar for an expired sign-in carries the row's own badge.
For one key in config.yaml the bar's button is the only one. A fallback model's row says so, and a model without a key is said in the
desktop's confirm.
"""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

CANT_READ = "Can't read this profile's config.yaml. Another program may have it open."
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."
TWO_KEYS = "Keys are written in config.yaml, where the sandbox could read them. Move them to .env first."
MODEL_GONE = "This profile's model uses Qwen OAuth, which isn't available in the sandbox."
WHY_GONE = "Qwen OAuth keeps its sign-in outside this profile."
EXPIRED = "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."
LAPSED = "The xAI sign-in wasn't renewed in time. The model answers again once it is."
NO_KEY = "This profile's model has no key in .env (OPENROUTER_API_KEY). It won't answer in the sandbox until one is set."
PURPOSE = "Runs this profile in a sandbox that limits the files and websites it can reach."
EXPIRED_BADGE = {"text": "Sign-in expired", "variant": "destructive"}
MOVE = {"text": "Move to .env", "disabled": False}


def _held(run):  # noqa: F811
    held = run["held"]
    assert "error" not in held, held.get("error")
    return held


def test_a_switch_that_cannot_be_turned_on_says_so_beside_it(run):  # noqa: F811
    switch = _held(run)["switch"]
    assert switch["copy"] == "Can't turn on"
    for case, reason in (("key", ONE_KEY), ("model", MODEL_GONE), ("unread", CANT_READ), ("unreadNoRows", CANT_READ),
                         ("host", "Needs Docker."), ("olderDesktop", "Needs a newer version of the desktop app.")):
        assert switch[case] == {"checked": False, "disabled": True, "tip": reason, "label": "Can't turn on"}, case
    # Free, or only waiting for an answer the card's own buttons give: the plain word for its state.
    assert switch["fine"] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}
    assert switch["noKey"] == {"checked": False, "disabled": False, "tip": None, "label": "Off"}
    assert switch["review"] == {"checked": False, "disabled": True, "tip": "Changes need an answer first.", "label": "Off"}
    assert switch["whileOn"] == {"checked": True, "disabled": False, "tip": None, "label": "On"}


def test_a_file_that_cannot_be_read_keeps_the_rows_and_is_never_shown_as_no_providers(run):  # noqa: F811
    section = _held(run)["section"]
    assert [row["title"] for row in section["unreadKept"]["rows"]] == ["OpenRouter"]
    assert CANT_READ not in section["unreadKept"]["texts"]  # the bar says it; the rows are the last ones read
    assert section["unreadNothing"]["rows"] == [] and CANT_READ in section["unreadNothing"]["texts"]
    assert "No providers set up." not in section["unreadNothing"]["texts"]
    assert "No providers set up." in section["empty"]
    bar = _held(run)["bar"]
    assert bar["unread"] == {"role": "status", "texts": [CANT_READ], "badges": [], "buttons": []}


def test_a_click_on_a_held_switch_says_the_reason_and_starts_nothing(run):  # noqa: F811
    clicks = _held(run)["clicks"]
    assert clicks["unread"] == [{"notify": CANT_READ}]
    assert clicks["modelGone"] == [{"notify": MODEL_GONE}]
    assert clicks["routeRefused"] == [{"notify": CANT_READ}]  # the host route's refusal, not "422: {...}"


def test_one_button_moves_the_keys_and_the_bar_says_where_each_goes(run):  # noqa: F811
    held = _held(run)
    bar, section = held["bar"], held["section"]
    assert bar["oneKey"] == {"role": "status", "badges": [], "buttons": [MOVE],
                             "texts": [ONE_KEY, "model.api_key moves to .env as MODEL_API_KEY", "Move to .env"]}
    assert bar["twoKeys"]["texts"] == [TWO_KEYS, "model.api_key moves to .env as MODEL_API_KEY",
                                       "providers.spare.api_key moves to .env as SPARE_API_KEY", "Move to .env"]
    assert bar["pending"]["buttons"] == [{**MOVE, "disabled": True}]  # another edit is on its way
    # One key: the bar's button is the one, and the row has none. Several: each row also moves its own key.
    rows = section["inline"]["rows"]
    assert [(row["title"], row["buttons"]) for row in rows] == [("Key in config.yaml", []), ("OpenRouter", [])]
    assert rows[0]["note"] == "Written in config.yaml, where the sandbox could read it."
    assert [row["buttons"] for row in section["inlineTwo"]["rows"]] == [["Move to .env"], ["Move to .env"], []]
    # Rows last read from a config that cannot be read now offer no move: it would change nothing.
    assert [row["buttons"] for row in section["inlineUnread"]["rows"]] == [[], [], []]
    assert held["dialog"] == [{
        "kind": "confirm", "title": "Move 2 keys to .env?", "confirmLabel": "Move",
        "body": "Takes each key out of config.yaml and saves it in this profile's .env. config.yaml then refers to each by name.",
        "target": "model.api_key -> MODEL_API_KEY, providers.spare.api_key -> SPARE_API_KEY"}]
    assert held["copy"]["moveBody"][0] == (
        "Takes the key out of config.yaml and saves it in this profile's .env. config.yaml then refers to it by name.")
    assert all("copy" not in body for body in held["copy"]["moveBody"])  # no copy of the files is kept any more


def test_the_bar_for_the_models_provider_says_why_once(run):  # noqa: F811
    bar = _held(run)["bar"]
    assert bar["modelGone"] == {"role": "status", "texts": [MODEL_GONE, WHY_GONE], "badges": [], "buttons": []}
    assert " ".join(bar["modelGone"]["texts"]).lower().count("available in the sandbox") == 1
    assert bar["modelGoneOlder"]["texts"] == [
        MODEL_GONE, "Not available in the sandbox: Qwen OAuth keeps its sign-in outside this profile."]


def test_the_bar_for_an_expired_sign_in_carries_the_rows_badge(run):  # noqa: F811
    bar = _held(run)["bar"]
    assert bar["expired"] == {"role": "status", "buttons": [], "badges": [EXPIRED_BADGE],
                              "texts": ["Nous Portal", "Sign-in expired", EXPIRED]}
    assert bar["expiredTwo"]["badges"] == [EXPIRED_BADGE, EXPIRED_BADGE]
    assert bar["expiredTwo"]["texts"] == ["Nous Portal", "Sign-in expired", EXPIRED, "xAI", "Sign-in expired", LAPSED]


def test_a_fallback_models_row_has_its_own_badge(run):  # noqa: F811
    section = _held(run)["section"]
    assert section["copy"] == {"fallback": "Fallback", "tip": "This profile's fallback model uses this provider."}
    model, fallback = {"text": "Model", "variant": "muted"}, {"text": "Fallback", "variant": "muted"}
    rows = {row["title"]: row for row in section["fallback"]["rows"]}
    assert rows["OpenRouter"]["badges"] == [model]
    assert rows["Qwen OAuth"]["badges"] == [fallback, {"text": "Not available", "variant": "muted"}]
    assert rows["Qwen OAuth"]["tips"] == ["This profile's fallback model uses this provider."]
    assert rows["Anthropic"]["badges"] == [model, fallback]
    assert {row["title"]: row["badges"] for row in section["fallbackOn"]["rows"]}["Qwen OAuth"][0] == fallback


def test_a_model_without_a_key_is_said_in_the_confirm_and_holds_nothing(run):  # noqa: F811
    held = _held(run)
    confirm = held["confirm"]
    assert confirm["view"] == {"block": None, "note": {"code": "model_no_key", "reason": NO_KEY, "rows": ["key:openrouter"]}}
    assert confirm["noNote"] is None and confirm["onIgnoresTheNote"] is None and confirm["purpose"] == PURPOSE
    assert confirm["noKey"] == [NO_KEY] and confirm["fromTheSwitch"] == [NO_KEY] and confirm["fromTheCard"] == [NO_KEY]
    assert confirm["plain"] == [PURPOSE] and confirm["tooLong"] == [PURPOSE]
    assert confirm["olderDesktop"] == [NO_KEY]  # a desktop that asks after the start gets the same line
    assert held["bar"]["noKey"] is None  # no bar: nothing is held
    (row,) = held["section"]["noKey"]["rows"]
    assert row["badges"] == [{"text": "Model", "variant": "muted"}, {"text": "No key", "variant": "muted"}]
    assert row["note"].endswith("The model won't answer in the sandbox without it.")
