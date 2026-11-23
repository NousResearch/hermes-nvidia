"""The provider rows as a person reads them (launcher/settings_view.py, provider_rows.py, pins.py).

One word for one thing: a key on an endpoint of the user's own is a "Custom endpoint" (its badge says whether the
model or a fallback model uses it), an address on this computer is said once, the row of a key in config.yaml
states the fact and leaves the instruction to the bar, and the switch's refusal does not say "not available in the
sandbox" twice. A model without a key does not hold the switch; its row and one line say what follows. Every key
here is made up.
"""
import pytest

pytest.importorskip("openshell.launcher.signins", reason="the sign-in report is not in this tree")

import page_provider_fixtures as fx  # noqa: E402
from page_provider_fixtures import INLINE_KEY, write_env  # noqa: E402
from signin_home import world  # noqa: E402,F401

from openshell.launcher import pins as P  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import standins  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

WORKS = "Works in the sandbox. The key stays on this computer and is used only at {}."
NO_KEY = "No key found: {} is not set in this profile's .env."
NO_KEY_MAIN = NO_KEY + " The model won't answer in the sandbox without it."
NOTE = "This profile's model has no key in .env ({}). It won't answer in the sandbox until one is set."
LOCAL = {"provider": "custom", "base_url": "http://127.0.0.1:8080/v1", "key_env": "LOCAL_MODEL_KEY", "default": "m"}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    fx.offline_catalog(monkeypatch)
    SV.forget_providers()
    yield
    SV.forget_providers()


def _layout(world):  # noqa: F811
    return ProfileLayout(name="work", home=world.home, root=world.root)


def _view(world):  # noqa: F811
    SV.forget_providers(_layout(world))
    return SV.provider_view(_layout(world))


def _by_id(view):
    return {row["id"]: row for row in view["providers"]}


def test_a_key_on_an_endpoint_of_the_users_own_is_not_titled_with_its_badges_word(world):  # noqa: F811
    world.config({"model": LOCAL})
    write_env(world.home, ["LOCAL_MODEL_KEY"])
    (row,) = _view(world)["providers"]
    assert row == {"id": "key:LOCAL_MODEL_KEY", "label": "Custom endpoint", "kind": "key", "state": "ready", "main": True,
                   "env": "LOCAL_MODEL_KEY", "detail": WORKS.format("localhost:8080")}
    assert row["detail"].count("this computer") == 1


def test_an_address_on_this_computer_is_named_like_any_other(world):  # noqa: F811
    assert SV._host_text("127.0.0.1", 47970) == "localhost:47970" and SV._host_text("LOCALHOST", None) == "localhost"
    assert SV._host_text("host.openshell.internal", 443) == "localhost:443" and SV._host_text("::1", 8080) == "localhost:8080"
    assert SV._host_text("openrouter.ai", 443) == "openrouter.ai" and SV._host_text("llm.example.com", 8443) == "llm.example.com:8443"
    rows = SV.page_rows([{"id": "key:A", "label": "Custom endpoint", "kind": "key", "state": "ready", "env": "A",
                          "hosts": [{"host": "api.x.ai", "port": 443}, {"host": "127.0.0.1", "port": 8080}]}])
    assert rows[0]["detail"] == WORKS.format("api.x.ai and localhost:8080")


def test_a_fallback_models_row_says_that_it_is_the_fallbacks(world):  # noqa: F811
    world.config({"model": LOCAL, "fallback_model": {"provider": "qwen-oauth", "model": "x"},
                  "fallback_providers": [{"provider": "openrouter", "model": "y"},
                                         {"provider": "custom", "base_url": "https://llm.example.com/v1",
                                          "key_env": "ANTHROPIC_API_KEY", "model": "z"}]})
    write_env(world.home, ["LOCAL_MODEL_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"])
    view = _view(world)
    rows = _by_id(view)
    assert view["providers_block"] is None  # a fallback model that cannot run in the sandbox does not hold the switch
    assert rows["key:LOCAL_MODEL_KEY"]["main"] is True and "fallback" not in rows["key:LOCAL_MODEL_KEY"]
    assert rows["sign_in:qwen-oauth"]["fallback"] is True and rows["sign_in:qwen-oauth"]["main"] is False
    assert rows["key:OPENROUTER_API_KEY"]["fallback"] is True and rows["key:OPENROUTER_API_KEY"]["label"] == "OpenRouter"
    assert rows["key:ANTHROPIC_API_KEY"]["fallback"] is True and rows["key:ANTHROPIC_API_KEY"]["main"] is False
    # The model and a fallback on one provider: both are said.
    world.config({"model": {"provider": "openrouter", "default": "m"}, "fallback_model": {"provider": "openrouter", "model": "n"}})
    row = _by_id(_view(world))["key:OPENROUTER_API_KEY"]
    assert row["main"] is True and row["fallback"] is True


def test_the_launchers_rows_carry_the_same_mark_and_nothing_else_new_reaches_the_page(world):  # noqa: F811
    rows = SV.page_rows([
        {"id": "sign_in:qwen-oauth", "label": "Qwen OAuth", "kind": "sign_in", "state": "unavailable",
         "reason": "outside_profile", "used_by": ["fallback 1"], "secret": "made-up-value-that-must-not-pass"},
        {"id": "key:A", "label": "Custom endpoint", "kind": "key", "state": "ready", "env": "A", "fallback": True},
        {"id": "key:B", "label": "OpenRouter", "kind": "key", "state": "ready", "env": "B", "fallback": "yes",
         "used_by": ["model", "auxiliary vision"]}])
    assert [(row["id"], row.get("fallback"), row["main"]) for row in rows] == [
        ("key:B", None, True), ("sign_in:qwen-oauth", True, False), ("key:A", True, False)]
    assert all(set(row) <= {"id", "label", "kind", "state", "detail", "main", "fallback", "env", "path"} for row in rows)
    # While on, a key's row names the model routes that use it, as a sign-in's does.
    world.config({"model": LOCAL, "fallback_model": {"provider": "custom", "base_url": "https://llm.example.com/v1",
                                                    "key_env": "SPARE_MODEL_KEY", "model": "z"}})
    write_env(world.home, ["LOCAL_MODEL_KEY"])
    with open(world.home / ".env", "a", encoding="utf-8") as fh:
        fh.write("SPARE_MODEL_KEY=made-up-spare-model-key-5b6c7d8e9f0a1b2c\n")
    layout = _layout(world)
    from openshell.launcher.openshell_driver import discover_routes

    secrets = P.secrets(layout)
    found = discover_routes(layout.home, secrets, {"models": P.model_entries(SV.read_config(layout)), "allowed": []})
    facts, _envs = SV.key_rows_of(found.routes, secrets, facts=True)
    used = {row["env"]: row["used_by"] for row in facts}
    assert used == {"LOCAL_MODEL_KEY": ["model"], "SPARE_MODEL_KEY": ["fallback"]}
    live = {row["id"]: row for row in R.live_rows(layout, [], facts, [], [])}
    assert live["key:LOCAL_MODEL_KEY"]["used_by"] == ["model"] and live["key:LOCAL_MODEL_KEY"]["main"] is True
    assert live["key:SPARE_MODEL_KEY"]["fallback"] is True and live["key:SPARE_MODEL_KEY"]["label"] == "Custom endpoint"
    assert "made-up-spare-model-key" not in str(live)


def test_a_main_model_without_a_key_does_not_hold_the_switch_and_one_line_says_what_follows(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "m"}, "fallback_model": {"provider": "deepseek", "model": "d"}})
    view = _view(world)
    rows = _by_id(view)
    assert view["providers_block"] is None and R.refusal(_layout(world)) is None
    assert rows["key:openrouter"]["state"] == "no_key" and rows["key:openrouter"]["main"] is True
    assert rows["key:openrouter"]["detail"] == NO_KEY_MAIN.format("OPENROUTER_API_KEY")
    # A fallback model without a key is named, in the plain sentence: the model itself still answers.
    assert rows["key:deepseek"]["detail"] == NO_KEY.format("DEEPSEEK_API_KEY") and rows["key:deepseek"]["fallback"] is True
    assert view["providers_note"] == {"code": "model_no_key", "reason": NOTE.format("OPENROUTER_API_KEY"), "rows": ["key:openrouter"]}
    assert len(view["providers_note"]["reason"]) <= 160  # the desktop's confirm takes one line of that length
    assert SV.switch_note(view["providers"]) == view["providers_note"]
    # With the key in place there is nothing to say, and the answer carries no such field.
    write_env(world.home, ["OPENROUTER_API_KEY"])
    assert "providers_note" not in _view(world)
    # What holds the switch is said instead of the note, never beside it.
    world.config({"model": {"provider": "openrouter", "default": "m"},
                  "providers": {"spare": {"base_url": "https://spare.example.com/v1", "api_key": INLINE_KEY}}})
    (world.home / ".env").unlink()
    held = _view(world)
    assert held["providers_block"]["code"] == "key_in_config" and "providers_note" not in held
    assert _by_id(held)["key:openrouter"]["state"] == "no_key"


def test_the_row_of_a_key_in_the_config_states_the_fact_and_the_bar_says_what_to_do(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "api_key": INLINE_KEY, "default": "m"}})
    view = _view(world)
    assert view["providers"][0]["detail"] == "Written in config.yaml, where the sandbox could read it."
    assert view["providers_block"]["reason"] == (
        "A key is written in config.yaml, where the sandbox could read it. Move it to .env first.")
    # While on, the row is all there is, so it still says what to do.
    (row,) = SV.page_rows([{"id": "config:model.api_key", "kind": "key", "state": "key_in_config", "path": "model.api_key"}])
    assert row["detail"] == "Written in config.yaml, where the sandbox can read it. Turn the sandbox off, then move it to .env."


def test_a_refusal_for_the_models_provider_says_why_once(world):  # noqa: F811
    world.config({"model": {"provider": "qwen-oauth", "default": "m"}})
    view = _view(world)
    (row,) = view["providers"]
    assert row["detail"] == "Not available in the sandbox: Qwen OAuth keeps its sign-in outside this profile."
    assert view["providers_block"] == {
        "code": "model_unavailable", "rows": ["sign_in:qwen-oauth"],
        "reason": "This profile's model uses Qwen OAuth, which isn't available in the sandbox.",
        "detail": "Qwen OAuth keeps its sign-in outside this profile."}
    refusal = R.refusal(_layout(world))
    assert refusal["detail"] == ("This profile's model uses Qwen OAuth, which isn't available in the sandbox. Qwen OAuth "
                                 "keeps its sign-in outside this profile.")
    assert refusal["detail"].lower().count("available in the sandbox") == 1
    # A provider Hermes has no entry for: said as that, whatever the reason it has none.
    world.config({"model": {"provider": "copilot", "default": "m"}})
    view = _view(world)
    assert view["providers"][0]["detail"] == 'Not available in the sandbox: Hermes doesn\'t know the provider "copilot".'
    assert view["providers_block"]["detail"] == 'Hermes doesn\'t know the provider "copilot".'
    # A row whose sentence gives no reason of its own adds nothing to the refusal.
    bare = [{"id": "sign_in:x", "label": "X", "kind": "sign_in", "state": "unavailable", "main": True,
             "detail": "Not available in the sandbox."}]
    assert SV.switch_block(bare)["detail"] == ""
    assert R.refusal(_layout(world), bare)["detail"] == "This profile's model uses X, which isn't available in the sandbox."
    # A sign-in that is needed first: the row's sentence says what to do, as before.
    world.config({"model": {"provider": "openai-codex", "default": "m"}})
    assert R.refusal(_layout(world))["detail"] == ("This profile's model uses OpenAI Codex, which needs a sign-in first. "
                                                   "Not signed in. Sign in to OpenAI Codex first.")


def test_the_stand_in_folder_goes_with_the_switch_off_once_the_sandbox_is_gone(world):  # noqa: F811
    world.config({"model": {"provider": "openrouter", "default": "m"}})
    write_env(world.home, ["OPENROUTER_API_KEY"])
    layout = _layout(world)

    def switched_on():
        P.take(layout)
        folder = standins.folder(layout)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / standins.TEMPLATE_FILE).write_text("{}", encoding="utf-8")
        return folder

    folder = switched_on()
    P.release(layout, unhold=False)  # a sandbox may still run and read its start-up step there
    assert folder.is_dir() and not P.present(layout)
    P.release(layout)  # nothing is pinned any more: the next switch-off or switch-on still clears it
    assert not folder.exists()
    folder = switched_on()
    P.release(layout)
    assert not folder.exists() and not P.present(layout)
