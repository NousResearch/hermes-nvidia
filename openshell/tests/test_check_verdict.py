"""``hermes sandbox check`` does not contradict itself (launcher_cli.py).

``ok`` is about this computer: it can run the sandbox. ``ready`` is about this profile on this computer: the
switch would turn on now. A profile the switch refuses gets ``"ready": false`` beside the reason
(``switch_refused``), the reason on stderr, and exit status 2; exit status 1 stays what it was, a computer that
cannot run the sandbox. Every key here is made up.
"""
import json

import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

import hermes_yaml  # noqa: E402
import page_provider_fixtures as fx  # noqa: E402
from held_open import held_open  # noqa: E402

from openshell import launcher_cli as CLI  # noqa: E402
from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher import settings_view as SV  # noqa: E402
from openshell.launcher import switch as SW  # noqa: E402
from openshell.launcher.layout import ProfileLayout  # noqa: E402

KEY = "sk-made-up-" + "c" * 32
ONE_KEY = "A key is written in config.yaml, where the sandbox could read it. Move it to .env first."
HOST_OK = {"ok": True, "platform": "test", "code": "ok", "reason": None, "action": None}
NO_KEY = "This profile's model has no key in .env (OPENROUTER_API_KEY). It won't answer in the sandbox until one is set."


@pytest.fixture
def check(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    layout = ProfileLayout(name="work", home=home, root=root)
    world = {"host": dict(HOST_OK), "status": (None, "no sandbox running for profile 'work'"), "layout": layout}
    fx.offline_catalog(monkeypatch)
    monkeypatch.setattr(L, "current_profile", lambda: layout)
    monkeypatch.setattr(SW, "host_check", lambda layout, refresh=False: dict(world["host"]))
    monkeypatch.setattr(CLI, "_call_running", lambda method, route, body=None: world["status"])
    SV.forget_providers()

    def run(config=None, env=""):
        if config is not None:
            (home / "config.yaml").write_text(hermes_yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        (home / ".env").write_text(env, encoding="utf-8")
        code = CLI._cmd_check(None)
        out = capsys.readouterr()
        return code, json.loads(out.out), out.err

    run.world = world
    yield run
    SV.forget_providers()


def test_a_profile_that_would_switch_on_is_ok_and_ready(check):
    code, said, err = check({"model": {"provider": "openrouter", "default": "m"}}, f"OPENROUTER_API_KEY={KEY}\n")
    assert code == 0 and said["ok"] is True and said["ready"] is True and err == ""
    assert "switch_refused" not in said and "note" not in said
    assert [row["id"] for row in said["providers"]] == ["key:OPENROUTER_API_KEY"] and KEY not in json.dumps(said)


def test_a_refused_switch_is_not_ready_says_why_and_has_its_own_exit_status(check):
    code, said, err = check({"model": {"provider": "openrouter", "api_key": KEY, "default": "m"}})
    assert code == 2, "0 would say the switch works; 1 would say this computer cannot run the sandbox"
    assert said["ok"] is True and said["ready"] is False
    assert said["switch_refused"] == ONE_KEY + " Key: model.api_key."
    assert err == f"hermes sandbox: {said['switch_refused']}\n" and KEY not in json.dumps(said) + err


def test_a_computer_that_cannot_run_the_sandbox_is_neither_and_exits_1_as_before(check):
    check.world["host"] = {**HOST_OK, "ok": False, "code": "needs_update", "reason": "Windows needs an update."}
    code, said, err = check({"model": {"provider": "openrouter", "default": "m"}}, f"OPENROUTER_API_KEY={KEY}\n")
    assert code == 1 and said["ok"] is False and said["ready"] is False and "switch_refused" not in said
    # Both at once: the computer's verdict decides the exit status, the profile's reason is still said.
    code, said, err = check({"model": {"provider": "openrouter", "api_key": KEY, "default": "m"}})
    assert code == 1 and said["ok"] is False and said["ready"] is False and said["switch_refused"].startswith(ONE_KEY)


def test_a_config_that_cannot_be_read_is_not_ready(check):
    home = check.world["layout"].home
    (home / "config.yaml").write_text("model:\n  provider: openrouter\n", encoding="utf-8")
    with held_open(home / "config.yaml"):
        code, said, err = check(None, f"OPENROUTER_API_KEY={KEY}\n")
    sentence = "Can't read this profile's config.yaml. Another program may have it open."
    assert code == 2 and said["ok"] is True and said["ready"] is False and said["switch_refused"] == sentence
    assert "providers_error" not in said and err == f"hermes sandbox: {sentence}\n"


def test_a_main_model_without_a_key_is_ready_with_one_line_about_it(check):
    code, said, err = check({"model": {"provider": "openrouter", "default": "m"}})
    assert code == 0 and said["ok"] is True and said["ready"] is True and "switch_refused" not in said
    assert said["note"] == NO_KEY and err == f"hermes sandbox: {NO_KEY}\n"
    (row,) = said["providers"]
    assert row["state"] == "no_key" and row["main"] is True and row["detail"] == (
        "No key found: OPENROUTER_API_KEY is not set in this profile's .env. The model won't answer in the sandbox "
        "without it.")


def test_a_switch_on_hands_the_line_on_and_the_terminal_says_it(check, monkeypatch, capsys):
    from test_switch_flow import FakeDriver, FakeMarkers, FakeRuntime, FakeService

    layout = check.world["layout"]
    (layout.home / "config.yaml").write_text("model:\n  provider: openrouter\n  default: m\n", encoding="utf-8")
    assert SW.refuse_unready(layout) == NO_KEY
    (layout.home / ".env").write_text(f"OPENROUTER_API_KEY={KEY}\n", encoding="utf-8")
    assert SW.refuse_unready(layout) is None
    (layout.home / ".env").write_text("", encoding="utf-8")
    log = []
    monkeypatch.setattr(SW, "marker_api", lambda: FakeMarkers(log))
    monkeypatch.setattr(SW, "launcher_call", lambda port, token, method, route, body=None, timeout=5.0: (
        200, {"state": "running", "ticket": "undo"}))
    turn_on = SW.turn_on
    monkeypatch.setattr(SW, "turn_on", lambda layout, handback_answer=None: turn_on(
        layout, runtime=FakeRuntime(layout.root / "py.exe", layout.root), manager=lambda defn: FakeService(defn, log),
        environ={}, make_driver=lambda spec: FakeDriver(), sleep=lambda s: None, handback_answer=handback_answer))
    monkeypatch.setattr(CLI, "_check_profile_name", lambda layout: None)
    capsys.readouterr()
    assert CLI._cmd_on(type("Args", (), {"handback_answer": None, "move_keys": False})()) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["state"] == "running" and out.err == f"hermes sandbox: {NO_KEY}\n"


def test_while_the_sandbox_is_on_the_launchers_rows_are_shown_and_the_profile_is_ready(check):
    rows = [{"id": "sign_in:nous", "label": "Nous Portal", "kind": "sign_in", "state": "expired", "main": True,
             "detail": "Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on."}]
    check.world["status"] = ({"state": "running", "providers": rows}, None)
    code, said, err = check({"model": {"provider": "openrouter", "api_key": KEY, "default": "m"}})
    assert code == 0 and said["ok"] is True and said["ready"] is True and said["providers"] == rows
    assert "switch_refused" not in said and err == ""
