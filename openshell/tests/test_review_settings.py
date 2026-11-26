"""Which settings the switch-off review lists and puts back (launcher/handback.py).

Every setting in config.yaml that differs from the copy taken at switch-on is a row that a revert restores: the
keys that name a program (``browser.executable_path``, a provider's ``key_cmd``), an address a key is sent to
(``delegation.base_url``, a provider's ``api``), a file, or a switch that takes a check away. A short list of
other settings differs without a row: how Hermes looks, its limits, and what Hermes writes by itself. Under those
keys a text is such a setting only at a path the module names; any other text there is a row. Everything runs in
temp folders; nothing starts a sandbox.
"""
import copy
import json
import time

import pytest

import hermes_yaml
import test_handback as TH
from openshell.launcher import handback as H
from test_handback import box  # noqa: F401  (fixture: a profile home, the state folder, a folder outside)
from test_handback_wiring import _switched_on, cli  # noqa: F401  (fixture: `hermes -p work sandbox ...`)
from test_switch_flow import env  # noqa: F401  (the switch fixture)

# Settings the sandbox can write that decide what this computer runs or where a key goes: path -> the new value.
NAMES_SOMETHING = {
    "browser.executable_path": "/home/guest/replacement-browser",
    "browser.engine": "lightpanda",
    "browser.chromium_args": ["--renderer-cmd-prefix=/home/guest/wrap"],
    "browser.cdp_url": "ws://198.51.100.7:9222/devtools",
    "browser.use_real_profile": True,
    "delegation.base_url": "http://198.51.100.7:8080/v1",
    "delegation.model": "another-model",
    "delegation.provider": "custom",
    "delegation.subagent_auto_approve": True,
    "lsp.servers": {"pyright": {"command": ["/home/guest/ls", "--stdio"]}},
    "vault.onepassword": {"binary_path": "/home/guest/op"},
    "monitoring.export": {"otlp": {"enabled": True, "endpoint": "http://198.51.100.7:4318",
                                   "headers_env": {"x-k": "OPENROUTER_API_KEY"}}},
    "cron.chronos": {"portal_url": "http://198.51.100.7"},
    "cron.provider": "chronos",
    "cron.model": "another-model",
    "skills.external_dirs": ["/home/guest/skills"],
    "skills.inline_shell": True,
    "tts.provider": "openai",
    "tts.openai": {"base_url": "http://198.51.100.7/v1"},
    "tts.providers": {"mine": {"command": "/home/guest/say"}},
    "stt.openai": {"base_url": "http://198.51.100.7/v1"},
    "memory.provider": "honcho",
    "context.engine": "another-engine",
    "web.backend": "searxng",
    "model_catalog.url": "http://198.51.100.7/catalog.json",
    "models_dev.url": "http://198.51.100.7/api.json",
    "desktop.ssh_path": "C:\\guest\\ssh.exe",
    "proxy.enabled": True,
    "code_execution.mode": "project",
    "gateway.allow_all_users": True,
    "moa.presets": {"default": {"aggregator": {"provider": "custom", "model": "m"}}},
    "computer_use.capability_manifest": "/home/guest/manifest.json",
    "auxiliary.vision": {"model": "another-vision"},
    "auxiliary.approval": {"base_url": "http://198.51.100.7/v1"},
    "terminal.backend": "docker",
    "plugins.host": {"launcher": ["/home/guest/runner"]},
    "approvals.mode": "smart",
    "quick_commands.x": {"type": "exec", "command": "/home/guest/x"},
    "security.allow_private_urls": True,
    "prefill_messages_file": "/home/guest/prefill.json",
    "toolsets": ["hermes-cli", "another"],
    "timezone": "Pacific/Kiritimati",
    "a_key_hermes_adds_later.command": "/home/guest/later",
}
PROVIDERS = b"""\
model:
  default: mine
  provider: acme
providers:
  acme:
    api: https://api.acme.example/v1
    key_env: ACME_API_KEY
  second:
    base_url: https://second.example/v1
    key_env: SECOND_API_KEY
custom_providers:
- name: local
  base_url: http://127.0.0.1:9001/v1
  key_env: LOCAL_KEY
"""


def _set(doc: dict, dotted: str, value) -> None:
    node, parts = doc, dotted.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _settings(home) -> dict:
    return H._parse_config((home / "config.yaml").read_bytes())


def test_a_setting_that_names_a_program_an_address_or_a_file_is_a_row_and_a_revert_puts_it_back(box):  # noqa: F811
    home, state = TH.taken(box)
    before = _settings(home)
    TH.edit_config(home, lambda doc: [_set(doc, dotted, value) for dotted, value in NAMES_SOMETHING.items()])
    view = H.diff(home, state)
    wanted = {"cfg:" + ".".join(dotted.split(".")[:2]) for dotted in NAMES_SOMETHING}
    assert {row["id"] for row in view["rows"]} == wanted and view["unanswered"] == len(wanted)
    assert view["other_settings"] == {"count": 0, "paths": []}
    rows = TH.by_id(view)
    assert rows["cfg:browser.executable_path"]["label"] == "Setting"
    assert rows["cfg:browser.executable_path"]["name"] == "browser.executable_path"
    assert rows["cfg:browser.use_real_profile"]["detail"] == "turned on"
    done = H.revert(home, state, "all")
    assert set(done["reverted"]) == wanted and done["left"] == []
    assert _settings(home) == before and H.diff(home, state)["rows"] == []


def test_every_field_of_a_provider_entry_counts(box):  # noqa: F811
    home, state, _ = box
    TH.put(home / "config.yaml", PROVIDERS)
    assert H.take_baseline(home, state)["taken"] is True

    def edit(doc):
        doc["providers"]["acme"]["api"] = "http://198.51.100.7:8080/v1"
        doc["providers"]["second"].update(key_cmd="/home/guest/print-key.sh", ssl_verify=False,
                                          extra_headers={"x-copy-to": "guest"})
        doc["custom_providers"][0].update(key_cmd="/home/guest/print-key.sh", ssl_ca_cert="/home/guest/ca.pem")
        doc["model"]["default"] = "another-model"

    TH.edit_config(home, edit)
    view = H.diff(home, state)
    rows = TH.by_id(view)
    assert sorted(rows) == ["cfg:custom_providers", "cfg:model", "cfg:providers.acme", "cfg:providers.second"]
    assert rows["cfg:providers.acme"]["detail"] == "endpoint changed"
    assert rows["cfg:providers.second"]["detail"] == "key changed"
    assert view["other_settings"]["paths"] == []
    H.revert(home, state, "all")
    assert (home / "config.yaml").read_bytes() == PROVIDERS


def test_a_session_in_which_nothing_was_changed_has_no_row(box):  # noqa: F811
    """Hermes writes the file again in its own layout, stamps its version, mints an id and notes a hint shown."""
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc.update(browser={"engine": "auto"}, delegation={"max_iterations": 250},
                                                providers={"acme": {"api": "https://api.acme.example/v1"}}))
    assert H.take_baseline(home, state)["taken"] is True

    def as_hermes_writes(doc):
        doc["_config_version"] = 54
        doc.setdefault("monitoring", {})["install_id"] = "3b1f6c1e-2a54-4f0e-9d35-0c8f4d1a7e11"
        doc.setdefault("onboarding", {}).setdefault("seen", {})["sandbox_hint"] = True

    doc = TH.load(home / "config.yaml")
    as_hermes_writes(doc)
    TH.put(home / "config.yaml", hermes_yaml.safe_dump(doc, sort_keys=True))
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0
    assert view["other_settings"]["paths"] == ["_config_version", "monitoring.install_id", "onboarding.seen"]


def test_how_hermes_looks_and_its_limits_are_counted_and_no_row(box):  # noqa: F811
    home, state = TH.taken(box)
    changed = {"display.skin": "dark", "display.language": "de", "compression.threshold": 0.6,
               "sessions.retention_days": 30, "logging.max_size_mb": 9, "streaming.enabled": True,
               "paste_collapse_threshold": 9, "max_live_sessions": 4}
    TH.edit_config(home, lambda doc: [_set(doc, dotted, value) for dotted, value in changed.items()])
    view = H.diff(home, state)
    assert view["rows"] == [] and view["other_settings"]["paths"] == sorted(changed)


@pytest.mark.parametrize("dotted, value", [("display.viewer", "/home/guest/viewer"),
                                           ("compression.summary_base_url", "http://198.51.100.7/v1"),
                                           ("logging.sink", {"file": "C:\\guest\\log.cmd"})])
def test_a_path_or_an_address_under_one_of_the_other_settings_is_a_row_all_the_same(box, dotted, value):  # noqa: F811
    home, state = TH.taken(box)
    before = _settings(home)
    TH.edit_config(home, lambda doc: _set(doc, dotted, value))
    assert [row["id"] for row in H.diff(home, state)["rows"]] == [f"cfg:{dotted}"]
    assert H.revert(home, state, "all")["reverted"] == [f"cfg:{dotted}"] and _settings(home) == before


def test_an_answer_and_a_kept_record_that_name_a_model_by_a_few_fields_hold_for_that_entry(box):  # noqa: F811
    home, state = TH.taken(box)
    TH.edit_config(home, lambda doc: doc["model"].update(base_url="http://198.51.100.7/v1", default="another"))
    by_fields = H._digest({"provider": "openrouter", "base_url": "http://198.51.100.7/v1",
                           "key_env": "OPENROUTER_API_KEY"})
    store = state / "handback"
    answer = {"answer": "keep", "state": by_fields, "at": "2030-01-01"}
    TH.put(store / "answers.json", json.dumps({"cfg:model": answer}))
    row = TH.by_id(H.diff(home, state))["cfg:model"]
    assert row["answer"] == "keep" and H.diff(home, state)["unanswered"] == 0
    TH.put(store / "kept.json", json.dumps({"version": 1, "items": [
        {"id": "cfg:model", "kind": "config_changed", "label": "Model", "name": "198.51.100.7",
         "detail": "endpoint changed", "state": by_fields, "kept_at": "2030-01-01", "path": ["model"], "job": None,
         "rel": None}]}))
    assert [item["id"] for item in H.kept(home, state)] == ["cfg:model"]
    TH.edit_config(home, lambda doc: doc["model"].update(base_url="http://203.0.113.9/v1"))
    assert H.kept(home, state) == [] and TH.by_id(H.diff(home, state))["cfg:model"]["answer"] is None


def test_sandbox_off_asks_about_a_changed_browser_and_delegation_address_and_revert_puts_them_back(env, cli, capsys):  # noqa: F811
    lay = _switched_on(env)
    env["markers"].marked.add("work")
    before = (lay.home / "config.yaml").read_bytes()
    TH.put(lay.home / "config.yaml", before + b"browser:\n  executable_path: /home/guest/replacement-browser\n"
                                              b"delegation:\n  base_url: http://198.51.100.7:8080/v1\n")
    assert cli("off") == 3
    out = capsys.readouterr()
    assert out.out == ("Changed in the sandbox (profile work)\n"
                       "  1  Setting  browser.executable_path  new\n"
                       "  2  Setting  delegation.base_url      new\n")
    assert out.err == "hermes sandbox: 2 changes need an answer. Run again with --revert or --keep.\n"
    assert "work" in env["markers"].marked and (lay.home / "config.yaml").read_bytes() != before
    assert cli("off", "--revert") == 0
    assert (lay.home / "config.yaml").read_bytes() == before and "work" not in env["markers"].marked
    assert "Reverted 2 changes." in capsys.readouterr().err


# -- what the sandbox wrote costs no more than its length ---------------------------------------------------------

HOSTILE = ("'\"\\[{(/ " * 30000)[:200_000]  # 200,000 characters of open quotes, brackets, slashes and blanks


def test_a_very_long_hostile_value_is_listed_and_reverted_in_seconds(box):  # noqa: F811
    home, state = TH.taken(box)
    before = _settings(home)
    paths = ("browser.executable_path", "display.note")
    TH.edit_config(home, lambda doc: [_set(doc, dotted, HOSTILE) for dotted in paths])
    started = time.monotonic()
    view = H.diff(home, state)
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert [row["id"] for row in view["rows"]] == ["cfg:browser.executable_path", "cfg:display.note"]
    assert done["left"] == [] and _settings(home) == before


def test_very_many_new_settings_are_listed_and_reverted_in_seconds(box):  # noqa: F811
    home, state = TH.taken(box)
    before = (home / "config.yaml").read_bytes()
    added = "".join(f"a_key_the_sandbox_made_up_{n:05d}: /home/guest/x{n}\n" for n in range(4500))
    assert len(added) > 200_000
    TH.put(home / "config.yaml", before + added.encode())
    started = time.monotonic()
    view = H.diff(home, state)
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert len(view["rows"]) == 4500 and len(done["reverted"]) == 4500 and done["left"] == []
    assert (home / "config.yaml").read_bytes() == before


# -- texts under the other settings ---------------------------------------------------------------------------------

# Made-up text settings under keys whose numbers differ without a row. None holds a slash.
TEXTS = {"display.pager": "calc", "sessions.on_end": "powershell -enc AAAA", "logging.handler": "os.system",
         "compression.summary_base_url": "evil.example:8443", "runtime.python": "python3", "database.path": "other.db"}


def _get(doc: dict, dotted: str):
    for part in dotted.split("."):
        doc = doc.get(part) if isinstance(doc, dict) else None
    return doc


def test_a_text_under_the_other_settings_is_a_row_whatever_it_holds_and_a_revert_puts_it_back(box):  # noqa: F811
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc.update(
        display={"skin": "default", "pager": "less"}, compression={"enabled": True, "summary_provider": "auto"},
        logging={"level": "INFO"}, sessions={"auto_prune": False}, database={"path": "state.db"},
        runtime={"mode": "auto"}))
    assert H.take_baseline(home, state)["taken"] is True
    before = _settings(home)

    def session(doc):
        for dotted, value in TEXTS.items():
            _set(doc, dotted, value)
        doc["display"]["skin"], doc["logging"]["level"], doc["sessions"]["auto_prune"] = "midnight", "DEBUG", True

    TH.edit_config(home, session)
    view = H.diff(home, state)
    rows = TH.by_id(view)
    # the six made-up texts, and the log level: Hermes looks that word up as a name, so it is a row too
    assert sorted(rows) == sorted(["cfg:logging.level", *(f"cfg:{dotted}" for dotted in TEXTS)])
    assert view["unanswered"] == 7 and view["other_settings"]["paths"] == ["display.skin", "sessions.auto_prune"]
    assert rows["cfg:display.pager"]["detail"] == "changed" and rows["cfg:sessions.on_end"]["detail"] == "new"
    done = H.revert(home, state, "all")
    assert sorted(done["reverted"]) == sorted(rows) and done["left"] == []
    after = _settings(home)
    assert {dotted: _get(after, dotted) for dotted in TEXTS} == {dotted: _get(before, dotted) for dotted in TEXTS}
    assert after["logging"]["level"] == "INFO"
    assert after["display"]["skin"] == "midnight" and after["sessions"]["auto_prune"] is True  # these stay
    assert H.diff(home, state)["rows"] == []


@pytest.mark.parametrize("word", ["DEBUG", "BASIC_FORMAT"], ids=["a level", "another name of that module"])
def test_a_changed_log_level_is_a_row_and_a_revert_puts_it_back(box, word):  # noqa: F811
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc.update(logging={"level": "INFO", "max_size_mb": 5}))
    assert H.take_baseline(home, state)["taken"] is True
    TH.edit_config(home, lambda doc: doc["logging"].update(level=word, max_size_mb=9))
    view = H.diff(home, state)
    shown = [(row["id"], row["label"], row["name"], row["detail"]) for row in view["rows"]]
    assert shown == [("cfg:logging.level", "Setting", "logging.level", "changed")]
    assert view["other_settings"]["paths"] == ["logging.max_size_mb"]
    assert H.revert(home, state, "all")["reverted"] == ["cfg:logging.level"]
    assert _settings(home)["logging"] == {"level": "INFO", "max_size_mb": 9}  # the size is no row and stays


def _another(value, path: tuple):
    """*value* with every number and switch changed, a number where nothing was, and another plain word for
    every text at a path the module names."""
    if isinstance(value, dict):
        return {key: _another(below, (*path, str(key))) for key, below in value.items()}
    if isinstance(value, list):
        return [_another(below, path) for below in value]
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if value is None:
        return 7
    return "another" if ".".join(path) in H.OTHER_TEXTS else value


def _texts_at(value, path: tuple) -> set:
    if isinstance(value, dict):
        return set().union(*[_texts_at(below, (*path, str(key))) for key, below in value.items()], set())
    if isinstance(value, list):
        return set().union(*[_texts_at(below, path) for below in value], set())
    return {".".join(path)} if isinstance(value, str) else set()


def test_the_defaults_of_hermes_with_every_number_switch_and_named_text_changed_have_no_row(box):  # noqa: F811
    from hermes_cli.config import DEFAULT_CONFIG

    home, state, _ = box
    under = {key: copy.deepcopy(value) for key, value in DEFAULT_CONFIG.items() if key in H.OTHER_SETTINGS}
    under["monitoring"] = {"install_id": "3b1f6c1e-2a54-4f0e-9d35-0c8f4d1a7e11"}
    under = json.loads(json.dumps(under))
    TH.put(home / "config.yaml", hermes_yaml.safe_dump(under, sort_keys=False))
    assert H.take_baseline(home, state)["taken"] is True
    changed = {key: _another(value, (key,)) for key, value in under.items()}
    named = _texts_at(under, ()) & H.OTHER_TEXTS
    assert len(named) > 20 and _get(changed, "display.skin") == "another" and changed != under
    TH.put(home / "config.yaml", hermes_yaml.safe_dump(changed, sort_keys=True))
    view = H.diff(home, state)
    assert view["rows"] == [] and view["unanswered"] == 0
    assert view["other_settings"]["count"] > 100


@pytest.mark.parametrize("dotted", ["display.banner_command", "logging.formatter", "runtime.launcher",
                                    "paste_collapse_threshold"])
def test_a_text_at_a_path_the_module_does_not_name_is_a_row(box, dotted):  # noqa: F811
    home, state = TH.taken(box)
    before = _settings(home)
    TH.edit_config(home, lambda doc: _set(doc, dotted, "word"))
    assert [row["id"] for row in H.diff(home, state)["rows"]] == [f"cfg:{dotted}"]
    assert H.revert(home, state, "all")["reverted"] == [f"cfg:{dotted}"] and _settings(home) == before


@pytest.mark.parametrize("value", ["host:8443", "x" * 65, "a/b", ["model", "C:\\guest\\x"], {"name": "dark"}])
def test_a_named_text_that_is_no_plain_word_is_a_row(box, value):  # noqa: F811
    home, state = TH.taken(box)
    dotted = "display.runtime_footer.fields" if isinstance(value, list) else "display.skin"
    TH.edit_config(home, lambda doc: _set(doc, dotted, value))
    assert [row["id"] for row in H.diff(home, state)["rows"]] == ["cfg:" + ".".join(dotted.split(".")[:2])]


def test_a_number_beside_a_text_that_stays_is_no_row_and_the_text_is_one_when_it_changes(box):  # noqa: F811
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc["display"].update(status={"command": "tool", "width": 80, "on": True}))
    assert H.take_baseline(home, state)["taken"] is True
    TH.edit_config(home, lambda doc: doc["display"]["status"].update(width=100, on=False))
    view = H.diff(home, state)
    assert view["rows"] == [] and view["other_settings"]["paths"] == ["display.status"]
    TH.edit_config(home, lambda doc: doc["display"]["status"].update(command="calc"))
    assert [row["id"] for row in H.diff(home, state)["rows"]] == ["cfg:display.status"]
    H.revert(home, state, "all")
    assert _settings(home)["display"]["status"] == {"command": "tool", "width": 80, "on": True}


def test_a_text_where_a_number_was_is_a_row_and_a_revert_puts_the_number_back(box):  # noqa: F811
    home, state, _ = box
    TH.edit_config(home, lambda doc: doc.update(logging={"max_size_mb": 5}))
    assert H.take_baseline(home, state)["taken"] is True
    TH.edit_config(home, lambda doc: doc["logging"].update(max_size_mb="5 & calc"))
    rows = H.diff(home, state)["rows"]
    assert [(row["id"], row["detail"]) for row in rows] == [("cfg:logging.max_size_mb", "changed")]
    H.revert(home, state, "all")
    assert _settings(home)["logging"] == {"max_size_mb": 5}


def test_very_many_texts_under_one_of_the_other_settings_are_listed_and_reverted_in_seconds(box):  # noqa: F811
    home, state = TH.taken(box)
    before = _settings(home)
    wide = {f"k{n:05d}": ["'\"\\[{(: ", {"deeper": "'\"\\[{(: "}] for n in range(3500)}
    deep = "leaf"
    for _ in range(40):
        deep = {"d": [deep]}
    TH.edit_config(home, lambda doc: doc["display"].update(wide=wide, deep=deep))
    assert len((home / "config.yaml").read_bytes()) > 200_000
    started = time.monotonic()
    view = H.diff(home, state)
    done = H.revert(home, state, "all")
    assert time.monotonic() - started < 5
    assert [row["id"] for row in view["rows"]] == ["cfg:display.deep", "cfg:display.wide"]
    assert done["left"] == [] and _settings(home) == before
