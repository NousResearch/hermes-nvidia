"""What reads text the sandbox can write is quick whatever the text holds (launcher/config_keys.py,
launcher/layout.py): ``config.yaml``, a copy of it, and the names of the files in the profile folder. Each case
is 200,000 characters made to be slow to read, and each gets its answer within seconds. Every key is made up."""
import pytest

pytest.importorskip("hermes_yaml", reason="Hermes's own YAML reader is not importable here")

from test_folder_spellings import HOSTILE, _within  # noqa: E402
from test_keys_anywhere_in_config import KEY, _layout  # noqa: E402

from openshell.launcher import config_keys as K  # noqa: E402
from openshell.launcher import layout as L  # noqa: E402
from openshell.launcher import provider_rows as R  # noqa: E402

# Text without a secret in it, each made for one of the shapes a secret is known by: many places where a match
# could begin, and long runs after a beginning that never end in one.
TEXTS = {
    "scheme-dots": "a." * 100_000,
    "scheme-starts": "a://" * 50_000,
    "url-colons": "x://" + "a:" * 100_000,
    "web-token-starts": "eyJ-" * 50_000,
    "web-token-run": "eyJ" + "a" * 20 + ".eyJ" + "a" * 200_000,
    "bearer-words": "bearer " * 28_572,
    "bearer-run": "bearer " + "a" * 200_000,
    "bearer-spaces": "bearer" + " " * 200_000 + "x",
    "authorization-spaces": "authorization" + " " * 200_000,
    "authorization-words": "authorization: basic " * 9_524,
    "flag-run": " -" + "a-" * 100_000,
    "flag-words": " --token" * 25_000,
    "flag-digits": " --token " + "1" * 200_000 + " ",
    "assignment-run": "A_" * 100_000,
    "assignment-words": ("TOKEN" * 8 + ";") * 4_900,
    "query": "?key=&" * 33_334,
    "webhook-digits": "https://discord.com/api/webhooks/" + "1" * 200_000,
    "vendor": "sk-!" * 50_000,
    "references": "${" * 100_000,
    "quotes": "'\"" * 100_000,
    "brackets": "([{" * 66_667,
}


def _config(text: str) -> dict:
    return {"hooks": {"on_x": [{"command": text}]}, "tts": {"openai": {"api_key": KEY}}}


@pytest.mark.parametrize("name", sorted(TEXTS))
def test_a_long_value_made_to_be_slow_is_named_and_the_key_beside_it_is_found(name):
    text = TEXTS[name]
    assert len(text) >= HOSTILE
    rows = _within(5, lambda: K.inline_keys(_config(text)))
    assert [(row["path"], bool(row.get("unread"))) for row in rows] == [
        ("hooks.on_x.0.command", True), ("tts.openai.api_key", False)]


@pytest.mark.parametrize("name", sorted(TEXTS))
def test_every_shape_is_searched_in_time_that_grows_with_the_text(name, monkeypatch):
    """With no limit on how much of a value is searched, the same text is read to its end, as quickly."""
    monkeypatch.setattr(K, "_SCAN_CHARS", 10 * HOSTILE)
    rows = _within(5, lambda: K.inline_keys(_config(TEXTS[name])))
    assert [row["path"] for row in rows] == ["tts.openai.api_key"]
    after = _within(5, lambda: K.inline_keys(_config(TEXTS[name] + " Authorization: Bearer " + KEY)))
    assert [row["path"] for row in after] == ["hooks.on_x.0.command", "tts.openai.api_key"]


def test_a_document_without_end_keeps_the_switch_off_and_the_key_in_it_is_found():
    deep = inner = []
    for _ in range(HOSTILE):
        inner.append([])
        inner = inner[0]
    again = {}
    again["again"], again["twice"] = again, [again, again]
    wide = {f"name{n}": "plain" for n in range(HOSTILE)}
    for hostile in (deep, again, wide):
        rows = _within(5, lambda: K.inline_keys({"tts": {"openai": {"api_key": KEY}}, "plugins": {"mine": hostile}}))
        assert rows[0]["path"] == "tts.openai.api_key" and len(rows) == 2
        assert rows[1]["unread"] is True and rows[1]["path"].startswith("plugins.mine")
        assert len(_within(5, lambda: K.describe(rows))) < 1000
    names = {f"name{n}": {"api_key": KEY} for n in range(HOSTILE // 10)}
    sentence = _within(5, lambda: K.describe(K.inline_keys({"web": names})))
    assert sentence.startswith("web.name0.api_key (move it by hand: ") and sentence.endswith(" more")
    assert len(sentence) < 3000 and KEY not in sentence


COPIES = {
    "brackets": "[" * HOSTILE,
    "braces": "{a: " * (HOSTILE // 4),
    "dashes": "- " * (HOSTILE // 2) + "x",
    "question-marks": "? " * (HOSTILE // 2),
    "indents": "".join(" " * n + "a:\n" for n in range(630)),
    "open-quote": "a: '" + "x" * HOSTILE,
    "aliases": "a: &a [*a, *a]\n" + "b: *a\n" * (HOSTILE // 6),
    "zero-bytes": "\x00" * HOSTILE,
}


@pytest.mark.parametrize("name", sorted(COPIES))
def test_a_copy_of_the_config_made_to_be_slow_keeps_the_switch_off(tmp_path, name):
    text = COPIES[name]
    layout = _layout(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1"}})
    (layout.home / "config.yaml.bak").write_bytes(text.encode("utf-8"))
    refusal = _within(5, lambda: R.refusal(layout))
    assert refusal["code"] == "key_in_config_copy" and refusal["detail"].startswith("config.yaml.bak in the profile")


def test_many_and_large_copies_of_the_config_cost_no_more_than_a_few(tmp_path):
    layout = _layout(tmp_path, {"model": {"provider": "custom", "base_url": "http://127.0.0.1:9/v1"}})
    plain = "\n".join(f"name{n}: plain" for n in range(HOSTILE // 14)).encode("utf-8")
    for n in range(40):
        (layout.home / f"config.yaml.{n:02d}").write_bytes(plain)
    found = _within(5, lambda: K.keys_in_copies(layout.home))
    # the first copy is read and holds no key; no later one fits in what is read in all, so each is named
    assert [item["file"] for item in found] == [f"config.yaml.{n:02d}" for n in range(1, 40)]
    assert all(item["unread"] for item in found)
    detail = _within(5, lambda: R.refusal(layout))["detail"]
    assert detail.startswith("config.yaml.01, config.yaml.02, ")
    assert " and 27 more in the profile folder are copies" in detail


NAMES = {
    "dots-after": ".env" + "." * HOSTILE,
    "temp-unfinished": ".env_" + "a" * HOSTILE + ".tm",
    "temp-repeated": ".keys-" + ".tmp" * (HOSTILE // 4) + "x",
    "hashes": "#" * HOSTILE,
    "dots-before": "." * HOSTILE + ".env.swp",
    "store-repeated": "auth.json" * (HOSTILE // 9),
    "gateway-repeated": "gateway-connection" * (HOSTILE // 18),
    "env-repeated": ".env" * (HOSTILE // 4),
}


@pytest.mark.parametrize("case", sorted(NAMES))
def test_a_file_name_of_any_length_is_judged_at_once(case):
    name = NAMES[case]
    assert _within(5, lambda: L.is_private_name(name)) is name.startswith((".env.", ".env_"))
    assert _within(5, lambda: L._write_under_way(L.Path("gone") / name)) in (True, False)


# A value under a key-like name is judged by what it looks like. Each of these is made to make that slow.
KEY_LIKE_VALUES = {
    "short-runs": ("a1-" * (HOSTILE // 3 + 1), False),
    "one-run-of-letters": ("a" * HOSTILE, False),
    "one-run-of-digits": ("1" * HOSTILE, False),
    "one-mixed-run": ("a1" * (HOSTILE // 2), True),
    "runs-one-short": ("a1b2c3d4e5f-" * (HOSTILE // 12 + 1), False),
    "pem-starts": ("-----BEGIN " * (HOSTILE // 11 + 1), False),
    "pem-long-label": ("-----BEGIN " + "A" * HOSTILE, False),
    "dashes": ("-" * HOSTILE, False),
    "spaces-at-the-end": ("a1" * (HOSTILE // 2 - 1) + "  ", True),
    "a-path": ("/" + "a1" * (HOSTILE // 2), False),
}


@pytest.mark.parametrize("name", sorted(KEY_LIKE_VALUES))
def test_a_long_value_under_a_key_like_name_is_judged_at_once(name, monkeypatch):
    """A value that looks like a credential in what is searched is a key; any other long value is named as too
    much to check. With no limit on what is searched, the whole value gets its answer as quickly."""
    value, credential = KEY_LIKE_VALUES[name]
    assert len(value) >= HOSTILE
    rows = _within(5, lambda: K.inline_keys({"cache": {"key": value, "sort_key": "name"}}))
    assert [(row["path"], bool(row.get("unread"))) for row in rows] == [("cache.key", not credential)]
    monkeypatch.setattr(K, "_SCAN_CHARS", 10 * HOSTILE)
    rows = _within(5, lambda: K.inline_keys({"cache": {"key": value, "sort_key": "name"}}))
    assert [row["path"] for row in rows] == (["cache.key"] if credential else [])
