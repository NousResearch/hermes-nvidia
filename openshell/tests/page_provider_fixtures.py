"""Stand-ins for the provider rows' tests: a module that finds and moves keys written in config.yaml, made-up
keys, and the strings of a profile that must never reach the page.

The module the page's data view asks for such keys (``launcher/config_keys.py``: ``inline_keys``,
``move_to_env``) is put in place for one test, whether or not the plugin tree has one of its own.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

# Made-up values. A row, a refusal or a log line that shows one fails a test.
KEYS = {
    "OPENROUTER_API_KEY": "made-up-openrouter-key-0f1e2d3c4b5a6978",
    "ANTHROPIC_API_KEY": "made-up-anthropic-key-8796a5b4c3d2e1f0",
    "TAVILY_API_KEY": "made-up-tavily-key-1a2b3c4d5e6f7089",
    "LOCAL_MODEL_KEY": "made-up-local-server-key-7c1f0b9e5d3a48f2",
}
INLINE_KEY = "made-up-inline-key-9a8b7c6d5e4f3021"
INLINE_KEY_2 = "made-up-second-inline-key-4d3c2b1a0f9e8d7c"
PACKAGES = ("openshell.launcher", "hermes_openshell_settings.launcher")


def offline_catalog(monkeypatch) -> None:
    """The driver's key discovery asks Hermes how a provider's requests are shaped, and Hermes then looks at its
    public model catalog, which it downloads when it has none. A test has none and reaches for nothing: the
    download fails here as it does on a computer without a network, and Hermes goes on without the catalog."""
    import pytest

    models_dev = pytest.importorskip("agent.models_dev")

    def offline(*args, **kwargs):
        raise OSError("no network in a test")

    monkeypatch.setattr(models_dev, "_fetch_models_dev_from_network", offline)


def write_env(home: Path, names) -> None:
    (Path(home) / ".env").write_text("".join(f"{name}={KEYS[name]}\n" for name in names), encoding="utf-8")


def _inline(config: dict) -> list[dict]:
    """Keys written in a config document, with the variable each would move to (a stand-in's naming)."""
    out = []
    model = config.get("model")
    if isinstance(model, dict) and model.get("api_key"):
        out.append({"path": "model.api_key", "env": "MODEL_API_KEY"})
    saved = config.get("providers")
    for name, entry in saved.items() if isinstance(saved, dict) else ():
        if isinstance(entry, dict) and entry.get("api_key"):
            out.append({"path": f"providers.{name}.api_key", "env": f"{str(name).upper()}_API_KEY"})
    return out


class ConfigKeys:
    """A ``config_keys`` module for one test. ``moves`` records each call; ``fail`` raises from the move;
    ``skip`` names paths the move leaves where they are."""

    def __init__(self):
        self.moves: list = []
        self.listed = 0
        self.fail: Exception | None = None
        self.skip: set = set()

    def inline_keys(self, config):
        self.listed += 1
        return _inline(config if isinstance(config, dict) else {})

    def move_to_env(self, home, items):
        import hermes_yaml

        self.moves.append((str(home), [dict(item) for item in items]))
        if self.fail is not None:
            raise self.fail
        path = Path(home) / "config.yaml"
        config = hermes_yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        lines, moved = [], []
        for item in items:
            if item["path"] in self.skip:
                continue
            node = config
            *parents, last = item["path"].split(".")
            for part in parents:
                node = node[part]
            lines.append(f"{item['env']}={node.pop(last)}\n")
            if parents[0] == "model":
                node["key_env"] = item["env"]
            moved.append(item["path"])
        path.write_text(hermes_yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        with open(Path(home) / ".env", "a", encoding="utf-8") as env:
            env.writelines(lines)
        return moved


def install(monkeypatch, keys=None) -> ConfigKeys:
    """Put a ``config_keys`` stand-in where the data view looks for the module."""
    keys = keys or ConfigKeys()
    for package in PACKAGES:
        module = types.ModuleType(f"{package}.config_keys")
        module.inline_keys = keys.inline_keys
        module.move_to_env = keys.move_to_env
        monkeypatch.setitem(sys.modules, f"{package}.config_keys", module)
    return keys


def remove(monkeypatch) -> None:
    """A plugin tree without the module: importing it fails."""
    for package in PACKAGES:
        monkeypatch.setitem(sys.modules, f"{package}.config_keys", None)


def store_strings(home: Path) -> set:
    """Every string a sign-in file of *home* holds that could be a token or a grant: all of them of twelve
    characters and more, whatever key they are under (an address and a provider's name are not one)."""
    from hermes_cli.auth import PROVIDER_REGISTRY

    found: set = set()

    def collect(node) -> None:
        if isinstance(node, dict):
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)
        elif isinstance(node, str) and len(node) >= 12 and not node.startswith(("http://", "https://")) \
                and node not in PROVIDER_REGISTRY:
            found.add(node)

    for name in ("auth.json", ".anthropic_oauth.json"):
        try:
            collect(json.loads((Path(home) / name).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return found


def secrets_of(home: Path) -> set:
    """The strings of a test profile no page may show: its keys, the keys written in its config, and what its
    sign-in files hold."""
    return {*KEYS.values(), INLINE_KEY, INLINE_KEY_2, *store_strings(home)}


def shown(payload) -> str:
    """A payload as the page receives it."""
    return json.dumps(payload, sort_keys=True)
