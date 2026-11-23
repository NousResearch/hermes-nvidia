"""The provider rows of a profile for the switch, the terminal commands and the launcher's status: which of its
providers work in the sandbox, and why one does not.

One row per provider, in one shape on both sides of the switch::

    {"id", "label", "kind": "key" | "sign_in", "state", "detail", "main"}

plus ``env`` (a key's variable) and ``path`` (where a key is written in ``config.yaml``) when known. ``state`` is
``ready`` (works in the sandbox), ``needs_sign_in`` (sign in on this computer with the sandbox off), ``expired``
(the sign-in could not be renewed), ``unavailable`` (cannot work in a sandbox; ``detail`` says why), ``withheld``
(the model's address was changed inside the sandbox, so the key stays on this computer), ``key_in_config`` (a key
written in ``config.yaml``) or, before the switch only, ``no_key``. ``main`` marks the provider of the profile's
model.

The rows and their sentences have one source, ``settings_view.py``, which also serves the Sandbox page:

* With the sandbox off (``host_rows``) the rows are the ones the page shows before the switch.
* While it is on (``live_rows``) the launcher makes them from what it holds: the sign-ins as their schedule
  stands, the keys as they were handed in at the sandbox's start. These also carry what the page words them
  from: ``reason`` (a sign-in's, as the sign-in engine names it), ``hosts`` (where a key is used) and ``used_by``
  (the model routes that name the provider).

``refusal`` is why the switch does not turn on, in the words the page uses for the same thing: a key in
``config.yaml``, a main model whose provider is not available in the sandbox or needs a sign-in first, or a file
the rows are read from that cannot be read (which is never taken for an empty one). Fallback and auxiliary
models in that state are only shown, and so is a main model without a key (``settings_view.switch_note``).
"""
from __future__ import annotations

import logging
from typing import Iterable, Optional

from . import config_keys, settings_view

log = logging.getLogger("openshell.provider_rows")

READY, NEEDS_SIGN_IN, EXPIRED = settings_view.READY, settings_view.NEEDS_SIGN_IN, settings_view.EXPIRED
UNAVAILABLE, WITHHELD, KEY_IN_CONFIG = settings_view.UNAVAILABLE, settings_view.WITHHELD, settings_view.KEY_IN_CONFIG

# The sign-in engine's states (signins.py) as the states of a row.
_SIGN_IN_STATES = {"works": READY, "retrying": READY, "lapsed": EXPIRED, "needs_sign_in": NEEDS_SIGN_IN,
                   "not_available": UNAVAILABLE}
_FACTS = ("reason", "hosts", "used_by", "uses")  # what a launcher's row carries beside what the page shows


def host_rows(layout) -> list[dict]:
    """The rows with the sandbox off, read from the profile's home now: the rows of the Sandbox page."""
    return settings_view.host_rows(layout)


def refusal(layout, rows: Optional[list] = None, *, seen: Optional[list] = None) -> Optional[dict]:
    """Why the switch does not turn on for this profile, or None: ``{"code", "detail", "keys"}``.

    ``unreadable``: the profile's ``config.yaml``, an env file or a sign-in file is there and cannot be read;
    ``detail`` is the sentence that names it. ``key_in_config``: keys are written in ``config.yaml`` (``keys``
    lists them, as ``inline_keys`` gives them, and ``detail`` names their places). ``model_unavailable`` and
    ``model_needs_sign_in``: the main model's provider cannot work in the sandbox, or needs a sign-in first;
    ``detail`` ends with why (the provider's own reason, or that row's sentence). The first sentence of
    ``detail`` is the one the page shows for the same thing. *seen* receives the rows that were read."""
    try:
        keys = config_keys.inline_keys(settings_view.read_config(layout))
        if keys:
            reason = settings_view._BLOCKS["key_in_config" if len(keys) == 1 else "keys_in_config"]
            return {"code": "key_in_config", "keys": keys,
                    "detail": f"{reason} {'Key' if len(keys) == 1 else 'Keys'}: {config_keys.describe(keys)}."}
        rows = host_rows(layout) if rows is None else rows
    except settings_view.Unreadable as exc:
        return {"code": "unreadable", "keys": [], "detail": str(exc)}
    if seen is not None:
        seen.extend(rows)
    block = settings_view.switch_block(rows)
    if block is None or block["code"] == "key_in_config":
        return None
    row = next(row for row in rows if row.get("id") in block["rows"])
    why = block["detail"] if "detail" in block else row.get("detail") or ""
    return {"code": block["code"], "keys": [], "detail": f"{block['reason']} {why}".strip()}


def sign_in_facts(row: dict, used_by: Iterable[str] = ()) -> dict:
    """A row of the sign-in engine (``SignIns.status``, ``signins.report``) as the facts of a provider row."""
    state = _SIGN_IN_STATES.get(str(row.get("state")), UNAVAILABLE)
    reason = str(row.get("reason") or "") or {"retrying": "retrying", "lapsed": "lapsed"}.get(str(row.get("state")), "")
    if row.get("state") == "needs_sign_in" and reason == "expired":
        state = EXPIRED
    used = list(row.get("used_by") or used_by or [])
    facts = {"id": f"sign_in:{row.get('provider')}", "label": str(row.get("label") or row.get("provider") or ""),
             "kind": "sign_in", "state": state, "reason": reason, "used_by": used, "main": "model" in used}
    if isinstance(row.get("hosts"), list):
        facts["hosts"] = row["hosts"]  # every address the sign-in is used at, each with what it is for
    return facts


def live_rows(layout, sign_ins: Optional[list], keys: Optional[list] = None, changed: Optional[list] = None,
              routes: Optional[list] = None) -> list[dict]:
    """The rows while the sandbox is on. *sign_ins*: the sign-in engine's rows as its schedule stands
    (``SignIns.status``). *keys*: the key rows of this sandbox's start (``settings_view.key_rows_of`` with
    facts). *changed*: the keys withheld because the model's address was changed inside. *routes*: the sign-in
    report made at the start (``signins.report`` over the launcher's copy), which says what each model route
    uses and names the providers that cannot work in a sandbox.

    Every row is worded by ``settings_view.page_rows``, as the page words it, and keeps its facts beside the
    sentence."""
    routes = [row for row in routes or [] if isinstance(row, dict)]
    used = {str(row.get("provider")): list(row.get("used_by") or []) for row in routes}
    facts = [{"id": f"config:{item['path']}", "label": item["path"], "kind": "key", "state": KEY_IN_CONFIG,
              "path": item["path"], "env": item["env"]}
             for item in settings_view.inline_keys_now(layout)]
    listed = set()
    for row in sign_ins or []:
        listed.add(str(row.get("provider")))
        facts.append(sign_in_facts(row, used.get(str(row.get("provider")), ())))
    for row in routes:
        # A provider a model route names that the engine holds no sign-in for: one that cannot work in a
        # sandbox, or one that was never signed in to. A provider that uses a key has its key's row.
        if row.get("state") in ("not_available", "needs_sign_in") and str(row.get("provider")) not in listed:
            listed.add(str(row.get("provider")))
            facts.append(sign_in_facts(row))
    main_keys = {env for row in routes if row.get("state") == "key" and "model" in (row.get("used_by") or [])
                 for env in settings_view._registered_envs(str(row.get("provider") or ""))}
    held = {str(item.get("env")) for item in changed or [] if isinstance(item, dict)}
    for row in keys or []:
        if row.get("env") not in held:  # a withheld key has its row below
            facts.append({**row, "main": bool(row.get("main")) or row.get("env") in main_keys})
    for item in changed or []:
        if isinstance(item, dict) and item.get("env"):
            facts.append({"id": f"key:{item['env']}", "label": str(item["env"]), "kind": "key", "state": WITHHELD,
                          "env": str(item["env"])})
    worded = {row["id"]: row for row in settings_view.page_rows(facts)}
    out = [{**worded[fact["id"]], **{name: fact[name] for name in _FACTS if name in fact}}
           for fact in facts if fact["id"] in worded]
    return settings_view._ordered(out)
