"""The pinned files while the sandbox is on (launcher/pins.py, launcher/host_routes.py).

* The env files are put back from the pin before every sandbox start and before the launcher lists or reveals a
  key, not only at switch-off: a ``.env`` the sandbox replaced or a ``.op.env`` it created never reaches the next
  sandbox start, and is never what the Keys list shows.
* What the launcher lists and reveals is the pinned ``.env``. It does not depend on what Hermes reads from the
  home: the same answers with a Hermes that reads the home's file and with one that reads no env file from a
  home that runs elsewhere (both stand-ins below). A key the user writes still lands in the home's ``.env`` and
  the pin follows it.
* The sign-in store (``auth.json``) is pinned too. One made while the sandbox is on goes to the quarantine
  folder. One that changed is put back where the sandbox can replace it (Windows); where it cannot (Linux) a
  host process wrote it and the pin follows. The launcher's own writes are always followed.
"""
import asyncio
import json
import os
import stat
from types import SimpleNamespace

import pytest

import test_settings_routes as SR
from openshell.launcher import handback as H
from openshell.launcher import host_routes as HR
from openshell.launcher import pins as P
from openshell.launcher import supervisor as S
from test_pins import ENV, KEY, OTHER, _write, layout  # noqa: F401  (a layout with a model entry and two keys)

AUTHED = SimpleNamespace(authenticated=True)
SIGNED_IN = '{"providers": {"nous": {"obtained_at": 1}}}'
PLANTED_STORE = '{"credential_pool": {"openrouter": [{"label": "planted-by-sandbox"}]}}'
KEYS, ENV_ROUTE, REVEAL = "/api/plugins/openshell/keys", "/api/env", "/api/env/reveal"


def _send(routes, method, path, body):
    return asyncio.run(routes.match(method, path)(AUTHED, json.dumps(body).encode()))


def _file(path):
    return [ln.split("=", 1) for ln in path.read_text(encoding="utf-8").splitlines() if "=" in ln] if path.exists() else []


@pytest.fixture(params=["reads the home", "reads nothing from a home that runs elsewhere"])
def core(request, layout, tmp_path, monkeypatch):  # noqa: F811
    """The launcher's key routes over two stand-ins for Hermes: one whose ``load_env`` and env rows read the home's
    ``.env`` (today's, and the Hermes that only skips the load at import), and one that answers nothing for a home
    a plugin runs elsewhere. Writes go to the home's file in both, and to ``auth.json`` when *touch_store* is set."""
    import hermes_cli.config as hermes_config
    from hermes_cli.web_routers import config_env

    reads = request.param == "reads the home"
    state = {"touch_store": None}

    def load_env():
        return dict(_file(layout.home / ".env")) if reads else {}

    async def get_env_vars(profile):
        on_disk = load_env()
        rows = {"MODEL_API_KEY": {"is_set": bool(on_disk.get("MODEL_API_KEY")), "redacted_value": None,
                                  "description": "The model's key", "custom": False}}
        rows.update({name: {"is_set": True, "redacted_value": None, "category": "custom", "custom": True}
                     for name in on_disk if name not in rows})
        return rows

    async def set_env_var(model, profile):
        path = layout.home / ".env"
        lines = [f"{k}={v}" for k, v in _file(path) if k != model.key]
        _write(path, "\n".join([*lines, f"{model.key}={model.value}"]) + "\n")
        if state["touch_store"]:
            _write(layout.home / "auth.json", state["touch_store"])
        return {"ok": True, "key": model.key}

    monkeypatch.setattr(hermes_config, "load_env", load_env)
    monkeypatch.setattr(config_env, "get_env_vars", get_env_vars)
    monkeypatch.setattr(config_env, "set_env_var", set_env_var)
    P.take(layout)
    sup = SR._supervisor(tmp_path, layout)
    return SimpleNamespace(routes=HR.HostRoutes(sup, lambda: None), reads=reads, state=state)


def _signed_in(layout):  # noqa: F811
    """Switched on with the user signed in: the sign-in store is there and pinned."""
    P.remove(layout)
    _write(layout.home / "auth.json", SIGNED_IN)
    return P.take(layout)


def _quarantined(layout, name):  # noqa: F811
    return [p.read_bytes() for p in sorted((layout.state_dir / "quarantine").glob(f"*/{name}*"))]


# -- before every sandbox start ---------------------------------------------------------------------------------

def test_a_sandbox_start_first_puts_back_env_files_the_sandbox_replaced_or_created(layout, monkeypatch):  # noqa: F811
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    P.take(layout)
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\nPLANTED=1\n")  # Windows: replaced by rename
    _write(layout.home / ".op.env", "PLANTED=by-the-sandbox\n")  # created: it was absent at switch-on
    assert S._profile_secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}
    assert (layout.home / ".env").read_bytes() == ENV.encode() and not (layout.home / ".op.env").exists()
    assert _quarantined(layout, ".env") == [b"MODEL_API_KEY=replaced-inside\nPLANTED=1\n"]
    assert _quarantined(layout, ".op.env") == [b"PLANTED=by-the-sandbox\n"]
    assert P.present(layout)  # a restart restores; it never releases or re-takes the pin


def test_a_users_own_op_env_is_still_there_at_a_sandbox_start(layout):  # noqa: F811
    _write(layout.home / ".op.env", "OP_SERVICE_ACCOUNT_TOKEN=ops-token\n")
    P.take(layout)
    S._profile_secrets(layout)
    assert (layout.home / ".op.env").read_bytes() == b"OP_SERVICE_ACCOUNT_TOKEN=ops-token\n"
    assert not (layout.state_dir / "quarantine").exists()


# -- the Keys list and the reveal read the pin -----------------------------------------------------------------

def test_the_keys_list_is_the_pinned_file_whatever_the_home_holds_and_whatever_hermes_reads(layout, core):  # noqa: F811
    _write(layout.home / ".env", "PLANTED=by-the-sandbox\n")
    status, payload, _ = _send(core.routes, "GET", KEYS, {})
    assert status == 200 and [row["name"] for row in payload["keys"]] == ["MODEL_API_KEY", "OTHER_API_KEY"]
    assert (layout.home / ".env").read_bytes() == ENV.encode()  # and the home's file is the user's again
    assert _quarantined(layout, ".env") == [b"PLANTED=by-the-sandbox\n"]


def test_the_env_rows_take_what_is_set_from_the_pin(layout, core, monkeypatch):  # noqa: F811
    # Even when the home's file could not be put back (held open by another program), nothing in it is shown.
    monkeypatch.setattr(P, "restore_env", lambda lay: [])
    _write(layout.home / ".env", "PLANTED=by-the-sandbox\n")
    status, rows, _ = _send(core.routes, "GET", ENV_ROUTE, {})
    assert status == 200 and sorted(rows) == ["MODEL_API_KEY", "OTHER_API_KEY"]
    assert rows["MODEL_API_KEY"]["is_set"] is True and rows["MODEL_API_KEY"]["description"] == "The model's key"
    assert rows["MODEL_API_KEY"]["redacted_value"] and KEY not in str(rows)  # a preview, never the value
    assert rows["OTHER_API_KEY"]["is_set"] is True and rows["OTHER_API_KEY"]["custom"] is True


def test_a_key_the_pinned_file_does_not_hold_is_not_set(layout, core):  # noqa: F811
    _write(layout.home / ".env", f"OTHER_API_KEY={OTHER}\n")  # the user never had it otherwise; re-pin without it
    P.update_env(layout)
    _write(layout.home / ".env", ENV)  # put there from inside
    rows = _send(core.routes, "GET", ENV_ROUTE, {})[1]
    assert rows["MODEL_API_KEY"]["is_set"] is False and rows["MODEL_API_KEY"]["redacted_value"] is None


def test_reveal_answers_from_the_pin_and_never_a_value_the_sandbox_planted(layout, core):  # noqa: F811
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\nPLANTED=by-the-sandbox\n")
    assert _send(core.routes, "POST", REVEAL, {"key": "PLANTED"})[0] == 404
    _write(layout.home / ".env", "MODEL_API_KEY=replaced-inside\n")
    status, payload, _ = _send(core.routes, "POST", REVEAL, {"key": "MODEL_API_KEY"})
    assert status == 200 and payload == {"key": "MODEL_API_KEY", "value": KEY}
    assert (layout.home / ".env").read_bytes() == ENV.encode()  # the reveal also put the user's file back


def test_a_key_the_user_saves_lands_in_the_homes_file_and_the_pin_follows(layout, core):  # noqa: F811
    _write(layout.home / ".env", "PLANTED=by-the-sandbox\n")
    status, payload, _ = _send(core.routes, "PUT", KEYS, {"key": "NEW_API_KEY", "value": "sk-new"})
    assert status == 200 and payload == {"ok": True, "sandbox_restart_required": True, "sandbox": "after_restart"}
    home = (layout.home / ".env").read_bytes()
    assert home == (ENV + "NEW_API_KEY=sk-new\n").encode() and (P.pin_dir(layout) / ".env").read_bytes() == home
    assert [row["name"] for row in _send(core.routes, "GET", KEYS, {})[1]["keys"]] == [
        "MODEL_API_KEY", "NEW_API_KEY", "OTHER_API_KEY"]
    assert _send(core.routes, "POST", REVEAL, {"key": "NEW_API_KEY"})[1]["value"] == "sk-new"
    assert P.secrets(layout)["NEW_API_KEY"] == "sk-new"  # and it is what the next sandbox start registers


def test_without_a_pin_the_list_and_the_reveal_are_hermes_own_as_before(layout, core):  # noqa: F811
    P.remove(layout)  # a sandbox switched on by a version without pins
    assert HR._pinned_rows({"X": {"is_set": True}}, P.env_values(layout)) == {"X": {"is_set": True}}
    status, payload, _ = _send(core.routes, "POST", REVEAL, {"key": "MODEL_API_KEY"})
    assert (status, payload.get("value")) == ((200, KEY) if core.reads else (404, None))


# -- the sign-in store -----------------------------------------------------------------------------------------

def test_take_keeps_a_copy_of_the_sign_in_store(layout):  # noqa: F811
    _write(layout.home / "auth.json", SIGNED_IN)
    doc = P.take(layout)
    copy = P.pin_dir(layout) / "auth.json"
    assert copy.read_bytes() == SIGNED_IN.encode() and doc["stores"]["auth.json"]["sha256"]
    if os.name != "nt":
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
    P.remove(layout)
    (layout.home / "auth.json").unlink()
    assert P.take(layout)["stores"] == {"auth.json": None, ".anthropic_oauth.json": None}  # absent is recorded as absent


@pytest.mark.parametrize("replaceable", [True, False])
def test_a_store_made_while_the_sandbox_is_on_is_taken_out_before_the_next_start_and_at_switch_off(layout, replaceable, monkeypatch):  # noqa: F811
    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: replaceable)
    P.take(layout)  # no auth.json at switch-on
    _write(layout.home / "auth.json", PLANTED_STORE)  # Windows: by rename; Linux: created, it was absent
    S._profile_secrets(layout)
    assert not (layout.home / "auth.json").exists() and _quarantined(layout, "auth.json") == [PLANTED_STORE.encode()]
    _write(layout.home / "auth.json", PLANTED_STORE)
    assert P.release(layout) == ["auth.json"]
    assert not (layout.home / "auth.json").exists() and not P.pin_dir(layout).exists()


def test_a_replaced_store_is_put_back_where_the_sandbox_can_replace_it(layout):  # noqa: F811
    _write(layout.home / "auth.json", SIGNED_IN)
    P.take(layout)
    _write(layout.home / "auth.json", PLANTED_STORE)
    assert P.restore_stores(layout, replaceable=True) == ["auth.json"]
    assert (layout.home / "auth.json").read_bytes() == SIGNED_IN.encode()  # the user stays signed in
    assert _quarantined(layout, "auth.json") == [PLANTED_STORE.encode()] and P.present(layout)
    (layout.home / "auth.json").unlink()  # removed from inside
    assert P.restore_stores(layout, replaceable=True) == ["auth.json"]
    assert (layout.home / "auth.json").read_bytes() == SIGNED_IN.encode()


def test_where_the_sandbox_cannot_write_it_a_changed_store_is_a_host_write_and_the_pin_follows(layout):  # noqa: F811
    refreshed = '{"providers": {"nous": {"obtained_at": 2}}}'
    _write(layout.home / "auth.json", SIGNED_IN)
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)
    _write(layout.home / "auth.json", refreshed)  # a token refresh by a `hermes` command on the host
    assert [row["id"] for row in H.diff(layout.home, layout.state_dir)["rows"]] == ["env:auth.json"]
    assert P.restore_stores(layout, replaceable=False) == []
    assert (layout.home / "auth.json").read_bytes() == refreshed.encode() == (P.pin_dir(layout) / "auth.json").read_bytes()
    assert P.load(layout)["stores"]["auth.json"] == P._file_state(layout.home / "auth.json")  # recorded, not only copied
    assert not (layout.state_dir / "quarantine").exists()
    assert H.diff(layout.home, layout.state_dir)["rows"] == []  # nor does the switch-off take it out as the sandbox's
    assert P.release(layout) == [] and (layout.home / "auth.json").read_bytes() == refreshed.encode()


def test_the_default_follows_the_operating_system():
    assert P.stores_replaceable_inside() is (os.name == "nt")
    assert P.stores_replaceable_inside(windows=True) is True and P.stores_replaceable_inside(windows=False) is False


def test_the_launchers_own_write_of_the_store_is_followed_never_undone(layout, core, monkeypatch):  # noqa: F811
    """Hermes's key handlers also rewrite auth.json (the pool entries of a key that was saved or removed)."""
    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: True)  # the strict case
    _signed_in(layout)
    H.take_baseline(layout.home, layout.state_dir)
    after = '{"providers": {"nous": {"obtained_at": 1}}, "credential_pool": {}}'
    core.state["touch_store"] = after
    assert _send(core.routes, "PUT", KEYS, {"key": "NEW_API_KEY", "value": "sk-new"})[0] == 200
    assert (P.pin_dir(layout) / "auth.json").read_bytes() == after.encode()
    assert P.restore_stores(layout) == [] and (layout.home / "auth.json").read_bytes() == after.encode()
    assert H.diff(layout.home, layout.state_dir)["rows"] == []  # the user's own write: no row at switch-off
    assert not (layout.state_dir / "quarantine").exists()


def test_a_write_first_puts_back_a_store_the_sandbox_replaced(layout, core, monkeypatch):  # noqa: F811
    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: True)
    _signed_in(layout)
    _write(layout.home / "auth.json", PLANTED_STORE)
    assert _send(core.routes, "PUT", KEYS, {"key": "NEW_API_KEY", "value": "sk-new"})[0] == 200
    assert (layout.home / "auth.json").read_bytes() == SIGNED_IN.encode() == (P.pin_dir(layout) / "auth.json").read_bytes()
    assert _quarantined(layout, "auth.json") == [PLANTED_STORE.encode()]


def test_a_pin_taken_before_stores_were_kept_leaves_the_store_alone(layout):  # noqa: F811
    _write(layout.home / "auth.json", SIGNED_IN)
    doc = P.take(layout)
    doc.pop("stores")
    P._save(layout, doc)  # as a version before this one wrote it
    _write(layout.home / "auth.json", PLANTED_STORE)
    assert P.restore_stores(layout, replaceable=True) == [] and P.update_stores(layout) == []
    assert P.release(layout) == [] and (layout.home / "auth.json").read_bytes() == PLANTED_STORE.encode()


def test_switch_off_puts_a_replaced_store_back_and_leaves_no_row_for_it(layout, monkeypatch):  # noqa: F811
    from openshell.launcher import switch as SW

    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: True)
    _write(layout.home / "auth.json", SIGNED_IN)
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)
    _write(layout.home / "auth.json", PLANTED_STORE)
    view = SW.review(layout)
    assert [row["id"] for row in view["rows"]] == ["env:auth.json"] and view["unanswered"] == 0  # asks nothing
    done = SW.hand_back(layout, view, None)
    assert done["blocked"] is None and done["result"]["reverted"] == []  # the pin put it back before the revert looked
    assert (layout.home / "auth.json").read_bytes() == SIGNED_IN.encode()  # nobody is signed out
    assert _quarantined(layout, "auth.json") == [PLANTED_STORE.encode()]


# -- the list of what changed ------------------------------------------------------------------------------------

REFRESHED = '{"providers": {"nous": {"obtained_at": 2}}}'


def _on_with_a_record(layout, monkeypatch, replaceable, signed_in=True):  # noqa: F811
    from openshell.launcher import switch as SW

    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: replaceable)
    if signed_in:
        _write(layout.home / "auth.json", SIGNED_IN)
    P.take(layout)
    H.take_baseline(layout.home, layout.state_dir)
    return SW


def test_the_list_has_no_row_for_a_store_a_host_process_wrote(layout, monkeypatch):  # noqa: F811
    """Where the sandbox cannot write a store that exists, the next sandbox start and the switch-off follow it.
    A row for it under the files that are always put back would say something no switch-off does."""
    SW = _on_with_a_record(layout, monkeypatch, replaceable=False)
    _write(layout.home / "auth.json", REFRESHED)  # a token refresh by a `hermes` command on the host
    view = SW.review(layout)
    assert view["open"] and view["rows"] == [] and view.get("error") is None
    assert (layout.home / "auth.json").read_bytes() == REFRESHED.encode() == (P.pin_dir(layout) / "auth.json").read_bytes()
    assert not (layout.state_dir / "quarantine").exists()


@pytest.mark.parametrize("replaceable, signed_in, planted_over", [(False, False, None), (True, True, SIGNED_IN)])
def test_making_the_list_moves_nothing(layout, monkeypatch, replaceable, signed_in, planted_over):  # noqa: F811
    """A store the sandbox made (both OSes) or may have replaced (Windows) stays where it is and stays a row; it
    is taken out before the next sandbox start and at the switch-off, as before."""
    SW = _on_with_a_record(layout, monkeypatch, replaceable, signed_in)
    pin_before = P.load(layout)
    _write(layout.home / "auth.json", PLANTED_STORE)
    view = SW.review(layout)
    assert [row["id"] for row in view["rows"]] == ["env:auth.json"] and view["unanswered"] == 0
    assert (layout.home / "auth.json").read_bytes() == PLANTED_STORE.encode()
    assert P.load(layout) == pin_before and not (layout.state_dir / "quarantine").exists()
    if planted_over:
        assert (P.pin_dir(layout) / "auth.json").read_bytes() == planted_over.encode()
    assert P.restore_stores(layout) == ["auth.json"]  # the next sandbox start
    assert _quarantined(layout, "auth.json") == [PLANTED_STORE.encode()]


def test_a_store_that_cannot_be_followed_does_not_stop_the_list(layout, monkeypatch):  # noqa: F811
    SW = _on_with_a_record(layout, monkeypatch, replaceable=False)
    _write(layout.home / "auth.json", REFRESHED)
    calls = []

    def fails(layout_, **kw):
        calls.append(kw)
        raise OSError("the pin folder cannot be written")

    monkeypatch.setattr(P, "restore_stores", fails)
    view = SW.review(layout)
    assert calls == [{"follow_only": True}]
    assert [row["id"] for row in view["rows"]] == ["env:auth.json"] and view.get("error") is None  # listed as before


# -- a pin that is still there -----------------------------------------------------------------------------------

def test_taking_a_pin_over_one_that_is_still_there_first_puts_its_files_back(layout, monkeypatch):  # noqa: F811
    """The earlier session ended without a switch-off: what the home holds now may be that sandbox's."""
    monkeypatch.setattr(P, "stores_replaceable_inside", lambda windows=None: True)
    _write(layout.home / "auth.json", SIGNED_IN)
    P.take(layout)
    _write(layout.home / ".env", "PLANTED=by-the-sandbox\n")
    _write(layout.home / "auth.json", PLANTED_STORE)
    doc = P.take(layout)
    assert (P.pin_dir(layout) / ".env").read_bytes() == ENV.encode() == (layout.home / ".env").read_bytes()
    assert (P.pin_dir(layout) / "auth.json").read_bytes() == SIGNED_IN.encode() and doc["stores"]["auth.json"]
    assert P.secrets(layout) == {"MODEL_API_KEY": KEY, "OTHER_API_KEY": OTHER}
