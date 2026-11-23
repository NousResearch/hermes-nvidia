"""The sign-in files between switch-on and switch-off (launcher/pins.py).

While the sandbox is on, the launcher's copy of a sign-in file is the only real one: the launcher renews the
sign-in there, the file in the home goes stale, and a stand-in the sandbox writes may stand under its name. The
switch-off puts the copy back, so the user is still signed in. These tests stop between every two steps, as a
launcher that is killed would, and check that the newest grant is never lost. Run against issuers that end a
sign-in when a spent refresh token is presented.
"""
import json

import pytest

pytest.importorskip("openshell.launcher.credential_sink", reason="the driver's credential sink is not in this tree")

import signin_home  # noqa: E402
from signin_home import world  # noqa: E402,F401
from test_signins_handback import on, renew  # noqa: E402,F401

from openshell.inside import standin  # noqa: E402
from openshell.launcher import handback, pins, standins  # noqa: E402


class Killed(BaseException):
    """The launcher's process ends here: nothing after this line runs."""


@pytest.fixture(params=["windows", "linux"])
def rule(request, monkeypatch):
    """Both rules for a store that differs in the home: the sandbox may have replaced it (Windows), or only a
    program on this computer can have (Linux)."""
    monkeypatch.setattr(pins, "stores_replaceable_inside", lambda windows=None: request.param == "windows")
    return request.param


def still_signed_in(world, provider):
    """Hermes on this computer, in the profile's own home, renews with what the home holds."""
    if provider == "nous":  # Hermes's shared Nous store is a second way back: not the one under test
        (world.root / "shared-store" / "nous_auth.json").unlink(missing_ok=True)
    assert world.issuers.valid(provider, world.renew_in_home(provider))
    assert world.issuers.refreshes(provider)[-1]["presented"] == "current" and not world.issuers.ended(provider)


def stand_in_bytes(engine) -> bytes:
    """What the start-up step writes under ``auth.json`` inside the sandbox for the engine's sign-ins."""
    template, names, _left = standins.build(engine)
    assert "auth.json" in names
    environ = {entry["env"]: f"{standin.PLACEHOLDER_PREFIX}v1_{entry['env']}" for entry in template["credentials"].values()}
    files, _exports = standin.fill(template, environ)
    return json.dumps(files["auth.json"], indent=2).encode("utf-8")


def quarantined(layout, name="auth.json"):
    return list((layout.state_dir / "quarantine").rglob(name))


# -- the switch-off ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("provider", ["nous", "openai-codex", "anthropic"])
def test_the_switch_off_keeps_the_user_signed_in_after_a_renewal_nothing_recorded(world, on, rule, provider):
    layout, engine, _cred = on(provider)
    renew(world, engine)
    engine.close()
    pins.release(layout)
    assert not world.copy.exists()
    still_signed_in(world, provider)


def test_a_stand_in_under_the_name_is_thrown_away_and_the_copy_comes_back(world, on, rule):
    layout, engine, _cred = on("nous")
    assert pins.vacate(layout, ["auth.json"]) == ["auth.json"]
    assert not (world.home / "auth.json").exists(), "the file that was pinned is still under the name"
    assert pins.load(layout)["standin"] == ["auth.json"] and pins.standin_names(layout) == ["auth.json"]
    renew(world, engine)
    engine.close()
    fake = stand_in_bytes(engine)
    (world.home / "auth.json").write_bytes(fake)
    live = signin_home.refresh_token_in(world.copy, "nous")
    # Before a sandbox start and before a host route's write: nothing of the user's goes under the name.
    assert pins.restore_stores(layout) == [] and (world.home / "auth.json").read_bytes() == fake
    # After a host route's write: the stand-in never becomes the copy.
    assert pins.update_stores(layout) == [] and signin_home.refresh_token_in(world.copy, "nous") == live
    assert pins.release(layout) == ["auth.json"]
    assert signin_home.refresh_token_in(world.home, "nous") == world.issuers.current_refresh_token("nous") == live
    assert not world.copy.exists()
    assert not quarantined(layout), "a stand-in was kept as if it were the user's"
    still_signed_in(world, "nous")


def test_a_file_under_the_name_that_is_no_stand_in_is_kept_not_deleted(world, on, rule):
    """A sign-in typed in a terminal for the profile while its sandbox is on lands under the name. It is not the
    live sign-in (the copy is), and it is not thrown away either."""
    layout, engine, _cred = on("openai-codex")
    pins.vacate(layout, ["auth.json"])
    engine.close()
    (world.home / "auth.json").write_text(json.dumps({"providers": {"openai-codex": {"tokens": {"access_token": "t"}}}}),
                                          encoding="utf-8")
    pins.release(layout)
    assert len(quarantined(layout)) == 1
    still_signed_in(world, "openai-codex")


def test_a_renewed_copy_is_never_replaced_by_the_homes_stale_store(world, on, rule):
    layout, engine, _cred = on("openai-codex", on_change=lambda names: None)
    engine._on_change = lambda names: pins.follow_copy(layout)
    renew(world, engine)
    live = signin_home.refresh_token_in(world.copy, "openai-codex")
    assert live == world.issuers.current_refresh_token("openai-codex")
    assert pins.restore_stores(layout) == ["auth.json"]  # before the next sandbox start, before a host route's write
    assert signin_home.refresh_token_in(world.copy, "openai-codex") == live
    assert signin_home.refresh_token_in(world.home, "openai-codex") == live
    assert pins.update_stores(layout) == []  # after a host route's write: the home is the copy's file
    assert signin_home.refresh_token_in(world.copy, "openai-codex") == live
    engine.close()


def test_the_return_is_not_listed_as_a_change_of_the_sandbox(world, on, rule):
    layout, engine, _cred = on("openai-codex")
    handback.take_baseline(world.home, layout.state_dir, replace=True)
    renew(world, engine)
    engine.close()
    pins.release(layout)
    listed = [str(row.get("name")) for row in handback.diff(world.home, layout.state_dir)["rows"]]
    assert not any("auth.json" in name for name in listed), listed


def test_a_stand_in_is_not_listed_as_a_change_of_the_sandbox(world, on, rule):
    layout, engine, _cred = on("nous")
    handback.take_baseline(world.home, layout.state_dir, replace=True)
    pins.vacate(layout, ["auth.json"])
    (world.home / "auth.json").write_bytes(stand_in_bytes(engine))
    engine.close()
    pins.restore_stores(layout, follow_only=True)  # what the review does before it makes its list
    listed = [str(row.get("name")) for row in handback.diff(world.home, layout.state_dir)["rows"]]
    assert not any("auth.json" in name for name in listed), listed
    pins.release(layout)
    listed = [str(row.get("name")) for row in handback.diff(world.home, layout.state_dir)["rows"]]
    assert not any("auth.json" in name for name in listed), listed


# -- a launcher that is killed, at every step between switch-on and switch-off ------------------------------------

def test_killed_while_the_pin_is_taken_the_home_still_holds_the_sign_in(world, on, monkeypatch):
    """The copy is written, the record is not: the home was never touched, and the next switch-on pins again."""
    from openshell.launcher.layout import ProfileLayout

    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    world.config({"model": {"provider": "openai-codex", "default": "a-model"}})
    world.sign_in("openai-codex")
    before = (world.home / "auth.json").read_bytes()
    save = pins._save

    def killed(*_args, **_kwargs):
        raise Killed()

    monkeypatch.setattr(pins, "_save", killed)
    with pytest.raises(Killed):
        pins.take(layout)
    monkeypatch.setattr(pins, "_save", save)
    assert (world.home / "auth.json").read_bytes() == before and not pins.present(layout)
    assert pins.release(layout) == [] and (world.home / "auth.json").read_bytes() == before
    assert pins.take(layout)["stores"]["auth.json"] == pins._file_state(world.home / "auth.json")
    pins.release(layout)
    still_signed_in(world, "openai-codex")


def test_killed_after_the_names_were_recorded_and_before_the_home_was_cleared(world, on, monkeypatch, rule):
    """``vacate`` records the names first. The file under the name is then still the pinned one; the switch-off
    replaces it with the copy, and a later start clears it."""
    layout, engine, _cred = on("openai-codex")
    renew(world, engine)

    def killed(*_args, **_kwargs):
        raise Killed()

    clear = pins._clear_name
    monkeypatch.setattr(pins, "_clear_name", killed)
    with pytest.raises(Killed):
        pins.vacate(layout, ["auth.json"])
    monkeypatch.setattr(pins, "_clear_name", clear)
    assert pins.load(layout)["standin"] == ["auth.json"] and (world.home / "auth.json").is_file()
    assert pins.restore_stores(layout) == []  # a name that was handed over is not written before the switch-off
    assert pins.vacate(layout, ["auth.json"]) == ["auth.json"] and not (world.home / "auth.json").exists()
    assert not quarantined(layout), "the pinned file was kept although the copy holds it"
    engine.close()
    pins.release(layout)
    still_signed_in(world, "openai-codex")


@pytest.mark.parametrize("provider", ["nous", "openai-codex"])
def test_killed_while_the_sandbox_runs_then_started_again_then_switched_off(world, on, rule, provider):
    layout, engine, cred = on(provider)
    pins.vacate(layout, ["auth.json"])
    (world.home / "auth.json").write_bytes(stand_in_bytes(engine))
    renew(world, engine)  # the copy is one renewal ahead of anything recorded when the process ends
    engine.close()
    # The launcher's next start: a new engine over the same copy, the same steps before the sandbox.
    world.sink.declared.clear()
    again = world.engine()
    assert [d.id for d in again.declare()] == [cred]
    assert world.issuers.valid(provider, world.sink.values[cred][0])
    assert pins.vacate(layout, ["auth.json"]) == ["auth.json"], "the stand-in of the sandbox before was left"
    assert not (world.home / "auth.json").exists() and not quarantined(layout)
    (world.home / "auth.json").write_bytes(stand_in_bytes(again))
    renew(world, again)
    again.close()
    pins.release(layout)
    still_signed_in(world, provider)


def test_killed_while_the_sandbox_runs_then_switched_off_from_a_terminal(world, on, rule):
    """No launcher answers: ``sandbox off`` releases the pins with the files alone."""
    layout, engine, _cred = on("openai-codex")
    pins.vacate(layout, ["auth.json"])
    (world.home / "auth.json").write_bytes(stand_in_bytes(engine))
    renew(world, engine)
    engine.close()
    pins.release(layout)
    assert not quarantined(layout)
    still_signed_in(world, "openai-codex")


def test_killed_in_the_switch_off_before_the_copy_reached_the_home(world, on, monkeypatch, rule):
    """The stand-in is gone and the copy is not under the name yet: the pins are still there, and the next
    switch-off or switch-on finishes the return."""
    layout, engine, _cred = on("openai-codex")
    pins.vacate(layout, ["auth.json"])
    (world.home / "auth.json").write_bytes(stand_in_bytes(engine))
    renew(world, engine)
    engine.close()
    write = pins._write_private

    def killed(path, data, **kwargs):
        if path == world.home / "auth.json":
            raise Killed()
        return write(path, data, **kwargs)

    monkeypatch.setattr(pins, "_write_private", killed)
    with pytest.raises(Killed):
        pins.release(layout)
    monkeypatch.setattr(pins, "_write_private", write)
    assert not (world.home / "auth.json").exists() and pins.present(layout)
    assert pins.stranded(layout) == ["auth.json"]
    assert signin_home.refresh_token_in(world.copy, "openai-codex") == world.issuers.current_refresh_token("openai-codex")
    pins.take(layout)  # the next switch-on: the return first, then the pin
    assert signin_home.refresh_token_in(world.home, "openai-codex") == world.issuers.current_refresh_token("openai-codex")
    pins.release(layout)
    still_signed_in(world, "openai-codex")


def test_killed_in_the_switch_off_after_the_copy_reached_the_home(world, on, monkeypatch, rule):
    layout, engine, _cred = on("openai-codex")
    renew(world, engine)
    engine.close()

    def killed(*_args, **_kwargs):
        raise Killed()

    remove = pins.remove
    monkeypatch.setattr(pins, "remove", killed)
    with pytest.raises(Killed):
        pins.release(layout)
    monkeypatch.setattr(pins, "remove", remove)
    assert pins.present(layout) and pins.stranded(layout) == []
    assert pins.release(layout) == [] and not world.copy.exists()
    still_signed_in(world, "openai-codex")


@pytest.mark.parametrize("left", ["the record", "the copy"])
def test_killed_while_the_pins_are_deleted(world, on, rule, left):
    """The pins are deleted only after the copy is in the home, so whatever half is left changes nothing."""
    layout, engine, _cred = on("openai-codex")
    renew(world, engine)
    engine.close()
    pins.follow_copy(layout)
    pins.restore_stores(layout)
    (world.copy / ("auth.json" if left == "the record" else "pins.json")).unlink()
    assert pins.release(layout) == [] and not world.copy.exists()
    still_signed_in(world, "openai-codex")


def test_a_copy_that_cannot_go_back_stays_and_is_not_pinned_over(world, on, monkeypatch, rule):
    layout, engine, _cred = on("openai-codex")
    pins.vacate(layout, ["auth.json"])
    renew(world, engine)
    engine.close()
    write = pins._write_private

    def refused(path, data, **kwargs):
        if path == world.home / "auth.json":
            raise PermissionError(13, "the profile's folder cannot be written")
        return write(path, data, **kwargs)

    monkeypatch.setattr(pins, "_write_private", refused)
    assert pins.release(layout) == []
    assert pins.present(layout) and pins.stranded(layout) == ["auth.json"]
    with pytest.raises(pins.PinError, match="could not be put back"):
        pins.take(layout)
    assert signin_home.refresh_token_in(world.copy, "openai-codex") == world.issuers.current_refresh_token("openai-codex")
    monkeypatch.setattr(pins, "_write_private", write)
    assert pins.release(layout) == ["auth.json"] and not world.copy.exists()
    still_signed_in(world, "openai-codex")


def test_while_a_sandbox_may_still_run_the_copy_stays_in_the_pins(world, on, rule):
    """The sandbox could not be confirmed gone: under the name it could read the real file. The stand-in stays
    and so do the pins, until a switch-off or a switch-on that knows the sandbox is gone."""
    layout, engine, _cred = on("nous")
    pins.vacate(layout, ["auth.json"])
    fake = stand_in_bytes(engine)
    (world.home / "auth.json").write_bytes(fake)
    renew(world, engine)
    engine.close()
    assert pins.release(layout, unhold=False) == []
    assert (world.home / "auth.json").read_bytes() == fake and pins.present(layout)
    assert pins.release(layout) == ["auth.json"] and not world.copy.exists()
    still_signed_in(world, "nous")


# -- the rules around the stand-in ---------------------------------------------------------------------------------

def test_the_home_is_untouched_when_the_copy_is_not_the_recorded_file(world, on):
    layout, engine, _cred = on("openai-codex")
    engine.close()
    before = (world.home / "auth.json").read_bytes()
    (world.copy / "auth.json").write_bytes(b"{ half a file")
    with pytest.raises(pins.PinError, match="not the file that was recorded"):
        pins.vacate(layout, ["auth.json"])
    assert (world.home / "auth.json").read_bytes() == before and pins.load(layout)["standin"] == []


def test_a_copy_that_is_not_the_recorded_file_is_never_put_back_and_nothing_is_cleared(world, on, rule):
    """The switch-off reads and checks the copy before it touches the home: what stands under the name stays."""
    layout, engine, _cred = on("openai-codex")
    pins.vacate(layout, ["auth.json"])
    fake = stand_in_bytes(engine)
    (world.home / "auth.json").write_bytes(fake)
    engine.close()
    (world.copy / "auth.json").write_bytes(b"{ half a file")
    assert pins.release(layout) == []
    assert (world.home / "auth.json").read_bytes() == fake and pins.present(layout)
    assert pins.stranded(layout) == ["auth.json"] and not quarantined(layout)


def test_only_sign_in_files_can_be_handed_to_a_stand_in(world, on):
    layout, engine, _cred = on("openai-codex")
    engine.close()
    with pytest.raises(ValueError):
        pins.vacate(layout, [".env"])
    assert pins.vacate(layout, []) == [] and pins.load(layout)["standin"] == []


def test_a_stand_in_left_without_its_pins_is_never_pinned_as_the_users_sign_in(world, on):
    layout, engine, _cred = on("nous")
    fake = stand_in_bytes(engine)
    engine.close()
    pins.remove(layout)  # the launcher's folder was removed by hand
    (world.home / "auth.json").write_bytes(fake)
    doc = pins.take(layout)
    assert doc["stores"]["auth.json"] is None and not (world.home / "auth.json").exists()
    assert not (world.copy / "auth.json").exists()


def test_a_profile_with_no_sign_in_is_pinned_and_released_as_before(world, monkeypatch):
    """No sign-in is renewed, so the copy never changes: a store a program on this computer wrote while the
    sandbox was on is followed where the sandbox cannot have written it, exactly as before."""
    from openshell.launcher.layout import ProfileLayout

    monkeypatch.setattr(pins, "stores_replaceable_inside", lambda windows=None: False)
    layout = ProfileLayout(name="work", home=world.home, root=world.root)
    (world.home / "auth.json").write_text(json.dumps({"version": 1, "providers": {}}), encoding="utf-8")
    doc = pins.take(layout)
    assert doc["standin"] == [] and doc["origin"] == doc["stores"]
    written = json.dumps({"version": 1, "providers": {}, "note": "written on this computer"})
    (world.home / "auth.json").write_text(written, encoding="utf-8")
    assert pins.restore_stores(layout) == []
    assert (world.copy / "auth.json").read_text(encoding="utf-8") == written
    assert pins.release(layout) == [] and (world.home / "auth.json").read_text(encoding="utf-8") == written
    assert not world.copy.exists() and not quarantined(layout)
