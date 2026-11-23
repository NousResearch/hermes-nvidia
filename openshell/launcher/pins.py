"""Host-only copies of what the launcher takes from a profile's home: the pins.

The sandbox writes most of its profile home, so the launcher does not read its keys or its key routes from
there while the sandbox is on. When the sandbox is switched on, on the host, three things are copied into
``<root>/openshell/<profile>/pins/`` (the launcher's state folder, which no sandbox is granted):

* the env files (``.env``, ``.op.env``) with their hashes,
* the sign-in files (``auth.json``, ``.anthropic_oauth.json``) with their hashes,
* the ``secrets:`` block of ``config.yaml`` (the user's own secret sources),
* the model entries (which key goes to which endpoint).

A restart never takes a pin: by then the sandbox has had the home. After ``take`` the only writers are
``allow`` (the user allowed a changed endpoint) and ``update_env`` / ``update_stores`` / ``add_models`` (a key
or an endpoint written through the launcher's own host routes). ``secrets`` resolves the pinned env file and
the pinned secret sources into a private dict; the process environment is never written.

The home's copies are put back from the pin (``restore_env``, ``restore_stores``) before every sandbox start,
before the launcher lists or reveals a key, before it writes one, and when the switch turns off (``release``,
which then deletes the pins): an env file the sandbox created or replaced never reaches a sandbox start or a
host process, and the other version is kept in the quarantine folder. What the launcher shows of the keys
(``env_values``) is read from the pin, never from the home.

Every file written here (a pinned copy, ``pins.json``, a file put back into the home) is written whole to a temp
file in the pin folder and renamed into place (``_write_private``): a reader sees the old file or the new one,
and a launcher that is killed mid-write leaves no half-written key file. A pinned copy is put back only when
it is still the file that was recorded (its hash).

Where the sandbox's driver keeps these files in a folder of their own while it runs (Linux, ``held.py``), each
name in the home is the launcher's link to the file there. Every function here reads and writes the file behind
that link and never puts a key file under a name the sandbox can open; whatever stands under such a name instead
of the link is moved to the quarantine folder first (``_settle``).

The sign-in files are different from the env files in one way: while the sandbox is on, the copy here is the
live sign-in. The launcher keeps the profile signed in from it (``signins.py``: Hermes renews a sign-in in the
store it read it from, so every renewal rewrites the copy), and the file in the home goes stale. So for these
files the copy is never replaced by the home's file once it was renewed, its recorded state follows it
(``follow_copy``), and the switch-off puts the copy back under the file's name (``release``): the user is still
signed in afterwards. A sign-in file the sandbox gets a stand-in for (``inside/standin.py``) leaves its name in
the home before the sandbox starts (``vacate``), only after the copy was checked against its record; the name
then holds the stand-in the sandbox writes, which is thrown away at the switch-off. The pin folder is deleted
only once every sign-in file is back in the home.

A sandbox switched on by an older version has no pin. Nothing is pinned for it later: ``secrets`` then reads
the home's ``.env`` values only and runs no secret source, and the drivers register a key only for its own
provider's address (``openshell_driver.route_decisions``) until the sandbox is turned off and on once.
"""
from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from ..inside import standin as stand_in
from . import held

log = logging.getLogger("openshell.pins")

PINS_DIRNAME = "pins"
PIN_FILE = "pins.json"
ENV_FILES = (".env", ".op.env")
# The sign-in files. The sandbox never gets them (it holds placeholders). While the sandbox is on the copy in the
# pin folder is the live sign-in: the launcher renews it there (signins.py), and its own key and endpoint routes
# are the only other writers (``update_stores``).
STORE_FILES = ("auth.json", ".anthropic_oauth.json")
VERSION = 1
QUARANTINE_DIRNAME = "quarantine"  # shared with the driver's own quarantine of credential stores created inside


class PinError(OSError):
    """The pin cannot be taken or used without putting a sign-in at risk. The message says what is in the way."""


def pin_dir(layout) -> Path:
    return layout.state_dir / PINS_DIRNAME


def load(layout) -> Optional[dict]:
    """The pin, or None when the sandbox was switched on without one (or the file is unreadable)."""
    try:
        doc = json.loads((pin_dir(layout) / PIN_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("version") == VERSION else None


def present(layout) -> bool:
    return load(layout) is not None


# -- taking and releasing (the switch) -------------------------------------------------------------

def take(layout) -> dict:
    """Pin the home as it is now. Called on the host when the sandbox is switched on (``switch.turn_on``, a
    foreground ``sandbox serve``), never by a restart. Replaces an earlier pin: one that is still there belongs
    to a session that ended without a switch-off, so the files it holds are put back first (the home's may be
    that sandbox's) and only then is the home pinned again. A file that is there and cannot be read is never
    pinned as an empty one: ``PinError`` names it, and nothing is pinned."""
    from .settings_view import Unreadable, must_read, read_config

    release(layout)
    for name in STORE_FILES:
        if _is_stand_in(layout.home / name):
            # A stand-in whose pins are gone (the launcher's folder was removed by hand): never pinned as the
            # user's sign-in.
            log.warning("%s is a stand-in a sandbox left; removed", layout.home / name)
            (layout.home / name).unlink(missing_ok=True)
    left = stranded(layout)
    if left:
        # The pin folder still holds a sign-in that could not be put back. Pinning again would overwrite it.
        raise PinError(f"the sign-in kept on this computer while the sandbox was last on could not be put back "
                       f"into the profile ({', '.join(left)}); it is still in {pin_dir(layout)}")
    try:
        must_read(layout)
        config = read_config(layout)
    except Unreadable as exc:
        # Copied as it is, the profile would be pinned without its keys, its models or its sign-in.
        raise PinError(str(exc)) from None
    folder = pin_dir(layout)
    folder.mkdir(parents=True, exist_ok=True)
    _owner_only(folder, 0o700)
    block = config.get("secrets")
    stores = {name: _copy_in(layout.home / name, folder / name) for name in STORE_FILES}
    # ``origin``: each sign-in file as the home had it at this moment (``stores`` follows the copy from now
    # on). ``standin``: the sign-in files whose name in the home was handed to a stand-in (``vacate``).
    doc = {"version": VERSION, "taken_at": time.time(),
           "files": {name: _copy_in(layout.home / name, folder / name) for name in ENV_FILES},
           "stores": stores, "origin": dict(stores), "standin": [],
           "secrets": block if isinstance(block, dict) else {},
           "models": model_entries(config), "allowed": []}
    _save(layout, doc)
    _copy_config(layout, folder)
    return doc


def _copy_config(layout, folder: Path) -> None:
    """The copy's own ``config.yaml``: what Hermes needs to tell which provider a model route uses when the
    launcher asks it with the copy bound as its home (signins.py). Never raises: without it no sign-in is
    carried into the sandbox, and nothing else depends on it."""
    try:
        from . import signins

        signins.write_copy_config(layout.home, folder)
    except Exception as exc:
        log.warning("the copy's config.yaml could not be written: %s", exc)


def remove(layout) -> None:
    shutil.rmtree(pin_dir(layout), ignore_errors=True)


def _drop_stand_in_folder(layout) -> None:
    """The stand-in's template and start-up step (standins.py) serve one sandbox start. Once that sandbox is
    gone nothing reads them, and the next start writes its own."""
    from . import standins

    shutil.rmtree(standins.folder(layout), ignore_errors=True)


def release(layout, *, unhold: bool = True) -> list[str]:
    """The switch turning off: put back every env file that is no longer the pinned one and every sign-in file
    whose copy is the newer one, then delete the pins. Returns the names put back.

    The sign-in files come back from the copy as it is now (``follow_copy`` first: a launcher that was killed
    may have left the record one renewal behind), under Hermes's own lock of the copy, so no renewal is under
    way meanwhile. A stand-in under a sign-in file's name is thrown away, never kept as the user's. The pins
    are deleted only when every sign-in file of the copy is in the home; otherwise the folder stays (it holds
    the only live sign-in) and the next switch-on or switch-off tries again.

    *unhold* False: a sandbox of this profile may still run, so the files a driver keeps in the held folder
    stay there, and a sign-in file whose name holds a stand-in stays in the copy (under its name the sandbox
    could read it). They are put back once the sandbox is known to be gone: the next switch-on stops it
    first."""
    if load(layout) is None:
        if unhold:
            _unhold(layout)
            _drop_stand_in_folder(layout)
        remove(layout)
        return []
    with _settled(layout):
        follow_copy(layout)
        if unhold:
            _unhold(layout)
        restored = restore_env(layout)
        doc = load(layout) or {}
        stores = doc.get("stores") if isinstance(doc.get("stores"), dict) else {}
        handed = [name for name in STORE_FILES if name in stores and name in (doc.get("standin") or [])]
        returned = []
        for name in handed if unhold else ():
            if _return_copy(layout, name, stores[name], doc):
                returned.append(name)
        returned += restore_stores(layout)
        for name in returned:
            _baseline_follows(layout, name)  # the launcher's own return is not a change of the sandbox's
        # What is not in the home as the copy has it. A name that still holds a stand-in counts even when the
        # profile had no such file: without the pins nothing would know the stand-in for what it is.
        left = [name for name in STORE_FILES if name in stores and (name in handed or stores[name] is not None)
                and _file_state(layout.home / name) != stores[name]]
    restored += returned
    if left:
        log.warning("%s: not back in the profile yet (%s); the pins stay in %s", layout.home, ", ".join(left),
                    pin_dir(layout))
        return restored
    remove(layout)
    if unhold:
        _drop_stand_in_folder(layout)
    return restored


def stranded(layout) -> list[str]:
    """The sign-in files a ``release`` left in the pin folder because they could not be put back into the home
    ([] when there is no pin). A switch-on must not pin over them."""
    doc = load(layout)
    stores = (doc or {}).get("stores")
    if not isinstance(stores, dict):
        return []
    return [name for name in STORE_FILES if stores.get(name) is not None and (pin_dir(layout) / name).is_file()
            and _file_state(layout.home / name) != stores[name]]


@contextmanager
def _settled(layout) -> Iterator[None]:
    """Hermes's own lock of the copy's sign-in store, held for a body: no renewal is under way in this or any
    other process meanwhile. Without Hermes (nothing renews then) the body just runs."""
    from . import signins

    try:
        lock = signins.settled(pin_dir(layout))
        lock.__enter__()
    except signins.Unavailable:
        lock = None
    try:
        yield
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)


def follow_copy(layout) -> list[str]:
    """The sign-in files in the pin folder are renewed in place: their recorded state follows them. Called
    after every renewal, and before the record is used to put a file back (a launcher that was killed between
    the issuer's answer and this call left the record one renewal behind). A copy that is not a whole store
    (it cannot be: Hermes writes these files by a rename) is not followed. Returns the names that changed."""
    from . import signins

    doc = load(layout)
    if doc is None or not isinstance(doc.get("stores"), dict):
        return []
    changed = []
    with _settled(layout):
        doc = load(layout) or doc
        stores = dict(doc.get("stores") or {})
        for name, state in signins.copy_states(pin_dir(layout)).items():
            if name in STORE_FILES and name in stores and state is not None and stores[name] != state:
                stores[name] = state
                changed.append(name)
        if changed:
            _save(layout, {**doc, "stores": stores})
    return changed


def standin_names(layout) -> list[str]:
    """The sign-in files whose name in the home was handed to a stand-in since the switch-on."""
    doc = load(layout) or {}
    return [name for name in STORE_FILES if name in (doc.get("standin") or [])]


def vacate(layout, names) -> list[str]:
    """Before a sandbox starts: the sign-in files *names* leave their names in the home, so the sandbox can put
    its stand-in there (``inside/standin.py``) and nothing of the user's is under a name it reads.

    The order keeps the sign-in whatever happens in between: the copy is checked against its record first (a
    copy that is not the recorded file stops here, with the home untouched), then the names are recorded in
    the pin, and only then is the home's file removed. From the record on, the copy is the only real sign-in
    file and the switch-off puts it back. What stands under such a name is the file that was pinned (removed:
    the copy holds it, or a newer one), the stand-in of the sandbox before (removed), or something else, which
    goes to the quarantine folder. Returns the names that held something."""
    names = [name for name in dict.fromkeys(names)]
    if not names:
        return []
    unknown = [name for name in names if name not in STORE_FILES]
    if unknown:
        raise ValueError(f"not a sign-in file of a profile home: {', '.join(unknown)}")
    if load(layout) is None:
        raise PinError("this sandbox was switched on without a copy of the profile's sign-in; turn it off and on")
    cleared = []
    with _settled(layout):
        follow_copy(layout)
        doc = load(layout) or {}
        stores = doc.get("stores") if isinstance(doc.get("stores"), dict) else {}
        for name in names:
            if stores.get(name) is not None:
                _checked_copy(layout, name, stores[name])
        listed = [name for name in STORE_FILES if name in names or name in (doc.get("standin") or [])]
        if listed != (doc.get("standin") or []):
            doc = {**doc, "standin": listed}
            _save(layout, doc)
        with held.lock(layout.home):
            for name in names:
                if _clear_name(layout, name, doc):
                    cleared.append(name)
    return cleared


def _checked_copy(layout, name: str, pinned: dict) -> bytes:
    """The bytes of the copy of *name*, when they are the recorded ones."""
    try:
        data = (pin_dir(layout) / name).read_bytes()
    except OSError as exc:
        raise PinError(f"the copy of {name} cannot be read: {exc.strerror or exc}") from None
    if hashlib.sha256(data).hexdigest() != pinned.get("sha256"):
        raise PinError(f"the copy of {name} is not the file that was recorded")
    return data


def _is_stand_in(path) -> bool:
    """Whether the plain file at *path* is a stand-in sign-in store: it names a placeholder or carries the word
    a stand-in holds in place of a refresh grant. Such a file holds nothing of the user's."""
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > 8 * 1024 * 1024:
            return False
        data = Path(path).read_bytes()
    except OSError:
        return False
    return any(mark.encode("utf-8") in data for mark in (stand_in.ALIAS_MARKER, stand_in.PLACEHOLDER_PREFIX,
                                                         f'"{stand_in.NO_REFRESH}"'))


def _clear_name(layout, name: str, doc: dict) -> Optional[str]:
    """Take whatever stands under the sign-in file name *name* out of the home. A stand-in is deleted. The file
    that was pinned is deleted when the copy is still the recorded one (nothing is lost with it). Anything else
    goes to the quarantine folder. Returns what it was (``stand-in``, ``pinned``, ``other``), None when the
    name was free. The caller holds the home's lock."""
    path = layout.home / name
    real = held.displaced(path)
    if real is None:
        if os.path.islink(path):  # the launcher's own link with nothing behind it
            os.unlink(path)
        return None
    origin = doc.get("origin") if isinstance(doc.get("origin"), dict) else {}
    stores = doc.get("stores") if isinstance(doc.get("stores"), dict) else {}
    if _is_stand_in(real):
        os.unlink(real)
        what = "stand-in"
    elif origin.get(name) is not None and _file_state(path) == origin[name] and _copy_is_recorded(layout, name, stores):
        os.unlink(real)
        what = "pinned"
    else:
        target = _quarantine(layout, real)
        log.warning("%s was not the file that was pinned; it is kept in %s", path, target)
        what = "other"
    if real != path and os.path.islink(path):
        os.unlink(path)
    return what


def _copy_is_recorded(layout, name: str, stores: dict) -> bool:
    try:
        _checked_copy(layout, name, stores.get(name) or {})
    except PinError:
        return False
    return True


def _return_copy(layout, name: str, pinned: Optional[dict], doc: dict) -> bool:
    """The switch-off, for a sign-in file whose name held a stand-in: the stand-in is thrown away and the copy
    goes back under the name (nothing, when the profile had no such file). The copy is read and checked before
    anything in the home is touched. True when the home changed."""
    path = layout.home / name
    with held.lock(layout.home):
        if _file_state(path) == pinned and not _is_stand_in(held.source(path)):
            return False
        try:
            data = _checked_copy(layout, name, pinned) if pinned is not None else None
            _clear_name(layout, name, doc)
            if data is not None:
                _write_private(held.destination(path), data, staging=pin_dir(layout))
                held.relink(path)
        except OSError as exc:
            log.warning("could not put the sign-in file %s back from its copy: %s", path, exc)
            return False
    log.info("%s is back in the profile, as it was kept on this computer while the sandbox was on", path)
    return True


def _unhold(layout) -> None:
    """The switch turning off (or on again after a session that ended without one): no sandbox runs, so the files
    a driver kept in the held folder go back under their names (``held.release``). Never raises."""
    try:
        held.release(layout.home, lambda path: _quarantine(layout, path))
    except OSError as exc:
        log.warning("could not put the held credential files of %s back: %s", layout.home, exc)


def _settle(layout) -> None:
    """Before the home's credential files are read or written while a sandbox may run: every held name is the
    launcher's link again (``held.guard``), so what is read next is the file only this computer wrote, never one
    the sandbox put under the name. Nothing to do where no driver holds files. Never raises."""
    try:
        held.guard(layout.home, lambda path: _quarantine(layout, path))
    except OSError as exc:
        log.warning("could not check the held credential files of %s: %s", layout.home, exc)


def restore_env(layout) -> list[str]:
    """Make the home's env files the pinned ones again: a file the sandbox created or replaced (or one edited
    by hand while the sandbox was on) is moved to the launcher's quarantine folder, and the pinned copy is
    written back (nothing, when there was no such file). Returns the names put back; [] without a pin."""
    doc = load(layout)
    if doc is None:
        return []
    _settle(layout)
    return [name for name in ENV_FILES if _put_back(layout, name, (doc.get("files") or {}).get(name))]


def stores_replaceable_inside(windows: Optional[bool] = None) -> bool:
    """Whether a sandbox can replace a credential store that exists. Windows: yes, by a rename onto its name
    (MXC does not check rename targets). Linux: no. The store is in the held folder, which the sandbox cannot
    write; what it can replace is the link under the store's name, and whatever stands there instead of the link
    is taken out before the store is looked at (``_settle``)."""
    return os.name == "nt" if windows is None else bool(windows)


def restore_stores(layout, *, replaceable: Optional[bool] = None, follow_only: bool = False) -> list[str]:
    """The same for the sign-in files. Their copy is the live sign-in while the sandbox is on, so the record
    follows the copy first (``follow_copy``), and then, for each file:

    * Its name was handed to a stand-in (``vacate``): nothing of the user's goes under the name before the
      switch-off (``release``). What stands there is the sandbox's and is not listed as a change of its own.
    * It was absent at switch-on and is there now: made while the sandbox was on. Moved to the quarantine folder.
    * The copy was renewed since the switch-on: the copy is the newer sign-in. It is put back and the home's
      other version is kept in the quarantine folder, on every system.
    * It differs from the pinned copy where the sandbox can replace it (*replaceable*; Windows): that cannot be
      told from a host process's write, so the pinned copy is put back and the other one is kept in the
      quarantine folder. A sign-in a ``hermes`` command made for this profile while its sandbox was on is
      therefore undone (the newer file is in the quarantine folder): sign in with the sandbox off.
    * It differs where the sandbox cannot write a store that exists (Linux), and the copy was not renewed: a
      host process wrote it. The pin follows it, so does the hand-back's record of the home (the switch-off
      would otherwise take the file out as changed in the sandbox), and nothing in the home is touched.

    With *follow_only* (before the list of what changed is made, ``switch.review``) nothing in the home is
    moved: the list then has no row for a store a host process wrote or for a stand-in, and still has one for
    a store this function takes out or puts back at the next sandbox start and at the switch-off.

    Returns the names put back or taken out; [] without a pin, and for a pin taken before stores were kept."""
    doc = load(layout)
    if not isinstance((doc or {}).get("stores"), dict):
        return []
    follow_copy(layout)
    doc = load(layout) or doc
    stores = doc["stores"]
    origin = doc.get("origin") if isinstance(doc.get("origin"), dict) else {}
    handed = doc.get("standin") or []
    if replaceable is None:
        replaceable = stores_replaceable_inside()
    if not follow_only:
        _settle(layout)
    restored, followed = [], False
    for name in STORE_FILES:
        if name not in stores:
            continue
        pinned = stores[name]
        if name in handed:
            _baseline_follows(layout, name)
            continue
        renewed = name in origin and origin[name] != pinned
        if pinned is None or replaceable or renewed:
            if not follow_only and _put_back(layout, name, pinned):
                restored.append(name)
        elif _file_state(layout.home / name) != pinned:
            if held.active(layout.home) and not held.is_link(layout.home / name):
                # Something stands under a held name instead of the launcher's link: not the store this
                # computer wrote. Never followed; it is taken out at the next start or at the switch-off.
                continue
            state = _copy_in(layout.home / name, pin_dir(layout) / name)
            stores, origin = {**stores, name: state}, {**origin, name: state}
            followed = True
            _baseline_follows(layout, name)
            log.info("%s was written on the host while the sandbox was on; the pin follows it", layout.home / name)
    if followed:
        _save(layout, {**doc, "stores": stores, "origin": origin})
    return restored


def _baseline_follows(layout, name: str) -> None:
    """A host process's write of *name* joins the hand-back's baseline, when one is open. Never raises."""
    try:
        from . import handback

        if handback.is_open(layout.state_dir):
            handback.update_baseline_for_host_write(layout.home, layout.state_dir, files=[name])
    except Exception as exc:
        log.warning("hand-back: %s as a host process wrote it could not join the baseline: %s", name, exc)


def _put_back(layout, name: str, pinned: Optional[dict]) -> bool:
    """Make ``<home>/<name>`` the pinned file again (absent, when *pinned* is None). True when it was not."""
    path = layout.home / name
    with held.lock(layout.home):
        return _put_back_locked(layout, path, name, pinned)


def _put_back_locked(layout, path: Path, name: str, pinned: Optional[dict]) -> bool:
    if _file_state(path) == pinned:
        return False
    try:
        gone = held.displaced(path)  # the file behind the launcher's link, or what stands under the name
        if gone is not None:
            _quarantine(layout, gone)
        if pinned is not None:
            data = (pin_dir(layout) / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != pinned.get("sha256"):
                # A launcher killed while it copied: never written into the home. The home is left without
                # the file (its other version is in the quarantine folder).
                raise OSError("the pinned copy is not the file that was recorded")
            # While a sandbox holds the home's files the copy goes into the held folder, never under the name.
            _write_private(held.destination(path), data, staging=pin_dir(layout))
        held.relink(path)
    except OSError as exc:
        log.warning("could not restore %s from its pin: %s", path, exc)
        return False
    log.warning("%s was changed while the sandbox was on; restored from the pin", path)
    return True


# -- the only writers after take (called from the launcher's host routes) --------------------------

def allow(layout, route: dict) -> bool:
    """The user allowed a key at an endpoint that is not the pinned one. False without a pin."""
    doc = load(layout)
    if doc is None:
        return False
    pair = {"env": str(route["env"]), "host": str(route["host"]).lower(), "port": int(route["port"])}
    allowed = [a for a in doc.get("allowed") or [] if isinstance(a, dict)]
    if not any(all(a.get(k) == v for k, v in pair.items()) for a in allowed):
        allowed.append({**pair, "allowed_at": time.time()})
        _save(layout, {**doc, "allowed": allowed})
    return True


def update_env(layout) -> bool:
    """A host route wrote a key: the home's env files, as that write left them, become the pinned ones. The
    route calls ``restore_env`` before it writes, so nothing the sandbox put there is taken. False without
    a pin."""
    doc = load(layout)
    if doc is None:
        return False
    _settle(layout)
    folder = pin_dir(layout)
    files = {name: _copy_in(layout.home / name, folder / name) for name in ENV_FILES}
    _save(layout, {**doc, "files": files})
    return True


def update_stores(layout) -> list[str]:
    """A host route wrote a key or an endpoint, which may rewrite the sign-in store too (Hermes drops the pool
    entries of a key that was removed): the store as that write left it becomes the pinned one. The route
    calls ``restore_stores`` before it writes, so nothing the sandbox put there is taken. A sign-in file whose
    name holds a stand-in is left out: what the route's write did there was done to the stand-in. Returns the
    names whose pinned copy changed; [] without a pin, and for a pin taken before stores were kept."""
    doc = load(layout)
    stores = (doc or {}).get("stores")
    if not isinstance(stores, dict):
        return []
    _settle(layout)
    folder, changed = pin_dir(layout), []
    origin = doc.get("origin") if isinstance(doc.get("origin"), dict) else {}
    for name in STORE_FILES:
        if name in (doc.get("standin") or []):
            continue  # the name holds the sandbox's stand-in: never taken into the copy
        if name in stores and _file_state(layout.home / name) != stores[name]:
            state = _copy_in(layout.home / name, folder / name)
            stores, origin = {**stores, name: state}, {**origin, name: state}
            changed.append(name)
    if changed:
        _save(layout, {**doc, "stores": stores, "origin": origin})
    return changed


def add_models(layout, before: list[dict], base_url: str) -> list[dict]:
    """A host route saved a model endpoint: the model entries that write added (not in *before*, and at
    *base_url*) join the pinned ones. Returns the entries added; [] without a pin."""
    doc = load(layout)
    if doc is None:
        return []
    from .settings_view import _read_config

    wanted = str(base_url or "").strip().rstrip("/").lower()
    known = [_identity(e) for e in [*before, *(doc.get("models") or [])]]
    added = [e for e in model_entries(_read_config(layout))
             if _identity(e) not in known and wanted and e["base_url"].strip().rstrip("/").lower() == wanted]
    if added:
        _save(layout, {**doc, "models": [*(doc.get("models") or []), *added]})
    return added


# -- what the launcher reads -----------------------------------------------------------------------

def model_entries(config: dict) -> list[dict]:
    """The model entries of a config.yaml document, reduced to what decides a key's endpoint and where the key
    travels on the wire. ``url`` is the address the entry had when it was read (its ``base_url``, else its
    provider's registered one)."""
    from .settings_view import _model_entries, _provider_default_url

    out = []
    for label, entry in _model_entries(config if isinstance(config, dict) else {}):
        row = {"label": label, **{k: str(entry.get(k) or "") for k in ("provider", "base_url", "key_env", "api_key_env")}}
        row["url"] = row["base_url"].strip() or _provider_default_url(row["provider"])
        row["api_mode"] = str(entry.get("api_mode") or "")
        row["model"] = str(entry.get("model") or entry.get("default") or "")
        out.append(row)
    return out


def current_models(layout) -> list[dict]:
    """The home's model entries as they are now (a host route reads them before it writes)."""
    from .settings_view import _read_config

    return model_entries(_read_config(layout))


def route_pin(layout) -> dict:
    """What the drivers check a key's endpoint against: the pinned model entries and the pairs the user
    allowed. ``present`` is False for a sandbox that was switched on without a pin."""
    doc = load(layout)
    if doc is None:
        return {"present": False, "models": [], "allowed": []}
    return {"present": True, "models": [m for m in doc.get("models") or [] if isinstance(m, dict)],
            "allowed": [a for a in doc.get("allowed") or [] if isinstance(a, dict)]}


def env_values(layout) -> Optional[dict[str, str]]:
    """The names and values of the pinned ``.env``, as the file defines them: what the launcher lists and
    reveals as the profile's keys while the sandbox is on. Read from the pin, never from the home (the sandbox
    writes the home, and a Hermes that reads no env file from a home that runs elsewhere would answer nothing).
    None without a pin."""
    if load(layout) is None:
        return None
    path = pin_dir(layout) / ".env"
    try:
        from agent.secret_scope import load_env_file  # Hermes's one tokenizer for these files
    except ImportError:
        return _raw_dotenv(path)
    try:
        return dict(load_env_file(path))
    except Exception as exc:
        log.warning("could not read %s: %s", path, exc)
        return {}


def secrets(layout) -> dict[str, str]:
    """The profile's keys, from the pin: the values of the pinned ``.env`` plus what the pinned ``secrets:``
    block resolves. The user's own secret sources run from the definition as it was at switch-on, against a
    private copy of the environment; nothing is written to the process environment. Without a pin: the
    home's ``.env`` values only (no secret source runs from a home the sandbox has had)."""
    doc = load(layout)
    if doc is None:
        return {k: v for k, v in _dotenv(layout.home).items() if v}
    folder = pin_dir(layout)
    values = _dotenv(folder)
    out = {k: v for k, v in values.items() if v}
    block = doc.get("secrets")
    if not isinstance(block, dict) or not any(isinstance(v, dict) and v.get("enabled") is True for v in block.values()):
        return out
    env = _private_environ(folder, values)
    try:
        from agent.secret_sources.registry import apply_all

        report = apply_all(block, _source_home(layout, folder), environ=env)
    except Exception as exc:  # a broken source never stops the sandbox: its keys are missing, as on the host
        log.warning("the pinned secret sources did not resolve: %s", exc)
        return out
    for name in getattr(report, "provenance", None) or {}:
        if env.get(name):
            out[name] = env[name]
    return out


# -- helpers ---------------------------------------------------------------------------------------

def _private_environ(folder: Path, pinned_env: dict) -> dict:
    """The environment the pinned secret sources see: this process's own, then the pinned ``.op.env`` (never
    over a value already set, as Hermes loads it), then the pinned ``.env`` (over everything, as Hermes loads
    it). What Hermes itself loaded into this process from the profile's home (env files, secret sources) is
    taken out first: on a Hermes that still loads a marked home's files at start those values may be the
    sandbox's, and a value already present would win over the pinned source that supplies it."""
    env = dict(os.environ)
    try:
        from hermes_cli import env_loader

        loaded = set(env_loader.launch_dotenv_keys()) | set(env_loader.secret_source_names())
    except Exception:  # a Hermes without that record: nothing to take out by name
        loaded = set()
    for name in loaded:
        env.pop(name, None)
    for key, value in _raw_dotenv(folder / ".op.env").items():
        env.setdefault(key, value)
    env.update(pinned_env)
    return env


def _source_home(layout, folder: Path) -> Path:
    """The folder secret sources get as their home: inside the pin, so their value caches stay host-only, and
    shaped ``profiles/<name>`` for a named profile, which is how Hermes finds the profile's name there."""
    home = folder / "source" if layout.is_root_home else folder / "profiles" / layout.name
    home.mkdir(parents=True, exist_ok=True)
    for path in {home, home.parent} - {folder}:
        _owner_only(path, 0o700)
    return home


def _dotenv(folder: Path) -> dict[str, str]:
    """``<folder>/.env`` as Hermes would load it (its own reader where this Hermes has it), read-only."""
    try:
        from hermes_cli.env_loader import resolve_home_dotenv
    except ImportError:
        return _raw_dotenv(folder / ".env")
    try:
        return dict(resolve_home_dotenv(folder))
    except Exception as exc:
        log.warning("could not read %s: %s", folder / ".env", exc)
        return {}


def _raw_dotenv(path: Path) -> dict[str, str]:
    try:
        from dotenv import dotenv_values

        return {k: v for k, v in dotenv_values(path, interpolate=False).items() if isinstance(v, str)}
    except Exception:  # absent, unreadable, not a dotenv file
        return {}


def _identity(entry: dict) -> tuple:
    return tuple(str(entry.get(k) or "").strip() for k in ("provider", "base_url", "key_env", "api_key_env"))


def _file_state(path: Path) -> Optional[dict]:
    """What identifies an env file: its bytes' sha256 and, for a link, where it points. None when absent
    (a folder or an unreadable file under the name counts as another file). The launcher's own link to a held
    file is that file."""
    path = held.source(path)
    if not os.path.lexists(path):
        return None
    link = os.readlink(path) if os.path.islink(path) else None
    try:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        digest = ""
    return {"sha256": digest, "link": link}


def _copy_in(source: Path, target: Path) -> Optional[dict]:
    """Make *target* (in the pin folder) the copy of *source* and return the state that copy has: read once,
    hashed and written from the same bytes, so the recorded hash is the copy's whatever happens to the source
    meanwhile. No copy is left for a source that is absent or cannot be read."""
    source = held.source(source)
    link = os.readlink(source) if os.path.islink(source) else None
    try:
        data = Path(source).read_bytes()
    except OSError:
        Path(target).unlink(missing_ok=True)
        return {"sha256": "", "link": link} if os.path.lexists(source) else None
    _write_private(target, data)
    return {"sha256": hashlib.sha256(data).hexdigest(), "link": link}


def _quarantine(layout, path: Path) -> Path:
    dest = layout.state_dir / QUARANTINE_DIRNAME / time.strftime("%Y%m%d-%H%M%S")
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / path.name
    n = 0
    while os.path.lexists(target):
        n += 1
        target = dest / f"{path.name}.{n}"
    shutil.move(str(path), str(target))
    return target


def _save(layout, doc: dict) -> None:
    folder = pin_dir(layout)
    folder.mkdir(parents=True, exist_ok=True)
    _write_private(folder / PIN_FILE, json.dumps(doc, indent=1, sort_keys=True).encode("utf-8"))


def _write_private(path: Path, data: bytes, *, staging: Optional[Path] = None) -> None:
    """Write *data* to *path*, owner-only, whole or not at all: to a temp file, flushed to disk, then renamed
    over *path* (whatever is there, a link included, is replaced, never written through). The temp file is made
    in *staging* when given, else beside *path*. A file that goes into the home is staged in the pin folder: a
    key file must never sit in the home under another name, where the sandbox could read it, and a file made in
    the pin folder carries none of the access the home's folder hands down to the sandbox (Windows). Where the
    home is on another volume than the pin folder a rename cannot cross, and the file is written in place."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=staging or path.parent, prefix=".pin-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _owner_only(tmp, 0o600)
        try:
            _replace(tmp, path)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            _write_in_place(path, data)
            os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _replace(src, dst) -> None:
    for attempt in range(6):
        try:
            os.replace(src, dst)
            return
        except PermissionError:  # Windows: a scanner or an indexer holds the target for a moment
            if os.name != "nt" or attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def _write_in_place(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    _owner_only(path, 0o600)


def _owner_only(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass
