"""Where a profile's top-level credential files are while a Linux sandbox runs.

The Linux driver hides a credential file with a read-only mount on the file's name. A mount on a name is gone
the moment a process on this computer replaces the file by rename, which is how Hermes writes these files (a temp
file beside the target, then a rename): the new file is then readable inside until the sandbox restarts, and so
was the temp file while it was written. A mount on a folder does not have that problem: whatever is replaced
below it stays below it.

So while a sandbox runs, the launcher keeps every credential file that sits at the top of the home in one folder
there, ``.openshell-held``, which is mounted over as a whole, and leaves a relative link under the file's own
name. Hermes's writers follow such a link: they stage their temp file beside the real file and rename there, so a
key saved, a sign-in or a token refresh on this computer lands inside the folder, and nothing readable ever
appears under a name the sandbox can open. Readers on this computer follow the link as well. ``.env``, ``.op.env``
and ``auth.json`` get the link even when they do not exist (a link with nothing behind it reads as absent): a
first key saved or a first sign-in while the sandbox runs then creates the file inside the folder.

The files are moved back under their names when the sandbox stops (``release``), before anything else looks at
the home, so the layout exists only while a sandbox runs; a launcher that was killed leaves links that still
resolve inside the home, and the next start or switch-off puts the files back.

What this cannot do: the link itself is an ordinary entry of a folder the sandbox writes, so the sandbox can
replace it (as it can create any credential file that does not exist), and a program on this computer that
replaces the name by rename without following the link (an editor, ``mv``) puts a plain file there. ``guard``
looks every second while the sandbox runs: whatever stands under a held name instead of the link goes to the
quarantine folder and the link comes back. The file inside the folder is never written by the sandbox.

Only the driver that hides by mounts calls ``hold``. Everything else here is safe to call anywhere: without the
folder nothing is held and every function answers for a plain home.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import stat
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

log = logging.getLogger("openshell.held")

DIRNAME = ".openshell-held"
# Held even when absent: the files a process on this computer may create while the sandbox runs.
ALWAYS = (".env", ".op.env", "auth.json")
QUARANTINE_DIRNAME = "quarantine"  # the launcher's folder for what it takes out of a home (pins.py, the drivers)
_RECORD = ".linked.json"  # in the held folder: the names ``hold`` put its link under (what ``guard`` watches)


class HeldError(OSError):
    """The home cannot take the layout (something else stands where the folder goes)."""


_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def lock(home) -> threading.RLock:
    """One lock per home for everything that moves a held file or its link (``hold``, ``release``, ``guard``, the
    pins' put-back): the launcher does these from several threads (a stop, the every-second check, a key route).
    Re-entrant, and per process: one launcher runs a profile."""
    key = os.path.normcase(os.path.abspath(str(home)))
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


def folder(home) -> Path:
    return Path(home) / DIRNAME


def _target(name: str) -> str:
    return f"{DIRNAME}/{name}"


def is_link(path) -> bool:
    """Whether *path* (a name at the top of a home) is the launcher's own link to its held file."""
    path = Path(path)
    try:
        return os.readlink(path) == _target(path.name)
    except (OSError, ValueError):
        return False


def active(home) -> bool:
    """Whether a sandbox holds this home's credential files (the folder is there)."""
    held = folder(home)
    return held.is_dir() and not held.is_symlink()


def source(path) -> Path:
    """Where the bytes of the home's top-level file *path* are: in the held folder while its name is the
    launcher's link, else under the name itself. A held name with nothing behind it gives a path that does not
    exist: the file is absent."""
    path = Path(path)
    return path.parent / DIRNAME / path.name if is_link(path) else path


def displaced(path) -> Optional[Path]:
    """What has to leave when the file under *path* is replaced: the held file behind the launcher's link, or
    whatever else stands under the name; None when nothing is there."""
    real = source(path)
    return real if os.path.lexists(real) else None


def destination(path) -> Path:
    """Where a file written for the name *path* goes: into the held folder while a sandbox holds the home (call
    ``relink`` afterwards), else under the name."""
    path = Path(path)
    return folder(path.parent) / path.name if active(path.parent) else path


def relink(path) -> bool:
    """Put the launcher's link under the name *path* while a sandbox holds the home. The name must be free or
    hold a link or a file (it is replaced in one step); a folder there has to be moved away first. True when the
    link was made."""
    path = Path(path)
    if not active(path.parent) or is_link(path):
        return False
    tmp = path.parent / f".openshell-link-{secrets.token_hex(6)}"
    os.symlink(_target(path.name), tmp)
    try:
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def quarantine(state_dir, path) -> Path:
    """Move *path* into the launcher's quarantine folder (``<state>/quarantine/<time>/<name>``)."""
    path = Path(path)
    dest = Path(state_dir) / QUARANTINE_DIRNAME / time.strftime("%Y%m%d-%H%M%S")
    dest.mkdir(parents=True, exist_ok=True)
    target, n = dest / path.name, 0
    while os.path.lexists(target):
        n += 1
        target = dest / f"{path.name}.{n}"
    shutil.move(str(path), str(target))
    return target


def _lstat(path) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _held_names(home) -> list[str]:
    """The credential files in the held folder (its regular files, without the launcher's own record)."""
    held = folder(home)
    try:
        names = sorted(os.listdir(held))
    except OSError:
        return []
    return [n for n in names if n != _RECORD and (st := _lstat(held / n)) is not None and stat.S_ISREG(st.st_mode)]


def _linked(home) -> list[str]:
    """The names ``hold`` put its link under, from its record; the held files when the record cannot be read."""
    try:
        names = json.loads((folder(home) / _RECORD).read_text(encoding="utf-8"))
        if isinstance(names, list) and all(isinstance(n, str) and n and "/" not in n and "\\" not in n for n in names):
            return [n for n in names if n not in (".", "..", DIRNAME)]
    except (OSError, ValueError):
        pass
    return _held_names(home)


def hold(home, names: Iterable[str], take_out: Callable[[Path], object], leave: Iterable[str] = ()) -> list[str]:
    """Move the credential files *names* (at the top of *home*) into the held folder and leave the launcher's link
    under each name; ``ALWAYS`` names get the link even when absent. Call only while no sandbox runs over the
    home. A layout left by a launcher that ended without stopping is settled first (``release``). Only regular
    files are moved: a folder, another link or anything else under a name is left to the driver's other ways of
    hiding. Returns the names that now have the link. *take_out* moves a path out of the home for good.

    *leave*: names that are neither moved nor linked, ``ALWAYS`` or not. They are the sign-in files the sandbox
    writes a stand-in for: the launcher took the real file out of the home beforehand (``pins.vacate``), and the
    name has to stay a plain entry the sandbox can create."""
    home = Path(home)
    left = set(leave)
    with lock(home):
        release(home, take_out)
        held = folder(home)
        if os.path.lexists(held):
            raise HeldError(f"{held} is in the way (not a folder the launcher made, or not empty)")
        held.mkdir(mode=0o700)
        os.chmod(held, 0o700)
        linked = []
        for name in dict.fromkeys([*names, *ALWAYS]):
            if not name or name in (".", "..", DIRNAME) or "/" in name or "\\" in name or name in left:
                continue
            top = home / name
            st = _lstat(top)
            if st is None:
                if name not in ALWAYS:
                    continue
            elif stat.S_ISREG(st.st_mode):
                os.rename(top, held / name)
            else:
                continue
            relink(top)
            linked.append(name)
        (held / _RECORD).write_text(json.dumps(linked), encoding="utf-8")
        return linked


def release(home, take_out: Callable[[Path], object]) -> dict:
    """Move every held file back under its name and remove the links and the folder. Call only while no sandbox
    runs over the home. Something that stands under a held name instead of the launcher's link (the sandbox put
    it there, or a program on this computer replaced the name without following the link) is moved out with
    *take_out* first: the held file is the one only this computer wrote. Returns ``{"restored": [names],
    "taken_out": [names]}``; nothing to do without the folder."""
    home = Path(home)
    with lock(home):
        return _release(home, take_out)


def _release(home: Path, take_out: Callable[[Path], object]) -> dict:
    held = folder(home)
    out: dict = {"restored": [], "taken_out": []}
    if active(home):
        for name in _held_names(home):
            top = home / name
            if os.path.lexists(top) and not is_link(top):
                take_out(top)
                out["taken_out"].append(name)
                log.warning("%s was replaced while the sandbox ran; the file that was kept from it is back", top)
            os.replace(held / name, top)
            out["restored"].append(name)
    try:
        with os.scandir(home) as entries:
            links = [entry.path for entry in entries if entry.is_symlink() and is_link(entry.path)]
    except OSError:
        links = []
    for link in links:  # a link of the launcher's with nothing behind it any more
        if not os.path.exists(link):
            try:
                os.unlink(link)
            except OSError:
                pass
    if active(home):
        try:
            (held / _RECORD).unlink(missing_ok=True)
            held.rmdir()
        except OSError as exc:  # not the launcher's files in there: left, and the next hold refuses
            log.warning("could not remove %s: %s", held, exc)
    return out


def guard(home, take_out: Callable[[Path], object]) -> list[str]:
    """While a sandbox runs: every name ``hold`` put its link under must still be that link. Whatever stands there
    instead is moved out with *take_out* and the link is put back. A name ``hold`` left alone (a link or a folder
    of the user's own) is not looked at. Returns the names repaired."""
    home = Path(home)
    with lock(home):
        return _guard(home, take_out)


def _guard(home: Path, take_out: Callable[[Path], object]) -> list[str]:
    if not active(home):
        return []
    repaired = []
    for name in _linked(home):
        top = home / name
        if is_link(top):
            continue
        try:
            if os.path.lexists(top):
                take_out(top)
            relink(top)
        except OSError as exc:
            log.warning("could not put the link for %s back: %s", top, exc)
            continue
        repaired.append(name)
    return repaired
