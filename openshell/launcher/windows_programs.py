"""The two programs a Windows sandbox needs besides OpenShell, installed and checked by the plugin.

* ``wxc-exec``: Microsoft's MXC launcher. OpenShell's MXC driver starts every sandbox through it, and the launcher
  asks it whether this PC can run one (``mxc.py``, ``compat.py``).
* ``busybox``: busybox-w32, the shell of the sandbox's terminal (``busybox_env.py``; Git Bash cannot start there).

Both are pinned in the plugin (``runtime/pins.json``, ``windows_programs``) and land in the host-only runtime
folder, each alone in a folder named for its pin and the PC's architecture:

    <hermes root>/openshell/runtime/programs/<pin id>-<x64|arm64>/<file>

The sandbox is granted the shell's folder read-only, which is why that folder holds the shell and nothing else.
No record is kept beside the files: a program is installed when the file at its pin's path has the pinned sha256.
A pin with another ``id`` names another folder, so the new build is installed beside the old one; a file that no
longer matches its pin is installed again before anything uses it.

What an install does, in this order, in a staging folder of its own beside the targets:

1. Download: the file itself, or the archive that holds it. An archive is refused unless it matches the pinned
   ``integrity`` (the digest npm publishes for a package), and exactly one member is read out of it, by its pinned
   name; nothing is unpacked, and an archive with an entry whose path could lead out of a folder is refused.
2. The file must have the pinned sha256.
3. It must be a Windows program built for this PC's architecture.
4. A pin that names a ``signer`` requires a valid Authenticode signature of that publisher, as for OpenShell's
   own programs (``openshell_install._check_publisher``). A pin whose ``signer`` is null says that the program is
   published without a signature: only its sha256 is checked. A signed build later needs the publisher's name in
   the pin and no change here.
5. Only then is the folder that holds the file moved into place. Nothing here runs the file.
"""
from __future__ import annotations

import base64
import logging
import os
import shutil
import stat
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Optional

from . import authenticode, hostarch
from . import openshell_install as inst
from .openshell_install import Fetch, InstallError

log = logging.getLogger("openshell.install")

PROGRAMS = ("wxc-exec", "busybox")
DIRNAME = "programs"  # Under <root>/openshell/runtime/
# The variable that names a person's own copy of each program; it is used instead of the plugin's.
ENV = {"wxc-exec": "OPENSHELL_WXC_EXEC_PATH", "busybox": "OPENSHELL_BUSYBOX"}
_WHAT = {"wxc-exec": "the MXC package", "busybox": "the sandbox's shell"}  # The pinned thing, before its id
_ROLE = {"wxc-exec": "MXC, which starts the sandbox", "busybox": "the sandbox's shell"}
_BUILD_WORD = {"x86_64": "x64", "aarch64": "arm64"}
_INTEGRITY = ("sha512", "sha384", "sha256")  # The digests an npm integrity value can carry
_SPEC_KEY = {"wxc-exec": "wxc_exec", "busybox": "busybox"}
PINNED = "pinned install"  # The ``source`` of a file the plugin installed itself
NOT_INSTALLED = ("not installed yet: `hermes sandbox runtime install` installs it, and so does switching the "
                 "sandbox on")
# (file, pinned sha256) -> (size, mtime) the file had when it last hashed to that pin. A look at what is installed
# (``installed``, ``chosen``, ``status``) trusts a file that has not changed since; a use (``ensure``) never does.
_seen: dict = {}


def programs_dir(root: Path) -> Path:
    return inst.runtime_dir(root) / DIRNAME


def pinned(name: str, *, arch: Optional[str] = None) -> dict:
    """The pin of *name* for this PC's architecture (or *arch*): ``id``, ``version``, ``source``, ``signer``,
    ``arch``, ``file``, ``sha256`` and ``url``; for a file that is one member of an archive, ``url`` is the
    archive's, with its ``integrity`` (algorithm, base64 digest) and the ``member`` path."""
    block = (inst.load_pins().get("windows_programs") or {}).get(name)
    if not isinstance(block, dict) or not inst.plain_name(block.get("id")):
        raise InstallError(f"this version of the plugin pins no {name} for Windows")
    arch = arch or inst.windows_arch()
    builds = block.get("builds") if isinstance(block.get("builds"), dict) else {}
    build = builds.get(arch) if arch in _BUILD_WORD else None
    if not isinstance(build, dict):
        have = ", ".join(hostarch.label(a) for a in _BUILD_WORD if isinstance(builds.get(a), dict)) or "no"
        raise InstallError(f"{_WHAT[name]} {block['id']} has no build for Windows on {hostarch.label(arch)}; "
                           f"this version of the plugin supports {have} Windows PCs")
    pin = {"name": name, "arch": arch, **{k: block.get(k) for k in ("id", "version", "source", "signer")},
           "file": build.get("file"), "sha256": str(build.get("sha256") or "").lower()}
    if not inst.plain_name(pin["file"]) or len(pin["sha256"]) != 64:
        raise InstallError(f"the pin of {_WHAT[name]} {block['id']} must name a plain file name and its sha256")
    if build.get("member"):  # One member of an archive, which is pinned by its integrity
        archive = block.get("archive") if isinstance(block.get("archive"), dict) else {}
        algorithm, _, digest = str(archive.get("integrity") or "").partition("-")
        if not archive.get("url") or algorithm not in _INTEGRITY or not digest:
            raise InstallError(f"the pin of {_WHAT[name]} {block['id']} must name its archive's url and integrity "
                               f"({' or '.join(_INTEGRITY)}, as npm publishes it)")
        pin.update(url=str(archive["url"]), integrity=(algorithm, digest), member=str(build["member"]))
    elif build.get("url"):
        pin["url"] = str(build["url"])
    else:
        raise InstallError(f"the pin of {_WHAT[name]} {block['id']} names nothing to download")
    return pin


def path(root: Path, pin: dict) -> Path:
    """Where the pinned build of a program is installed."""
    return programs_dir(root) / f"{pin['id']}-{_BUILD_WORD[pin['arch']]}" / pin["file"]


def _matches(file: Path, pin: dict, *, unchanged_counts: bool = False) -> bool:
    """Whether *file* is there and has the pinned sha256. With *unchanged_counts*, a file that has the size and
    the time it had when it last matched is not read again."""
    key = (str(file), pin["sha256"])
    try:
        info = file.stat()
        if not stat.S_ISREG(info.st_mode):
            return False
        mark = (info.st_size, info.st_mtime_ns)
        if unchanged_counts and _seen.get(key) == mark:
            return True
        same = inst.sha256_file(file) == pin["sha256"]
    except OSError:
        return False
    if same:
        _seen[key] = mark
    return same


def installed(root: Path, name: str, *, arch: Optional[str] = None) -> Optional[Path]:
    """The installed file of *name* when it is there and has the pinned sha256, else None. Reads only."""
    try:
        pin = pinned(name, arch=arch)
    except InstallError:
        return None
    file = path(root, pin)
    return file if _matches(file, pin, unchanged_counts=True) else None


def ensure(root: Path, name: str, *, fetch: Optional[Fetch] = None, arch: Optional[str] = None) -> Path:
    """The pinned build of *name*, installed and checked: its sha256 is compared with the pin on every call, and
    the build is installed when it is missing, when the pin changed, or when the file no longer matches."""
    pin = pinned(name, arch=arch)
    file = path(root, pin)
    if _matches(file, pin):
        return file
    return _install(root, pin, file, fetch or inst._download)


def _install(root: Path, pin: dict, file: Path, fetch: Fetch) -> Path:
    what = _WHAT[pin["name"]]
    base = inst._private_dir(inst._private_dir(inst.runtime_dir(root)) / DIRNAME)
    staging = Path(tempfile.mkdtemp(prefix=f".staging-{pin['id']}-", dir=base))
    try:
        got = staging / pin["file"]
        download = staging / "package.tgz" if pin.get("member") else got
        try:
            fetch(pin["url"], download)
        except InstallError as exc:
            raise InstallError(
                f"{pin['file']} ({_ROLE[pin['name']]}) is not installed and could not be downloaded: {exc}. "
                f"Check this PC's internet connection and try again, or set {ENV[pin['name']]} to a copy you "
                f"already have.") from exc
        origin = pin["url"]
        if pin.get("member"):
            _check_integrity(download, pin)
            _read_member(download, pin["member"], got, what)
            origin = f"{pin['url']} ({pin['member']})"
        have = inst.sha256_file(got)
        if have != pin["sha256"]:
            raise InstallError(f"{pin['file']} from {origin} has sha256 {have[:12]}..., pinned "
                               f"{pin['sha256'][:12]}...; refused")
        built = hostarch.pe_machine(got)
        if built is None:
            raise InstallError(f"{pin['file']} of {what} {pin['id']} is not a Windows program; refused")
        if built != pin["arch"]:
            raise InstallError(f"{pin['file']} of {what} {pin['id']} is built for {hostarch.label(built)}, but this "
                               f"PC is {hostarch.label(pin['arch'])}; refused")
        payload = staging / "payload"  # The folder that is moved into place: it holds the one checked file
        payload.mkdir()
        os.replace(got, payload / pin["file"])
        inst._check_publisher(payload, {"id": pin["id"], "signer": pin["signer"],
                                        "binaries": {pin["file"]: pin["sha256"]}}, what)
        _put_in_place(payload, file, pin)
        if not _matches(file, pin):  # The installed copy, read once more where it will be used from
            raise InstallError(f"{pin['file']} of {what} {pin['id']} changed while it was installed; refused")
        log.info("installed %s of %s %s at %s", pin["file"], what, pin["id"], file)
        return file
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _check_integrity(archive: Path, pin: dict) -> None:
    """Refuse a downloaded archive whose digest is not the pinned one (``<algorithm>-<base64 digest>``)."""
    algorithm, want = pin["integrity"]
    got = base64.b64encode(inst.file_digest(archive, algorithm).digest()).decode()
    if got != want:
        raise InstallError(f"{pin['url']} does not match its pinned integrity ({algorithm}-{got[:12]}..., pinned "
                           f"{algorithm}-{want[:12]}...); refused")


def _read_member(archive: Path, member: str, dest: Path, what: str) -> None:
    """Write the one file *member* of the gzipped tar *archive* to *dest*, and nothing else: no other entry is
    written to disk, and the file gets the name the caller chose, never a path taken from the archive.

    Refused: an archive that cannot be read; one with an entry whose path is absolute or holds a backslash, a
    colon, a NUL, or an empty, ``.`` or ``..`` step; one that lacks *member* or holds that path more than once
    (in any letter case); and a *member* that is a link, a folder or anything else that is not a plain file."""
    label = what[4:] if what.startswith("the ") else what
    try:
        with tarfile.open(archive, "r:gz") as tar:
            found = []
            for info in tar:
                if inst.entry_steps(info.name) is None:
                    raise InstallError(f"{what} has an entry with an unsafe path ({info.name[:120]!r}); refused")
                if info.name.lower() == member.lower():
                    found.append(info)
            if len(found) > 1:
                raise InstallError(f"{what} has more than one {member}; refused")
            if not found or found[0].name != member:
                raise InstallError(f"{what} has no {member}; refused")
            if not found[0].isreg():
                raise InstallError(f"{member} in {what} is not a plain file; refused")
            with tar.extractfile(found[0]) as src, open(dest, "wb") as fh:
                shutil.copyfileobj(src, fh, 1 << 20)
    except (tarfile.TarError, zlib.error, EOFError, OSError) as exc:
        raise InstallError(f"the downloaded {label} is not a readable .tgz file ({exc}); refused") from exc


def _put_in_place(payload: Path, file: Path, pin: dict) -> None:
    """Move the checked folder to its final name. A folder already there holds a file that no longer matches
    the pin, or the same build installed a moment ago by another launcher, which is kept."""
    try:
        if file.parent.exists():
            if _matches(file, pin):
                return
            shutil.rmtree(file.parent)
        os.replace(payload, file.parent)
    except OSError as exc:
        if _matches(file, pin):
            return
        raise InstallError(f"could not put {pin['file']} in place at {file.parent} ({exc}); if a sandbox is "
                           f"running, switch it off and try again") from exc


# -- which file the launcher uses ---------------------------------------------------------------------------

def _on_windows() -> bool:
    return os.name == "nt"


def supported(name: str) -> bool:
    """Whether the plugin installs *name* itself here: on Windows, with a pinned build for this PC."""
    if not _on_windows():
        return False
    try:
        pinned(name)
    except InstallError:
        return False
    return True


def own(name: str, spec: Optional[dict] = None) -> dict:
    """The person's own copy of *name*, when one is named and is there: the profile's sandbox spec first
    (``--wxc-exec`` / ``--busybox``, saved by ``sandbox serve``), then the variable (``ENV``). A named file that
    does not exist is skipped and listed. Returns ``{"file": Path | None, "source", "ignored": [...]}``."""
    spec = spec if isinstance(spec, dict) else {}
    key = _SPEC_KEY[name]
    named = [("spec", spec.get(key))]
    if name == "wxc-exec" and isinstance(spec.get("openshell"), dict):
        named.append(("spec", spec["openshell"].get(key)))
    named.append((f"variable {ENV[name]}", os.environ.get(ENV[name])))
    ignored = []
    for source, value in named:
        if not value:
            continue
        if Path(value).is_file():
            return {"file": Path(value).resolve(), "source": source, "ignored": ignored}
        ignored.append({"source": source, "file": str(value), "reason": "no such file"})
    return {"file": None, "source": None, "ignored": ignored}


def on_path(name: str) -> Optional[Path]:
    """*name* as found without the plugin's own install: ``wxc-exec`` on PATH; the shell on PATH or in the
    plugin's ``bin`` folder."""
    if name == "busybox":
        from ..busybox_env import find_busybox

        found = find_busybox()
    else:
        found = shutil.which("wxc-exec")
    return Path(found).resolve() if found else None


def _pick(name: str, spec: Optional[dict], root: Path, install: bool, fetch: Optional[Fetch]) -> dict:
    out = {"name": name, **own(name, spec)}
    if out["file"] is not None:
        return out
    if supported(name):
        file = ensure(root, name, fetch=fetch) if install else installed(root, name)
        out.update(file=file, source=PINNED, installed=file is not None)
    else:
        found = on_path(name)
        if found is not None:
            out.update(file=found, source="PATH")
    return out


def chosen(name: str, spec: Optional[dict], root: Path) -> dict:
    """Which file the launcher uses for *name* and where it comes from; nothing is installed or downloaded.

    The person's own copy wins (``own``: ``source`` is ``spec`` or ``variable <NAME>``). Without one, the plugin's
    own install is the file (``source`` ``pinned install``; ``installed`` says whether it is there with the pinned
    sha256, and ``file`` is None until it is). Only where the plugin installs none (not Windows, or no pinned build
    for this PC) is a program on PATH used (``source`` ``PATH``). ``ignored`` lists named files that do not exist."""
    return _pick(name, spec, root, False, None)


def use(name: str, spec: Optional[dict], root: Path, *, fetch: Optional[Fetch] = None) -> dict:
    """As ``chosen``, for a caller about to use the file: the plugin's own copy is installed when it is missing
    and its sha256 is compared with the pin again (``ensure``). Raises ``InstallError`` when that fails."""
    return _pick(name, spec, root, True, fetch)


def status(root: Path, spec: Optional[dict] = None) -> dict:
    """What ``sandbox check`` and ``sandbox runtime status`` print for the two programs. For each: ``file`` and
    ``source`` as ``chosen`` gives them; for that file its ``sha256``, ``is_pinned_build`` and what Windows says of
    its signature now (``signature``: ``valid``, ``unsigned``, ``invalid`` or ``not checked``; ``signer``);
    ``pinned``, the build the plugin installs; ``installed`` for the plugin's own copy; ``ignored`` when a named
    file was skipped."""
    out = {}
    for name in PROGRAMS:
        got = chosen(name, spec, root)
        row: dict = {"file": str(got["file"]) if got["file"] else None, "source": got["source"]}
        if "installed" in got:
            row["installed"] = got["installed"]
        try:
            pin = pinned(name)
            row["pinned"] = {k: pin[k] for k in ("id", "version", "arch", "file", "sha256", "signer")}
        except InstallError as exc:
            pin = None
            row["pinned"] = {"error": str(exc)}
        if got["file"] is not None:
            row.update(_facts(got["file"], pin))
        else:
            row["note"] = NOT_INSTALLED if got["source"] == PINNED else "not found"
        if got["ignored"]:
            row["ignored"] = got["ignored"]
        out[name] = row
    return out


def _facts(file: Path, pin: Optional[dict]) -> dict:
    """What *file* is: its sha256, whether that is the pinned one, and its signature as Windows reads it now."""
    try:
        sha = inst.sha256_file(file)
    except OSError as exc:
        return {"sha256": None, "is_pinned_build": False, "error": str(exc)}
    facts = {"sha256": sha, "is_pinned_build": bool(pin) and sha == pin["sha256"]}
    try:
        got = authenticode.signature(file)
        facts.update(signature=got["status"], signer=got.get("signer"))
    except authenticode.Unavailable:
        facts.update(signature="not checked", signer=None)
    return facts


def prune(root: Path) -> list[str]:
    """Remove from the programs folder what no pin names: the builds of an earlier pin, and what an interrupted
    install left. Only for a moment when no sandbox runs: a running one may still use the shell of an earlier
    pin. Removes nothing when a pin cannot be read. Returns the names removed."""
    base = programs_dir(root)
    if not base.is_dir():
        return []
    try:
        keep = {path(root, pinned(name)).parent.name for name in PROGRAMS}
    except InstallError:
        return []
    removed = []
    for child in sorted(base.iterdir()):
        if child.name in keep:
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        except OSError:
            continue
        removed.append(child.name)
    return removed
