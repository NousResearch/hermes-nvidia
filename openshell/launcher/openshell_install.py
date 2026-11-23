"""Install pinned, verified OpenShell binaries for this Hermes root.

Everything lands under the host-only ``<hermes root>/openshell/runtime/`` (no sandbox is granted it, but for
the one folder that holds a Windows sandbox's shell, read-only; the default profile's sandbox has
``<root>/openshell`` denied):

    runtime/installed.json        {"current": <id>}
    runtime/<id>/bin/             the binaries (openshell, openshell-gateway, ...)
    runtime/<id>/python/          Linux: the OpenShell SDK wheel plus any of its dependencies the
                                  Hermes environment lacks (the launcher's Linux driver speaks gRPC)
    runtime/<id>/identity.json    what was verified: source, asset and binary sha256s, images
    runtime/programs/             Windows: MXC's wxc-exec and the sandbox's shell, each alone in a folder of
                                  its own (windows_programs.py)
    runtime/gateway/              the private gateway (gateway_service.py)
    runtime/base-image.json       Linux: the locally built sandbox base image (base_image.py)

What is pinned lives in the plugin (``runtime/pins.json``), never in user-writable state:

* Linux: one OpenShell release. Its four checksum files are pinned by sha256; every asset must match
  its line in those files before anything is extracted. The Docker driver's runtime images are pulled
  by pinned digest and the binary inside each must be byte-identical to the verified release asset.
  The SDK's Python dependencies are pinned wheels (sha256 each).
* Windows: NVIDIA's signed Windows package from an OpenShell release, one zip per architecture
  (``windows.archive``: ``{"url", "sha256"}``). The installer downloads the zip and refuses it unless it
  matches its pinned sha256. It unpacks only the files named under ``binaries``, which must sit together
  in the zip's one ``<top folder>/bin/`` (or at its top level); the zip's scripts, SDKs and documents are
  never written to disk. Each file must match its own pinned sha256. On Windows each installed file must
  also carry a valid Authenticode signature of the pinned publisher (``windows.signer``; see
  ``authenticode.py``). A folder that already holds the files installs the same way, without a download
  (``hermes sandbox runtime install --build-dir DIR`` or ``HERMES_OPENSHELL_BUILD_DIR``).
  One pin covers both Windows architectures, built from the same source: the top-level ``binaries``
  and ``archive`` are the x64 package, and an ``aarch64`` block names the Arm64 package with its own
  ``id``, ``binaries`` and ``archive``. The installer picks the machine's own architecture
  (``hostarch.windows_native_arch``: an x64 Python emulated on Arm64 still installs the Arm64 package).

Installs are staged beside the target and renamed into place, so a half-finished install is never
``current``; the gateway's bootstrap re-checks the binary hashes at every start.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import platform as _platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Callable, Optional

from . import authenticode, hostarch
from .driver import DriverUnavailable

log = logging.getLogger("openshell.install")

RUNTIME_DIRNAME = "runtime"  # under <root>/openshell/ (layout.STATE_DIRNAME)
INSTALLED_FILE = "installed.json"
IDENTITY_FILE = "identity.json"
BUILD_DIR_ENV = "HERMES_OPENSHELL_BUILD_DIR"  # Windows: a folder that holds the pinned files
PINS_PATH = Path(__file__).resolve().parent.parent / "runtime" / "pins.json"
_EXE = ".exe" if os.name == "nt" else ""
# Windows architectures a pin can carry a build for. x86_64 is the pin's top level; any other has its own block.
WINDOWS_ARCHES = ("x86_64", "aarch64")


class InstallError(DriverUnavailable):
    """OpenShell could not be installed or failed verification."""


Fetch = Callable[[str, Path], None]


def load_pins() -> dict:
    return json.loads(PINS_PATH.read_text(encoding="utf-8"))


def platform_key(sys_platform: Optional[str] = None) -> str:
    p = sys_platform or sys.platform
    if p.startswith("win"):
        return "windows"
    if p == "darwin":
        return "darwin"
    return "linux"


def runtime_dir(root: Path) -> Path:
    return Path(root) / "openshell" / RUNTIME_DIRNAME


def pinned(platform: Optional[str] = None, *, arch: Optional[str] = None) -> dict:
    """The pin for *platform* (default: this one). On Windows, the build for *arch* (default: this machine's own
    architecture), with ``arch`` set."""
    key = platform or platform_key()
    pins = load_pins()
    if key not in ("linux", "windows"):
        raise InstallError(f"OpenShell is not available for {key} yet (Linux and Windows only).")
    if key == "windows":
        return windows_pin(pins[key], arch or windows_arch())
    return pins[key]


def windows_arch() -> str:
    """This Windows machine's architecture (``x86_64``, ``aarch64``, ...), not the interpreter's."""
    return hostarch.windows_native_arch()


def windows_pin(pin: dict, arch: str) -> dict:
    """The Windows build for *arch* out of the shared pin. The top-level ``binaries`` and ``archive`` are the x64
    build; ``pin[<arch>]`` names another architecture's build of the same source (same ``version`` and
    ``features``): its own ``id``, ``binaries``, and optional ``archive`` and ``source``."""
    common = {k: v for k, v in pin.items() if k not in WINDOWS_ARCHES}
    if arch == "x86_64" and common.get("binaries"):
        return {**common, "arch": arch}
    block = pin.get(arch) if arch in WINDOWS_ARCHES and arch != "x86_64" else None
    if not isinstance(block, dict) or not block.get("id") or not block.get("binaries"):
        raise InstallError(f"the pinned OpenShell build {pin.get('id')} has no build for Windows on "
                           f"{hostarch.label(arch)}; this plugin version supports "
                           f"{', '.join(hostarch.label(a) for a in windows_arches(pin)) or 'no'} Windows PCs")
    out = {k: v for k, v in common.items() if k != "archive"}
    out.update({k: block[k] for k in ("id", "binaries", "archive", "source") if block.get(k)})
    out["arch"] = arch
    return out


def windows_arches(pin: Optional[dict] = None) -> list[str]:
    """The Windows architectures the pin (default: the shipped one) has a build for."""
    pin = (load_pins().get("windows") or {}) if pin is None else pin
    found = ["x86_64"] if pin.get("binaries") else []
    return found + [a for a in WINDOWS_ARCHES if a != "x86_64" and isinstance(pin.get(a), dict)
                    and pin[a].get("id") and pin[a].get("binaries")]


def file_digest(path: Path, algorithm: str = "sha256"):
    """The hash object of the file at *path* (``hashlib``'s *algorithm*), read in pieces."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h


def sha256_file(path: Path) -> str:
    return file_digest(path).hexdigest()


def plain_name(name) -> bool:
    """Whether *name* is a file name and nothing more: no folder step, no drive, not ``.`` or ``..``."""
    return bool(name) and isinstance(name, str) and name not in (".", "..") \
        and not any(mark in name for mark in ("/", "\\", ":", "\0"))


def entry_steps(raw: str) -> Optional[list]:
    """The folder steps of an archive entry's path as the archive stores it, or None when the path could lead
    out of the folder it is unpacked into: absolute, or holding a backslash, a colon, a NUL, or an empty, ``.``
    or ``..`` step."""
    steps = raw[:-1].split("/") if raw.endswith("/") else raw.split("/")
    if "\\" in raw or ":" in raw or "\0" in raw or any(step in ("", ".", "..") for step in steps):
        return None
    return steps


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
    return path


# -- what is installed --------------------------------------------------------------------------

def installed(root: Path) -> Optional[dict]:
    """The current install's identity, or None (nothing installed, or a broken record)."""
    base = runtime_dir(root)
    try:
        current = json.loads((base / INSTALLED_FILE).read_text(encoding="utf-8")).get("current")
        ident = json.loads((base / str(current) / IDENTITY_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return ident if ident.get("id") == current else None


def identity_dir(root: Path, ident: dict) -> Path:
    return runtime_dir(root) / ident["id"]


def bin_path(root: Path, ident: dict, name: str) -> Path:
    """``name`` without extension (``openshell``, ``openshell-gateway``, ...)."""
    return identity_dir(root, ident) / "bin" / (name + (".exe" if ident.get("platform") == "windows" else ""))


def sdk_path(root: Path, ident: dict) -> Optional[Path]:
    path = identity_dir(root, ident) / "python"
    return path if ident.get("sdk") and path.is_dir() else None


def verify(root: Path, ident: dict) -> None:
    """Re-hash every installed binary against the identity recorded at install time."""
    for name, want in (ident.get("binaries") or {}).items():
        path = identity_dir(root, ident) / "bin" / name
        try:
            got = sha256_file(path)
        except OSError as exc:
            raise InstallError(f"installed OpenShell file {path} is unreadable ({exc}); reinstall it") from exc
        if got != want:
            raise InstallError(f"installed OpenShell file {path} no longer matches its pinned sha256 "
                               f"({got[:12]}..., expected {want[:12]}...); refusing to run it")


def ensure_installed(root: Path, *, platform: Optional[str] = None, build_dir: Optional[Path] = None,
                     container_cli: Optional[str] = None, fetch: Optional[Fetch] = None,
                     run=subprocess.run) -> dict:
    """The pinned OpenShell for this platform, installed and verified (installs it when missing or when
    the pin changed). Windows installs from a build directory (argument or ``HERMES_OPENSHELL_BUILD_DIR``)
    when one is given, else from the pinned archive."""
    key = platform or platform_key()
    want = pinned(key)
    have = installed(root)
    # Windows: the same id built for another architecture (a Hermes root moved to another PC) is not this PC's build.
    same_arch = "arch" not in want or have is None or have.get("arch") in (None, want["arch"])
    if have is not None and have.get("id") == want["id"] and same_arch:
        verify(root, have)
        return have
    if key == "windows":
        build = build_dir or os.environ.get(BUILD_DIR_ENV)
        if build:
            return install_windows(root, Path(build))
        if (want.get("archive") or {}).get("url"):
            return install_windows_archive(root, fetch=fetch)
        raise InstallError(f"OpenShell for Windows is not installed and the pin names no archive to download. "
                           f"Install the pinned {hostarch.label(want['arch'])} build {want['id']} once: "
                           f"`hermes sandbox runtime install --build-dir <dir>` (or set {BUILD_DIR_ENV}).")
    return install_linux(root, container_cli=container_cli, fetch=fetch, run=run)


def _activate(root: Path, staging: Path, ident: dict) -> dict:
    """Move a verified staging dir into place as ``<id>`` and make it current."""
    base = runtime_dir(root)
    target = base / ident["id"]
    _write_json(staging / IDENTITY_FILE, ident)
    if target.exists():  # a broken earlier attempt at the same id (never current: installed() said so)
        shutil.rmtree(target)
    os.replace(staging, target)
    _write_json(base / INSTALLED_FILE, {"current": ident["id"], "installed_at": time.time()})
    return ident


def _staging(root: Path, ident_id: str) -> Path:
    base = _private_dir(runtime_dir(root))
    return Path(tempfile.mkdtemp(prefix=f".staging-{ident_id}-", dir=base))


def prune(root: Path, keep: set) -> list[str]:
    """Remove installed runtimes not in *keep* (ids) and leftover staging dirs."""
    removed = []
    base = runtime_dir(root)
    if not base.is_dir():
        return removed
    for child in base.iterdir():
        if not child.is_dir() or child.name in keep or child.name == "gateway":
            continue
        if child.name.startswith(".staging-") or (child / IDENTITY_FILE).is_file():
            shutil.rmtree(child, ignore_errors=True)
            removed.append(child.name)
    return removed


# -- Windows: the pinned archive, or a folder holding the same files ----------------------------

def install_windows(root: Path, build_dir: Path, *, origin: Optional[dict] = None) -> dict:
    """Install the pinned build from *build_dir*, refusing any file whose sha256 differs from the pin and,
    when the pin names a ``signer``, any file that publisher did not sign (``_check_publisher``).
    *origin* replaces ``source_dir`` in the identity (the pinned archive it was unpacked from)."""
    want = pinned("windows")
    build_dir = Path(build_dir).expanduser().resolve()
    if not build_dir.is_dir():
        raise InstallError(f"OpenShell build directory {build_dir} does not exist")
    where = (origin or {}).get("source_archive") or build_dir
    mismatched, found = [], {}
    for name, sha in want["binaries"].items():
        path = build_dir / name
        if not path.is_file():
            mismatched.append(f"{name}: missing")
            continue
        got = sha256_file(path)
        if got != sha:
            mismatched.append(f"{name}: sha256 {got[:12]}... (pinned {sha[:12]}...)")
        found[name] = got
    if mismatched:
        raise InstallError(f"{where} is not the pinned OpenShell build {want['id']}; refused: "
                           + "; ".join(mismatched) + _other_arch_hint(build_dir, want))
    staging = _staging(root, want["id"])
    try:
        (staging / "bin").mkdir()
        for name in want["binaries"]:
            shutil.copy2(build_dir / name, staging / "bin" / name)
            if sha256_file(staging / "bin" / name) != want["binaries"][name]:  # the copy, not the source
                raise InstallError(f"copy of {name} changed while installing; refused")
        signed = _check_publisher(staging / "bin", want)  # the copies that will run, after their hashes matched
        ident = {"id": want["id"], "version": want["version"], "platform": "windows",
                 "arch": want.get("arch") or "x86_64",
                 "source": want["source"], **(origin or {"source_dir": str(build_dir)}), **signed,
                 "binaries": dict(want["binaries"]), "features": list(want.get("features") or []), "sdk": False,
                 "installed_at": time.time()}
        return _activate(root, staging, ident)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _check_publisher(bin_dir: Path, want: dict, what: str = "the OpenShell build") -> dict:
    """A pin that names a ``signer``: every file in *bin_dir* must carry a valid Authenticode signature whose
    signing certificate has that common name. A file that is unsigned, whose signature Windows does not accept,
    or that someone else signed refuses the install. When the check itself cannot run (``authenticode.Unavailable``:
    not Windows, the API missing or failing) the install goes on with the sha256 pins it has already passed, and
    one line is logged. Returns what the identity records: ``signer`` and ``signature`` (``valid`` or
    ``not checked``); nothing for a pin without a signer. *what* names the pinned thing in the messages (the
    OpenShell build, or one of the programs in ``windows_programs.py``)."""
    signer = want.get("signer")
    if not signer:
        return {}
    try:
        for name in want["binaries"]:
            got = authenticode.signature(bin_dir / name)
            if got["status"] == authenticode.UNSIGNED:
                raise InstallError(f"{name} of {what} {want['id']} is not signed; the pinned build is "
                                   f"signed by {signer}. Refused.")
            if got["status"] != authenticode.VALID:
                raise InstallError(f"Windows does not accept the signature on {name} of {what} "
                                   f"{want['id']}: {got.get('detail')}. Refused.")
            if got.get("signer") != signer:
                raise InstallError(f"{name} of {what} {want['id']} is signed by {got.get('signer')!r}, "
                                   f"not by {signer}. Refused.")
    except authenticode.Unavailable as exc:
        log.warning("%s %s: the %s signatures could not be checked (%s); installed on the pinned sha256 "
                    "checksums alone", what, want["id"], signer, exc)
        return {"signer": signer, "signature": "not checked"}
    return {"signer": signer, "signature": "valid"}


def _other_arch_hint(build_dir: Path, want: dict) -> str:
    """When *build_dir* holds the pinned build for another Windows architecture, say so (an x64 build copied to
    an Arm64 PC, or the reverse); else ``""``."""
    try:
        pin = load_pins().get("windows") or {}
        for arch in windows_arches(pin):
            if arch == want.get("arch"):
                continue
            other = windows_pin(pin, arch)
            if all((build_dir / n).is_file() and sha256_file(build_dir / n) == s for n, s in other["binaries"].items()):
                return (f". It holds the {hostarch.label(arch)} build {other['id']}; this PC needs the "
                        f"{hostarch.label(want.get('arch') or 'x86_64')} build {want['id']}")
    except (OSError, ValueError, InstallError):
        pass
    return ""


def install_windows_archive(root: Path, *, fetch: Optional[Fetch] = None) -> dict:
    """Download the pinned Windows archive (``windows.archive``), refuse it unless its sha256 is the pinned
    one, unpack only the pinned files and install them as ``install_windows`` does (each file against its own
    pinned sha256, then the publisher's signature). Nothing is kept of the download."""
    want = pinned("windows")
    archive = want.get("archive") or {}
    url, sha = archive.get("url"), str(archive.get("sha256") or "").lower()
    if not url or len(sha) != 64:
        raise InstallError(f"the pinned OpenShell build {want['id']} names no archive to download (url and sha256)")
    scratch = _staging(root, want["id"])
    try:
        path = scratch / "openshell-windows.zip"
        (fetch or _download)(url, path)
        got = sha256_file(path)
        if got != sha:
            raise InstallError(f"{url} has sha256 {got[:12]}..., pinned {sha[:12]}...; refused")
        build = scratch / "build"
        _unpack_pinned(path, want["binaries"], build)
        return install_windows(root, build, origin={"source_archive": url, "archive_sha256": got})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _unpack_pinned(archive: Path, names, dest: Path) -> None:
    """Extract each of *names* from the zip *archive* into *dest*, and nothing else: the zip's other entries
    (scripts, SDKs, documents, license files) are never written to disk, and a file is written under its pinned
    name, never under a path taken from the zip.

    The files must sit together in one folder of the zip: ``<top folder>/bin/`` (NVIDIA's Windows packages) or
    the top level. Refused: a name the zip lacks; a name it holds more than once, in any folder and in any
    letter case; a name in any other folder; names spread over two folders; a zip with an entry whose path is
    absolute or holds a backslash, a colon, a NUL, or a ``.`` or ``..`` step; and a pinned file that cannot be
    read out of the zip (damaged, or stored in a way Python's zipfile does not handle)."""
    dest.mkdir(parents=True)
    wanted = {}
    for name in names:
        if not plain_name(name):
            raise InstallError(f"pinned file name {name!r} is not a plain file name")
        wanted[name.lower()] = name
    try:
        z = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise InstallError(f"the downloaded OpenShell archive is not a readable zip file ({exc}); refused") from exc
    with z:
        found: dict = {}
        for info in z.infolist():
            raw = getattr(info, "orig_filename", None) or info.filename  # as stored: Windows rewrites backslashes
            steps = entry_steps(raw)
            if steps is None:
                raise InstallError(f"the OpenShell archive has an entry with an unsafe path ({raw[:120]!r}); refused")
            name = wanted.get(steps[-1].lower())
            if name is not None and not raw.endswith("/"):
                found.setdefault(name, []).append((tuple(steps[:-1]), info))
        folders = set()
        for name in names:
            entries = found.get(name) or []
            if len(entries) != 1:
                raise InstallError(f"the OpenShell archive has {'no' if not entries else 'more than one'} {name}; "
                                   "refused")
            folder = entries[0][0]
            if folder and not (len(folder) == 2 and folder[1] == "bin"):
                raise InstallError(f"the OpenShell archive holds {name} in {'/'.join(folder)}/, not in its "
                                   "<top folder>/bin/ or at its top level; refused")
            folders.add(folder)
        if len(folders) > 1:
            raise InstallError("the OpenShell archive holds the pinned files in more than one folder ("
                               + ", ".join(sorted("/".join(f) + "/" if f else "its top level" for f in folders))
                               + "); refused")
        for name in names:
            try:
                with z.open(found[name][0][1]) as src, open(dest / name, "wb") as fh:
                    shutil.copyfileobj(src, fh, 1 << 20)
            except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError) as exc:
                raise InstallError(f"the OpenShell archive's {name} cannot be unpacked ({exc}); refused") from exc


# -- Linux: the pinned release ------------------------------------------------------------------

def _download(url: str, dest: Path, timeout: float = 120.0, attempts: int = 3) -> None:
    tmp = dest.with_name(dest.name + ".part")
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hermes-openshell-plugin"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
                shutil.copyfileobj(resp, fh, 1 << 20)
            os.replace(tmp, dest)
            return
        except OSError as exc:
            last = exc
            time.sleep(1.5 * (i + 1))
    raise InstallError(f"could not download {url}: {last}")


def linux_arch(machine: Optional[str] = None) -> str:
    m = (machine or _platform.machine()).lower()
    return {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(m, m)


def parse_checksums(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1].lstrip("*")] = parts[0].lower()
    return out


def install_linux(root: Path, *, container_cli: Optional[str] = None, fetch: Optional[Fetch] = None,
                  run=subprocess.run, machine: Optional[str] = None) -> dict:
    want = pinned("linux")
    fetch = fetch or _download
    arch = linux_arch(machine)
    assets = want["assets"].get(arch)
    if not assets:
        raise InstallError(f"OpenShell {want['version']} has no Linux release for {arch}")
    staging = _staging(root, want["id"])
    try:
        dl = staging / "downloads"
        dl.mkdir()
        sums: dict = {}
        for name, sha in want["checksum_files"].items():  # the trust anchor, pinned in the plugin
            fetch(f"{want['release_url']}/{name}", dl / name)
            got = sha256_file(dl / name)
            if got != sha:
                raise InstallError(f"release checksum file {name} has sha256 {got[:12]}..., pinned {sha[:12]}...; refused")
            sums.update(parse_checksums((dl / name).read_text(encoding="utf-8")))
        verified = {}
        for asset in assets.values():
            expected = sums.get(asset)
            if not expected:
                raise InstallError(f"{asset} is not listed in the release checksum files; refused")
            fetch(f"{want['release_url']}/{asset}", dl / asset)
            got = sha256_file(dl / asset)
            if got != expected:
                raise InstallError(f"{asset} has sha256 {got[:12]}..., the release lists {expected[:12]}...; refused")
            verified[asset] = got
        sdk_wheel = _fetch_sdk_wheel(want, sums, dl, fetch)
        verified[sdk_wheel.name] = sha256_file(sdk_wheel)
        (staging / "bin").mkdir()
        binaries = {}
        for binary, asset in assets.items():
            _extract_single(dl / asset, binary, staging / "bin" / binary)
            binaries[binary] = sha256_file(staging / "bin" / binary)
        sdk_info = install_sdk(sdk_wheel, staging / "python", want.get("python_deps") or [],
                               fetch=fetch, scratch=dl, machine=arch)
        images = verify_images(want.get("images") or {}, staging / "bin", container_cli, run=run)
        shutil.rmtree(dl, ignore_errors=True)
        ident = {"id": want["id"], "version": want["version"], "platform": "linux", "arch": arch,
                 "source": want["release_url"], "assets": verified, "binaries": binaries, "sdk": True,
                 "sdk_deps": sdk_info, "images": images, "installed_at": time.time()}
        return _activate(root, staging, ident)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _fetch_sdk_wheel(want: dict, sums: dict, scratch: Path, fetch: Fetch) -> Path:
    """The pinned OpenShell Python SDK wheel, downloaded into *scratch* and verified. ``sdk_wheel`` is either

    * a file name: an asset of the release, which must match its line in the pinned checksum files (releases up
      to v0.1.7 attach the wheel); or
    * ``{"file", "sha256", "url"}``: the wheel at its own https URL with its own pinned sha256, like every
      ``python_deps`` wheel (from v0.1.8 on the SDK is published on PyPI only and no release file lists it).
    """
    pin = want.get("sdk_wheel")
    if isinstance(pin, str) and pin:
        expected = sums.get(pin)
        if not expected:
            raise InstallError(f"{pin} is not listed in the release checksum files; refused")
        url, what = f"{want['release_url']}/{pin}", "the release lists"
    elif isinstance(pin, dict):
        pin = {k: str(pin.get(k) or "") for k in ("file", "sha256", "url")}
        name, expected, url, what = pin["file"], pin["sha256"].lower(), pin["url"], "pinned"
        plain = name.endswith(".whl") and name not in (".", "..") and "/" not in name and "\\" not in name
        if not plain or len(expected) != 64 or not url.startswith("https://"):
            raise InstallError(f"the pinned OpenShell SDK wheel must name a .whl file, its sha256 and an https "
                               f"URL (file {name!r}, url {url!r}); refused")
        pin = name
    else:
        raise InstallError(f"the pinned OpenShell {want.get('version')} names no Python SDK wheel")
    path = scratch / pin
    fetch(url, path)
    got = sha256_file(path)
    if got != expected:
        raise InstallError(f"{pin} has sha256 {got[:12]}..., {what} {expected[:12]}...; refused")
    return path


def _extract_single(tarball: Path, member: str, dest: Path) -> None:
    """Extract one regular file named *member* (at the archive root) and nothing else."""
    with tarfile.open(tarball, "r:gz") as tar:
        for info in tar.getmembers():
            if info.name.lstrip("./") == member and info.isfile():
                src = tar.extractfile(info)
                with open(dest, "wb") as fh:
                    shutil.copyfileobj(src, fh)
                dest.chmod(0o755)
                return
    raise InstallError(f"{tarball.name} does not contain {member}")


def _install_wheel(wheel: Path, target: Path) -> None:
    """Unpack a wheel into a plain directory added to sys.path (purelib/platlib content only)."""
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(wheel) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            if parts[0].endswith(".data"):
                if len(parts) > 2 and parts[1] in ("purelib", "platlib"):
                    parts = parts[2:]
                else:
                    continue
            dest = root.joinpath(*parts)
            if root not in dest.resolve().parents:
                raise InstallError(f"{wheel.name} has an entry outside its target: {info.filename}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(dest, "wb") as fh:
                shutil.copyfileobj(src, fh)


def _have_module(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _pick_wheel(dep: dict, machine: str) -> Optional[dict]:
    py = f"cp{sys.version_info.major}{sys.version_info.minor}"
    libc = "glibc" if (_platform.libc_ver()[0] or "glibc") == "glibc" else "musl"
    for wheel in dep["wheels"]:
        if wheel.get("python") not in (None, py):
            continue
        if wheel.get("machine") not in (None, machine) or wheel.get("libc") not in (None, libc):
            continue
        return wheel
    return None


def install_sdk(wheel: Path, target: Path, deps: list, *, fetch: Fetch, scratch: Path, machine: str,
                have_module: Callable[[str], bool] = _have_module) -> dict:
    """The verified SDK wheel, plus each pinned dependency the running interpreter cannot import.
    The launcher appends the directory to ``sys.path``, so the Hermes environment's own packages win."""
    _install_wheel(wheel, target)
    added = {}
    for dep in deps:
        if have_module(dep["module"]):
            continue
        pick = _pick_wheel(dep, machine)
        if pick is None:
            raise InstallError(f"no pinned {dep['name']} {dep['version']} wheel for Python "
                               f"{sys.version_info.major}.{sys.version_info.minor} on {machine}; the OpenShell SDK "
                               f"needs it and the Hermes environment does not have it")
        path = scratch / pick["file"]
        fetch(pick["url"], path)
        got = sha256_file(path)
        if got != pick["sha256"]:
            raise InstallError(f"{pick['file']} has sha256 {got[:12]}..., pinned {pick['sha256'][:12]}...; refused")
        _install_wheel(path, target)
        added[dep["name"]] = {"version": dep["version"], "file": pick["file"], "sha256": got}
    return added


def verify_images(images: dict, bin_dir: Path, container_cli: Optional[str], *, run=subprocess.run) -> dict:
    """Pull each runtime image by its pinned digest and require the binary inside to be byte-identical
    to the verified release asset (the gateway runs these images with pull policy ``never``)."""
    if not images:
        return {}
    if not container_cli:
        raise InstallError("Docker (or Podman) is needed for OpenShell's Linux sandboxes and was not found")
    out = {}
    for binary, image in images.items():
        ref = image["ref"]
        pulled = run([container_cli, "pull", "-q", ref], capture_output=True, text=True, timeout=600,
                     stdin=subprocess.DEVNULL)
        if pulled.returncode != 0:
            raise InstallError(f"could not pull {ref}: {(pulled.stderr or pulled.stdout).strip()[-300:]}")
        created = run([container_cli, "create", ref], capture_output=True, text=True, timeout=120,
                      stdin=subprocess.DEVNULL)
        cid = (created.stdout or "").strip().splitlines()[-1] if created.returncode == 0 and created.stdout else ""
        if not cid:
            raise InstallError(f"could not inspect {ref}: {(created.stderr or created.stdout).strip()[-300:]}")
        copy = bin_dir.parent / f".image-{binary}"
        try:
            done = run([container_cli, "cp", f"{cid}:{image['path']}", str(copy)], capture_output=True, text=True,
                       timeout=120, stdin=subprocess.DEVNULL)
            if done.returncode != 0:
                raise InstallError(f"could not read {image['path']} from {ref}: {(done.stderr or '').strip()[-300:]}")
            inside, asset = sha256_file(copy), sha256_file(bin_dir / binary)
        finally:
            run([container_cli, "rm", cid], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            copy.unlink(missing_ok=True)
        if inside != asset:
            raise InstallError(f"{ref} carries {image['path']} with sha256 {inside[:12]}..., but the verified release "
                               f"asset is {asset[:12]}...; refused")
        out[binary] = {"ref": ref, "sha256": inside}
    return out


def remove_runtime(root: Path) -> bool:
    """Delete every installed runtime (the gateway must be gone first)."""
    base = runtime_dir(root)
    if not base.is_dir():
        return False
    for child in list(base.iterdir()):
        if child.name == "gateway":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)
    return True
