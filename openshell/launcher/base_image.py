"""The Linux sandbox base image, built on the user's machine.

The OpenShell Docker driver needs a non-root image; the launcher mounts the host's Hermes runtime
into it read-only, so the image only carries glibc, a shell, curl/procps and a user whose uid/gid are
the host user's (bind-mounted homes and folders keep their ownership). It is built from the plugin's
``runtime/Containerfile`` on top of a base pinned by digest (``runtime/pins.json``), and tagged with
the Containerfile's hash plus the uid/gid, so a changed Containerfile (or another user) builds a new
image instead of reusing a stale one. What was built is recorded in the host-only
``<root>/openshell/runtime/base-image.json``.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from .openshell_install import InstallError, load_pins, runtime_dir

CONTAINERFILE = Path(__file__).resolve().parent.parent / "runtime" / "Containerfile"
RECORD_FILE = "base-image.json"
LABEL_HASH = "org.nousresearch.hermes.containerfile-sha256"
LABEL_BASE = "org.nousresearch.hermes.base"
LABEL_MANAGED = "org.nousresearch.hermes.managed"


def containerfile_text() -> str:
    """The Containerfile with LF line endings (a Windows checkout may carry CRLF)."""
    return CONTAINERFILE.read_bytes().decode("utf-8").replace("\r\n", "\n")


def containerfile_hash() -> str:
    return hashlib.sha256(containerfile_text().encode("utf-8")).hexdigest()


def host_ids() -> tuple[int, int]:
    return (os.getuid(), os.getgid()) if hasattr(os, "getuid") else (1000, 1000)


def image_tag(uid: Optional[int] = None, gid: Optional[int] = None) -> str:
    """Deterministic tag (no side effects): ``hermes-sandbox-base:<hash12>-u<uid>g<gid>``."""
    if uid is None or gid is None:
        uid, gid = host_ids()
    repo = load_pins()["base_image"]["repository"]
    return f"{repo}:{containerfile_hash()[:12]}-u{uid}g{gid}"


def record_path(root: Path) -> Path:
    return runtime_dir(root) / RECORD_FILE


def _inspect(cli: str, ref: str, run) -> Optional[dict]:
    done = run([cli, "image", "inspect", ref], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        return None
    try:
        data = json.loads(done.stdout or "[]")
    except ValueError:
        return None
    return data[0] if data else None


def ensure_base_image(root: Path, container_cli: Optional[str], *, run=subprocess.run,
                      uid: Optional[int] = None, gid: Optional[int] = None) -> dict:
    """The base image for this Containerfile and host user, built when missing or stale."""
    if not container_cli:
        raise InstallError("Docker (or Podman) is needed to build the sandbox base image and was not found")
    if uid is None or gid is None:
        uid, gid = host_ids()
    pins = load_pins()["base_image"]
    want_hash = containerfile_hash()
    tag = image_tag(uid, gid)
    found = _inspect(container_cli, tag, run)
    labels = ((found or {}).get("Config") or {}).get("Labels") or {}
    if found and labels.get(LABEL_HASH) == want_hash and labels.get(LABEL_BASE) == pins["base"]:
        return _record(root, tag, found, want_hash, pins["base"], uid, gid, built=False)
    pulled = run([container_cli, "pull", "-q", pins["base"]], capture_output=True, text=True, timeout=900,
                 stdin=subprocess.DEVNULL)
    if pulled.returncode != 0:
        raise InstallError(f"could not pull the pinned base image {pins['base']}: "
                           f"{(pulled.stderr or pulled.stdout).strip()[-300:]}")
    context = runtime_dir(root) / "image-build" / want_hash[:12]
    context.mkdir(parents=True, exist_ok=True)
    (context / "Containerfile").write_text(containerfile_text(), encoding="utf-8", newline="\n")
    cmd = [container_cli, "build", "-q", "-f", str(context / "Containerfile"), "-t", tag,
           "--build-arg", f"BASE={pins['base']}", "--build-arg", f"HOST_UID={uid}", "--build-arg", f"HOST_GID={gid}",
           "--label", f"{LABEL_HASH}={want_hash}", "--label", f"{LABEL_BASE}={pins['base']}",
           "--label", f"{LABEL_MANAGED}=1", str(context)]
    built = run(cmd, capture_output=True, text=True, timeout=1800, stdin=subprocess.DEVNULL)
    if built.returncode != 0:
        raise InstallError(f"building the sandbox base image failed: {(built.stderr or built.stdout).strip()[-500:]}")
    found = _inspect(container_cli, tag, run)
    if not found:
        raise InstallError(f"the sandbox base image {tag} was built but cannot be inspected")
    _remove_stale(container_cli, tag, run)
    return _record(root, tag, found, want_hash, pins["base"], uid, gid, built=True)


def _remove_stale(cli: str, keep: str, run) -> None:
    """Best effort: older plugin-built base images (another Containerfile hash). An image a sandbox
    still uses is refused by the engine and stays."""
    done = run([cli, "images", "--filter", f"label={LABEL_MANAGED}=1", "--format", "{{.Repository}}:{{.Tag}}"],
               capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    for ref in (done.stdout or "").split():
        if ref != keep and not ref.endswith(":<none>"):
            run([cli, "image", "rm", ref], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


def _record(root: Path, tag: str, found: dict, want_hash: str, base: str, uid: int, gid: int, *, built: bool) -> dict:
    path = record_path(root)
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {}
    built_at = time.time() if built else (previous.get("built_at") if previous.get("tag") == tag else None)
    rec = {"tag": tag, "image_id": found.get("Id"), "size": found.get("Size"), "containerfile_sha256": want_hash,
           "base": base, "uid": uid, "gid": gid, "built_at": built_at, "image_created": found.get("Created"),
           "checked_at": time.time()}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(rec, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    return {**rec, "built": built}
