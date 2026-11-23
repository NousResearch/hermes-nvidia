"""Where the installer takes the OpenShell Python SDK wheel from, and what it checks it against.

Releases up to v0.1.7 attach the wheel and list it in a release checksum file: the pin names the file
(``"sdk_wheel": "openshell-0.1.6-py3-none-any.whl"``). From v0.1.8 on the SDK is published on PyPI only
(NVIDIA/OpenShell#5350): no release file lists it, so the pin carries the wheel's own URL and sha256
(``{"file", "sha256", "url"}``), like every ``python_deps`` wheel. Both shapes install; neither installs a
wheel whose bytes differ from what the plugin pins.

No network and no container engine: a fake fetch serves files built in the test, a fake runner the images.
"""
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from openshell.launcher import base_image as bi
from openshell.launcher import openshell_install as inst

REL = "https://example.invalid/rel"
PYPI = "https://files.example.invalid/packages/ab/cd/openshell-9.9.9-py3-none-any.whl"
WHEEL = "openshell-9.9.9-py3-none-any.whl"
BINS = {"openshell": b"cli-bin", "openshell-gateway": b"gateway-bin", "openshell-supervisor": b"supervisor-bin",
        "openshell-sandbox": b"sandbox-bin"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tarball(member: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size, info.mode = len(data), 0o755
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _wheel(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class Release:
    """A fake release without the SDK wheel among its files (as v0.1.8), and the wheel on its own URL."""

    def __init__(self, *, wheel_in_release: bool = False):
        self.sdk = _wheel({"openshell/__init__.py": b"VERSION = '9.9.9'\n", "openshell-9.9.9.dist-info/METADATA": b"Name: openshell\n"})
        self.by_url = {f"{REL}/{b}-x86_64.tar.gz": _tarball(b, data) for b, data in BINS.items()}
        listed = {url.rsplit("/", 1)[1]: data for url, data in self.by_url.items()}
        if wheel_in_release:
            listed[WHEEL] = self.sdk
            self.by_url[f"{REL}/{WHEEL}"] = self.sdk
        else:
            self.by_url[PYPI] = self.sdk
        sums = "".join(f"{sha(data)}  {name}\n" for name, data in listed.items()).encode()
        self.by_url[f"{REL}/sums.txt"] = sums
        self.pins = {"linux": {
            "id": "openshell-v9.9.9", "version": "9.9.9", "release_url": REL, "checksum_files": {"sums.txt": sha(sums)},
            "assets": {"x86_64": {b: f"{b}-x86_64.tar.gz" for b in BINS}},
            "sdk_wheel": WHEEL if wheel_in_release else {"file": WHEEL, "sha256": sha(self.sdk), "url": PYPI},
            "images": {"openshell-supervisor": {"ref": "ghcr.invalid/sup@sha256:aa", "path": "/openshell-supervisor"},
                       "openshell-sandbox": {"ref": "ghcr.invalid/sbx@sha256:bb", "path": "/openshell-sandbox"}},
            "python_deps": []},
            "windows": {}, "base_image": {"repository": "hermes-sandbox-base", "base": "debian:trixie-slim@sha256:" + "0" * 64}}
        self.fetched = []

    def fetch(self, url, dest):
        self.fetched.append(url)
        dest.write_bytes(self.by_url[url])  # KeyError: the installer asked for something this release does not have

    def engine(self, cmd, **kw):
        if cmd[1] == "create":
            return subprocess.CompletedProcess(cmd, 0, "cid\n", "")
        if cmd[1] == "cp":
            Path(cmd[3]).write_bytes(BINS[cmd[2].split(":", 1)[1].lstrip("/")])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def install(self, root, monkeypatch):
        monkeypatch.setattr(inst, "load_pins", lambda: json.loads(json.dumps(self.pins)))
        monkeypatch.setattr(bi, "load_pins", lambda: json.loads(json.dumps(self.pins)))
        return inst.install_linux(root, container_cli="docker", fetch=self.fetch, run=self.engine, machine="x86_64")


@pytest.fixture
def root(tmp_path):
    return tmp_path / "root"


def test_an_sdk_wheel_pinned_by_url_and_hash_installs_though_no_release_file_lists_it(root, monkeypatch):
    rel = Release()
    ident = rel.install(root, monkeypatch)
    assert PYPI in rel.fetched and f"{REL}/{WHEEL}" not in rel.fetched  # from its own URL, not the release
    assert ident["assets"][WHEEL] == sha(rel.sdk) and ident["sdk"] is True
    sdk = inst.sdk_path(root, ident)
    assert (sdk / "openshell" / "__init__.py").read_bytes() == b"VERSION = '9.9.9'\n"
    assert inst.installed(root)["id"] == "openshell-v9.9.9"
    assert not list(inst.runtime_dir(root).glob(".staging-*"))


def test_an_sdk_wheel_that_differs_from_its_pinned_hash_is_refused(root, monkeypatch):
    rel = Release()
    rel.by_url[PYPI] = _wheel({"openshell/__init__.py": b"import os  # not the pinned wheel\n"})
    with pytest.raises(inst.InstallError, match=f"{WHEEL} has sha256 .* pinned .*refused"):
        rel.install(root, monkeypatch)
    assert inst.installed(root) is None and not list(inst.runtime_dir(root).glob(".staging-*"))


@pytest.mark.parametrize("pin,said", [
    ({"file": WHEEL, "url": PYPI}, "must name a .whl file, its sha256 and an https URL"),                      # no hash
    ({"file": WHEEL, "sha256": "ab" * 16, "url": PYPI}, "must name a .whl file, its sha256 and an https URL"),  # short
    ({"file": WHEEL, "sha256": "0" * 64, "url": PYPI.replace("https://", "http://")}, "an https URL"),
    ({"file": "../" + WHEEL, "sha256": "0" * 64, "url": PYPI}, "must name a .whl file"),
    ({"file": "openshell.tar.gz", "sha256": "0" * 64, "url": PYPI}, "must name a .whl file"),
    (None, "names no Python SDK wheel"),
    ("", "names no Python SDK wheel"),
], ids=["no-sha256", "short-sha256", "http-url", "path-in-file-name", "not-a-wheel", "missing", "empty"])
def test_a_malformed_sdk_wheel_pin_is_refused_before_anything_is_fetched_for_it(root, monkeypatch, pin, said):
    rel = Release()
    rel.pins["linux"]["sdk_wheel"] = pin
    with pytest.raises(inst.InstallError, match=said):
        rel.install(root, monkeypatch)
    assert PYPI not in rel.fetched and inst.installed(root) is None


def test_a_wheel_the_release_lists_still_installs_from_the_release(root, monkeypatch):
    """The pin shape of v0.1.6 and older: a file name, checked against the release's checksum files."""
    rel = Release(wheel_in_release=True)
    ident = rel.install(root, monkeypatch)
    assert f"{REL}/{WHEEL}" in rel.fetched and ident["assets"][WHEEL] == sha(rel.sdk)
    assert (inst.sdk_path(root, ident) / "openshell" / "__init__.py").is_file()


def test_a_wheel_named_as_a_release_file_that_no_checksum_file_lists_is_refused(root, monkeypatch):
    """What a v0.1.8 pin in the old shape would be: the release has no such file and lists no such line."""
    rel = Release()
    rel.pins["linux"]["sdk_wheel"] = WHEEL
    with pytest.raises(inst.InstallError, match=f"{WHEEL} is not listed in the release checksum files"):
        rel.install(root, monkeypatch)
    assert inst.installed(root) is None


def test_the_shipped_linux_pin_names_an_sdk_wheel_the_installer_can_fetch_and_check(tmp_path):
    """Whichever shape runtime/pins.json uses today: one https download of a .whl, refused when its bytes are not
    the pinned ones."""
    want = inst.pinned("linux")
    asked = []

    def fetch(url, dest):
        asked.append(url)
        dest.write_bytes(b"not the pinned wheel")

    listed = {want["sdk_wheel"]: "0" * 64} if isinstance(want["sdk_wheel"], str) else {}
    with pytest.raises(inst.InstallError, match="has sha256"):
        inst._fetch_sdk_wheel(want, listed, tmp_path, fetch)
    assert len(asked) == 1 and asked[0].startswith("https://") and asked[0].endswith(".whl")
