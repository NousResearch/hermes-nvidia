"""The plugin's OpenShell installer: pinned, checksum-verified binaries under <root>/openshell/runtime/.

No network and no container engine: downloads come from a fake fetch serving files built in the test,
container calls from a fake runner. Every check that guards what gets executed has a refusal test.
"""
import hashlib
import io
import json
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from openshell.launcher import base_image as bi
from openshell.launcher import openshell_install as inst


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tarball(member: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class Release:
    """A fake OpenShell release: assets, checksum files, and the pins that trust them."""

    URL = "https://example.invalid/rel"

    def __init__(self, arch="x86_64"):
        self.bins = {"openshell": b"cli-bin", "openshell-gateway": b"gateway-bin",
                     "openshell-supervisor": b"supervisor-bin", "openshell-sandbox": b"sandbox-bin"}
        self.assets = {f"{b}-{arch}.tar.gz": b for b in self.bins}
        self.files = {name: tarball(b, self.bins[b]) for name, b in self.assets.items()}
        self.files["openshell-9.9.9-py3-none-any.whl"] = wheel({"openshell/__init__.py": b"VERSION = '9.9.9'\n",
                                                                 "openshell-9.9.9.dist-info/METADATA": b"Name: openshell\n"})
        sums = "".join(f"{sha(data)}  {name}\n" for name, data in self.files.items())
        self.files["sums-a.txt"] = sums.encode()
        self.dep = wheel({"fakedep/__init__.py": b"X = 1\n"})
        self.files["fakedep-1.0-py3-none-any.whl"] = self.dep
        self.pins = {"linux": {
            "id": "openshell-v9.9.9", "version": "9.9.9", "release_url": self.URL,
            "checksum_files": {"sums-a.txt": sha(self.files["sums-a.txt"])},
            "assets": {arch: {b: f"{b}-{arch}.tar.gz" for b in self.bins}},
            "sdk_wheel": "openshell-9.9.9-py3-none-any.whl",
            "images": {"openshell-supervisor": {"ref": "ghcr.invalid/sup@sha256:aa", "path": "/openshell-supervisor"},
                       "openshell-sandbox": {"ref": "ghcr.invalid/sbx@sha256:bb", "path": "/openshell-sandbox"}},
            "python_deps": [{"module": "fakedep_not_installed_anywhere", "name": "fakedep", "version": "1.0",
                             "wheels": [{"file": "fakedep-1.0-py3-none-any.whl", "sha256": sha(self.dep),
                                         "url": f"{self.URL}/fakedep-1.0-py3-none-any.whl"}]}]},
            "windows": {}, "base_image": {"repository": "hermes-sandbox-base",
                                          "base": "debian:trixie-slim@sha256:" + "0" * 64}}
        self.fetched = []

    def fetch(self, url, dest):
        self.fetched.append(url)
        dest.write_bytes(self.files[url.rsplit("/", 1)[1]])


class Engine:
    """Fake docker: pull/create/cp/rm; cp writes the image's binary (tamperable)."""

    def __init__(self, release, tamper=None):
        self.release, self.tamper, self.calls = release, tamper, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        verb = cmd[1]
        if verb == "create":
            return subprocess.CompletedProcess(cmd, 0, "cid-" + cmd[2].split("/")[-1].split("@")[0] + "\n", "")
        if verb == "cp":
            path = cmd[2].split(":", 1)[1].lstrip("/")
            data = self.release.bins[path]
            if self.tamper == path:
                data = b"evil"
            Path(cmd[3]).write_bytes(data)
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def root(tmp_path):
    return tmp_path / "root"


def use_pins(monkeypatch, pins):
    monkeypatch.setattr(inst, "load_pins", lambda: json.loads(json.dumps(pins)))
    monkeypatch.setattr(bi, "load_pins", lambda: json.loads(json.dumps(pins)))


# -- Linux release ------------------------------------------------------------------------------

def test_linux_install_verifies_checksums_images_and_records_identity(root, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    engine = Engine(rel)
    ident = inst.install_linux(root, container_cli="docker", fetch=rel.fetch, run=engine, machine="x86_64")
    assert ident["id"] == "openshell-v9.9.9" and inst.installed(root)["id"] == ident["id"]
    for name, data in rel.bins.items():
        path = inst.bin_path(root, ident, name)
        assert path.read_bytes() == data and ident["binaries"][name] == sha(data)
    assert set(ident["images"]) == {"openshell-supervisor", "openshell-sandbox"}
    assert ["docker", "pull", "-q", "ghcr.invalid/sup@sha256:aa"] in engine.calls
    sdk = inst.sdk_path(root, ident)
    assert (sdk / "openshell" / "__init__.py").is_file() and (sdk / "fakedep" / "__init__.py").is_file()
    assert ident["sdk_deps"]["fakedep"]["sha256"] == sha(rel.dep)
    assert not (inst.identity_dir(root, ident) / "downloads").exists()  # tarballs are not kept
    assert not list(inst.runtime_dir(root).glob(".staging-*"))
    inst.verify(root, ident)  # clean
    assert inst.ensure_installed(root, platform="linux", fetch=lambda *a: pytest.fail("refetched")) == ident


def test_linux_install_refuses_a_checksum_file_that_differs_from_the_pin(root, monkeypatch):
    rel = Release()
    rel.pins["linux"]["checksum_files"]["sums-a.txt"] = "f" * 64
    use_pins(monkeypatch, rel.pins)
    with pytest.raises(inst.InstallError, match="checksum file sums-a.txt"):
        inst.install_linux(root, container_cli="docker", fetch=rel.fetch, run=Engine(rel), machine="x86_64")
    assert inst.installed(root) is None and not list(inst.runtime_dir(root).glob(".staging-*"))


def test_linux_install_refuses_an_asset_that_differs_from_the_checksum_file(root, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    good = rel.fetch

    def tampered(url, dest):
        good(url, dest)
        if url.endswith("openshell-gateway-x86_64.tar.gz"):
            dest.write_bytes(tarball("openshell-gateway", b"evil-gateway"))

    with pytest.raises(inst.InstallError, match="openshell-gateway-x86_64.tar.gz has sha256"):
        inst.install_linux(root, container_cli="docker", fetch=tampered, run=Engine(rel), machine="x86_64")
    assert inst.installed(root) is None


def test_linux_install_refuses_an_unlisted_asset_and_an_unknown_arch(root, monkeypatch):
    rel = Release()
    rel.pins["linux"]["assets"]["x86_64"]["openshell"] = "not-in-sums.tar.gz"
    use_pins(monkeypatch, rel.pins)
    with pytest.raises(inst.InstallError, match="not listed in the release checksum files"):
        inst.install_linux(root, container_cli="docker", fetch=rel.fetch, run=Engine(rel), machine="x86_64")
    with pytest.raises(inst.InstallError, match="no Linux release for riscv64"):
        inst.install_linux(root, container_cli="docker", fetch=rel.fetch, run=Engine(rel), machine="riscv64")


def test_linux_install_refuses_an_image_whose_binary_is_not_the_verified_asset(root, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    with pytest.raises(inst.InstallError, match="ghcr.invalid/sup@sha256:aa carries /openshell-supervisor"):
        inst.install_linux(root, container_cli="docker", fetch=rel.fetch, run=Engine(rel, tamper="openshell-supervisor"),
                           machine="x86_64")
    assert inst.installed(root) is None


def test_linux_install_needs_a_container_engine(root, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    with pytest.raises(inst.InstallError, match="Docker"):
        inst.install_linux(root, container_cli=None, fetch=rel.fetch, run=Engine(rel), machine="x86_64")


def test_sdk_dependencies_install_only_what_the_environment_lacks_and_check_hashes(tmp_path):
    rel = Release()
    dep = rel.pins["linux"]["python_deps"][0]
    wheel_path = tmp_path / "sdk.whl"
    wheel_path.write_bytes(rel.files["openshell-9.9.9-py3-none-any.whl"])
    got = inst.install_sdk(wheel_path, tmp_path / "a", [dep], fetch=rel.fetch, scratch=tmp_path, machine="x86_64",
                           have_module=lambda m: True)
    assert got == {} and not (tmp_path / "a" / "fakedep").exists()
    bad = dict(dep, wheels=[dict(dep["wheels"][0], sha256="0" * 64)])
    with pytest.raises(inst.InstallError, match="fakedep-1.0-py3-none-any.whl has sha256"):
        inst.install_sdk(wheel_path, tmp_path / "b", [bad], fetch=rel.fetch, scratch=tmp_path, machine="x86_64",
                         have_module=lambda m: False)
    nowheel = dict(dep, wheels=[dict(dep["wheels"][0], python="cp27")])
    with pytest.raises(inst.InstallError, match="no pinned fakedep"):
        inst.install_sdk(wheel_path, tmp_path / "c", [nowheel], fetch=rel.fetch, scratch=tmp_path, machine="x86_64",
                         have_module=lambda m: False)


def test_wheel_entries_outside_the_target_are_refused(tmp_path):
    evil = tmp_path / "evil.whl"
    evil.write_bytes(wheel({"../../escape.py": b"x"}))
    with pytest.raises(inst.InstallError, match="outside its target"):
        inst._install_wheel(evil, tmp_path / "t")
    assert not (tmp_path / "escape.py").exists()


def test_the_shipped_pins_cover_both_platforms_and_pin_every_python_dependency():
    pins = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))
    linux = pins["linux"]
    assert linux["version"] == "0.1.9" and len(linux["checksum_files"]) == 4
    assert linux["release_url"] == "https://github.com/ai-openshell/openshell/releases/download/v0.1.9"
    sdk = linux["sdk_wheel"]  # the release attaches no wheel: pinned by its own sha256 and URL
    assert sdk["file"] == f"openshell-{linux['version']}-py3-none-any.whl" and len(sdk["sha256"]) == 64
    assert sdk["url"].startswith("https://files.pythonhosted.org/") and sdk["url"].endswith("/" + sdk["file"])
    assert all(len(v) == 64 for v in linux["checksum_files"].values())
    assert set(linux["assets"]) == {"x86_64", "aarch64"}
    assert all("@sha256:" in img["ref"] for img in linux["images"].values())
    for dep in linux["python_deps"]:
        assert dep["wheels"] and all(len(w["sha256"]) == 64 and w["url"].startswith("https://") for w in dep["wheels"])
    win = pins["windows"]
    assert set(win["binaries"]) == {"openshell.exe", "openshell-gateway.exe", "openshell-supervisor.exe",
                                    "openshell-windows-sandbox.exe"}
    assert all(len(v) == 64 for v in win["binaries"].values())
    assert win["archive"]["url"].startswith("https://") and len(win["archive"]["sha256"]) == 64
    assert "@sha256:" in pins["base_image"]["base"]


NVIDIA_RELEASE = "https://github.com/ai-openshell/openshell/releases/download/v0.1.9/"


def test_the_shipped_windows_pin_is_nvidias_signed_package_from_the_release():
    win = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))["windows"]
    arm = win["aarch64"]
    assert (win["id"], arm["id"]) == ("openshell-windows-0.1.9", "openshell-windows-0.1.9-arm64")
    assert win["version"] == "0.1.9" and win["signer"] == "NVIDIA Corporation"
    assert "version" not in arm and "signer" not in arm and "features" not in arm  # shared: one release, one source
    # each architecture has its own zip on NVIDIA's release, pinned by the sha256 the release's checksum file lists
    assert win["archive"] == {"url": NVIDIA_RELEASE + "OpenShell-Windows-0.1.9-x64.zip",
                              "sha256": "f95c30cfc957d1d3150269c6e681c5cadec4a717408956e7ff3a9d265056ffc4"}
    assert arm["archive"] == {"url": NVIDIA_RELEASE + "OpenShell-Windows-0.1.9-arm64.zip",
                              "sha256": "253413c616685ca1633a9f9d279ae4514c493a1a996c057e88feb53d9dba8131"}
    for block, word in ((win, "x64"), (arm, "Arm64")):
        # says what it is: NVIDIA's package, the branch commit it was built from, and that it is not the tag's source
        assert f"NVIDIA's signed Windows package for {word}" in block["source"] and "v0.1.9 release" in block["source"]
        assert "windows branch at 7e4e113e3" in block["source"] and "not built from the v0.1.9 tag" in block["source"]
    # what the plugin relies on is listed as features, never read off the number
    assert win["features"] == ["ca-bundle-system-roots", "mxc-driver-config-denied-paths"]
    notes = json.dumps({k: v for k, v in win.items() if k.startswith("_")})
    assert "e451bb390" not in json.dumps(win) and "No OpenShell release ships" not in json.dumps(win)
    assert "absent" not in notes and "local build" not in notes and "top level" not in win["_archive"]
    for arch in ("x86_64", "aarch64"):
        got = inst.windows_pin(win, arch)
        assert got["signer"] == "NVIDIA Corporation" and got["version"] == "0.1.9" and got["archive"]["url"].endswith(
            {"x86_64": "-x64.zip", "aarch64": "-arm64.zip"}[arch])


# -- Windows pinned build -----------------------------------------------------------------------

def windows_build(tmp_path, monkeypatch, files=None):
    files = files or {"openshell.exe": b"cli", "openshell-gateway.exe": b"gw", "openshell-supervisor.exe": b"sup",
                      "openshell-windows-sandbox.exe": b"sbx", "libz3.dll": b"z3"}
    build = tmp_path / "build"
    build.mkdir(exist_ok=True)
    for name, data in files.items():
        (build / name).write_bytes(data)
    pins = {"linux": {}, "windows": {"id": "openshell-windows-test", "version": "0.0.0+test", "source": "test build",
                                     "binaries": {n: sha(d) for n, d in files.items()}},
            "base_image": {"repository": "r", "base": "b"}}
    use_pins(monkeypatch, pins)
    return build


def test_windows_install_copies_only_a_build_matching_the_pinned_identity(root, tmp_path, monkeypatch):
    build = windows_build(tmp_path, monkeypatch)
    ident = inst.install_windows(root, build)
    assert ident["id"] == "openshell-windows-test" and ident["platform"] == "windows"
    assert inst.bin_path(root, ident, "openshell-gateway").name == "openshell-gateway.exe"
    assert inst.bin_path(root, ident, "openshell-gateway").read_bytes() == b"gw"
    assert inst.installed(root)["id"] == ident["id"] and ident["sdk"] is False
    # tampering with the installed copy is caught on the next use
    inst.bin_path(root, ident, "openshell-supervisor").write_bytes(b"evil")
    with pytest.raises(inst.InstallError, match="no longer matches its pinned sha256"):
        inst.ensure_installed(root, platform="windows")


def test_windows_install_refuses_a_different_or_incomplete_build(root, tmp_path, monkeypatch):
    build = windows_build(tmp_path, monkeypatch)
    (build / "openshell-gateway.exe").write_bytes(b"unpatched gateway")
    (build / "libz3.dll").unlink()
    with pytest.raises(inst.InstallError) as err:
        inst.install_windows(root, build)
    assert "openshell-gateway.exe: sha256" in str(err.value) and "libz3.dll: missing" in str(err.value)
    assert inst.installed(root) is None and not (inst.runtime_dir(root) / "openshell-windows-test").exists()


def test_windows_needs_a_build_dir_the_first_time(root, tmp_path, monkeypatch):
    build = windows_build(tmp_path, monkeypatch)
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    with pytest.raises(inst.InstallError, match="runtime install --build-dir"):
        inst.ensure_installed(root, platform="windows")
    monkeypatch.setenv(inst.BUILD_DIR_ENV, str(build))
    ident = inst.ensure_installed(root, platform="windows")
    monkeypatch.delenv(inst.BUILD_DIR_ENV)
    assert inst.ensure_installed(root, platform="windows") == ident  # installed: no build dir needed again


# -- Windows pinned archive (windows.archive: a zip by url and sha256), files at the zip's top level ---------------

WIN_FILES = {"openshell.exe": b"cli", "openshell-gateway.exe": b"gw", "openshell-supervisor.exe": b"sup",
             "openshell-windows-sandbox.exe": b"sbx", "libz3.dll": b"z3"}
ARCHIVE_URL = "https://example.invalid/releases/openshell-windows-test-x64.zip"


def zipped(entries) -> bytes:
    """A zip of (name, data) pairs, in order (duplicates and nested names allowed). Names are stored exactly as
    given: on Windows ``ZipInfo(name)`` would rewrite a backslash to a slash."""
    import warnings

    buf = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        warnings.simplefilter("ignore")  # "Duplicate name": wanted here
        for name, data in entries:
            info = zipfile.ZipInfo("entry")
            info.filename = name
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, b"" if name.endswith("/") else data)
    return buf.getvalue()


def windows_archive(monkeypatch, entries=None, *, pinned_files=None, url=ARCHIVE_URL, archive_sha=None):
    """Pins whose Windows build is *pinned_files* (default WIN_FILES) with an archive of *entries* (default: the
    pinned files plus a license file) pinned by its own sha256. Returns (archive bytes, fetch, fetched urls)."""
    pinned_files = pinned_files or WIN_FILES
    data = zipped(entries if entries is not None else [*WIN_FILES.items(), ("LICENSE", b"license text")])
    pins = {"linux": {}, "windows": {"id": "openshell-windows-test", "version": "0.0.0+test", "source": "test build",
                                     "binaries": {n: sha(d) for n, d in pinned_files.items()},
                                     "archive": {"url": url, "sha256": archive_sha or sha(data)}},
            "base_image": {"repository": "r", "base": "b"}}
    use_pins(monkeypatch, pins)
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    fetched = []

    def fetch(got_url, dest):
        fetched.append(got_url)
        dest.write_bytes(data)

    return data, fetch, fetched


def _nothing_left(root):
    return inst.installed(root) is None and not list(inst.runtime_dir(root).glob(".staging-*"))


def test_windows_installs_the_pinned_archive_when_no_build_dir_is_given(root, monkeypatch):
    data, fetch, fetched = windows_archive(monkeypatch)
    ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert fetched == [ARCHIVE_URL]
    assert ident["id"] == "openshell-windows-test" and inst.installed(root)["id"] == ident["id"]
    assert ident["source_archive"] == ARCHIVE_URL and ident["archive_sha256"] == sha(data)
    assert "source_dir" not in ident  # the unpacked files are gone; the archive is what was verified
    bin_dir = inst.identity_dir(root, ident) / "bin"
    assert sorted(p.name for p in bin_dir.iterdir()) == sorted(WIN_FILES)  # LICENSE stays in the zip
    assert all((bin_dir / n).read_bytes() == d for n, d in WIN_FILES.items())
    assert not list(inst.runtime_dir(root).glob(".staging-*"))  # neither the download nor the unpacked copy kept
    inst.verify(root, ident)
    assert inst.ensure_installed(root, platform="windows", fetch=lambda *a: pytest.fail("refetched")) == ident


def test_windows_archive_refused_unless_its_sha256_is_the_pinned_one(root, monkeypatch):
    _, fetch, _ = windows_archive(monkeypatch, archive_sha="0" * 64)
    with pytest.raises(inst.InstallError, match=r"openshell-windows-test-x64\.zip has sha256 .*pinned 000000000000"):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root)


def test_windows_archive_whose_files_differ_from_their_pins_is_refused(root, monkeypatch):
    # The zip matches its pinned sha256, but a file in it is not the pinned build (a pin made from a wrong archive).
    tampered = dict(WIN_FILES, **{"openshell-gateway.exe": b"unpatched gateway"})
    _, fetch, _ = windows_archive(monkeypatch, list(tampered.items()))
    with pytest.raises(inst.InstallError, match=r"is not the pinned OpenShell build .*openshell-gateway\.exe: sha256"):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root)


@pytest.mark.parametrize("entries, why", [
    ([(n, d) for n, d in WIN_FILES.items() if n != "libz3.dll"], "has no libz3.dll"),
    ([*WIN_FILES.items(), ("libz3.dll", b"z3")], "more than one libz3.dll"),
    ([(n, d) for n, d in WIN_FILES.items() if n != "openshell.exe"] + [("bin/openshell.exe", b"cli")],
     "holds openshell.exe in bin/, not in its <top folder>/bin/ or at its top level"),
    ([(n, d) for n, d in WIN_FILES.items() if n != "openshell.exe"] + [("../openshell.exe", b"cli")],
     "an entry with an unsafe path"),
])
def test_windows_archive_needs_each_pinned_file_once_at_its_top_level(root, monkeypatch, entries, why):
    _, fetch, _ = windows_archive(monkeypatch, entries)
    with pytest.raises(inst.InstallError, match=why):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root) and not (root.parent / "openshell.exe").exists()


# -- NVIDIA's package layout: <top folder>/bin/<file>, among scripts, SDKs and documents ---------------------

TOP = "OpenShell-Windows-9.9.9-x64"
PACKAGE_EXTRAS = [(f"{TOP}/README.md", b"readme"), (f"{TOP}/LICENSE", b"license"),
                  (f"{TOP}/release-manifest.json", b"{}"), (f"{TOP}/licenses/Z3-LICENSE.txt", b"mit"),
                  (f"{TOP}/scripts/Install-OpenShell.ps1", b"Write-Host hi"), (f"{TOP}/config/gateway.toml", b"x = 1"),
                  (f"{TOP}/sdk/openshell-9.9.9-py3-none-any.whl", b"PK wheel"), (f"{TOP}/sdk/openshell-9.9.9.tgz", b"tgz"),
                  (f"{TOP}/policies/default.yaml", b"version: 1"), (f"{TOP}/examples/run.ps1", b"exit 0")]


def package(files=None, *, top=TOP, extras=PACKAGE_EXTRAS) -> list:
    """Entries of a zip laid out like NVIDIA's Windows package: the pinned files in <top>/bin/, the rest around."""
    files = WIN_FILES if files is None else files
    return [*extras[:3], *((f"{top}/bin/{n}", d) for n, d in files.items()), *extras[3:]]


def _files_under(path: Path) -> list:
    return sorted(p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file())


def test_windows_installs_only_the_pinned_files_from_the_packages_bin_folder(root, monkeypatch):
    data, fetch, fetched = windows_archive(monkeypatch, package())
    ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert fetched == [ARCHIVE_URL] and ident["archive_sha256"] == sha(data) and ident["source_archive"] == ARCHIVE_URL
    bin_dir = inst.identity_dir(root, ident) / "bin"
    assert all((bin_dir / n).read_bytes() == d for n, d in WIN_FILES.items())
    # nothing else from the zip is on disk anywhere under the root: no script, SDK, document or top folder
    assert _files_under(root) == sorted(
        [f"openshell/runtime/{inst.INSTALLED_FILE}", f"openshell/runtime/{ident['id']}/{inst.IDENTITY_FILE}",
         *(f"openshell/runtime/{ident['id']}/bin/{n}" for n in WIN_FILES)])
    assert _files_under(root.parent) == ["root/" + f for f in _files_under(root)]
    inst.verify(root, ident)


def test_the_unpacker_writes_only_the_pinned_names_whatever_else_the_zip_holds(tmp_path):
    archive = tmp_path / "package.zip"
    archive.write_bytes(zipped(package()))
    inst._unpack_pinned(archive, list(WIN_FILES), tmp_path / "out")
    assert _files_under(tmp_path / "out") == sorted(WIN_FILES)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out", "package.zip"]


def test_a_package_whose_file_differs_from_its_pin_is_refused(root, monkeypatch):
    # The zip matches its pinned sha256, but one program in it is not the pinned one.
    tampered = dict(WIN_FILES, **{"openshell-supervisor.exe": b"another supervisor"})
    _, fetch, _ = windows_archive(monkeypatch, package(tampered))
    with pytest.raises(inst.InstallError, match=r"openshell-windows-test-x64\.zip is not the pinned OpenShell build "
                                                r"openshell-windows-test; refused: openshell-supervisor\.exe: sha256"):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root)


def _without(name):
    return {n: d for n, d in WIN_FILES.items() if n != name}


@pytest.mark.parametrize("entries, why", [
    # a pinned file is missing
    (package(_without("libz3.dll")), "has no libz3.dll"),
    (package({}), "has no openshell.exe"),
    # a pinned name is there more than once: twice in bin/, again elsewhere in the package, in a second package
    # folder, at the top level as well, or under another letter case
    ([*package(), (f"{TOP}/bin/libz3.dll", b"z3")], "more than one libz3.dll"),
    ([*package(), (f"{TOP}/sdk/libz3.dll", b"other z3")], "more than one libz3.dll"),
    ([*package(), ("Other-Package/bin/openshell.exe", b"cli")], "more than one openshell.exe"),
    ([*package(), ("openshell-gateway.exe", b"gw")], "more than one openshell-gateway.exe"),
    ([*package(), (f"{TOP}/bin/OpenShell.EXE", b"cli")], "more than one openshell.exe"),
    # every name once, but not together in one <top folder>/bin/
    ([*package(_without("openshell.exe")), ("Other-Package/bin/openshell.exe", b"cli")], "in more than one folder"),
    ([*package(_without("openshell.exe")), ("openshell.exe", b"cli")], "in more than one folder"),
    ([*package(_without("openshell.exe")), (f"{TOP}/tools/openshell.exe", b"cli")],
     f"holds openshell.exe in {TOP}/tools/, not in its <top folder>/bin/"),
    ([*package(_without("openshell.exe")), (f"{TOP}/bin/x64/openshell.exe", b"cli")],
     f"holds openshell.exe in {TOP}/bin/x64/, not in its <top folder>/bin/"),
    ([(f"a/b/{TOP}/bin/{n}", d) for n, d in WIN_FILES.items()], "not in its <top folder>/bin/"),
    ([(f"{TOP}/BIN/{n}", d) for n, d in WIN_FILES.items()], f"holds openshell.exe in {TOP}/BIN/"),
])
def test_a_package_needs_each_pinned_file_once_in_its_one_bin_folder(root, monkeypatch, entries, why):
    _, fetch, _ = windows_archive(monkeypatch, entries)
    with pytest.raises(inst.InstallError, match=why):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root) and _files_under(root.parent) == []


@pytest.mark.parametrize("name", [
    "../openshell.exe", f"{TOP}/bin/../../openshell.exe", f"{TOP}/../evil.txt", "/abs/bin/openshell.exe",
    "C:/Windows/System32/evil.dll", f"{TOP}\\bin\\openshell.exe", f"{TOP}/bin/openshell.exe:stream",
    f"{TOP}//bin/openshell.exe", f"{TOP}/./bin/openshell.exe", "..\\..\\evil.exe", f"{TOP}/docs/../../../evil/",
])
def test_a_package_with_a_path_trick_in_any_entry_is_refused(root, monkeypatch, name):
    _, fetch, _ = windows_archive(monkeypatch, [*package(), (name, b"cli")])
    with pytest.raises(inst.InstallError, match="an entry with an unsafe path"):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root) and _files_under(root.parent) == []


def test_a_package_with_a_damaged_member_is_refused(root, monkeypatch):
    # The zip's own sha256 is the pinned one, but a program inside cannot be read back (its bytes no longer match the
    # zip's checksum for it): a refusal, not a crash, and nothing stays behind.
    data = bytearray(zipped(package()))
    at = bytes(data).index(b"openshell-supervisor.exe") + len("openshell-supervisor.exe") + 1  # inside its packed bytes
    data[at] ^= 0xFF
    _, _, _ = windows_archive(monkeypatch, package(), archive_sha=sha(bytes(data)))
    with pytest.raises(inst.InstallError, match=r"the OpenShell archive's openshell-supervisor\.exe cannot be unpacked"):
        inst.ensure_installed(root, platform="windows", fetch=lambda url, dest: dest.write_bytes(bytes(data)))
    assert _nothing_left(root) and _files_under(root.parent) == []


def test_a_pinned_name_is_never_a_path(tmp_path):
    archive = tmp_path / "package.zip"
    archive.write_bytes(zipped(package()))
    for bad in ("../openshell.exe", "bin/openshell.exe", "bin\\openshell.exe", "C:openshell.exe", "..", ""):
        with pytest.raises(inst.InstallError, match="is not a plain file name"):
            inst._unpack_pinned(archive, [bad], tmp_path / f"out-{len(bad)}-{abs(hash(bad))}")
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == ["package.zip"]


# -- the publisher's signature (windows.signer): checked on the installed copies, with the verifier faked ----

SIGNER = "Example Publisher"


def signed_archive(monkeypatch, verdicts=None, *, signer=SIGNER, entries=None):
    """Pins like ``windows_archive`` plus ``signer``, and a fake ``authenticode.signature`` that answers from
    *verdicts* ({file name: answer or exception}; default: valid, signed by SIGNER). Returns (fetch, calls)."""
    data, fetch, _ = windows_archive(monkeypatch, package() if entries is None else entries)
    pins = inst.load_pins()
    if signer:
        pins["windows"]["signer"] = signer
    use_pins(monkeypatch, pins)
    calls = []

    def fake(path):
        calls.append(Path(path))
        answer = (verdicts or {}).get(Path(path).name, {"status": "valid", "signer": SIGNER, "code": 0, "detail": "valid"})
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(inst.authenticode, "signature", fake)
    return fetch, calls


def test_each_installed_file_must_carry_the_pinned_publishers_signature(root, monkeypatch, caplog):
    fetch, calls = signed_archive(monkeypatch)
    with caplog.at_level("WARNING", logger="openshell.install"):
        ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert ident["signer"] == SIGNER and ident["signature"] == "valid" and inst.installed(root) == ident
    # every pinned file was checked once, as the copy that was then moved into place (not the unpacked one)
    assert sorted(p.name for p in calls) == sorted(WIN_FILES)
    assert all(p.parent.name == "bin" and p.parent.parent.name.startswith(".staging-") for p in calls)
    assert not caplog.records
    # an install that is already current is verified by its hashes, not signed again
    assert inst.ensure_installed(root, platform="windows", fetch=lambda *a: pytest.fail("refetched")) == ident
    assert len(calls) == len(WIN_FILES)


@pytest.mark.parametrize("verdict, why", [
    ({"status": "invalid", "signer": None, "code": 0x80096010,
      "detail": "The digital signature of the object did not verify. (0x80096010)"},
     r"Windows does not accept the signature on openshell-gateway\.exe of the OpenShell build "
     r"openshell-windows-test: The digital signature of the object did not verify\. \(0x80096010\)\. Refused"),
    ({"status": "unsigned", "signer": None, "code": 0x800B0100, "detail": "No signature was present in the subject."},
     r"openshell-gateway\.exe of the OpenShell build openshell-windows-test is not signed; the pinned build is "
     r"signed by Example Publisher\. Refused"),
    ({"status": "valid", "signer": "Someone Else Ltd", "code": 0, "detail": "valid"},
     r"openshell-gateway\.exe of the OpenShell build openshell-windows-test is signed by 'Someone Else Ltd', not by "
     r"Example Publisher\. Refused"),
    ({"status": "valid", "signer": "example publisher", "code": 0, "detail": "valid"}, "is signed by"),
    ({"status": "valid", "signer": SIGNER + " ", "code": 0, "detail": "valid"}, "is signed by"),
    ({"status": "valid", "signer": "", "code": 0, "detail": "valid"}, "is signed by ''"),
    ({"status": "valid", "signer": None, "code": 0, "detail": "valid"}, "is signed by None"),
    ({"status": "something new", "signer": SIGNER, "code": 1, "detail": "?"}, "Windows does not accept the signature"),
])
def test_a_definite_signature_failure_refuses_the_install(root, monkeypatch, verdict, why):
    fetch, calls = signed_archive(monkeypatch, {"openshell-gateway.exe": verdict})
    with pytest.raises(inst.InstallError, match=why):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root) and _files_under(root.parent) == []


def test_a_signature_failure_on_any_one_file_refuses(root, monkeypatch):
    for name in WIN_FILES:
        fetch, _ = signed_archive(monkeypatch, {name: {"status": "unsigned", "signer": None, "code": 1, "detail": "-"}})
        with pytest.raises(inst.InstallError, match=f"{name} of the OpenShell build .* is not signed"):
            inst.ensure_installed(root, platform="windows", fetch=fetch)
        assert _nothing_left(root)


def test_when_the_signature_check_cannot_run_the_install_continues_on_the_checksums(root, monkeypatch, caplog):
    fetch, calls = signed_archive(monkeypatch, {"openshell.exe": inst.authenticode.Unavailable("no wintrust here")})
    with caplog.at_level("WARNING", logger="openshell.install"):
        ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert ident["signer"] == SIGNER and ident["signature"] == "not checked" and inst.installed(root) == ident
    inst.verify(root, ident)  # the sha256 pins still hold
    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) == 1 and "could not be checked (no wintrust here)" in lines[0]
    assert "installed on the pinned sha256 checksums alone" in lines[0] and "openshell-windows-test" in lines[0]


def test_a_file_that_fails_its_checksum_is_refused_before_any_signature_is_read(root, monkeypatch):
    tampered = dict(WIN_FILES, **{"libz3.dll": b"another z3"})
    fetch, calls = signed_archive(monkeypatch, entries=package(tampered))
    with pytest.raises(inst.InstallError, match=r"is not the pinned OpenShell build .*libz3\.dll: sha256"):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert calls == [] and _nothing_left(root)


def test_a_pin_without_a_signer_checks_no_signature(root, monkeypatch):
    fetch, calls = signed_archive(monkeypatch, signer=None)
    ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert calls == [] and "signer" not in ident and "signature" not in ident


def test_a_build_dir_install_checks_the_publisher_too(root, tmp_path, monkeypatch):
    fetch, calls = signed_archive(monkeypatch, {"libz3.dll": {"status": "valid", "signer": "Someone Else Ltd",
                                                              "code": 0, "detail": "valid"}})
    build = tmp_path / "build"
    build.mkdir()
    for name, data in WIN_FILES.items():
        (build / name).write_bytes(data)
    with pytest.raises(inst.InstallError, match="libz3.dll of the OpenShell build .* is signed by 'Someone Else Ltd'"):
        inst.install_windows(root, build)
    assert _nothing_left(root) and len(calls) == len(WIN_FILES)


@pytest.mark.skipif(os.name == "nt", reason="on Windows the real check runs (test_authenticode.py)")
def test_off_windows_the_real_check_is_unavailable_and_the_install_continues(root, monkeypatch, caplog):
    data, fetch, _ = windows_archive(monkeypatch, package())
    pins = inst.load_pins()
    pins["windows"]["signer"] = SIGNER
    use_pins(monkeypatch, pins)
    with caplog.at_level("WARNING", logger="openshell.install"):
        ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert ident["signature"] == "not checked" and len(caplog.records) == 1


@pytest.mark.skipif(os.name != "nt", reason="asks Windows for the files' signatures")
def test_on_windows_unsigned_files_are_refused_by_the_real_check(root, monkeypatch):
    data, fetch, _ = windows_archive(monkeypatch, package())  # the test files are plain bytes: no signature
    pins = inst.load_pins()
    pins["windows"]["signer"] = SIGNER
    use_pins(monkeypatch, pins)
    with pytest.raises(inst.InstallError, match=r"openshell\.exe of the OpenShell build openshell-windows-test is not "
                                                r"signed; the pinned build is signed by Example Publisher\."):
        inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert _nothing_left(root)


def test_runtime_and_gateway_status_name_the_publisher(root, monkeypatch, capsys):
    from openshell import launcher_cli
    from openshell.launcher import gateway_service

    fetch, _ = signed_archive(monkeypatch)
    inst.ensure_installed(root, platform="windows", fetch=fetch)
    monkeypatch.setattr(inst, "platform_key", lambda *a: "windows")
    monkeypatch.setattr(inst, "windows_arch", lambda: "x86_64")
    runtime = gateway_service.gateway_status(root)["runtime"]
    assert runtime["signer"] == SIGNER and runtime["signature"] == "valid"
    monkeypatch.setattr(launcher_cli, "_hermes_root", lambda: root)

    class Args:
        action, build_dir = "status", None

    assert launcher_cli._cmd_runtime(Args()) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["pinned"]["signer"] == SIGNER and shown["installed"]["signer"] == SIGNER
    assert shown["installed"]["signature"] == "valid"


def test_windows_archive_that_is_not_a_zip_is_refused(root, monkeypatch):
    use_pins(monkeypatch, {"linux": {}, "base_image": {"repository": "r", "base": "b"}, "windows": {
        "id": "openshell-windows-test", "version": "0", "source": "t", "binaries": {n: sha(d) for n, d in WIN_FILES.items()},
        "archive": {"url": ARCHIVE_URL, "sha256": sha(b"not a zip")}}})
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    with pytest.raises(inst.InstallError, match="not a readable zip file"):
        inst.ensure_installed(root, platform="windows", fetch=lambda url, dest: dest.write_bytes(b"not a zip"))
    assert _nothing_left(root)


def test_a_build_dir_still_wins_over_the_pinned_archive(root, tmp_path, monkeypatch):
    windows_archive(monkeypatch)
    build = tmp_path / "build"
    build.mkdir()
    for name, data in WIN_FILES.items():
        (build / name).write_bytes(data)
    monkeypatch.setenv(inst.BUILD_DIR_ENV, str(build))
    ident = inst.ensure_installed(root, platform="windows", fetch=lambda *a: pytest.fail("downloaded"))
    assert ident["source_dir"] == str(build.resolve()) and "source_archive" not in ident


def test_without_an_archive_pin_windows_still_asks_for_a_build_dir(root, tmp_path, monkeypatch):
    windows_build(tmp_path, monkeypatch)  # pins without "archive"
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    with pytest.raises(inst.InstallError, match="runtime install --build-dir"):
        inst.ensure_installed(root, platform="windows", fetch=lambda *a: pytest.fail("downloaded"))


@pytest.fixture
def http_server(tmp_path, monkeypatch):
    """A loopback HTTP server over a folder (the real download path, no internet)."""
    import functools
    import http.server
    import threading

    served = tmp_path / "served"
    served.mkdir()
    for var in ("NO_PROXY", "no_proxy"):  # never send loopback through a configured proxy
        monkeypatch.setenv(var, "127.0.0.1,localhost")
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(served)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield served, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_windows_archive_downloads_over_http_and_refuses_a_tampered_one(root, monkeypatch, http_server):
    served, base = http_server
    data = zipped(WIN_FILES.items())
    (served / "build.zip").write_bytes(data)
    windows_archive(monkeypatch, list(WIN_FILES.items()), url=f"{base}/build.zip")
    ident = inst.ensure_installed(root, platform="windows")  # the real downloader
    assert ident["archive_sha256"] == sha(data) and inst.bin_path(root, ident, "openshell").read_bytes() == b"cli"
    # the same pin, but the server now hands out a different zip: refused, the installed runtime kept
    root2 = root.parent / "root2"
    (served / "build.zip").write_bytes(zipped([*WIN_FILES.items(), ("extra.txt", b"x")]))
    with pytest.raises(inst.InstallError, match="build.zip has sha256"):
        inst.ensure_installed(root2, platform="windows")
    assert _nothing_left(root2) and inst.installed(root)["id"] == ident["id"]


def test_windows_archive_download_failure_is_reported(root, monkeypatch, http_server):
    _, base = http_server
    windows_archive(monkeypatch, url=f"{base}/missing.zip")
    monkeypatch.setattr(inst.time, "sleep", lambda s: None)  # no backoff between the retries
    with pytest.raises(inst.InstallError, match="could not download .*missing.zip"):
        inst.ensure_installed(root, platform="windows")
    assert _nothing_left(root)


def test_prune_keeps_the_active_runtime_the_gateway_and_the_image_record(root, tmp_path, monkeypatch):
    build = windows_build(tmp_path, monkeypatch)
    ident = inst.install_windows(root, build)
    old = inst.runtime_dir(root) / "openshell-old"
    (old / "bin").mkdir(parents=True)
    (old / inst.IDENTITY_FILE).write_text("{}", encoding="utf-8")
    (inst.runtime_dir(root) / "gateway").mkdir()
    (inst.runtime_dir(root) / "image-build").mkdir()
    assert inst.prune(root, keep={ident["id"]}) == ["openshell-old"]
    assert (inst.runtime_dir(root) / ident["id"]).is_dir() and (inst.runtime_dir(root) / "gateway").is_dir()
    assert (inst.runtime_dir(root) / "image-build").is_dir()


# -- the base image -----------------------------------------------------------------------------

class ImageEngine:
    def __init__(self, labels=None):
        self.labels, self.calls, self.built = labels, [], False

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[1:3] == ["image", "inspect"]:
            if self.labels is None and not self.built:
                return subprocess.CompletedProcess(cmd, 1, "", "No such image")
            labels = self.labels if self.labels is not None else self.built_labels
            return subprocess.CompletedProcess(cmd, 0, json.dumps([{"Id": "sha256:img", "Size": 144_000_000,
                                                                    "Config": {"Labels": labels}}]), "")
        if cmd[1] == "build":
            self.built = True
            self.built_labels = dict(a.split("=", 1) for a in cmd[cmd.index("--label") + 1::2] if "=" in a
                                     and a.startswith("org."))
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_base_image_is_built_from_the_containerfile_with_host_ids_and_the_pinned_base(root, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    engine = ImageEngine()
    rec = bi.ensure_base_image(root, "docker", run=engine, uid=1234, gid=5678)
    want = bi.containerfile_hash()
    assert rec["tag"] == f"hermes-sandbox-base:{want[:12]}-u1234g5678" and rec["built"] is True
    build = next(c for c in engine.calls if c[1] == "build")
    base = rel.pins["base_image"]["base"]
    assert f"BASE={base}" in build and "HOST_UID=1234" in build and "HOST_GID=5678" in build
    assert f"{bi.LABEL_HASH}={want}" in build
    assert ["docker", "pull", "-q", base] in engine.calls
    ctx = Path(build[-1])
    assert b"\r\n" not in (ctx / "Containerfile").read_bytes()
    assert json.loads(bi.record_path(root).read_text())["containerfile_sha256"] == want


def test_base_image_is_reused_when_current_and_rebuilt_when_the_containerfile_changes(root, tmp_path, monkeypatch):
    rel = Release()
    use_pins(monkeypatch, rel.pins)
    base = rel.pins["base_image"]["base"]
    current = ImageEngine(labels={bi.LABEL_HASH: bi.containerfile_hash(), bi.LABEL_BASE: base})
    rec = bi.ensure_base_image(root, "docker", run=current, uid=1, gid=1)
    assert rec["built"] is False and not any(c[1] == "build" for c in current.calls)
    changed = tmp_path / "Containerfile"
    changed.write_text(bi.containerfile_text() + "# changed\n", encoding="utf-8")
    monkeypatch.setattr(bi, "CONTAINERFILE", changed)
    stale = ImageEngine(labels={bi.LABEL_HASH: "old", bi.LABEL_BASE: base})
    rec2 = bi.ensure_base_image(root, "docker", run=stale, uid=1, gid=1)
    assert rec2["built"] is True and rec2["tag"] != rec["tag"]


def test_base_image_needs_a_container_engine(root):
    with pytest.raises(inst.InstallError, match="Docker"):
        bi.ensure_base_image(root, None)
