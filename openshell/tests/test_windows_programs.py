"""The two programs a Windows sandbox needs besides OpenShell (launcher/windows_programs.py): MXC's ``wxc-exec.exe``,
read out of Microsoft's npm package, and the sandbox's shell, busybox-w32. The plugin installs both itself, pinned
in ``runtime/pins.json`` (``windows_programs``), each alone in a folder of its own under
``<root>/openshell/runtime/programs/``.

No request leaves this computer: a loopback server hands out files built in the test, through the installer's real
downloader. The programs here are made-up bytes behind the smallest header that names an architecture; the
signature check is faked, except where a test says it asks Windows.
"""
import base64
import functools
import gzip
import hashlib
import http.server
import io
import json
import os
import tarfile
import threading
from pathlib import Path

import pytest

from test_openshell_install import root, sha, use_pins  # noqa: F401  (root is a fixture)
from openshell.launcher import authenticode
from openshell.launcher import openshell_install as inst
from openshell.launcher import windows_programs as P

X64, ARM64 = 0x8664, 0xAA64
SIGNER = "Example Systems"


def program(machine: int, body: bytes) -> bytes:
    """A file with the header a Windows program starts with (it names the architecture) and *body* after it."""
    head = bytearray(64)
    head[:2] = b"MZ"
    head[0x3C:0x40] = (64).to_bytes(4, "little")
    return bytes(head) + b"PE\0\0" + machine.to_bytes(2, "little") + body


WXC = {"x86_64": program(X64, b"wxc for x64"), "aarch64": program(ARM64, b"wxc for arm64")}
SHELL = {"x86_64": program(X64, b"shell for x64"), "aarch64": program(ARM64, b"shell for arm64")}
MEMBER = {"x86_64": "package/bin/x64/wxc-exec.exe", "aarch64": "package/bin/arm64/wxc-exec.exe"}
SHELL_FILE = {"x86_64": "busybox64u.exe", "aarch64": "busybox64a.exe"}
PACKAGE = [("package/package.json", b"{}"), ("package/README.md", b"read me"),
           (MEMBER["x86_64"], WXC["x86_64"]), (MEMBER["aarch64"], WXC["aarch64"]),
           ("package/bin/x64/other.exe", b"another program"), ("package/dist/index.js", b"js")]


def tgz(entries) -> bytes:
    """A gzipped tar of *entries*: ``(name, bytes)`` for a file, or a ready ``tarfile.TarInfo``. The same entries
    give the same bytes every time (the gzip header carries no time)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as packed, tarfile.open(fileobj=packed, mode="w") as tar:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                tar.addfile(entry)
                continue
            name, data = entry
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def integrity(data: bytes, algorithm: str = "sha512") -> str:
    return f"{algorithm}-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


@pytest.fixture
def site(tmp_path, monkeypatch):
    """A loopback web server over a folder, and the list of paths it was asked for."""
    served = tmp_path / "served"
    served.mkdir()
    for var in ("NO_PROXY", "no_proxy"):  # Never send loopback through a configured proxy
        monkeypatch.setenv(var, "127.0.0.1,localhost")
    asked: list = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            asked.append(self.path)
            super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(served)))
    # A short poll: the server stops within a moment of each test's end
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield served, f"http://127.0.0.1:{server.server_address[1]}", asked
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def pins_for(base: str, *, package=None, wxc_id="mxc-test-1", shell_id="shell-test-1") -> dict:
    archive = tgz(PACKAGE) if package is None else package
    return {"linux": {}, "windows": {}, "base_image": {"repository": "r", "base": "b"}, "windows_programs": {
        "wxc-exec": {"id": wxc_id, "version": "1", "source": "a test package", "signer": SIGNER,
                     "archive": {"url": f"{base}/mxc.tgz", "integrity": integrity(archive)},
                     "builds": {arch: {"file": "wxc-exec.exe", "member": MEMBER[arch], "sha256": sha(WXC[arch])}
                                for arch in WXC}},
        "busybox": {"id": shell_id, "version": "1", "source": "a test shell", "signer": None,
                    "builds": {arch: {"file": SHELL_FILE[arch], "url": f"{base}/{SHELL_FILE[arch]}",
                                      "sha256": sha(SHELL[arch])} for arch in SHELL}}}}


@pytest.fixture
def world(site, monkeypatch):
    """The server holding the package and both shells, pins that name them, and a signature check that answers
    'valid, signed by SIGNER' and lists the files it was asked about."""
    served, base, asked = site
    (served / "mxc.tgz").write_bytes(tgz(PACKAGE))
    for arch, name in SHELL_FILE.items():
        (served / name).write_bytes(SHELL[arch])
    use_pins(monkeypatch, pins_for(base))
    checked: list = []
    monkeypatch.setattr(authenticode, "signature", lambda path: checked.append(Path(path)) or {
        "status": "valid", "signer": SIGNER, "code": 0, "detail": "valid"})
    monkeypatch.setattr(inst.time, "sleep", lambda s: None)  # No waiting between the downloader's retries

    class World:
        pass

    w = World()
    w.served, w.base, w.asked, w.checked, w.monkeypatch = served, base, asked, checked, monkeypatch
    return w


def files_under(folder: Path) -> list:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


def nothing_installed(root: Path) -> bool:  # noqa: F811
    """No program, no download and no staging folder is left under the root."""
    return files_under(root) == [] if root.exists() else True


# -- the shell: one file, downloaded as it is ------------------------------------------------------------

def test_the_shell_is_downloaded_checked_and_put_alone_in_a_folder_of_its_own(root, world):  # noqa: F811
    path = P.ensure(root, "busybox")
    folder = inst.runtime_dir(root) / "programs" / "shell-test-1-x64"
    assert path == folder / "busybox64u.exe" and path.read_bytes() == SHELL["x86_64"]
    # The sandbox is granted this whole folder: it holds the shell and nothing else, and nothing else was written
    assert [p.name for p in folder.iterdir()] == ["busybox64u.exe"]
    assert files_under(root) == ["openshell/runtime/programs/shell-test-1-x64/busybox64u.exe"]
    assert world.asked == ["/busybox64u.exe"]
    assert world.checked == []  # Its pin names no signer: no signature is asked for


def test_a_shell_with_another_sha256_is_refused_and_nothing_stays(root, world):  # noqa: F811
    (world.served / "busybox64u.exe").write_bytes(program(X64, b"another shell"))
    with pytest.raises(inst.InstallError, match=r"busybox64u\.exe from http://127\.0\.0\.1:\d+/busybox64u\.exe has "
                                                r"sha256 [0-9a-f]{12}\.\.\., pinned [0-9a-f]{12}\.\.\.; refused"):
        P.ensure(root, "busybox")
    assert nothing_installed(root)


def test_an_installed_program_is_checked_against_its_pin_and_not_downloaded_again(root, world):  # noqa: F811
    first = P.ensure(root, "busybox")
    assert P.ensure(root, "busybox") == first and world.asked == ["/busybox64u.exe"]
    assert P.installed(root, "busybox") == first


def test_a_changed_pin_id_installs_the_new_build_beside_the_old_one(root, world):  # noqa: F811
    old = P.ensure(root, "busybox")
    newer = program(X64, b"a newer shell")
    (world.served / "busybox64u.exe").write_bytes(newer)
    pins = pins_for(world.base, shell_id="shell-test-2")
    pins["windows_programs"]["busybox"]["builds"]["x86_64"]["sha256"] = sha(newer)
    use_pins(world.monkeypatch, pins)
    assert P.installed(root, "busybox") is None  # The pin moved: what is there is not the pinned build
    new = P.ensure(root, "busybox")
    assert new.parent.name == "shell-test-2-x64" and new.read_bytes() == newer
    # The old folder stays for now: a sandbox that is running may still use it (see prune)
    assert old.read_bytes() == SHELL["x86_64"]


def test_an_installed_file_that_was_changed_is_installed_again_before_it_is_used(root, world):  # noqa: F811
    path = P.ensure(root, "busybox")
    path.write_bytes(program(X64, b"changed on disk"))
    assert P.installed(root, "busybox") is None
    assert P.ensure(root, "busybox") == path and path.read_bytes() == SHELL["x86_64"]
    assert world.asked == ["/busybox64u.exe"] * 2 and [p.name for p in path.parent.iterdir()] == ["busybox64u.exe"]


def test_a_download_that_fails_is_reported_with_the_way_around_it(root, world):  # noqa: F811
    (world.served / "busybox64u.exe").unlink()
    with pytest.raises(inst.InstallError) as refused:
        P.ensure(root, "busybox")
    said = str(refused.value)
    assert "could not download" in said and "/busybox64u.exe" in said
    assert "OPENSHELL_BUSYBOX" in said  # The person's own copy is the way around a download that cannot be made
    assert nothing_installed(root)


# -- wxc-exec: one member read out of Microsoft's npm package --------------------------------------------

def test_wxc_exec_is_read_out_of_the_package_by_its_pinned_name_and_nothing_else_is_unpacked(root, world):  # noqa: F811
    path = P.ensure(root, "wxc-exec")
    assert path == inst.runtime_dir(root) / "programs" / "mxc-test-1-x64" / "wxc-exec.exe"
    assert path.read_bytes() == WXC["x86_64"]
    # Of the whole package only the one program is on disk, under its pinned file name; the archive is not kept
    assert files_under(root) == ["openshell/runtime/programs/mxc-test-1-x64/wxc-exec.exe"]
    assert world.asked == ["/mxc.tgz"]
    # The publisher's signature was asked for once, on the copy that was then moved into place
    assert [p.name for p in world.checked] == ["wxc-exec.exe"]
    assert world.checked[0].parent.parent.name.startswith(".staging-mxc-test-1-")
    assert P.ensure(root, "wxc-exec") == path and world.asked == ["/mxc.tgz"] and len(world.checked) == 1


def test_a_package_that_is_not_the_pinned_one_is_refused_before_anything_is_read_from_it(root, world):  # noqa: F811
    (world.served / "mxc.tgz").write_bytes(tgz([*PACKAGE, ("package/extra.txt", b"x")]))
    with pytest.raises(inst.InstallError, match=r"/mxc\.tgz does not match its pinned integrity \(sha512-.{12}\.\.\., "
                                                r"pinned sha512-.{12}\.\.\.\); refused"):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root) and world.checked == []


def repackaged(world, entries) -> None:
    """Serve a package made of *entries* and pin its integrity: only the checks after the first one can refuse."""
    data = tgz(entries)
    (world.served / "mxc.tgz").write_bytes(data)
    use_pins(world.monkeypatch, pins_for(world.base, package=data))


def test_the_program_inside_the_package_must_have_its_own_pinned_sha256(root, world):  # noqa: F811
    other = program(X64, b"another wxc")
    repackaged(world, [(n, other if n == MEMBER["x86_64"] else d) for n, d in PACKAGE])
    with pytest.raises(inst.InstallError, match=r"wxc-exec\.exe from http://127\.0\.0\.1:\d+/mxc\.tgz "
                                                r"\(package/bin/x64/wxc-exec\.exe\) has sha256 [0-9a-f]{12}\.\.\., "
                                                r"pinned [0-9a-f]{12}\.\.\.; refused"):
        P.ensure(root, "wxc-exec")
    # Hash first, signature second: a file with the wrong sha256 is never shown to the signature check
    assert nothing_installed(root) and world.checked == []


@pytest.mark.parametrize("name", [
    "../evil.exe", "package/bin/x64/../../../evil.exe", "package/../../evil.txt", "/abs/bin/wxc-exec.exe",
    "C:/Windows/System32/evil.dll", "package\\bin\\x64\\evil.exe", "package/bin/x64/wxc-exec.exe:stream",
    "package//bin/evil.exe", "package/./bin/evil.exe", "..\\..\\evil.exe",
])
def test_a_package_with_an_entry_that_could_leave_the_folder_is_refused(root, world, name):  # noqa: F811
    repackaged(world, [*PACKAGE, (name, b"evil")])
    with pytest.raises(inst.InstallError, match="the MXC package has an entry with an unsafe path"):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root) and world.checked == []
    # Nothing was written anywhere else either: beside the root there is only what the test itself put there
    assert [p.name for p in root.parent.rglob("*") if p.is_file() and "evil" in p.name] == []


def link(name: str, target: str, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info


def folder(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    return info


@pytest.mark.parametrize("entries, why", [
    ([e for e in PACKAGE if e[0] != MEMBER["x86_64"]], r"the MXC package has no package/bin/x64/wxc-exec\.exe"),
    ([*PACKAGE, (MEMBER["x86_64"], WXC["x86_64"])], r"the MXC package has more than one package/bin/x64/wxc-exec\.exe"),
    ([*PACKAGE, ("package/bin/X64/WXC-EXEC.EXE", b"same name in other letters")], "has more than one"),
    ([e for e in PACKAGE if e[0] != MEMBER["x86_64"]] + [("package/bin/x64/WXC-EXEC.exe", WXC["x86_64"])],
     r"the MXC package has no package/bin/x64/wxc-exec\.exe"),
    ([e for e in PACKAGE if e[0] != MEMBER["x86_64"]] + [link(MEMBER["x86_64"], "other.exe", tarfile.SYMTYPE)],
     r"package/bin/x64/wxc-exec\.exe in the MXC package is not a plain file"),
    ([e for e in PACKAGE if e[0] != MEMBER["x86_64"]]
     + [link(MEMBER["x86_64"], "package/bin/arm64/wxc-exec.exe", tarfile.LNKTYPE)], "is not a plain file"),
    ([e for e in PACKAGE if e[0] != MEMBER["x86_64"]] + [folder(MEMBER["x86_64"])], "is not a plain file"),
])
def test_the_pinned_member_must_be_there_once_as_a_plain_file(root, world, entries, why):  # noqa: F811
    repackaged(world, entries)
    with pytest.raises(inst.InstallError, match=why):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root) and world.checked == []


@pytest.mark.parametrize("data", [b"not an archive at all", tgz(PACKAGE)[:200], b"\x1f\x8b\x08\x00" + b"\0" * 64])
def test_a_download_that_is_not_a_readable_package_is_refused(root, world, data):  # noqa: F811
    (world.served / "mxc.tgz").write_bytes(data)
    use_pins(world.monkeypatch, pins_for(world.base, package=data))
    with pytest.raises(inst.InstallError, match="the downloaded MXC package is not a readable .tgz file"):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root)


def test_a_pin_with_an_integrity_the_installer_cannot_compute_is_refused(root, world):  # noqa: F811
    pins = pins_for(world.base)
    for bad in ("md5-abc", "sha512", "", None):
        pins["windows_programs"]["wxc-exec"]["archive"]["integrity"] = bad
        use_pins(world.monkeypatch, pins)
        with pytest.raises(inst.InstallError, match="must name its archive's url and integrity"):
            P.ensure(root, "wxc-exec")
    assert nothing_installed(root) and world.asked == []


@pytest.mark.parametrize("name, key, bad, why", [
    ("busybox", "file", "bin/busybox64u.exe", "must name a plain file name and its sha256"),
    ("busybox", "file", "..", "must name a plain file name and its sha256"),
    ("busybox", "file", "C:busybox64u.exe", "must name a plain file name and its sha256"),
    ("wxc-exec", "file", "..\\wxc-exec.exe", "must name a plain file name and its sha256"),
    ("busybox", "sha256", "abc", "must name a plain file name and its sha256"),
    ("busybox", "url", "", "names nothing to download"),
])
def test_a_pin_whose_build_is_not_a_plain_file_with_a_sha256_and_a_source_is_refused(
        root, world, name, key, bad, why):  # noqa: F811
    pins = pins_for(world.base)
    pins["windows_programs"][name]["builds"]["x86_64"][key] = bad
    use_pins(world.monkeypatch, pins)
    with pytest.raises(inst.InstallError, match=why):
        P.ensure(root, name)
    assert nothing_installed(root) and world.asked == [] and P.installed(root, name) is None


@pytest.mark.parametrize("bad", ["../outside", "a/b", "C:x", "", None, 7])
def test_a_pin_id_that_is_not_a_plain_name_is_refused(root, world, bad):  # noqa: F811
    # The id names the folder the program is installed into
    pins = pins_for(world.base)
    pins["windows_programs"]["busybox"]["id"] = bad
    use_pins(world.monkeypatch, pins)
    with pytest.raises(inst.InstallError, match="this version of the plugin pins no busybox for Windows"):
        P.ensure(root, "busybox")
    assert nothing_installed(root) and world.asked == []


def test_a_plugin_without_the_pin_installs_neither_program(root, world):  # noqa: F811
    use_pins(world.monkeypatch, {"linux": {}, "windows": {}})
    for name in P.PROGRAMS:
        with pytest.raises(inst.InstallError, match=f"this version of the plugin pins no {name} for Windows"):
            P.ensure(root, name)
        assert P.installed(root, name) is None and P.supported(name) is False


def test_a_build_for_an_architecture_this_plugin_does_not_install_for_is_refused(root, world):  # noqa: F811
    # A pin may come to name more architectures than this version of the plugin knows a folder name for
    pins = pins_for(world.base)
    for name in P.PROGRAMS:
        builds = pins["windows_programs"][name]["builds"]
        builds["x86"] = dict(builds["x86_64"])
    use_pins(world.monkeypatch, pins)
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    for name in P.PROGRAMS:
        with pytest.raises(inst.InstallError, match="has no build for Windows on 32-bit x86"):
            P.ensure(root, name)
        assert P.installed(root, name) is None
    assert nothing_installed(root) and world.asked == []


def test_a_build_another_launcher_installed_meanwhile_is_kept(root, world):  # noqa: F811
    # Two launchers start at sign-in and both find the shell missing. The one that finishes second finds the
    # checked file in place and leaves it alone: the first may be running it already.
    target = P.path(root, P.pinned("busybox"))
    others = []

    def fetch(url, dest):
        inst._download(url, dest)
        target.parent.mkdir(parents=True)  # The other launcher finishes its install during this download
        target.write_bytes(SHELL["x86_64"])
        others.append((target.stat().st_ino, target.stat().st_mtime_ns))

    assert P.ensure(root, "busybox", fetch=fetch) == target
    assert [(target.stat().st_ino, target.stat().st_mtime_ns)] == others  # The same file, not a replacement
    assert files_under(root) == ["openshell/runtime/programs/shell-test-1-x64/busybox64u.exe"]


# -- the publisher's signature, with the verifier faked ---------------------------------------------------

def answers(world, verdict) -> None:
    def fake(path):
        world.checked.append(Path(path))
        if isinstance(verdict, Exception):
            raise verdict
        return verdict

    world.monkeypatch.setattr(authenticode, "signature", fake)


@pytest.mark.parametrize("verdict, why", [
    ({"status": "unsigned", "signer": None, "code": 0x800B0100, "detail": "No signature was present in the subject."},
     r"wxc-exec\.exe of the MXC package mxc-test-1 is not signed; the pinned build is signed by Example Systems\. "
     r"Refused"),
    ({"status": "valid", "signer": "Another Vendor Ltd", "code": 0, "detail": "valid"},
     r"wxc-exec\.exe of the MXC package mxc-test-1 is signed by 'Another Vendor Ltd', not by Example Systems\. Refused"),
    ({"status": "invalid", "signer": None, "code": 0x80096010,
      "detail": "The digital signature of the object did not verify. (0x80096010)"},
     r"Windows does not accept the signature on wxc-exec\.exe of the MXC package mxc-test-1: The digital signature"),
    ({"status": "valid", "signer": "example systems", "code": 0, "detail": "valid"}, "is signed by"),
])
def test_wxc_exec_must_carry_the_pinned_publishers_signature(root, world, verdict, why):  # noqa: F811
    answers(world, verdict)
    with pytest.raises(inst.InstallError, match=why):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root) and len(world.checked) == 1


def test_when_the_signature_check_cannot_run_wxc_exec_is_installed_on_its_checksums(root, world, caplog):  # noqa: F811
    answers(world, authenticode.Unavailable("no wintrust here"))
    with caplog.at_level("WARNING", logger="openshell.install"):
        path = P.ensure(root, "wxc-exec")
    assert path.read_bytes() == WXC["x86_64"]
    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) == 1 and "the MXC package mxc-test-1" in lines[0]
    assert "could not be checked (no wintrust here)" in lines[0]


def test_a_shell_whose_pin_names_a_signer_gets_the_same_signature_check(root, world):  # noqa: F811
    # Today's shell is published without a signature and its pin says so (signer: null). A signed build needs only
    # the publisher's name in the pin: the same check then refuses a file that publisher did not sign.
    pins = pins_for(world.base)
    pins["windows_programs"]["busybox"]["signer"] = "Shell Publisher"
    use_pins(world.monkeypatch, pins)
    answers(world, {"status": "unsigned", "signer": None, "code": 0x800B0100, "detail": "No signature"})
    with pytest.raises(inst.InstallError, match=r"busybox64u\.exe of the sandbox's shell shell-test-1 is not signed; "
                                                r"the pinned build is signed by Shell Publisher"):
        P.ensure(root, "busybox")
    assert nothing_installed(root)
    answers(world, {"status": "valid", "signer": "Shell Publisher", "code": 0, "detail": "valid"})
    assert P.ensure(root, "busybox").read_bytes() == SHELL["x86_64"]


# -- the PC's architecture -------------------------------------------------------------------------------

@pytest.mark.parametrize("name, folder_name, file_name, data", [
    ("wxc-exec", "mxc-test-1-arm64", "wxc-exec.exe", WXC["aarch64"]),
    ("busybox", "shell-test-1-arm64", "busybox64a.exe", SHELL["aarch64"]),
])
def test_an_arm_pc_gets_the_arm64_builds(root, world, name, folder_name, file_name, data):  # noqa: F811
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "aarch64")
    path = P.ensure(root, name)
    assert (path.parent.name, path.name) == (folder_name, file_name) and path.read_bytes() == data


@pytest.mark.parametrize("name, why", [
    ("wxc-exec", "the MXC package mxc-test-1 has no build for Windows on 32-bit x86; this version of the plugin "
                 "supports x64, Arm64 Windows PCs"),
    ("busybox", "the sandbox's shell shell-test-1 has no build for Windows on 32-bit x86"),
])
def test_a_pc_the_pin_has_no_build_for_is_refused_before_any_download(root, world, name, why):  # noqa: F811
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    with pytest.raises(inst.InstallError, match=why):
        P.ensure(root, name)
    assert nothing_installed(root) and world.asked == []


def test_a_program_built_for_another_architecture_is_refused_under_this_pcs_pin(root, world):  # noqa: F811
    # The x64 pin names the Arm64 program, sha256 and all: every hash matches, and the file's own header refuses.
    pins = pins_for(world.base)
    wxc, shell = pins["windows_programs"]["wxc-exec"]["builds"], pins["windows_programs"]["busybox"]["builds"]
    wxc["x86_64"] = dict(wxc["aarch64"])
    shell["x86_64"] = {**shell["aarch64"], "file": "busybox64u.exe"}
    use_pins(world.monkeypatch, pins)
    with pytest.raises(inst.InstallError, match=r"wxc-exec\.exe of the MXC package mxc-test-1 is built for Arm64, "
                                                r"but this PC is x64; refused"):
        P.ensure(root, "wxc-exec")
    with pytest.raises(inst.InstallError, match=r"busybox64u\.exe of the sandbox's shell shell-test-1 is built for "
                                                r"Arm64, but this PC is x64; refused"):
        P.ensure(root, "busybox")
    assert nothing_installed(root) and world.checked == []  # Refused before the signature is read


def test_a_file_that_is_no_windows_program_is_refused(root, world):  # noqa: F811
    text = b"#!/bin/sh\necho not a Windows program\n"
    (world.served / "busybox64u.exe").write_bytes(text)
    pins = pins_for(world.base)
    pins["windows_programs"]["busybox"]["builds"]["x86_64"]["sha256"] = sha(text)
    use_pins(world.monkeypatch, pins)
    with pytest.raises(inst.InstallError, match=r"busybox64u\.exe of the sandbox's shell shell-test-1 is not a "
                                                r"Windows program; refused"):
        P.ensure(root, "busybox")
    assert nothing_installed(root)


# -- which file is used: the person's own copy, else the plugin's ------------------------------------------

@pytest.fixture
def windows_pc(monkeypatch):
    """A Windows PC whose user set neither variable and has neither program on PATH."""
    from openshell import busybox_env

    monkeypatch.setattr(P, "_on_windows", lambda: True)
    for variable in P.ENV.values():
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(P.shutil, "which", lambda name, *a, **kw: None)
    monkeypatch.setattr(busybox_env, "find_busybox", lambda: None)


def own_copy(tmp_path, name: str) -> Path:
    file = tmp_path / "own" / name
    file.parent.mkdir(exist_ok=True)
    file.write_bytes(program(X64, b"the person's own " + name.encode()))
    return file


@pytest.mark.parametrize("name", P.PROGRAMS)
def test_with_nothing_of_the_persons_own_the_pinned_install_is_used(root, world, windows_pc, name):  # noqa: F811
    # Asking which file is used installs nothing and downloads nothing
    asked = P.chosen(name, {}, root)
    assert asked == {"name": name, "file": None, "source": "pinned install", "installed": False, "ignored": []}
    assert world.asked == [] and nothing_installed(root)
    used = P.use(name, {}, root)
    assert used["file"] == P.installed(root, name) and used["file"].is_file()
    assert (used["source"], used["installed"], used["ignored"]) == ("pinned install", True, [])
    assert P.chosen(name, {}, root) == used


@pytest.mark.parametrize("name", P.PROGRAMS)
def test_the_variable_wins_over_the_pinned_install_and_the_spec_wins_over_the_variable(
        root, world, windows_pc, tmp_path, name):  # noqa: F811
    P.ensure(root, name)
    downloads = list(world.asked)
    by_variable, by_spec = own_copy(tmp_path, f"variable-{name}.exe"), own_copy(tmp_path, f"spec-{name}.exe")
    world.monkeypatch.setenv(P.ENV[name], str(by_variable))
    for pick in (P.chosen, P.use):
        got = pick(name, {}, root)
        assert (got["file"], got["source"]) == (by_variable.resolve(), f"variable {P.ENV[name]}")
        assert "installed" not in got  # That word is about the plugin's own copy
        spec = {"wxc_exec" if name == "wxc-exec" else "busybox": str(by_spec)}
        got = pick(name, spec, root)
        assert (got["file"], got["source"], got["ignored"]) == (by_spec.resolve(), "spec", [])
    assert world.asked == downloads


def test_the_older_place_for_wxc_exec_in_the_spec_still_counts(root, world, windows_pc, tmp_path):  # noqa: F811
    first, second = own_copy(tmp_path, "first.exe"), own_copy(tmp_path, "second.exe")
    got = P.chosen("wxc-exec", {"wxc_exec": str(first), "openshell": {"wxc_exec": str(second)}}, root)
    assert got["file"] == first.resolve()
    assert P.chosen("wxc-exec", {"openshell": {"wxc_exec": str(second)}}, root)["file"] == second.resolve()


@pytest.mark.parametrize("name", P.PROGRAMS)
def test_a_variable_that_names_no_file_is_skipped_and_listed(root, world, windows_pc, tmp_path, name):  # noqa: F811
    gone = tmp_path / "removed" / "program.exe"
    world.monkeypatch.setenv(P.ENV[name], str(gone))
    got = P.use(name, {}, root)
    assert got["source"] == "pinned install" and got["file"] == P.installed(root, name)
    assert got["ignored"] == [{"source": f"variable {P.ENV[name]}", "file": str(gone), "reason": "no such file"}]


def test_a_program_on_path_is_not_used_where_the_plugin_installs_its_own(root, world, windows_pc, tmp_path):  # noqa: F811
    from openshell import busybox_env

    on_path = own_copy(tmp_path, "on-path.exe")
    world.monkeypatch.setattr(P.shutil, "which", lambda name, *a, **kw: str(on_path))
    world.monkeypatch.setattr(busybox_env, "find_busybox", lambda: str(on_path))
    for name in P.PROGRAMS:
        assert P.chosen(name, {}, root)["source"] == "pinned install"
    # Where the pin has no build for the PC, and off Windows, PATH is what is left
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    for name in P.PROGRAMS:
        got = P.use(name, {}, root)
        assert (got["file"], got["source"]) == (on_path.resolve(), "PATH") and "installed" not in got
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86_64")
    world.monkeypatch.setattr(P, "_on_windows", lambda: False)
    for name in P.PROGRAMS:
        assert P.use(name, {}, root)["source"] == "PATH"
    assert world.asked == [] and nothing_installed(root)


def test_with_nothing_anywhere_no_file_is_named(root, world, windows_pc):  # noqa: F811
    world.monkeypatch.setattr(P, "_on_windows", lambda: False)
    for name in P.PROGRAMS:
        assert P.use(name, None, root) == {"name": name, "file": None, "source": None, "ignored": []}


def test_a_look_at_what_is_installed_reads_an_unchanged_file_once(root, world, windows_pc):  # noqa: F811
    # The Sandbox page asks which wxc-exec would be used every few seconds; a use hashes the file every time.
    path = P.ensure(root, "wxc-exec")
    hashed = []
    real = inst.sha256_file
    world.monkeypatch.setattr(inst, "sha256_file", lambda file: hashed.append(Path(file).name) or real(file))
    assert P.installed(root, "wxc-exec") == path and P.chosen("wxc-exec", {}, root)["file"] == path
    assert hashed == []  # Checked when it was installed, and not changed since
    assert P.ensure(root, "wxc-exec") == path and P.use("wxc-exec", {}, root)["file"] == path
    assert hashed == ["wxc-exec.exe"] * 2
    path.write_bytes(WXC["x86_64"] + b"!")
    assert P.installed(root, "wxc-exec") is None and hashed == ["wxc-exec.exe"] * 3


# -- what `sandbox check` and `sandbox runtime status` print for the two programs ---------------------------

def signatures(world, by_name: dict) -> None:
    def fake(path):
        answer = by_name.get(Path(path).name, {"status": "unsigned", "signer": None, "code": 1, "detail": "-"})
        if isinstance(answer, Exception):
            raise answer
        return answer

    world.monkeypatch.setattr(authenticode, "signature", fake)


VALID = {"status": "valid", "signer": SIGNER, "code": 0, "detail": "valid"}


def test_status_names_the_file_its_source_and_what_windows_says_of_it(root, world, windows_pc, tmp_path):  # noqa: F811
    signatures(world, {"wxc-exec.exe": VALID})
    wxc_pin = {"id": "mxc-test-1", "version": "1", "arch": "x86_64", "file": "wxc-exec.exe",
               "sha256": sha(WXC["x86_64"]), "signer": SIGNER}
    shell_pin = {"id": "shell-test-1", "version": "1", "arch": "x86_64", "file": "busybox64u.exe",
                 "sha256": sha(SHELL["x86_64"]), "signer": None}
    note = "not installed yet: `hermes sandbox runtime install` installs it, and so does switching the sandbox on"
    assert P.status(root, {}) == {
        "wxc-exec": {"file": None, "source": "pinned install", "installed": False, "pinned": wxc_pin, "note": note},
        "busybox": {"file": None, "source": "pinned install", "installed": False, "pinned": shell_pin, "note": note}}
    wxc, shell = P.ensure(root, "wxc-exec"), P.ensure(root, "busybox")
    assert P.status(root, {}) == {
        "wxc-exec": {"file": str(wxc), "source": "pinned install", "installed": True, "pinned": wxc_pin,
                     "sha256": sha(WXC["x86_64"]), "is_pinned_build": True, "signature": "valid", "signer": SIGNER},
        # The shell is published without a signature: its pin says so (signer null) and so does Windows
        "busybox": {"file": str(shell), "source": "pinned install", "installed": True, "pinned": shell_pin,
                    "sha256": sha(SHELL["x86_64"]), "is_pinned_build": True, "signature": "unsigned", "signer": None}}
    assert json.loads(json.dumps(P.status(root, {}))) == P.status(root, {})  # Printable as it is


def test_status_shows_a_variable_in_use_and_one_that_names_no_file(root, world, windows_pc, tmp_path):  # noqa: F811
    signatures(world, {"wxc-exec.exe": VALID,
                       "mine.exe": {"status": "valid", "signer": "Somebody Else", "code": 0, "detail": "valid"}})
    mine, gone = own_copy(tmp_path, "mine.exe"), tmp_path / "gone" / "busybox64u.exe"
    P.ensure(root, "wxc-exec")
    world.monkeypatch.setenv("OPENSHELL_WXC_EXEC_PATH", str(mine))
    world.monkeypatch.setenv("OPENSHELL_BUSYBOX", str(gone))
    shown = P.status(root, {})
    wxc = shown["wxc-exec"]
    # The person's own file is the one in use, although the pinned build is installed: the line cannot be missed
    assert (wxc["file"], wxc["source"]) == (str(mine.resolve()), "variable OPENSHELL_WXC_EXEC_PATH")
    assert wxc["sha256"] == sha(mine.read_bytes()) and wxc["is_pinned_build"] is False
    assert (wxc["signature"], wxc["signer"]) == ("valid", "Somebody Else") and "installed" not in wxc
    assert wxc["pinned"]["id"] == "mxc-test-1" and "ignored" not in wxc
    shell = shown["busybox"]
    assert (shell["file"], shell["source"], shell["installed"]) == (None, "pinned install", False)
    assert shell["ignored"] == [{"source": "variable OPENSHELL_BUSYBOX", "file": str(gone), "reason": "no such file"}]


def test_status_off_windows_and_without_a_pin_says_so_instead_of_failing(root, world, windows_pc):  # noqa: F811
    signatures(world, {"wxc-exec.exe": authenticode.Unavailable("not Windows")})
    P.ensure(root, "wxc-exec")
    assert (P.status(root)["wxc-exec"]["signature"], P.status(root)["wxc-exec"]["signer"]) == ("not checked", None)
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    shown = P.status(root)
    for name in P.PROGRAMS:
        assert shown[name]["file"] is None and shown[name]["source"] is None and shown[name]["note"] == "not found"
        assert "has no build for Windows on 32-bit x86" in shown[name]["pinned"]["error"]


# -- builds no pin names any more ---------------------------------------------------------------------------

def test_prune_removes_earlier_builds_and_interrupted_installs_and_keeps_the_pinned_ones(root, world):  # noqa: F811
    old, wxc = P.ensure(root, "busybox"), P.ensure(root, "wxc-exec")
    newer = program(X64, b"a newer shell")
    (world.served / "busybox64u.exe").write_bytes(newer)
    pins = pins_for(world.base, shell_id="shell-test-2")
    pins["windows_programs"]["busybox"]["builds"]["x86_64"]["sha256"] = sha(newer)
    use_pins(world.monkeypatch, pins)
    new = P.ensure(root, "busybox")
    interrupted = P.programs_dir(root) / ".staging-mxc-test-1-abc"
    interrupted.mkdir()
    (interrupted / "package.tgz").write_bytes(b"half a download")
    (P.programs_dir(root) / "stray.txt").write_bytes(b"x")
    assert P.prune(root) == [".staging-mxc-test-1-abc", "shell-test-1-x64", "stray.txt"]
    assert files_under(P.programs_dir(root)) == ["mxc-test-1-x64/wxc-exec.exe", "shell-test-2-x64/busybox64u.exe"]
    assert new.read_bytes() == newer and wxc.is_file() and not old.exists()
    assert P.prune(root) == [] and P.prune(root.parent / "another-root") == []


def test_prune_leaves_everything_when_a_pin_cannot_be_read(root, world):  # noqa: F811
    P.ensure(root, "busybox")
    world.monkeypatch.setattr(inst, "windows_arch", lambda: "x86")
    assert P.prune(root) == [] and files_under(P.programs_dir(root)) == ["shell-test-1-x64/busybox64u.exe"]


def test_removing_the_runtime_removes_the_programs(root, world):  # noqa: F811
    P.ensure(root, "busybox"), P.ensure(root, "wxc-exec")
    (inst.runtime_dir(root) / "gateway").mkdir()
    assert inst.remove_runtime(root) is True
    assert [p.name for p in inst.runtime_dir(root).iterdir()] == ["gateway"]
    assert P.installed(root, "busybox") is None and P.installed(root, "wxc-exec") is None


def test_clearing_out_old_openshell_runtimes_leaves_the_programs(root, world):  # noqa: F811
    # After a gateway moved to a new OpenShell runtime, the installer removes the old runtime's folder
    wxc, shell = P.ensure(root, "wxc-exec"), P.ensure(root, "busybox")
    old = inst.runtime_dir(root) / "openshell-old"
    old.mkdir()
    (old / inst.IDENTITY_FILE).write_text("{}", encoding="utf-8")
    assert inst.prune(root, keep={"openshell-current"}) == ["openshell-old"]
    assert wxc.is_file() and shell.is_file()


def test_installing_a_program_starts_no_program():
    # The installer hashes the file and asks Windows for its signature inside this process (authenticode.py):
    # nothing it downloads is run by it, and nothing is started that could open a window.
    text = Path(P.__file__).read_text(encoding="utf-8")
    for word in ("subprocess", "Popen", "os.system", "os.startfile", "os.exec", "os.spawn", "ShellExecute",
                 "CreateProcess", "powershell", "tar.extractall", ".extract("):
        assert word not in text, f"windows_programs.py mentions {word}"
    assert "inst._check_publisher(" in text and "tar.extractfile(" in text


# -- the shipped pin ----------------------------------------------------------------------------------------

def shipped() -> dict:
    return json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))["windows_programs"]


def test_the_shipped_pin_names_microsofts_package_and_its_two_programs():
    wxc = shipped()["wxc-exec"]
    assert (wxc["id"], wxc["version"], wxc["signer"]) == ("mxc-sdk-1.0.1", "1.0.1", "Microsoft Corporation")
    assert wxc["archive"] == {
        "url": "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.1.tgz",
        "integrity": "sha512-2cP925G5+lQyKzjBVha8uNtVd7XESgDBtgi1yCYYSo9M3xiFyZWtCO4SWPGTk509rdI6nqjyGcZxvEP3t6l8Hg=="}
    assert wxc["builds"] == {
        "x86_64": {"file": "wxc-exec.exe", "member": "package/bin/x64/wxc-exec.exe",
                   "sha256": "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a"},
        "aarch64": {"file": "wxc-exec.exe", "member": "package/bin/arm64/wxc-exec.exe",
                    "sha256": "91aa4171e8809f33f19622c381116188eab7d8c8cffad231230a31b58146ee77"}}


def test_the_shipped_pin_names_the_two_shell_builds_and_says_they_are_not_signed():
    shell = shipped()["busybox"]
    assert shell["id"] == "busybox-w32-FRP-6075-g169694ebd"
    # The pin carries the field, and the field says so: no publisher, with the reason beside it
    assert "signer" in shell and shell["signer"] is None and "not code-signed" in shell["_signer"]
    assert shell["builds"] == {
        "x86_64": {"file": "busybox64u.exe",
                   "url": "https://frippery.org/files/busybox/busybox-w64u-FRP-6075-g169694ebd.exe",
                   "sha256": "6e263d154d8548d1eb936f65d1d8312c80df31c45974e48d6335e4dcc0f4f34c"},
        "aarch64": {"file": "busybox64a.exe",
                    "url": "https://frippery.org/files/busybox/busybox-w64a-FRP-6075-g169694ebd.exe",
                    "sha256": "e67f873d19d58c535cc9f0c4965ffd622e19b7bab87e3da89cb2185fb54464d7"}}
    # The name the shell is installed under is one the backend inside the sandbox looks for on PATH
    from openshell import busybox_env

    assert shell["builds"]["x86_64"]["file"] in busybox_env._BUSYBOX_NAMES["amd64"]
    assert shell["builds"]["aarch64"]["file"] == busybox_env._BUSYBOX_NAMES["arm64"][0]


@pytest.mark.parametrize("arch, word", [("x86_64", "x64"), ("aarch64", "arm64")])
def test_the_shipped_pin_reads_as_a_build_for_each_architecture_over_https(root, arch, word):  # noqa: F811
    for name in P.PROGRAMS:
        pin = P.pinned(name, arch=arch)
        assert pin["url"].startswith("https://") and pin["arch"] == arch and len(pin["sha256"]) == 64
        assert P.path(root, pin) == inst.runtime_dir(root) / "programs" / f"{pin['id']}-{word}" / pin["file"]
    assert P.pinned("wxc-exec", arch=arch)["integrity"][0] == "sha512"


# -- with the real signature check, where a real file is at hand -------------------------------------------

REAL_SIGNATURE = authenticode.signature
windows_only = pytest.mark.skipif(os.name != "nt", reason="asks Windows for a file's signature")


@windows_only
def test_on_windows_an_unsigned_file_under_the_wxc_exec_pin_is_refused_by_the_real_check(root, world):  # noqa: F811
    world.monkeypatch.setattr(authenticode, "signature", REAL_SIGNATURE)  # The test's program carries no signature
    with pytest.raises(inst.InstallError, match=r"wxc-exec\.exe of the MXC package mxc-test-1 is not signed; the "
                                                r"pinned build is signed by Example Systems\. Refused"):
        P.ensure(root, "wxc-exec")
    assert nothing_installed(root)


def _signed_program() -> Path:
    """A really signed Windows program for this PC, when the person running the tests named one: the wxc-exec
    of ``OPENSHELL_WXC_EXEC_PATH``."""
    named = os.environ.get("OPENSHELL_WXC_EXEC_PATH")
    if os.name != "nt" or not named or not Path(named).is_file():
        pytest.skip("set OPENSHELL_WXC_EXEC_PATH to a signed wxc-exec.exe to run against a really signed file")
    if REAL_SIGNATURE(named)["status"] != "valid" or P.hostarch.pe_machine(named) != "x86_64":
        pytest.skip("the wxc-exec named by OPENSHELL_WXC_EXEC_PATH is not a signed x64 program")
    return Path(named)


def test_on_windows_another_publishers_signed_program_under_the_pinned_name_is_refused(root, world):  # noqa: F811
    real = _signed_program()
    publisher = REAL_SIGNATURE(real)["signer"]
    data = real.read_bytes()
    world.monkeypatch.setattr(authenticode, "signature", REAL_SIGNATURE)
    package = tgz([(n, data if n == MEMBER["x86_64"] else d) for n, d in PACKAGE])
    (world.served / "mxc.tgz").write_bytes(package)
    pins = pins_for(world.base, package=package)
    pins["windows_programs"]["wxc-exec"]["builds"]["x86_64"]["sha256"] = sha(data)
    use_pins(world.monkeypatch, pins)  # Every hash matches; the pin names another publisher than the file's
    with pytest.raises(inst.InstallError) as refused:
        P.ensure(root, "wxc-exec")
    assert f"is signed by {publisher!r}, not by Example Systems. Refused." in str(refused.value)
    assert nothing_installed(root)
    # The same file under a pin that names its real publisher is installed
    pins["windows_programs"]["wxc-exec"]["signer"] = publisher
    use_pins(world.monkeypatch, pins)
    assert P.ensure(root, "wxc-exec").read_bytes() == data
    # And status reads the publisher's name off the file in use (the pinned build, wherever it is taken from)
    row = P.status(root)["wxc-exec"]
    assert (row["signature"], row["signer"], row["is_pinned_build"]) == ("valid", publisher, True)


@windows_only
@pytest.mark.parametrize("name", P.PROGRAMS)
def test_on_windows_a_real_copy_of_a_pinned_build_is_what_its_pin_says(name):
    """With the person's own copy of a pinned build at hand (the variable names it), Windows must say of it what
    the shipped pin says: the pinned publisher for wxc-exec, no signature for the shell."""
    named = os.environ.get(P.ENV[name])
    if not named or not Path(named).is_file():
        pytest.skip(f"set {P.ENV[name]} to a copy of the pinned build to compare it with its pin")
    block = shipped()[name]
    if inst.sha256_file(Path(named)) not in {build["sha256"] for build in block["builds"].values()}:
        pytest.skip(f"the file named by {P.ENV[name]} is not a pinned build")
    got = REAL_SIGNATURE(named)
    if block["signer"] is None:
        assert got["status"] == "unsigned"
    else:
        assert (got["status"], got["signer"]) == ("valid", block["signer"])
