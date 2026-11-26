"""A protected folder is refused under every name it has, on every route that takes a folder.

A layout under the test's own folder stands in for a computer: a user home with a credential folder, the Hermes
root in it with the launcher's folder and a profile folder, and an ordinary project folder. Each protected folder
is named in the ways Windows allows beside its drive path (extended-length, a share of this computer, a device,
a volume id) and through a link, and offered to each route: the settings page's check and save, ``--folder``, the
saved spec at a start, a folder card, and the request file the hook inside the sandbox writes.

No test opens a share. A share's name is text made from a folder's drive path, a link to a share is a link to a
folder of the test with its target replaced, and ``Watch`` stops any look at the file system that a test put off
limits.
"""
import asyncio
import builtins
import functools
import io
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_activity import T0, call, make_db
from test_cards import FakeDriver, FakeSup, _cards, _settle, _setup
from test_settings_routes import _call, _supervisor

from openshell.launcher import activity as A
from openshell.launcher import layout as L
from openshell.launcher import spec as SP
from openshell.launcher.host_routes import HostRoutes
from openshell.launcher.verdicts import read_requests

WINDOWS = os.name == "nt"
windows_only = pytest.mark.skipif(not WINDOWS, reason="these spellings are Windows paths")
links_leave = pytest.mark.skipif(not WINDOWS, reason="a link on this system names a path of the same computer")
PROTECTED = ("user", "root", "state", "cred", "home")
# The three kinds a drive path is also reachable by, the two a volume has, and two more of the same shape.
SPELLINGS = ("extended", "share-localhost", "share-loopback", "extended-share", "device", "volume-id",
             "device-drive", "extended-forward")
SHARE = "\\\\?\\UNC\\files.invalid\\share"  # how a link to a share of another computer reads


@pytest.fixture
def place(tmp_path, monkeypatch):
    user = tmp_path / "user"
    root = user / "AppData" / "Local" / "hermes"
    made = SimpleNamespace(tmp=tmp_path, user=user, root=root, state=root / "openshell" / "work",
                           home=root / "profiles" / "work", cred=user / ".ssh", project=user / "projects" / "app")
    for folder in (made.state, made.home, made.cred, made.project):
        folder.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: user))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    made.layout = L.ProfileLayout(name="work", home=made.home, root=root)
    return made


class Opened(AssertionError):
    """Something was looked at that a test put off limits."""


class Watch:
    """Stops every look at the file system that a test put off limits, and keeps what was tried (``seen``).

    ``below(link)``: nothing follows the link at *link*. A call that follows what it is given (``os.stat``,
    ``Path.exists``, ``Path.resolve``, ``open`` and the like) is stopped for *link* and for every path below it;
    a call that looks at the entry itself (``os.lstat``, ``os.readlink``) is stopped only below it, where it
    would follow the link on the way. ``shares()``: no call at all is made for a path that starts with two
    separators. The call is stopped before it is made, so nothing is opened whatever the code under test does."""

    FOLLOWING = ((os, "stat"), (os, "scandir"), (os, "listdir"), (os, "open"), (os, "access"), (os.path, "exists"),
                 (os.path, "isdir"), (os.path, "isfile"), (os.path, "realpath"), (os.path, "samefile"),
                 (os.path, "getsize"), (Path, "exists"), (Path, "is_dir"), (Path, "is_file"), (Path, "resolve"),
                 (Path, "stat"), (Path, "iterdir"), (Path, "open"), (Path, "read_text"), (Path, "read_bytes"),
                 (Path, "samefile"), (builtins, "open"), (io, "open"))
    NOT_FOLLOWING = ((os, "lstat"), (os, "readlink"), (os.path, "lexists"), (os.path, "islink"), (Path, "lstat"),
                     (Path, "is_symlink"))

    def __init__(self):
        self.seen, self._links, self._shares, self._undo = [], [], False, []

    def below(self, link) -> "Watch":
        self._links.append(os.path.normcase(str(link)))
        return self

    def shares(self) -> "Watch":
        self._shares = True
        return self

    def _off_limits(self, path, follows: bool) -> bool:
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if not isinstance(path, (str, os.PathLike)):
            return False
        text = os.path.normcase(os.fspath(path))
        if self._shares and re.match(r"[\\/]{2}", text):
            return True
        return any(text.startswith(link + os.sep) or (follows and text == link) for link in self._links)

    def start(self) -> "Watch":
        for follows, calls in ((True, self.FOLLOWING), (False, self.NOT_FOLLOWING)):
            for holder, name in calls:
                real = getattr(holder, name)

                @functools.wraps(real)
                def call(path=None, *args, _real=real, _follows=follows, _name=f"{holder.__name__}.{name}", **kwargs):
                    if self._off_limits(path, _follows and kwargs.get("follow_symlinks", True)):
                        self.seen.append(f"{_name}({os.fspath(path)!r})")
                        raise Opened(self.seen[-1])
                    return _real(path, *args, **kwargs)

                self._undo.append((holder, name, real))
                setattr(holder, name, call)
        return self

    def stop(self) -> None:
        while self._undo:
            holder, name, real = self._undo.pop()
            setattr(holder, name, real)


@pytest.fixture
def watch(request):
    made, failed = Watch(), request.session.testsfailed
    yield made
    made.stop()
    if made.seen and request.session.testsfailed == failed:  # stopped, and the code under test went on regardless
        pytest.fail("looked at what the test put off limits: " + "; ".join(made.seen), pytrace=False)


def _volume(drive: str) -> dict:
    """How Windows names the volume of *drive* (``C:``) beside its letter: its device and its id."""
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    out = {}
    device = ctypes.create_unicode_buffer(1024)
    if kernel.QueryDosDeviceW(drive, device, 1024):
        out["device"] = "\\\\?\\GLOBALROOT" + device.value
    volume = ctypes.create_unicode_buffer(128)
    if kernel.GetVolumeNameForVolumeMountPointW(drive + "\\", volume, 128):
        out["volume-id"] = volume.value.rstrip("\\")
    return out


def _spelled(folder: Path, spelling: str) -> str:
    """*folder* (a drive path) under another of its names. A share's name is made from the text of the drive
    path, as Windows names the drive's own share; nothing is asked of the share."""
    text = str(folder)
    drive, rest = text[:2], text[3:]
    if spelling == "extended":
        return "\\\\?\\" + text
    if spelling == "device-drive":
        return "\\\\.\\" + text
    if spelling == "extended-forward":
        return "//?/" + text.replace("\\", "/")
    if spelling in ("device", "volume-id"):
        named = _volume(drive).get(spelling)
        if not named:
            pytest.skip(f"Windows gives no {spelling} name for {drive}")
        return f"{named}\\{rest}"
    host = "127.0.0.1" if spelling == "share-loopback" else "localhost"
    start = "\\\\?\\UNC\\" if spelling == "extended-share" else "\\\\"
    return f"{start}{host}\\{drive[0]}$\\{rest}"


def _offer(route: str, raw: str, layout) -> dict:
    """*raw* offered as a folder on *route*; the folder as it would be saved. Raises ``LayoutError`` when refused."""
    if route == "validate":
        return {"path": str(L.validate_folder(raw, layout)), "access": "ro"}
    if route == "check":  # the settings page's check of one folder, and a card's
        return SP.folder_from_entry({"path": raw, "access": "ro"}, layout)
    if route == "save":
        return SP.folders_from_body({"folders": [{"path": raw, "access": "rw"}]}, layout)[0]
    if route == "cli":
        return SP.parse_folder_arg(raw + ":ro", layout)
    return SP.checked_folders({"folders": [{"path": raw, "access": "rw"}]}, layout)[0]  # the saved spec at a start


ROUTES = ("validate", "check", "save", "cli", "saved")


@windows_only
@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize("folder", PROTECTED)
@pytest.mark.parametrize("route", ROUTES)
def test_a_protected_folder_is_refused_under_another_spelling(place, watch, route, folder, spelling):
    raw = _spelled(getattr(place, folder), spelling)
    watch.shares().start()
    with pytest.raises(L.LayoutError):
        _offer(route, raw, place.layout)


@windows_only
@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize("route", ROUTES)
def test_an_ordinary_folder_is_taken_by_its_drive_path_only(place, watch, route, spelling):
    raw = _spelled(place.project, spelling)
    watch.shares().start()
    with pytest.raises(L.LayoutError) as refused:
        _offer(route, raw, place.layout)
    assert "drive of this computer" in str(refused.value)
    assert _offer(route, str(place.project), place.layout)["path"] == str(place.project)


@pytest.mark.parametrize("route", ROUTES)
def test_the_plain_spellings_of_a_folder_give_one_path(place, route):
    text = str(place.project)
    plain = [text, text + os.sep, str(place.project / "." / ".." / "app")]
    if WINDOWS:
        plain += [text.swapcase(), text.replace("\\", "/")]
    assert {_offer(route, raw, place.layout)["path"] for raw in plain} == {text}
    for folder in PROTECTED:
        protected = getattr(place, folder)
        for raw in (str(protected), str(protected / "." / ".." / protected.name)):
            with pytest.raises(L.LayoutError):
                _offer(route, raw, place.layout)


@pytest.mark.skipif(WINDOWS, reason="a second leading slash is a POSIX spelling")
@pytest.mark.parametrize("folder", PROTECTED)
@pytest.mark.parametrize("route", ROUTES)
def test_a_second_leading_slash_names_the_same_folder(place, route, folder):
    with pytest.raises(L.LayoutError):
        _offer(route, "/" + str(getattr(place, folder)), place.layout)
    assert _offer(route, "/" + str(place.project), place.layout)["path"] == str(place.project)


# -- the settings routes -------------------------------------------------------------------------------

@windows_only
@pytest.mark.parametrize("spelling", ("extended", "share-localhost", "extended-share", "device", "volume-id"))
def test_the_settings_page_refuses_the_launchers_folder_under_another_spelling(place, watch, spelling):
    raw = _spelled(place.state, spelling)
    routes = HostRoutes(_supervisor(place.tmp, place.layout), lambda: None)
    before = place.layout.spec_path.read_bytes()
    watch.shares().start()
    for access in ("ro", "rw"):
        status, payload, _ = _call(routes, "PUT", "folders", {"folders": [{"path": raw, "access": access}]})
        assert status == 422 and "drive of this computer" in payload["detail"], payload
        status, payload, _ = _call(routes, "POST", "folders/check", {"path": raw, "access": access})
        assert status == 422, payload
    assert place.layout.spec_path.read_bytes() == before


@windows_only
def test_a_start_refuses_a_folder_saved_under_another_spelling(place, watch):
    """The folders in the saved settings are checked at every start as a folder is when it is added."""
    watch.shares().start()
    sup = _supervisor(place.tmp, place.layout, [(_spelled(place.state, "share-localhost"), "rw")])

    async def main():
        try:
            with pytest.raises(L.LayoutError) as refused:
                await sup.start()
        finally:
            await sup.stop()
        return str(refused.value)

    assert "drive of this computer" in asyncio.run(main())


# -- links: another name of a folder that is a drive path too ------------------------------------------

def _link(link: Path, target: Path) -> None:
    """A link to a folder that needs no privilege: a junction on Windows, a symbolic link elsewhere."""
    if WINDOWS:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_a_credential_folder_that_is_a_link_is_protected_where_it_points(place):
    keys = place.tmp / "vault" / "ssh"
    (keys / "old").mkdir(parents=True)
    (place.tmp / "other").mkdir()
    place.cred.rmdir()
    _link(place.cred, keys)
    for folder in (keys, keys.parent, keys / "old", place.cred):
        with pytest.raises(L.LayoutError) as refused:
            L.validate_folder(str(folder), place.layout)
        assert "credential folder" in str(refused.value)
    assert L.validate_folder(str(place.tmp / "other"), place.layout) == place.tmp / "other"


def test_a_profile_folder_linked_out_of_the_root_is_protected_where_it_points(place):
    """A profile folder that is a link to another disk: the profile's files are there, the keys file among them."""
    ours, theirs = place.tmp / "disk" / "work", place.tmp / "disk2" / "other"
    for real in (ours, theirs):
        real.mkdir(parents=True)
    place.home.rmdir()
    _link(place.home, ours)
    _link(place.root / "profiles" / "other", theirs)
    (place.tmp / "disk3").mkdir()
    layout = L.ProfileLayout(name="work", home=ours, root=place.root)
    for folder in (ours, ours.parent, theirs, theirs.parent):
        with pytest.raises(L.LayoutError) as refused:
            L.validate_folder(str(folder), layout)
        assert "Hermes data folder" in str(refused.value)
    assert L.validate_folder(str(place.tmp / "disk3"), layout) == place.tmp / "disk3"


def test_a_file_system_without_file_ids_still_tells_folders_apart(place, monkeypatch):
    """Where the file system gives no id for a folder, no two folders count as one: an ordinary folder is taken
    and a protected one is refused by its path."""
    real = os.stat

    class NoId:
        st_ino = 0

        def __init__(self, found):
            self._found = found

        def __getattr__(self, name):
            return getattr(self._found, name)

    monkeypatch.setattr(L.os, "stat", lambda path, *args, **kwargs: NoId(real(path, *args, **kwargs)))
    assert L.validate_folder(str(place.project), place.layout) == place.project
    with pytest.raises(L.LayoutError):
        L.validate_folder(str(place.state), place.layout)


# -- cards and the hook's request file -----------------------------------------------------------------

def _harness(place, work: Path) -> dict:
    grants = L.Grants(readonly=[], readwrite=[place.home, work], denied=[place.home / ".env", place.root / "openshell"])
    return {"layout": place.layout, "sup": FakeSup(place.layout, FakeDriver(), grants)}


def _asked(place, path: str, access: str = "read", work=None, watch=None, **how) -> tuple:
    """What a refusal of *path* relayed from the sandbox gets: the answer, and the cards the desktop was sent.
    *watch* starts once the launcher's side is set up."""
    async def main():
        cards, conn = await _setup(_harness(place, work or place.project))
        if watch is not None:
            watch.start()
        status, payload = await cards.raise_access(path, access, origin="hook", **how)
        await _settle(5)
        sent = _cards(conn)
        await cards.stop()
        return status, payload, sent

    return asyncio.run(main())


@windows_only
@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize("folder", (*PROTECTED, "project"))
def test_no_card_asks_for_a_folder_under_another_spelling(place, watch, folder, spelling):
    raw = _spelled(getattr(place, folder), spelling)
    work = place.tmp / "work"
    work.mkdir()
    for how in ({}, {"missing": True}, {"must_exist": True}):
        status, payload, sent = _asked(place, raw + "\\notes.txt", work=work, watch=watch.shares(), **how)
        watch.stop()
        assert status == 204 and sent == [], (status, payload)


@windows_only
@pytest.mark.parametrize("spelling", SPELLINGS)
def test_the_hooks_request_file_cannot_name_a_folder_under_another_spelling(place, spelling):
    raw = _spelled(place.state, spelling)
    requests = L.box_dirs(place.layout)["requests"]
    requests.mkdir(parents=True)
    wanted = str(place.tmp / "elsewhere" / "notes.txt")
    (requests / "r1.json").write_text(json.dumps({"kind": "access", "paths": [{"path": raw, "access": "read"}]}),
                                      encoding="utf-8")
    (requests / "r2.json").write_text(json.dumps({"kind": "access", "paths": [
        {"path": raw + "\\token", "access": "read"}, {"path": wanted, "access": "read"}]}), encoding="utf-8")
    read = read_requests(requests)
    assert [(request["id"], [item["path"] for item in request["paths"]]) for request in read] == [("r2", [wanted])]


def test_the_hooks_request_file_names_full_paths_only(place):
    requests = L.box_dirs(place.layout)["requests"]
    requests.mkdir(parents=True)
    wanted = str(place.tmp / "elsewhere" / "notes.txt")
    other = "/srv/notes.txt" if WINDOWS else "C:\\Users\\notes.txt"  # a full path of the other kind of system
    (requests / "r1.json").write_text(json.dumps({"kind": "access", "paths": [
        {"path": "notes.txt", "access": "read"}, {"path": other, "access": "read"},
        {"path": wanted, "access": "read_write"}]}), encoding="utf-8")
    [request] = read_requests(requests)
    assert request["paths"] == [{"path": wanted, "access": "read_write", "missing": False}]


def test_a_refusal_that_names_a_granted_folder_through_a_link_asks_for_nothing(place):
    work = place.tmp / "work"
    work.mkdir()
    _link(place.tmp / "alias", work)
    status, payload, sent = _asked(place, str(place.tmp / "alias" / "notes.txt"), work=work)
    assert (status, payload.get("detail"), sent) == (204, "already granted read & write", [])


def test_a_refusal_that_names_a_hidden_file_through_a_link_asks_for_nothing(place):
    (place.home / ".env").write_text("", encoding="utf-8")
    _link(place.tmp / "alias", place.home)
    status, payload, sent = _asked(place, str(place.tmp / "alias" / ".env"))
    assert (status, payload.get("detail"), sent) == (204, "a path the sandbox is denied on purpose", [])


def test_an_ordinary_refusal_still_gets_its_card(place):
    outside = place.tmp / "outside"
    outside.mkdir()
    status, payload, sent = _asked(place, str(outside / "notes.txt"))
    assert status == 200 and [card["params"]["path"] for card in sent] == [str(outside)]


# -- a link that leads off this computer ---------------------------------------------------------------

def _link_to(link: Path, target, monkeypatch) -> Path:
    """A link at *link* that reads as a link to *target* (a text, or an error ``os.readlink`` raises). It is a
    real junction to a folder made beside it, with what ``os.readlink`` answers for it replaced: code that
    follows the link by mistake lands in that folder, and no share is asked for anything."""
    beside = link.with_name(link.name + "-target")
    beside.mkdir(parents=True)
    _link(link, beside)
    real, at = os.readlink, os.path.normcase(str(link))

    def readlink(path, *args, **kwargs):
        if os.path.normcase(os.fspath(path)) != at:
            return real(path, *args, **kwargs)
        if isinstance(target, BaseException):
            raise target
        return target

    monkeypatch.setattr(os, "readlink", readlink)
    return link


OFF_THIS_COMPUTER = {
    "share": "\\\\files.invalid\\share",
    "share-forward": "//files.invalid/share",
    "extended-share": SHARE,
    "object-share": "\\??\\UNC\\files.invalid\\share",
    "volume-id": "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\data",
    "device-root": "\\\\?\\GLOBALROOT\\Device\\Mup\\files.invalid\\share",
    "device": "\\\\.\\pipe\\data",
    "another-drives-folder": "D:data",
    "unreadable": OSError(5, "Access is denied"),
    "no-link": ValueError("not a symbolic link"),
}


@links_leave
@pytest.mark.parametrize("kind", sorted(OFF_THIS_COMPUTER))
def test_a_path_through_a_link_that_leads_off_this_computer_is_not_looked_at(place, watch, monkeypatch, kind):
    link = _link_to(place.tmp / "work" / "l", OFF_THIS_COMPUTER[kind], monkeypatch)
    watch.below(link).start()
    for path in (link, link / "notes.txt", link / "a" / "b" / "notes.txt", link / ".." / "l" / "notes.txt"):
        assert L.on_this_computer(path) is False
        assert L.identities(path) == frozenset()
        assert L.inside(place.project, path) is False
    assert L.on_this_computer(link.parent / "notes.txt") is True


@links_leave
def test_a_link_that_leads_back_to_itself_is_followed_a_few_times_only(place, watch, monkeypatch):
    link, reads = place.tmp / "work" / "l", []
    _link_to(link, str(link), monkeypatch)
    answer = os.readlink
    monkeypatch.setattr(os, "readlink", lambda path, *a, **k: reads.append(path) or answer(path, *a, **k))
    watch.below(link).start()
    assert L.on_this_computer(link / "notes.txt") is False
    assert len(reads) == L.LINKS_FOLLOWED + 1


@links_leave
@pytest.mark.parametrize("written", ["extended", "drive", "relative", "from-the-drive"])
def test_a_link_to_a_folder_of_this_computer_is_followed(place, monkeypatch, written):
    """A junction reads as an extended-length drive path, a symbolic link as it was written. Each leads to a
    folder of this computer, and the walk goes on there: a second link on the way is found too."""
    work, real = place.tmp / "work", place.tmp / "disk" / "data"
    work.mkdir()
    real.mkdir(parents=True)
    target = {"extended": "\\\\?\\" + str(real), "drive": str(real), "relative": "..\\disk\\data",
              "from-the-drive": str(real)[2:]}[written]
    link = work / "l"
    _link(link, real)
    answer = os.readlink
    monkeypatch.setattr(os, "readlink", lambda path, *a, **k: (
        target if os.path.normcase(os.fspath(path)) == os.path.normcase(str(link)) else answer(path, *a, **k)))
    assert L.on_this_computer(link / "notes.txt") is True
    assert L.identities(link / "notes.txt") == L.identities(real / "notes.txt") != frozenset()
    assert L.validate_folder(str(link), place.layout) == real
    _link_to(real / "out", SHARE, monkeypatch)
    assert L.on_this_computer(link / "out" / "notes.txt") is False


@links_leave
@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("named", ["the-link", "a-folder-below-it"])
def test_a_folder_reached_through_a_link_to_a_share_is_refused_unopened(place, watch, monkeypatch, route, named):
    link = _link_to(place.tmp / "work" / "l", SHARE, monkeypatch)
    watch.below(link).start()
    with pytest.raises(L.LayoutError) as refused:
        _offer(route, str(link if named == "the-link" else link / "projects" / "app"), place.layout)
    assert str(refused.value).startswith("This folder is not on a drive of this computer: ")
    watch.stop()
    assert _offer(route, str(link.parent), place.layout)["path"] == str(link.parent)


HOW_A_REFUSAL_NAMES_A_PATH = {"denied": {}, "not-found": {"missing": True}, "named-by-a-command": {"must_exist": True},
                              "a-write-named-by-a-command": {"access": "read_write", "must_exist": True}}


@links_leave
@pytest.mark.parametrize("how", sorted(HOW_A_REFUSAL_NAMES_A_PATH))
@pytest.mark.parametrize("where", ["in-a-granted-folder", "elsewhere"])
def test_no_card_follows_a_link_to_a_share(place, watch, monkeypatch, where, how):
    """The sandbox writes its granted folder and names the path of the refusal. Whatever the refusal says about
    the path (denied, not found, named by a command that did not fail), nothing follows the link."""
    work = place.tmp / "work"
    link = _link_to((work if where == "in-a-granted-folder" else place.tmp / "elsewhere") / "l", SHARE, monkeypatch)
    work.mkdir(exist_ok=True)
    status, payload, sent = _asked(place, str(link / "notes.txt"), work=work, watch=watch.below(link),
                                   **HOW_A_REFUSAL_NAMES_A_PATH[how])
    assert (status, sent) == (204, []), payload


@links_leave
def test_the_hooks_request_file_cannot_send_the_launcher_through_a_link_to_a_share(place, watch, monkeypatch):
    work = place.tmp / "work"
    link = _link_to(work / "l", SHARE, monkeypatch)
    paths = [{"path": str(link / "notes.txt"), "access": "read", "missing": True},
             {"path": str(link / "data"), "access": "read_write"}]

    async def main():
        cards, conn = await _setup(_harness(place, work))
        cards._requests_dir.mkdir(parents=True, exist_ok=True)
        (cards._requests_dir / "r1.json").write_text(json.dumps({"kind": "access", "paths": paths}), encoding="utf-8")
        watch.below(link).start()
        for request in read_requests(cards._requests_dir):
            await cards.on_request(request)
        await _settle(5)
        watch.stop()
        sent = _cards(conn)
        await cards.stop()
        return sent, cards.verdicts.requests.get("r1")

    sent, answer = asyncio.run(main())
    assert sent == [] and answer["status"] == "refused"


@links_leave
def test_the_activity_log_does_not_follow_a_link_to_a_share(place, watch, monkeypatch):
    """A failed call's "not found" is listed when this computer has the path. A path through a link that leads
    off it is not looked at, and the call that names a path this computer has is still listed."""
    link = _link_to(place.tmp / "work" / "l", SHARE, monkeypatch)
    here = place.tmp / "work" / "notes.txt"
    here.write_text("x", encoding="utf-8")
    calls = [call("c1", "read_file", {"path": str(link / "notes.txt")}), call("c2", "read_file", {"path": str(here)})]
    make_db(place.home, [
        ("chat-a", "user", T0 + 10, "read them", None, None, None),
        ("chat-a", "assistant", T0 + 11, "", None, None, json.dumps(calls)),
        ("chat-a", "tool", T0 + 12, json.dumps({"error": f"File not found: {link / 'notes.txt'}"}), "c1", "read_file",
         None),
        ("chat-a", "tool", T0 + 13, json.dumps({"error": f"File not found: {here}"}), "c2", "read_file", None),
    ])
    watch.below(link).start()
    rows, _ = A.file_rows(place.home, [(T0, T0 + 100)], None, None)
    assert [Path(row["path"]) for row in rows] == [here]


@links_leave
def test_a_folder_windows_keeps_in_a_cloud_is_the_folder_it_is(place, monkeypatch):
    """A folder of a cloud drive carries the mark of an entry that is stored elsewhere. It stands for no other
    name: nothing is read as a link, and a folder below it is added like any other."""
    cloud = place.user / "Cloud Drive" / "Documents"
    (cloud / "app").mkdir(parents=True)
    real, at, read = os.lstat, os.path.normcase(str(cloud.parent)), []

    class Marked:
        def __init__(self, found):
            self._found = found
            self.st_file_attributes = found.st_file_attributes | stat.FILE_ATTRIBUTE_REPARSE_POINT
            self.st_reparse_tag = 0x9000601A  # a cloud file's placeholder

        def __getattr__(self, name):
            return getattr(self._found, name)

    def lstat(path, *args, **kwargs):
        found = real(path, *args, **kwargs)
        return Marked(found) if os.path.normcase(os.fspath(path)).startswith(at) else found

    answer = os.readlink
    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", lambda path, *a, **k: read.append(path) or answer(path, *a, **k))
    assert L.on_this_computer(cloud / "app" / "notes.txt") is True and read == []
    assert L.validate_folder(str(cloud / "app"), place.layout) == cloud / "app"


@pytest.mark.skipif(WINDOWS, reason="on Windows a link can lead to a share, and the path is walked")
def test_where_a_link_stays_on_the_computer_a_path_from_the_root_needs_no_walk(place, monkeypatch):
    looked = []
    monkeypatch.setattr(os, "lstat", lambda path, *a, **k: looked.append(path))
    assert L.on_this_computer(place.project / "notes.txt") is True and looked == []
    assert L.on_this_computer("notes.txt") is False and L.on_this_computer("C:\\notes.txt") is False


# -- the folder of the OpenShell CLI's client keys -------------------------------------------------------

def _refused_as_a_credential_folder(place, keys: Path) -> None:
    """The folder *keys* and the folders in it are refused as that credential folder, and so is the folder above
    it, which holds it (as the first credential folder it holds)."""
    (keys / "gateways" / "mine" / "mtls").mkdir(parents=True)
    for folder in (keys, keys / "gateways" / "mine", keys / "gateways" / "mine" / "mtls"):
        with pytest.raises(L.LayoutError) as refused:
            L.validate_folder(str(folder), place.layout)
        assert str(refused.value) == f"Overlaps a credential folder ({keys}).", folder
    with pytest.raises(L.LayoutError) as refused:
        L.validate_folder(str(keys.parent), place.layout)
    assert str(refused.value).startswith("Overlaps a credential folder (")


@pytest.mark.parametrize("where", [".config", pytest.param("AppData/Roaming", marks=windows_only)])
def test_the_folder_of_the_openshell_clis_client_keys_is_protected(place, where):
    """The CLI keeps a registered gateway's client key in ``openshell/gateways/<name>/mtls`` of its config home:
    ``~/.config`` where the launcher hands it one, and on Windows the roaming application data folder."""
    (place.user / "Roaming notes").mkdir()
    _refused_as_a_credential_folder(place, place.user.joinpath(*where.split("/")) / "openshell")
    assert L.validate_folder(str(place.user / "Roaming notes"), place.layout) == place.user / "Roaming notes"
    assert L.validate_folder(str(place.project), place.layout) == place.project


def test_a_config_home_the_environment_names_is_protected_too(place, monkeypatch):
    home = place.tmp / "disk" / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    _refused_as_a_credential_folder(place, home / "openshell")
    (home / "editor").mkdir()
    assert L.validate_folder(str(home / "editor"), place.layout) == home / "editor"


def test_a_config_home_the_saved_settings_name_is_protected_too(place):
    home = place.tmp / "disk" / "gateway-config"
    spec = SP.load_spec(place.layout)
    spec["openshell"] = {"gateway": "mine", "config_home": str(home)}
    SP.save_spec(place.layout, spec)
    _refused_as_a_credential_folder(place, home / "openshell")
    (home / "editor").mkdir()
    assert L.validate_folder(str(home / "editor"), place.layout) == home / "editor"
    assert L.gateway_client_dirs(L.ProfileLayout(name="other", home=place.home, root=place.root), place.user) == [
        place.user / ".config" / "openshell", place.user / "AppData" / "Roaming" / "openshell"]


def test_the_launchers_own_grants_stay_clear_of_the_clis_key_folders(place, monkeypatch):
    """What the launcher grants a sandbox by itself (the profile folder, its scratch, the folder a first start
    adds) neither lies in a folder of client keys nor holds one."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(place.user / ".config"))
    first = place.user / "Hermes"
    first.mkdir()
    folder = SP.parse_folder_arg(f"{first}:rw", place.layout)
    assert folder == {"path": str(first), "access": "rw"}
    runtime = L.Runtime(python=place.tmp / "python.exe", code_dir=place.tmp / "code", env_dir=place.tmp / "env",
                        base_python=place.tmp / "base", store=None)
    grants = L.profile_grants(place.layout, runtime, [folder])
    for keys in L.gateway_client_dirs(place.layout, place.user):
        for granted in (*grants.readwrite, *grants.readonly):
            assert not L.inside(keys, granted) and not L.inside(granted, keys), (keys, granted)


# -- the Windows driver --------------------------------------------------------------------------------

@windows_only
def test_the_windows_policy_holds_one_spelling_of_a_granted_folder(place):
    from openshell.launcher import openshell_windows as W

    work = place.tmp / "work"
    (work / "private").mkdir(parents=True)
    net = {"egress": "deny", "allow": []}

    def built(folder):
        grants = L.Grants(readonly=[], readwrite=[place.home, folder], denied=[work / "private", place.home / ".env"])
        return W.build_windows_policy(grants, net, [])

    policy, denied, _notes = built(Path("\\\\?\\" + str(work)))
    assert (policy, denied) == built(work)[:2]
    assert str(work) in policy["filesystem_policy"]["read_write"] and str(work / "private") in denied


@windows_only
@pytest.mark.parametrize("named", ("extended", "link"))
def test_the_launchers_files_stay_hidden_when_the_root_is_granted_under_another_name(place, named):
    from openshell.launcher import openshell_windows as W

    if named == "link":
        granted = place.tmp / "alias"
        _link(granted, place.root)
    else:
        granted = Path("\\\\?\\" + str(place.root))
    request = SimpleNamespace(config_dir=place.state, grants=L.Grants(readonly=[], readwrite=[granted], denied=[]))
    hidden = W.OpenShellWindowsDriver._root_denials(None, request)
    assert place.root / "openshell" in hidden and place.state / "token" in hidden


# -- a path of any length costs little -------------------------------------------------------------------

def _within(seconds: float, call):
    """What *call* returns, when it returns within *seconds*; the test fails when it takes longer."""
    import threading

    done = {}

    def run():
        try:
            done["result"] = call()
        except BaseException as exc:  # handed to the test
            done["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"took longer than {seconds:g} seconds"
    if "error" in done:
        raise done["error"]
    return done["result"]


HOSTILE = 200_000


@pytest.mark.parametrize("shape", ["many-folders", "one-name", "dots", "separators"])
def test_a_relayed_path_of_any_length_is_answered_at_once(place, shape):
    """The sandbox chooses what a relayed refusal names. A text of 200,000 characters gets its answer, no card,
    in the time any other path takes, on every way in: the request file, a card, the folder check."""
    start = str(place.project) + os.sep
    filler = {"many-folders": "a" + os.sep, "one-name": "a", "dots": ".." + os.sep, "separators": os.sep}[shape]
    path = start + filler * ((HOSTILE - len(start)) // len(filler) + 1)
    assert len(path) >= HOSTILE
    requests = L.box_dirs(place.layout)["requests"]
    requests.mkdir(parents=True)
    (requests / "r1.json").write_text(json.dumps({"kind": "access", "paths": [{"path": path, "access": "read"}]}),
                                      encoding="utf-8")
    assert _within(5, lambda: read_requests(requests)) == []
    status, payload, sent = _within(5, lambda: _asked(place, path))
    assert (status, sent) == (204, []), payload
    with pytest.raises(L.LayoutError):
        _within(5, lambda: L.validate_folder(path, place.layout))
    assert _within(5, lambda: L.on_this_computer(path)) is False
    assert _within(5, lambda: L.inside(path, place.project)) is (shape != "dots")
    # (dot segments and bare separators fold away: the first names the drive's root, the second the folder itself)
    assert _within(5, lambda: L.inside(place.project, path)) is (shape in ("dots", "separators"))


@links_leave
def test_the_walk_to_a_path_looks_once_at_each_folder_of_a_path_of_bounded_length(place, monkeypatch):
    """The longest path that is walked has ``PATH_CHARS`` characters: one look at each of its folders, none at a
    longer text, and none again at a folder that a row of questions has found to be no link."""
    looked, folder = [], os.lstat(place.project)
    monkeypatch.setattr(os, "lstat", lambda path, *a, **k: looked.append(path) or folder)
    deep = str(place.project) + "\\a" * ((L.PATH_CHARS - len(str(place.project))) // 2)
    assert L.PATH_CHARS - 2 < len(deep) <= L.PATH_CHARS
    assert _within(5, lambda: L.on_this_computer(deep)) is True
    assert len(looked) == len(set(looked)) == deep.count("\\")
    looked.clear()
    assert _within(5, lambda: L.on_this_computer(deep + "\\a" * HOSTILE)) is False and looked == []
    plain: set = set()
    assert L.on_this_computer(place.project / "a" / "b", plain) and L.on_this_computer(place.project / "a" / "c", plain)
    assert looked[-1] == str(place.project / "a" / "c") and looked.count(str(place.project / "a")) == 1
