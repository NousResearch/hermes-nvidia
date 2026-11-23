"""Windows credential hiding the sandbox cannot undo by renaming a folder.

MXC hides and protects paths, not files: a workload that may rename a writable folder above a denied path reads it
at the new path (MXC 1.0.1; NVIDIA/OpenShell#5033). OpenShell's MXC driver rejects such a deny; the launcher must
never send one, and must hide every store some other way or refuse to start.
"""
import os
import re
import sys
from pathlib import Path

import pytest

from openshell.launcher import layout as L
from openshell.launcher import openshell_windows as W
from openshell.launcher.driver import DriverUnavailable

NET = {"egress": "deny", "allow": []}
# Where earlier Hermes releases kept its secret caches (core's home_data_layout.LEGACY_SECRET_CACHE_PATHS).
_LEGACY = ("cache/bws_cache.json", "cache/bws_cache.enc.json", "cache/op_cache.json", "runtime/photon-sidecar.json")


@pytest.fixture
def new_core(monkeypatch):
    """A core that keeps its secret caches at the top of the home and lists the old copies."""
    import hermes_cli.home_data_layout as hdl

    monkeypatch.setattr(hdl, "LEGACY_SECRET_CACHE_PATHS", _LEGACY, raising=False)


@pytest.fixture
def old_core(monkeypatch):
    """A core that still keeps its secret caches in cache and runtime (no LEGACY_SECRET_CACHE_PATHS)."""
    import hermes_cli.home_data_layout as hdl

    monkeypatch.delattr(hdl, "LEGACY_SECRET_CACHE_PATHS", raising=False)


def _runtime(tmp: Path) -> L.Runtime:
    for d in ("code", "env", "base", "store"):
        (tmp / d).mkdir(parents=True, exist_ok=True)
    return L.Runtime(python=tmp / "env" / "python.exe", code_dir=tmp / "code", env_dir=tmp / "env",
                     base_python=tmp / "base", store=tmp / "store", install_state=None)


def _named(tmp_path) -> L.ProfileLayout:
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    return L.ProfileLayout(name="work", home=home, root=tmp_path / "root")


def _default(tmp_path) -> L.ProfileLayout:
    root = tmp_path / "root"
    for d in ("hermes-agent", "profiles/other", "installs/k", "openshell/runtime/gateway/cli"):
        (root / d).mkdir(parents=True)
    (root / "openshell" / "runtime" / "gateway" / "cli" / "tls.key").write_text("dummy", encoding="utf-8")
    return L.ProfileLayout(name="default", home=root, root=root)


def _write(home: Path, *rels: str) -> None:
    for rel in rels:
        (home / rel).parent.mkdir(parents=True, exist_ok=True)
        (home / rel).write_text("DUMMY-MARKER (not a credential)", encoding="utf-8")


# Every credential store core lists today, present: a profile that has used every feature.
_EVERY_STORE_OUTSIDE_WRITABLE_DIRS = (".env", "auth.json", "auth/google_oauth.json", ".config/gh/hosts.yml",
                                      ".config/gcloud/credentials.db", "platforms/pairing/telegram-approved.json",
                                      "platforms/matrix/store/crypto.db", "platforms/whatsapp/session/creds.json",
                                      "matrix/store/crypto.db", "whatsapp/session/creds.json",
                                      "weixin/accounts/a.json", "mcp-tokens/x.json", "home/.gitconfig")


def _review_rule_accepts(deny: str, ro: list, rw: list) -> bool:
    """The rule a review of NVIDIA/OpenShell#5033 asked for: a deny is accepted only as a direct child of the
    read & write grant containing it, or with a read-only grant between them (no writable folder in between)."""
    def best(path):
        hits = [(len(W._key(g)), kind) for kind, items in (("ro", ro), ("rw", rw)) for g in items if W._inside(path, g)]
        return max(hits)[1] if hits else None

    holders = [g for g in rw if W._inside(deny, g) and W._key(g) != W._key(deny)]
    if not holders:
        return True
    grant = max(holders, key=lambda g: len(W._key(g)))
    folder = Path(deny).parent
    while W._key(folder) != W._key(grant):
        if best(folder) == "rw":
            return False
        folder = folder.parent
    return True


def _mxc_exposure(path, ro: list, rw: list, deny: list):
    """MXC 1.0.1's rename rule, written independently of the launcher's: a folder can be renamed when it and
    its parent are both read & write for the workload (most specific grant wins; deny > rw > ro on ties)."""
    def access(p):
        hits = [(len(W._key(g)), rank, kind) for rank, (kind, items) in enumerate((("ro", ro), ("rw", rw),
                                                                                  ("deny", deny)))
                for g in items if W._inside(p, g)]
        return max(hits)[2] if hits else None

    for folder in Path(path).parents:
        if folder.parent == folder:
            return None
        if access(folder) == "rw" and access(folder.parent) == "rw":
            return folder
    return None


def _assert_rename_safe(policy: dict, denied: list) -> None:
    fs = policy["filesystem_policy"]
    for d in denied:
        assert _mxc_exposure(d, fs["read_only"], fs["read_write"], denied) is None, d
        assert _review_rule_accepts(d, fs["read_only"], fs["read_write"]), d
    for ro in fs["read_only"]:
        assert _mxc_exposure(ro, fs["read_only"], fs["read_write"], denied) is None, ro


def test_rename_exposure_follows_what_mxc_lets_a_workload_rename(tmp_path):
    """MXC 1.0.1's rename behaviour, one layout per assertion; the launcher's rule
    and this file's independent copy agree on every arm."""
    G = tmp_path / "G"
    arms = [
        # A: a plain folder inside a read & write grant: renamed, the deny below it read at the new path
        (G / "a" / "s.txt", [], [G], [G / "a" / "s.txt"], G / "a"),
        # B: directly under the grant root, whose own parent the sandbox cannot write: refused
        (G / "s.txt", [], [G], [G / "s.txt"], None),
        # C: under read-only folders inside the read & write grant: refused
        (G / "r" / "q" / "s.txt", [G / "r", G / "r" / "q"], [G], [G / "r" / "q" / "s.txt"], None),
        # D: directly under a read & write grant root nested in another read & write grant: renamed
        (G / "c" / "s.txt", [], [G, G / "c"], [G / "c" / "s.txt"], G / "c"),
        # E: a read & write grant root under a read-only parent: refused
        (G / "c" / "s.txt", [G], [G / "c"], [G / "c" / "s.txt"], None),
        # R: a read-only grant two levels down: its writable parent is renamed and the file written
        (G / "a" / "r", [G / "a" / "r"], [G], [], G / "a"),
        # a path inside a denied folder: the folder itself cannot be renamed
        (G / "d" / "x", [], [G], [G / "d"], None),
    ]
    for path, ro, rw, deny, folder in arms:
        assert _mxc_exposure(path, ro, rw, deny) == folder, path
        assert W.rename_exposure(path, ro, rw, deny) == folder, path
    # D passes the review rule (a deny directly under a read & write grant root), yet MXC renames that root
    assert _review_rule_accepts(str(G / "c" / "s.txt"), [], [G, G / "c"])


def test_a_named_profile_hides_every_store_with_denies_the_sandbox_cannot_rename_away(tmp_path):
    layout = _named(tmp_path)
    _write(layout.home, *_EVERY_STORE_OUTSIDE_WRITABLE_DIRS, "cache/web/page.json", "runtime/active_sessions.json")
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    policy, denied, notes = W.build_windows_policy(grants, NET, [])
    _assert_rename_safe(policy, denied)
    home = layout.home
    for folder in (".config", "auth", "platforms", "matrix", "whatsapp", "weixin", "home", "mcp-tokens"):
        assert W.native(home / folder) in denied, folder  # hidden whole, directly under the home grant
    for path in denied:
        assert Path(path).parent == home, path  # nothing deeper is sent for a named profile
    # the folders Hermes writes in the sandbox stay writable
    for folder in ("cache", "runtime", "workspace", "sessions"):
        assert W.native(home / folder) not in denied
    # absent stores below them are left out, with a note, not sent below a folder the sandbox can rename
    assert any("bws_cache.json" in n for n in notes) and any("photon-sidecar.json" in n for n in notes)


@pytest.mark.parametrize("rel", [*_LEGACY, "workspace/meetings/node_token.json"])
def test_with_an_older_core_a_store_below_a_folder_the_sandbox_writes_refuses_the_launch(tmp_path, old_core, rel):
    """A core without LEGACY_SECRET_CACHE_PATHS still keeps its secret caches in cache and runtime: the launcher
    leaves them in place and refuses, naming the file and the old remedy."""
    layout = _named(tmp_path)
    _write(layout.home, ".env", rel)
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    with pytest.raises(DriverUnavailable, match=re.escape(str(layout.home / Path(rel)))) as err:
        W.build_windows_policy(grants, NET, [])
    assert W._REMEDY_OLD_CORE in str(err.value)
    assert (layout.home / rel).is_file()


def test_old_secret_store_copies_are_removed_before_a_launch_with_a_core_that_moved_them(tmp_path, new_core):
    layout = _named(tmp_path)
    home = layout.home
    _write(home, ".env", *_LEGACY, "cache/web/page.json", "runtime/active_sessions.json", "op_cache.json",
           "bws_cache.json")
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    for rel in _LEGACY:
        assert not os.path.lexists(home / rel), rel
    for rel in ("cache/web/page.json", "runtime/active_sessions.json", "op_cache.json", "bws_cache.json"):
        assert (home / rel).is_file(), rel  # the rest of cache and runtime, and the copies Hermes uses now
    policy, denied, _ = W.build_windows_policy(grants, NET, [])  # no longer refused
    _assert_rename_safe(policy, denied)
    assert W.native(home / ".env") in denied


def test_a_store_the_launcher_does_not_remove_still_refuses_with_a_core_that_moved_the_caches(tmp_path, new_core):
    layout = _named(tmp_path)
    rel = "workspace/meetings/node_token.json"
    _write(layout.home, ".env", rel)
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    with pytest.raises(DriverUnavailable, match=re.escape(str(layout.home / Path(rel)))) as err:
        W.build_windows_policy(grants, NET, [])
    assert str(err.value).endswith(W._REMEDY) and "until Hermes stores them" not in str(err.value)
    assert (layout.home / rel).is_file()


def _dir_link(link: Path, target: Path) -> None:
    """A junction on Windows (no privilege needed), a symlink elsewhere."""
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def _symlink(link: Path, target: Path, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError:
        pytest.skip("this host can't create symlinks")


def test_removal_unlinks_a_junction_itself_and_leaves_a_folder(tmp_path, new_core):
    home = _named(tmp_path).home
    outside = tmp_path / "outside"
    _write(outside, "dir/keep.txt")
    (home / "cache").mkdir()
    _dir_link(home / "cache" / "bws_cache.json", outside / "dir")
    _write(home, "cache/op_cache.json")
    _write(home, "runtime/photon-sidecar.json/inner.txt")  # a folder by that name: left alone
    removed = L.remove_legacy_secret_copies(home)
    assert set(removed) == {home / "cache" / "bws_cache.json", home / "cache" / "op_cache.json"}
    assert not os.path.lexists(home / "cache" / "bws_cache.json")
    assert (outside / "dir" / "keep.txt").is_file()  # the link went, not what it points at
    assert (home / "runtime" / "photon-sidecar.json" / "inner.txt").is_file()


def test_removal_unlinks_a_symlink_itself(tmp_path, new_core):
    home = _named(tmp_path).home
    outside = tmp_path / "outside"
    _write(outside, "target.json", "dir/keep.txt")
    (home / "cache").mkdir()
    _symlink(home / "cache" / "op_cache.json", outside / "target.json")
    _symlink(home / "cache" / "bws_cache.enc.json", outside / "dir", directory=True)
    assert set(L.remove_legacy_secret_copies(home)) == {home / "cache" / "op_cache.json",
                                                         home / "cache" / "bws_cache.enc.json"}
    assert not os.path.lexists(home / "cache" / "op_cache.json")
    assert not os.path.lexists(home / "cache" / "bws_cache.enc.json")
    assert (outside / "target.json").read_text(encoding="utf-8").startswith("DUMMY-MARKER")  # never followed
    assert (outside / "dir" / "keep.txt").is_file()


@pytest.mark.parametrize("kind", ["junction", "symlink"])
def test_nothing_is_removed_through_a_linked_folder(tmp_path, new_core, kind):
    home = _named(tmp_path).home
    elsewhere = tmp_path / "elsewhere"
    _write(elsewhere, "op_cache.json", "bws_cache.json")
    if kind == "junction":
        _dir_link(home / "cache", elsewhere)
    else:
        _symlink(home / "cache", elsewhere, directory=True)
    assert L.remove_legacy_secret_copies(home) == []
    assert (elsewhere / "op_cache.json").is_file() and (elsewhere / "bws_cache.json").is_file()


def test_removal_never_raises_and_stays_inside_the_home(tmp_path, monkeypatch):
    import hermes_cli.home_data_layout as hdl

    home = _named(tmp_path).home
    _write(tmp_path, "root/profiles/escape.json", "root/profiles/work/cache/op_cache.json")
    monkeypatch.setattr(hdl, "LEGACY_SECRET_CACHE_PATHS", ("../escape.json", "cache/../../escape.json", "op_cache",
                                                           str(tmp_path / "root" / "profiles" / "escape.json")),
                        raising=False)
    assert L.remove_legacy_secret_copies(home) == []
    assert (tmp_path / "root" / "profiles" / "escape.json").is_file()
    monkeypatch.setattr(hdl, "LEGACY_SECRET_CACHE_PATHS", None, raising=False)  # not a list: treated as an old core
    assert L.legacy_secret_cache_paths() is None and L.remove_legacy_secret_copies(home) == []
    monkeypatch.setattr(hdl, "LEGACY_SECRET_CACHE_PATHS", _LEGACY, raising=False)
    monkeypatch.setattr(L, "_plain_folders", lambda *a: 1 / 0)
    assert L.remove_legacy_secret_copies(home) == []
    assert (home / "cache" / "op_cache.json").is_file()


def test_a_core_without_the_layout_module_keeps_the_copies(tmp_path, monkeypatch):
    home = _named(tmp_path).home
    _write(home, "cache/op_cache.json")
    monkeypatch.setitem(sys.modules, "hermes_cli.home_data_layout", None)
    assert L.legacy_secret_cache_paths() is None
    assert L.remove_legacy_secret_copies(home) == []
    assert (home / "cache" / "op_cache.json").is_file()
    assert W._remedy() == W._REMEDY_OLD_CORE


def test_the_default_profile_hides_other_profiles_and_launcher_state_rename_safely(tmp_path):
    layout = _default(tmp_path)
    _write(layout.home, *_EVERY_STORE_OUTSIDE_WRITABLE_DIRS, "profiles/other/.env")
    runtime = _runtime(tmp_path)
    grants = L.profile_grants(layout, runtime, [])
    for d in L.box_dirs(layout).values():
        assert d in grants.readwrite
    state = layout.state_dir
    policy, denied, notes = W.build_windows_policy(
        grants, NET, [], extra_deny=[layout.root / "openshell", layout.root / "profiles_run_elsewhere",
                                     state / "token", state / "spec.yaml"])
    _assert_rename_safe(policy, denied)
    keys = {os.path.normcase(p) for p in denied}
    root = layout.root
    assert os.path.normcase(W.native(root / "profiles")) in keys  # every other profile, whole
    assert os.path.normcase(W.native(root / "installs")) in keys
    assert not any(W._inside(d, root / "installs") and W._key(d) != W._key(root / "installs") for d in denied)
    assert any(W._inside(root / "openshell" / "runtime" / "gateway" / "cli" / "tls.key", d) for d in denied)


def test_a_read_only_grant_below_a_renamable_folder_refuses_the_launch(tmp_path):
    """The default profile's PM uv cache (cache/uv, read-only inside the writable cache folder): the sandbox can
    rename cache and write the wheels the host installs next."""
    layout = _default(tmp_path)
    (layout.root / "cache" / "uv").mkdir(parents=True)
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    with pytest.raises(DriverUnavailable, match=re.escape(f"read-only {layout.root / 'cache' / 'uv'}")):
        W.build_windows_policy(grants, NET, [])


def test_a_stored_deny_below_a_writable_folder_refuses_the_launch_and_one_at_the_top_is_kept(tmp_path):
    layout = _named(tmp_path)
    _write(layout.home, ".env", "private/diary.txt")
    grants = L.profile_grants(layout, _runtime(tmp_path), [])
    with pytest.raises(DriverUnavailable, match=re.escape(str(layout.home / "private" / "diary.txt"))):
        W.build_windows_policy(grants, NET, [], stored_deny=[layout.home / "private" / "diary.txt"])
    policy, denied, _ = W.build_windows_policy(grants, NET, [], stored_deny=[layout.home / "private"])
    assert W.native(layout.home / "private") in denied
    _assert_rename_safe(policy, denied)


def test_a_deny_under_a_nested_read_write_grant_root_is_refused(tmp_path):
    """Stricter than the review rule: a deny directly under a read & write grant root that sits in another read & write
    grant (two folder grants) is renamed away with that root (MXC 1.0.1, arm D)."""
    layout = _named(tmp_path)
    ws = tmp_path / "ws"
    _write(ws, "sub/secret.txt")
    grants = L.profile_grants(layout, _runtime(tmp_path), [{"path": str(ws), "access": "rw"},
                                                           {"path": str(ws / "sub"), "access": "rw"}])
    with pytest.raises(DriverUnavailable, match=re.escape(f"the sandbox can rename {ws / 'sub'}")):
        W.build_windows_policy(grants, NET, [], stored_deny=[ws / "sub" / "secret.txt"])


def test_every_nested_store_core_lists_is_hidden_by_its_top_folder_or_named_below_a_writable_one():
    """A store core adds below a new folder needs a decision here: hidden whole (Hermes in the sandbox never uses
    the folder) or a folder the sandbox writes (then the Windows sandbox refuses while the store exists)."""
    from hermes_cli.profiles import PROFILE_CREDENTIAL_PATHS

    tops = {rel.split("/")[0] for rel in PROFILE_CREDENTIAL_PATHS if "/" in rel}
    assert tops <= set(L.HIDDEN_WHOLE_DIRS) | set(L.WRITABLE_STORE_DIRS), tops
    assert not set(L.HIDDEN_WHOLE_DIRS) & set(L.WRITABLE_STORE_DIRS)
