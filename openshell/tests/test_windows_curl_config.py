"""Windows' own curl.exe inside the sandbox, when certificate revocation servers are out of reach.

curl.exe is a Schannel build: Windows checks whether the site's certificate was revoked, and inside the sandbox
Windows has no route to the CA's OCSP/CRL servers. On an allowed https site that does not staple the answer curl
then stops with exit 35 (CRYPT_E_REVOCATION_OFFLINE). The Windows driver gives curl a config file holding
``ssl-revoke-best-effort``: in the launcher's state dir, read-only inside the sandbox, found through ``CURL_HOME``,
written again on every start. Certificate checks stay on, and the Linux driver does none of this.
"""
import asyncio
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_openshell_driver as LD
import test_openshell_windows as WD
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import openshell_windows as W
from test_openshell_windows import secrets_env  # noqa: F401  (fixture; rootdir-less import)

_CURL = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32" / "curl.exe"


def _named_tree(tmp_path):
    """The tree of test_openshell_windows with a named profile (its home below the root) in place of the default."""
    layout, runtime, cfg, bb = WD._tree(tmp_path)
    home = layout.root / "profiles" / "work"
    home.mkdir(parents=True)
    for name in ("config.yaml", ".env", "auth.json"):
        (home / name).write_bytes((layout.root / name).read_bytes())
    return L.ProfileLayout(name="work", home=home, root=layout.root), runtime, cfg, bb


@pytest.fixture(params=["default", "named"])
def tree(request, tmp_path):
    return WD._tree(tmp_path) if request.param == "default" else _named_tree(tmp_path)


def _launch(tree, tmp_path) -> dict:
    """Start and stop the sandbox once on a fresh fake gateway; what the gateway was sent."""
    layout, runtime, cfg, bb = tree
    fake = WD.FakeCli()
    sup = WD._supervisor(layout, runtime, WD._driver(cfg, fake, tmp_path), bb)

    async def once():
        await sup.start()
        await sup.stop()

    asyncio.run(once())
    create = next(argv for argv, _ in fake.calls if argv[1:3] == ["sandbox", "create"])
    name = create[create.index("--name") + 1]
    pairs = [create[i + 1] for i, arg in enumerate(create) if arg == "--env"]
    return {"env": dict(pair.split("=", 1) for pair in pairs),
            "fs": fake.revisions[name][0]["policy"]["filesystem_policy"],
            "denied": fake.driver_configs[name].get("denied_paths") or []}


def _driver(tmp_path):
    cfg = OD.OpenShellConfig(gateway="hermes-oswin", config_home=tmp_path / "xdg", cli=tmp_path / "openshell.exe")
    return WD._driver(cfg, WD.FakeCli(), tmp_path)


def test_the_sandbox_reads_curl_config_from_a_launcher_folder_it_cannot_write(tree, tmp_path, secrets_env):
    layout = tree[0]
    sent = _launch(tree, tmp_path)
    curl_home = layout.state_dir / "curl"
    assert sent["env"]["CURL_HOME"] == str(curl_home)
    assert (curl_home / ".curlrc").read_bytes() == W.CURL_CONFIG.encode("ascii")
    # Read-only inside: granted as such, not hidden (the fake gateway refuses a denied path that holds a grant, as
    # the MXC driver does), and below no folder the sandbox could rename to write it.
    fs, denied = sent["fs"], sent["denied"]
    assert W.native(curl_home) in fs["read_only"] and W.native(curl_home) not in fs["read_write"]
    assert W._access(curl_home / ".curlrc", fs["read_only"], fs["read_write"], denied) == "ro"
    assert W.rename_exposure(curl_home, fs["read_only"], fs["read_write"], denied) is None
    # The launcher writes nothing where the sandbox writes: the sandbox's profile folders are the ones the
    # supervisor made, with no curl config in them, and the launcher's file is the only one under the root.
    box = L.box_dirs(layout)
    assert sent["env"]["HOME"] == sent["env"]["USERPROFILE"] == str(box["userprofile"])
    assert sent["env"]["APPDATA"] == str(box["appdata"])
    assert [p for p in layout.root.rglob("*curlrc")] == [curl_home / ".curlrc"]


def test_the_curl_config_is_written_again_on_every_start(tmp_path, secrets_env):
    tree = WD._tree(tmp_path)
    config = tree[0].state_dir / "curl" / ".curlrc"
    _launch(tree, tmp_path)
    config.write_bytes(b"insecure\n")  # whatever became of the file since the last start
    _launch(tree, tmp_path)
    assert config.read_bytes() == W.CURL_CONFIG.encode("ascii")
    config.unlink()
    config.parent.rmdir()
    _launch(tree, tmp_path)
    assert config.read_bytes() == W.CURL_CONFIG.encode("ascii")


def test_the_curl_config_only_tolerates_an_unreachable_revocation_server():
    """One option. Nothing in the file switches off the certificate chain or host name check (``insecure``, curl's
    ``-k``) or the revocation check itself (``ssl-no-revoke``)."""
    lines = [line.strip() for line in W.CURL_CONFIG.splitlines()]
    assert [line for line in lines if line and not line.startswith("#")] == ["ssl-revoke-best-effort"]
    assert W.CURL_CONFIG.isascii() and W.CURL_CONFIG.endswith("\n") and "\r" not in W.CURL_CONFIG


@pytest.mark.parametrize("name", ["CURL_HOME", "curl_home"])  # Windows reads environment names in any case
def test_a_curl_home_the_environment_already_carries_is_left_alone(name, tmp_path):
    state = tmp_path / "state"
    env, extra_ro = _driver(tmp_path)._sandbox_env(
        SimpleNamespace(env={"PATH": "C:\\x", name: "C:\\mine"}, home=str(tmp_path), config_dir=state))
    assert {k: v for k, v in env.items() if k.upper() == "CURL_HOME"} == {name: "C:\\mine"}
    assert not (state / "curl").exists() and extra_ro == []


def test_a_curl_config_that_cannot_be_written_does_not_stop_the_sandbox(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "curl").write_text("a file where the folder goes", encoding="utf-8")
    env, extra_ro = _driver(tmp_path)._sandbox_env(
        SimpleNamespace(env={"PATH": "C:\\x"}, home=str(tmp_path), config_dir=state))
    assert "CURL_HOME" not in env and extra_ro == []  # curl checks revocation strictly, as it did before
    assert env["NODE_USE_ENV_PROXY"] == "1" and env["PATH"] == "C:\\x"  # the rest of the environment is as usual


def test_the_linux_sandbox_gets_no_curl_config(tmp_path, monkeypatch):
    """The Linux image's curl verifies with OpenSSL against the sandbox's CA bundle; nothing is written for it."""
    sup, api, _, layout = LD._supervisor(tmp_path, monkeypatch)

    async def once():
        await sup.start()
        try:
            (_, _, spec), = [call for call in api.calls if call[0] == "create"]
            return spec["environment"]
        finally:
            await sup.stop()

    env = asyncio.run(once())
    assert not [k for k in env if k.upper() == "CURL_HOME"]
    assert not (layout.state_dir / "curl").exists() and not list(tmp_path.rglob("*curlrc"))


@pytest.mark.skipif(os.name != "nt" or not _CURL.is_file(), reason="needs Windows' own curl.exe")
def test_windows_curl_reads_the_launcher_config_and_keeps_certificate_checks(tmp_path):
    """curl.exe itself, without a network: it fetches a local file and writes the options it set as libcurl source
    (``--libcurl``). The launcher's file is the one it reads (the first it finds; one in a profile folder is not
    read), every line is an option it knows, and the only TLS setting changed is best-effort revocation."""
    box = tmp_path / "box"
    for name in ("userprofile", "appdata"):
        (box / name).mkdir(parents=True)
        (box / name / ".curlrc").write_bytes(b"insecure\nssl-no-revoke\n")
    profile = {"HOME": str(box / "userprofile"), "USERPROFILE": str(box / "userprofile"), "APPDATA": str(box / "appdata")}
    env, _ = _driver(tmp_path)._sandbox_env(
        SimpleNamespace(env={"PATH": str(_CURL.parent), **profile}, home=str(tmp_path), config_dir=tmp_path / "state"))
    page, source = tmp_path / "page.txt", tmp_path / "options.c"
    page.write_bytes(b"x\n")
    done = subprocess.run(
        [str(_CURL), "-s", "-S", "-o", os.devnull, "--libcurl", str(source), page.as_uri()], capture_output=True,
        text=True, timeout=60, stdin=subprocess.DEVNULL,
        env={"SYSTEMROOT": str(_CURL.parent.parent), "PATH": str(_CURL.parent), "CURL_HOME": env["CURL_HOME"], **profile})
    assert done.returncode == 0 and done.stderr == ""  # curl reports an option it does not know on stderr
    options = source.read_text(encoding="utf-8", errors="replace")
    assert "CURLSSLOPT_REVOKE_BEST_EFFORT" in options
    for switched_off in ("CURLSSLOPT_NO_REVOKE", "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"):
        assert switched_off not in options
