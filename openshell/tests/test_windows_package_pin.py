"""The pinned Windows package (OpenShell 0.1.9, NVIDIA's signed zips), where it differs from the one before:

* four programs and no ``libz3.dll``: Z3 and the C runtime are inside the programs. The installer takes exactly the
  pinned names from a zip laid out as the package is, and the gateway service re-checks the three programs it starts;
* the release lives at ``github.com/ai-openshell/openshell`` (the repository formerly ``NVIDIA/OpenShell``);
* the pin before this one is kept whole under ``windows_previous``: putting it back is one edit of ``pins.json``;
* what this package's programs answer differently: three more lines after ``provider update``, and the supervisor
  refuses a live policy whose folders differ from the ones the sandbox started with.

``PACKAGE_ENTRIES`` is the entry list of the real x64 zip (names only; the contents here are made up). The
``provider update`` lines and the supervisor's sentence are the texts in the package's source.
"""
import asyncio
import json
from pathlib import Path

import pytest

from test_openshell_install import root, sha, use_pins, zipped  # noqa: F401  (root is a fixture)
from test_openshell_windows import FakeCli, Done, _driver, _supervisor, _tree, secrets_env  # noqa: F401
from openshell.launcher import authenticode
from openshell.launcher import gateway_service as GS
from openshell.launcher import openshell_install as inst
from openshell.launcher import openshell_windows as W

PROGRAMS = ("openshell.exe", "openshell-gateway.exe", "openshell-supervisor.exe", "openshell-windows-sandbox.exe")
RELEASES = "https://github.com/ai-openshell/openshell/releases/download/"
PACKAGE_ENTRIES = """\
bin/openshell-gateway.exe
bin/openshell-supervisor.exe
bin/openshell-windows-sandbox.exe
bin/openshell.exe
BUILD.md
config/gateway.windows.toml.template
dependencies/windows-z3.json
examples/powershell/harness.ps1
examples/python/health.py
examples/typescript/harness.mjs
HARNESS-INTEGRATION.md
KNOWN-LIMITATIONS.md
LICENSE
licenses/Z3-LICENSE.txt
policies/harness-local.yaml.template
README.md
release-manifest.json
sbom-source.cdx.json
scripts/Initialize-OpenShell.ps1
scripts/Start-OpenShell.ps1
scripts/Test-OpenShellHost.ps1
scripts/Test-OpenShellPackage.ps1
sdk/nvidia-openshell-sdk-0.1.9.tgz
sdk/openshell-0.1.9-py3-none-any.whl
SIGNING.md
THIRD-PARTY-NOTICES
VALIDATION.md
WINDOWS-UPSTREAM.md
""".split()


def shipped() -> dict:
    return json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))


def test_the_shipped_pin_names_four_programs_and_no_z3_library():
    win = shipped()["windows"]
    assert tuple(sorted(win["binaries"])) == tuple(sorted(PROGRAMS)) == tuple(sorted(win["aarch64"]["binaries"]))
    assert "libz3.dll" not in json.dumps(win)
    assert win["binaries"] == {
        "openshell.exe": "6ceb2c281e607b0dae48b58a04779c78e9747473db1f6006ba95b39326ae331d",
        "openshell-gateway.exe": "73693d257b7d04e7cff70fbb87469a2421e5ee835d7d8c01fe5efd7cdf8c36b3",
        "openshell-supervisor.exe": "5361660bcf9072b839786555387d60dbc1867be0c932ce2bd4b68792dc0c68c6",
        "openshell-windows-sandbox.exe": "168079859f5ff02983114f8878910e11604110082343f6e84b279ea7039c552e"}
    assert win["aarch64"]["binaries"] == {
        "openshell.exe": "b10173660cba40a99c5e929adfa08c72669d9bd485f95ef87a5d7b09c5d5b806",
        "openshell-gateway.exe": "94d9e156113f595cd3be53a7594db58fa5d8da2e29af46db01f884b8941bb0b1",
        "openshell-supervisor.exe": "0e64891ea7b641d498cf5a59d31bcf4555ae4a4a1e9500633cc1f4da78984348",
        "openshell-windows-sandbox.exe": "9b8e7ff97b2bb83093e8634800aa2df66309428922e20357ec82e65b09922d15"}


def test_the_download_source_is_the_repository_the_release_lives_in():
    pins = shipped()
    for block in (pins["windows"], pins["windows"]["aarch64"], pins["windows_previous"],
                  pins["windows_previous"]["aarch64"]):
        assert block["archive"]["url"].startswith(RELEASES), block["archive"]["url"]
    win = pins["windows"]
    assert win["archive"]["url"] == RELEASES + "v0.1.9/OpenShell-Windows-0.1.9-x64.zip"
    assert win["aarch64"]["archive"]["url"] == RELEASES + "v0.1.9/OpenShell-Windows-0.1.9-arm64.zip"
    # the pin says where the repository was, because the package's own records still name it that way
    assert "lives at github.com/ai-openshell/openshell" in win["_archive"]
    assert "was github.com/NVIDIA/OpenShell" in win["_archive"]


@pytest.mark.parametrize("arch, word", [("x86_64", "x64"), ("aarch64", "arm64")])
def test_the_installer_takes_the_four_programs_from_a_zip_laid_out_as_the_package(root, monkeypatch, arch, word):  # noqa: F811
    top = f"OpenShell-Windows-0.1.9-{word}"
    entries = [(f"{top}/{name}", f"{word}:{name}".encode()) for name in PACKAGE_ENTRIES]
    data = zipped(entries)
    pins = shipped()
    block = pins["windows"] if arch == "x86_64" else pins["windows"]["aarch64"]
    assert sorted(block["binaries"]) == sorted(PROGRAMS)
    block["binaries"] = {name: sha(f"{word}:bin/{name}".encode()) for name in block["binaries"]}
    block["archive"]["sha256"] = sha(data)
    use_pins(monkeypatch, pins)
    monkeypatch.delenv(inst.BUILD_DIR_ENV, raising=False)
    monkeypatch.setattr(inst, "windows_arch", lambda: arch)
    checked = []
    monkeypatch.setattr(authenticode, "signature", lambda path: checked.append(Path(path).name) or {
        "status": "valid", "signer": "NVIDIA Corporation", "code": 0, "detail": "valid"})
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes(data)

    ident = inst.ensure_installed(root, platform="windows", fetch=fetch)
    assert fetched == [RELEASES + f"v0.1.9/OpenShell-Windows-0.1.9-{word}.zip"]
    assert ident["id"] == "openshell-windows-0.1.9" + ("" if arch == "x86_64" else "-arm64")
    assert (ident["version"], ident["arch"], ident["signer"], ident["signature"]) == (
        "0.1.9", arch, "NVIDIA Corporation", "valid")
    assert ident["features"] == ["ca-bundle-system-roots", "mxc-driver-config-denied-paths"]
    assert sorted(checked) == sorted(PROGRAMS)  # the publisher of every installed file, and of nothing else
    on_disk = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    assert on_disk == sorted([f"openshell/runtime/{inst.INSTALLED_FILE}",
                              f"openshell/runtime/{ident['id']}/{inst.IDENTITY_FILE}",
                              *(f"openshell/runtime/{ident['id']}/bin/{name}" for name in PROGRAMS)])
    inst.verify(root, ident)


def _identity(root: Path, block: dict, ident_id: str) -> dict:  # noqa: F811
    bin_dir = inst.runtime_dir(root) / ident_id / "bin"
    bin_dir.mkdir(parents=True)
    return {"id": ident_id, "version": "x", "platform": "windows", "binaries": dict(block["binaries"]), "sdk": False}


def test_the_gateway_service_rechecks_the_programs_it_starts_and_no_library(root):  # noqa: F811
    pins = shipped()
    spec = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root,
                           ident=_identity(root, pins["windows"], "now"))
    assert sorted(Path(p).name for p in spec["verify"]) == ["openshell-gateway.exe", "openshell-supervisor.exe",
                                                             "openshell-windows-sandbox.exe"]
    assert spec["verify"] == {str(inst.runtime_dir(root) / "now" / "bin" / name): pins["windows"]["binaries"][name]
                              for name in PROGRAMS if name != "openshell.exe"}
    # the package before this one loaded Z3 from a library beside the gateway: with its pin back, that file is
    # re-checked again
    before = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root,
                             ident=_identity(root, pins["windows_previous"], "before"))
    assert sorted(Path(p).name for p in before["verify"]) == [
        "libz3.dll", "openshell-gateway.exe", "openshell-supervisor.exe", "openshell-windows-sandbox.exe"]


def test_binary_rules_stay_exact_whatever_the_users_environment_says(root):  # noqa: F811
    # This package can match a rule's program path loosely (either slash, any letter case) when the gateway's
    # environment asks for it. The launcher writes each rule's path in the form Windows reports and never asks:
    # the service's environment does not hold the switch, and the bootstrap drops every inherited OPENSHELL_*.
    spec = GS.service_spec("mxc", gw=GS.gateway_dir(root), port=17710, root=root,
                           ident=_identity(root, shipped()["windows"], "now"))
    assert "OPENSHELL_WINDOWS_BINARY_PATH_NORMALIZATION" not in spec["env"]
    assert 'if not k.upper().startswith(("OPENSHELL_", "XDG_", "HERMES_"))' in GS.BOOTSTRAP


# -- the pin before this one ------------------------------------------------------------------------------

def test_the_pin_before_this_one_is_kept_whole_and_nothing_reads_it(monkeypatch):
    pins = shipped()
    old = pins["windows_previous"]
    assert "windows_previous" in pins["_windows_previous"] and "windows" in pins["_windows_previous"]
    assert (old["id"], old["aarch64"]["id"], old["version"], old["signer"]) == (
        "openshell-windows-0.1.8", "openshell-windows-0.1.8-arm64", "0.1.8", "NVIDIA Corporation")
    assert old["features"] == ["ca-bundle-system-roots", "mxc-driver-config-denied-paths"]
    assert old["archive"] == {"url": RELEASES + "v0.1.8/OpenShell-Windows-0.1.8-x64.zip",
                              "sha256": "db8d321668208961dd35651af4a98d7885893151921cb98dfa2b3eded2d2117b"}
    assert old["aarch64"]["archive"] == {"url": RELEASES + "v0.1.8/OpenShell-Windows-0.1.8-arm64.zip",
                                         "sha256": "63c3aeb9b19f2cfeadfe9943629d7c53b783f34b3c735811dba21801eb0f275a"}
    assert old["binaries"] == {
        "openshell.exe": "ff3e47d0d36fa8bddba51fed3edd373fca22db5a66ff2c9dabc60340fe76bfed",
        "openshell-gateway.exe": "069b8def833d70e727408b0510870695efc45f9054b3814b7e2b8c77161efd66",
        "openshell-supervisor.exe": "8959b36f59efc603f964e7f2cf2e0d21185e740ceb61b41a4dee46efcd5cea30",
        "openshell-windows-sandbox.exe": "e80687d00cfe8a580e81ec2c155204dce2f9f75d3bb7e80aa7dd5ebd66a61a2b",
        "libz3.dll": "9211e2f44263a42890de77a490db8a153d4b64144b5b7ee005063d266e2ab63e"}
    assert old["aarch64"]["binaries"] == {
        "openshell.exe": "6e907a63db82924053fb7441c4fc9f20e992491f3ea09a7fef86192736f5baa3",
        "openshell-gateway.exe": "42baed7a4f330c282b153933edd99fc104e83a86c470d77eef9c4cdd5e79b940",
        "openshell-supervisor.exe": "bcff44e8888d3dec3b99e15d011a80fbbf5b72afbee6083e76f527d61e7d7ea2",
        "openshell-windows-sandbox.exe": "d0728df8998fca424cb252119d6ea3f35b4882c8b286ddffd56ed0327311d20e",
        "libz3.dll": "5e174245cec462276de4be33d4c42dbb68b3a8bf5e430523053d8ede3ea3310e"}
    # nothing reads it while it sits there
    assert inst.pinned("windows", arch="x86_64")["id"] == "openshell-windows-0.1.9"
    assert inst.windows_arches() == ["x86_64", "aarch64"]
    # the fallback is one edit: the block under the name ``windows``
    use_pins(monkeypatch, {**pins, "windows": old})
    for arch, ident_id, zip_name in (("x86_64", "openshell-windows-0.1.8", "OpenShell-Windows-0.1.8-x64.zip"),
                                     ("aarch64", "openshell-windows-0.1.8-arm64", "OpenShell-Windows-0.1.8-arm64.zip")):
        got = inst.pinned("windows", arch=arch)
        assert (got["id"], got["version"], got["signer"]) == (ident_id, "0.1.8", "NVIDIA Corporation")
        assert got["archive"]["url"].endswith("/v0.1.8/" + zip_name) and len(got["binaries"]) == 5
        assert got["features"] == old["features"]


# -- what this package's programs answer differently --------------------------------------------------------

ROTATION_LINES = (
    "  Ordinary static credentials: existing processes keep their old references, even with --wait.\n"
    "  After readiness, use `openshell sandbox exec` to launch a new client, or recreate the sandbox to restart its "
    "main process.\n"
    "  For live value-only rotation, configure stable_placeholder: true in the credential profile before starting "
    "the workload, or use gateway-managed refresh.\n")


def test_the_lines_provider_update_adds_about_rotation_are_not_a_refusal(tmp_path):
    # With a sandbox attached and a new value, `provider update` now ends with three lines of advice (they hold
    # the word stable_placeholder, which the profile import treats as a refusal when the IMPORT fails).
    layout, runtime, cfg, bb = _tree(tmp_path)
    calls = []

    def run(argv, env=None, **kw):
        calls.append(list(argv[1:]))
        if argv[1:3] == ["provider", "create"]:
            return Done(1, "", "Error: provider 'p' already exists")
        if argv[1:3] == ["provider", "update"]:
            return Done(0, "\u2713 Updated provider p\n" + ROTATION_LINES)
        raise AssertionError(argv)

    gw = W.CliGateway(cfg, run=run)
    assert gw.upsert_provider("p", "p", {"MODEL_KEY": "v1"}) == "updated"
    assert gw.update_provider("p", {"MODEL_KEY": "v2"}, {"MODEL_KEY": 1900000000.0}) is None
    assert [c[:2] for c in calls] == [["provider", "create"], ["provider", "update"], ["provider", "update"]]
    assert calls[-1][-2:] == ["--credential-expires-at", "MODEL_KEY=1900000000000"]


FS_SENTENCE = ("filesystem policy cannot be changed on a running sandbox; recreate the sandbox to apply filesystem "
               "changes")


class FoldersFixedCli(FakeCli):
    """The CLI in front of a supervisor that keeps the folders it started with: a policy whose filesystem section
    (``include_workdir``, the set of read-only paths, the set of read & write paths) differs from the first
    revision's is listed as failed with the supervisor's sentence, as this package's supervisor does."""

    @staticmethod
    def _folders(policy: dict) -> tuple:
        fs = policy.get("filesystem_policy") or {}
        return bool(fs.get("include_workdir")), frozenset(fs.get("read_only") or []), frozenset(fs.get("read_write") or [])

    def __call__(self, argv, env=None, **kw):
        args = argv[1:]
        if args[:2] == ["policy", "set"]:
            import hermes_yaml

            name = args[2]
            policy = hermes_yaml.safe_load(Path(args[args.index("--policy") + 1]).read_text(encoding="utf-8"))
            if self._folders(policy) != self._folders(self.revisions[name][0]["policy"]):
                self.calls.append((list(argv), dict(env or {})))
                self.policy_files.append(policy)
                version = len(self.revisions[name]) + 1
                self.revisions[name].append({"version": version, "status": "failed", "policy": policy,
                                             "load_error": FS_SENTENCE})
                return Done(1, "", f"\u2713 Policy version {version} submitted (hash: 0123456789ab)\n"
                                   f"\u2717 Policy version {version} failed to load: {FS_SENTENCE}")
        return super().__call__(argv, env=env, **kw)


def test_every_live_update_carries_the_folders_the_sandbox_started_with(tmp_path, secrets_env, monkeypatch):  # noqa: F811
    layout, runtime, cfg, bb = _tree(tmp_path)
    fake = FoldersFixedCli()
    driver = _driver(cfg, fake, tmp_path)
    sup = _supervisor(layout, runtime, driver, bb)

    async def scenario():
        await sup.start()
        try:
            started_with = json.loads(json.dumps(driver._launch_policy["filesystem_policy"]))
            assert started_with["read_write"] and started_with["read_only"]
            # a website allowed, a request approved, the first revision restored: each loads
            out = driver.apply_network({"egress": "deny", "allow": [{"host": "pypi.org", "port": 443}]})
            assert out["loaded"] is True and fake.policy_files[-1]["filesystem_policy"] == started_with
            pending = next(p for p in driver.proposals() if p["status"] == "pending")
            assert driver.approve(pending["id"])["status"] == "loaded"
            back = driver.rollback(1)
            assert back["loaded"] is True and fake.policy_files[-1]["filesystem_policy"] == started_with
            assert [r["status"] for r in fake.revisions["hermes-default"]].count("failed") == 0
            # and a policy with another folder in it is refused by the sandbox, with its reason
            other = json.loads(json.dumps(driver._launch_policy))
            other["filesystem_policy"]["read_write"].append("C:\\another\\folder")
            with pytest.raises(RuntimeError, match="rejected policy revision [0-9]+: filesystem policy cannot be changed"):
                driver._apply(other, "network")
            assert driver._launch_policy["filesystem_policy"] == started_with
        finally:
            await sup.stop()

    asyncio.run(scenario())
