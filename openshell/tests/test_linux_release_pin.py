"""The pinned Linux release (OpenShell v0.1.9), value for value: the release's home, its four checksum files, the two
Docker driver images by digest, and the Python SDK wheel, which the release no longer attaches and which is therefore
pinned by its own sha256 and URL. The installer checks every download against these (test_openshell_install.py,
test_sdk_wheel_pin.py); this file holds the values themselves, so that a changed digit is a failing test."""
import json

from openshell.launcher import openshell_install as inst

RELEASE = "https://github.com/ai-openshell/openshell/releases/download/v0.1.9"


def test_the_shipped_linux_pin_is_the_v0_1_9_release():
    linux = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))["linux"]
    assert (linux["id"], linux["version"], linux["release_url"]) == ("openshell-v0.1.9", "0.1.9", RELEASE)
    assert linux["checksum_files"] == {
        "openshell-checksums-sha256.txt": "842ab0b6314367e13bc4bdc3c9f225623a6f09ed0c88082a4ce5f709ca36e7bf",
        "openshell-gateway-checksums-sha256.txt": "f656fe163fd6a68957c4b06c88dd17dee0168359891d827ab189df32ea767ed7",
        "openshell-sandbox-checksums-sha256.txt": "4e7425814306730302f5acb62e8e36aa7459d7fa30685c18499932509a091ffb",
        "openshell-supervisor-checksums-sha256.txt": "5e50d1529a248e07f8cfc2de0a8f4c755b307026ececd83d39b9fd4d1f53047a"}
    assert linux["images"] == {
        "openshell-supervisor": {
            "ref": "ghcr.io/nvidia/openshell/supervisor@sha256:"
                   "f1ec231b5dbe5b6a40c33acb2ac847995aabb959a56134ef6d7d7aa4f43199d3", "path": "/openshell-supervisor"},
        "openshell-sandbox": {
            "ref": "ghcr.io/nvidia/openshell/sandbox@sha256:"
                   "e57d07cd6cc1fc314b80368d6b51ec6fbf825fb62cd8f081312941180846866f", "path": "/openshell-sandbox"}}
    assert linux["sdk_wheel"] == {
        "file": "openshell-0.1.9-py3-none-any.whl",
        "sha256": "5805829ef04b98d84dd6b2f4707f079c87bf8a4225a516b3b11bc6f84d56a9be",
        "url": "https://files.pythonhosted.org/packages/e8/44/c812c8d9a2f510f54f3c6a2e5ce492a0b50a2a002173f19a6d263d2edcc3/"
               "openshell-0.1.9-py3-none-any.whl"}
    # the same eight release files as before, four per architecture
    assert {arch: sorted(files) for arch, files in linux["assets"].items()} == {
        arch: ["openshell", "openshell-gateway", "openshell-sandbox", "openshell-supervisor"]
        for arch in ("x86_64", "aarch64")}
    assert linux["assets"]["x86_64"]["openshell-gateway"] == "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz"
    assert linux["assets"]["aarch64"]["openshell-sandbox"] == "openshell-sandbox-aarch64-unknown-linux-musl.tar.gz"


def test_one_openshell_version_on_both_systems():
    pins = json.loads(inst.PINS_PATH.read_text(encoding="utf-8"))
    assert pins["linux"]["version"] == pins["windows"]["version"] == "0.1.9"
    # the same release, in the repository it lives in
    assert pins["windows"]["archive"]["url"].startswith(pins["linux"]["release_url"] + "/")
