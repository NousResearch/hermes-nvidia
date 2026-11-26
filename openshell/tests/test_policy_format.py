"""The stored sandbox configuration is an OpenShell sandbox policy.

spec.yaml keeps the launcher's own settings beside ``policy:``, a document OpenShell's policy schema
accepts; the settings page keeps editing its view (folders, network) and the view folds back into
the document without losing what the view does not model.
"""
import copy

import pytest

import hermes_yaml
from openshell.launcher import layout as L
from openshell.launcher import spec as S
from openshell.launcher.openshell_driver import rule_name

GITHUB = rule_name("site", "api.github.com", 443)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    monkeypatch.setattr(L.Path, "home", classmethod(lambda cls: tmp_path / "userhome"))
    (tmp_path / "userhome").mkdir()
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    return L.ProfileLayout(name="work", home=home, root=root)


def _folders(tmp_path):
    rw, ro = tmp_path / "userhome" / "projects", tmp_path / "userhome" / "reference"
    rw.mkdir(parents=True)
    ro.mkdir(parents=True)
    return rw, ro


def _on_disk(layout):
    return hermes_yaml.safe_load(layout.spec_path.read_text(encoding="utf-8"))


def test_default_driver_is_openshell_on_every_os():
    assert S.default_driver() == "openshell" and S.default_spec()["driver"] == "openshell"


def test_saved_spec_stores_an_openshell_policy_and_reads_back_the_same_view(layout, tmp_path):
    rw, ro = _folders(tmp_path)
    spec = S.load_spec(layout)
    spec["folders"] = [{"path": str(rw), "access": "rw"}, {"path": str(ro), "access": "ro"}]
    spec["network"] = {"egress": "deny", "allow": [{"host": "api.github.com", "port": 443},
                                                   {"host": "pypi.org", "port": 443, "binary": "C:\\tools\\uv.exe"},
                                                   {"cidr": "203.0.113.0/24", "port": 8443}]}
    S.save_spec(layout, spec)
    disk = _on_disk(layout)
    assert "folders" not in disk and "network" not in disk and disk["egress"] == "deny"
    doc = disk["policy"]
    S.check_policy_document(doc)  # what OpenShell's schema accepts: no unknown fields, version 1
    assert doc["version"] == 1
    assert doc["filesystem_policy"] == {"include_workdir": False, "read_write": [str(rw)], "read_only": [str(ro)]}
    rules = doc["network_policies"]
    site = rules[GITHUB]
    assert site["endpoints"] == [{"host": "api.github.com", "port": 443}]
    assert site["binaries"] == [{"path": b} for b in S.hermes_binaries()] and site["binaries"]
    named = [r for n, r in rules.items() if n.startswith("hermes_site_pypi_org_443_")]
    assert len(named) == 1 and named[0]["binaries"] == [{"path": "C:\\tools\\uv.exe"}]
    assert rules[rule_name("addr", "203.0.113.0/24", 8443)]["endpoints"] == [
        {"port": 8443, "allowed_ips": ["203.0.113.0/24"]}]
    again = S.load_spec(layout)
    assert again["folders"] == spec["folders"]
    assert S.network_policy(again) == S.network_policy(spec)
    assert again["policy"] == doc


def test_a_spec_saved_before_the_policy_format_is_read_and_rewritten(layout, tmp_path):
    rw, _ = _folders(tmp_path)
    layout.state_dir.mkdir(parents=True)
    layout.spec_path.write_text(hermes_yaml.safe_dump({
        "port": 47811, "driver": "openshell", "folders": [{"path": str(rw), "access": "rw"}],
        "network": {"egress": "allow", "allow": [{"host": "example.org", "port": 443}]}}), encoding="utf-8")
    spec = S.load_spec(layout)
    assert spec["driver"] == "openshell" and spec["folders"] == [{"path": str(rw), "access": "rw"}]
    assert S.network_policy(spec)["egress"] == "allow"
    S.save_spec(layout, spec)
    disk = _on_disk(layout)
    assert set(disk) == {"port", "driver", "wxc_exec", "busybox", "openshell", "egress", "policy"}
    assert disk["egress"] == "allow" and rule_name("site", "example.org", 443) in disk["policy"]["network_policies"]
    assert S.load_spec(layout)["folders"] == spec["folders"]


def test_what_the_view_does_not_model_survives_a_page_edit(layout, tmp_path):
    rw, ro = _folders(tmp_path)
    approved = {"allow_example_com_443": {"name": "allow_example_com_443",
                                          "endpoints": [{"host": "example.com", "port": 443, "protocol": "rest",
                                                         "access": "read-only"}],
                                          "binaries": [{"path": "C:\\py\\python.exe"}]}}
    l7 = {"name": "hermes_site_api_github_com_443",
          "endpoints": [{"host": "api.github.com", "port": 443, "protocol": "rest", "access": "read-only"}],
          "binaries": [{"path": "C:/x/python-*/python.exe"}]}
    two_endpoints = {"name": "hermes_site_hand_written_443",
                     "endpoints": [{"host": "a.example.net", "port": 443}, {"host": "b.example.net", "port": 443}],
                     "binaries": [{"path": "C:\\py\\python.exe"}]}
    doc = {"version": 1, "filesystem_policy": {"read_write": [str(rw)], "deny": [str(rw / ".secrets")]},
           "network_policies": {**approved, "hermes_site_api_github_com_443": l7,
                                "hermes_site_hand_written_443": two_endpoints}}
    spec = S.set_policy(layout, doc)
    net = S.network_policy(spec)
    assert net["allow"] == [{"host": "api.github.com", "port": 443}]
    assert set(net["approved"]) == {"allow_example_com_443", "hermes_site_hand_written_443"}
    # A folder edit from the page: the rule's L7 settings, the deny path and the approved rules stay.
    spec = S.update_spec(layout, folders=[{"path": str(rw), "access": "rw"}, {"path": str(ro), "access": "ro"}])
    stored = _on_disk(layout)["policy"]
    assert "hermes_site_api_github_com_443" not in stored["network_policies"]  # saved under the rule's full name
    assert stored["network_policies"][GITHUB] == {**l7, "name": GITHUB}
    assert stored["network_policies"]["allow_example_com_443"] == approved["allow_example_com_443"]
    assert stored["network_policies"]["hermes_site_hand_written_443"] == two_endpoints
    assert stored["filesystem_policy"]["deny"] == [str(rw / ".secrets")]
    assert stored["filesystem_policy"]["read_only"] == [str(ro)]
    # Removing the destination on the page removes its rule; approved rules are kept unless named away.
    S.update_spec(layout, network={"egress": "deny", "allow": [], "approved": net["approved"]})
    stored = _on_disk(layout)["policy"]
    assert not [name for name in stored["network_policies"] if "api_github_com" in name]
    assert "allow_example_com_443" in stored["network_policies"]


@pytest.mark.parametrize("bad, words", [
    ({"version": 2}, "version must be 1"),
    ({"version": 1, "sandbox": {}}, "Unknown sandbox policy field"),
    ({"version": 1, "filesystem_policy": {"read_write": ["C:/x"], "hide": []}}, "Unknown filesystem_policy field"),
    ({"version": 1, "network_policies": {"_provider_x": {"endpoints": []}}}, "reserves _provider_"),
    ({"version": 1, "network_policies": {"r": {"endpoints": [], "methods": []}}}, "only name, endpoints and binaries"),
    ({"version": 1, "network_policies": {"r": {"binaries": ["C:/py.exe"]}}}, "binaries must be a list"),
])
def test_documents_openshell_would_refuse_are_refused(layout, bad, words):
    with pytest.raises(L.LayoutError, match=words):
        S.set_policy(layout, bad)
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    layout.spec_path.write_text(hermes_yaml.safe_dump({"policy": bad}), encoding="utf-8")
    with pytest.raises(L.LayoutError, match=words):
        S.load_spec(layout)


def test_a_stored_policy_goes_through_the_host_folder_checks(layout, tmp_path):
    with pytest.raises(L.LayoutError, match="home folder"):
        S.set_policy(layout, {"version": 1, "filesystem_policy": {"read_write": [str(tmp_path / "userhome")]}})
    assert not layout.spec_path.exists()


def test_policy_yaml_is_the_document_openshell_reads(layout, tmp_path):
    rw, _ = _folders(tmp_path)
    spec = S.load_spec(layout)
    spec["folders"] = [{"path": str(rw), "access": "rw"}]
    spec["network"] = {"egress": "deny", "allow": [{"host": "api.github.com", "port": 443}]}
    text = S.policy_yaml(spec)
    doc = hermes_yaml.safe_load(text)
    assert list(doc) == ["version", "filesystem_policy", "network_policies"]
    assert doc == S.policy_document(copy.deepcopy(spec))


def test_long_windows_paths_stay_on_one_line_for_openshells_parser(layout, tmp_path):
    deep = tmp_path / "userhome" / ("a folder with spaces " * 4).strip() / "and a long tail of nested names"
    deep.mkdir(parents=True)
    spec = S.load_spec(layout)
    spec["folders"] = [{"path": str(deep), "access": "rw"}]
    S.save_spec(layout, spec)
    for text in (S.policy_yaml(spec), layout.spec_path.read_text(encoding="utf-8")):
        assert any(line.strip() == f"- {deep}" for line in text.splitlines()), text
