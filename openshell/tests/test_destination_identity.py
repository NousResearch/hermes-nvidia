"""One identity per allowed destination: the exact host or address block, the port and the program.

The rule's name carries a hash of that identity, so two destinations never share a name, however alike their
names fold or begin. The saved policy, the loaded policy and every answer are built from the one list the user
last sent: a site that was removed stays removed after a restart, a wildcard and its bare domain are two rules,
and a policy saved under the short rule names is read as it stands and written under the full names at its next
save. A site a chat card saved is removed alone, also where it shares its saved rule with another site.
Fake gateways throughout: nothing here talks to a network.
"""
import asyncio
import copy
import json
import time

import pytest

import hermes_yaml
import test_cards as TC
import test_openshell_driver as LD
from openshell.launcher import cards as C
from openshell.launcher import layout as L
from openshell.launcher import openshell_driver as OD
from openshell.launcher import settings_view as SV
from openshell.launcher import spec as S
from openshell.launcher.host_routes import HostRoutes
from openshell.launcher.layout import current_profile
from test_cards import harness  # noqa: F401  (the cards fixture)
from test_settings_routes import _plugin_api, fake_home  # noqa: F401

PY = "/store/python3"
COMMON = "internal-document-index-for-team-fixture-"
A, B = "/opt/test/client-a", "/opt/test/client-b"


def site(host, port=443, binary=None):
    return {"host": host, "port": port, **({"binary": binary} if binary else {})}


def block(cidr, port=443):
    return {"cidr": cidr, "port": port}


FIRST, SECOND, CONTROL = site("api-one.example"), site("api.one.example"), site("unrelated.example")
EAST, WEST = site(COMMON + "east.example"), site(COMMON + "west.example")
V6 = "2001:db8:1111:2222:3333:4444:5555:6666"
PAIRS = [
    ("punctuation", FIRST, SECOND),
    ("the first forty characters", EAST, WEST),
    ("a wildcard and its bare domain", site("*.example.com"), site("example.com")),
    ("two wildcards", site("*.example.com"), site("**.example.com")),
    ("where a label ends", site("a.b-c.example"), site("a-b.c.example")),
    ("another port", FIRST, site("api-one.example", 8443)),
    ("two programs at one host", site("download.example", 443, A), site("download.example", 443, B)),
    ("one program and every program", site("download.example", 443, A), site("download.example")),
    ("two address blocks", block(f"{V6}/128"), block(f"{V6}/127")),
    ("a site and an address block", site("10-0-0-0.example"), block("10.0.0.0/8")),
]


def name_of(entry):
    return S.site_rule(entry)[0]


def targets(rules):
    """The destinations a set of OpenShell rules opens, as (host or block, port, programs)."""
    return sorted((ep.get("host") or ep["allowed_ips"][0], ep["port"], tuple(b["path"] for b in rule["binaries"]))
                  for rule in rules.values() for ep in rule["endpoints"])


def loaded(allow):
    """What a driver sends for *allow*: one rule per destination, a program's own or Hermes's interpreter."""
    return targets(OD.network_rules({"egress": "deny", "allow": allow}, (PY,)))


def wanted(allow):
    return sorted((e.get("host") or e["cidr"], e["port"], (e.get("binary") or PY,)) for e in allow)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    monkeypatch.setattr(L.Path, "home", classmethod(lambda cls: tmp_path / "userhome"))
    (tmp_path / "userhome").mkdir()
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    return L.ProfileLayout(name="work", home=home, root=tmp_path / "root")


def save(layout, allow):
    """One edit as a settings route makes it: validated, saved, and answered with the saved list."""
    network = S.network_from_body({"egress": "deny", "allow": allow}, host_loopback="closed", rules=("host", "cidr"),
                                  allow_all=False)
    return S.update_spec(layout, network=network)["network"]["allow"]


def stored(layout):
    return hermes_yaml.safe_load(layout.spec_path.read_text(encoding="utf-8"))["policy"].get("network_policies") or {}


# -- the name ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("case, one, other", PAIRS, ids=[pair[0] for pair in PAIRS])
def test_two_destinations_never_share_a_rule(case, one, other, layout):
    assert name_of(one) != name_of(other)
    assert loaded([one, other]) == wanted([one, other])  # both are in what the sandbox loads
    assert save(layout, [one, other]) == [one, other] == S.load_spec(layout)["network"]["allow"]
    assert len(stored(layout)) == 2
    assert save(layout, [other]) == [other] == S.load_spec(layout)["network"]["allow"]
    assert loaded(S.load_spec(layout)["network"]["allow"]) == wanted([other])
    assert list(stored(layout)) == [name_of(other)]


def test_a_rule_name_is_readable_stable_and_short():
    name = OD.rule_name("site", "api-one.example", 443)
    assert name == OD.rule_name("site", "api-one.example", 443) == name_of(FIRST)
    assert name.startswith("hermes_site_api_one_example_443_") and name != OD.rule_name("site", "api-one.example", 443, A)
    assert OD.rule_name("addr", "10.0.0.0/8", 443).startswith("hermes_addr_10_0_0_0_8_443_")
    longest = OD.rule_name("site", "a" * 60 + ".example", 65535, "/x")
    assert len(longest) <= 63 and longest != OD.rule_name("site", "a" * 60 + ".example", 65535, "/y")
    assert name not in OD.network_rules({"allow": [SECOND]}, (PY,))


# -- the saved list, the loaded policy and the answer are one list ---------------------------------------------

def test_a_removed_site_stays_removed_when_the_sandbox_starts_again(layout):
    """Add a second site whose name folds like the first one's, remove the first, start again."""
    for allow in ([FIRST, CONTROL], [FIRST, CONTROL, SECOND], [CONTROL, SECOND]):
        assert save(layout, allow) == allow  # what the route answers
        assert S.load_spec(layout)["network"]["allow"] == allow  # what a launcher that starts reads
        assert loaded(allow) == wanted(allow)  # what the sandbox loads
    sent = [OD.network_rules({"allow": allow}, (PY,)) for allow in ([FIRST, CONTROL, SECOND], [CONTROL, SECOND])]
    assert sent[0] != sent[1]  # the removal is a change of the policy, so the gateway gets a revision for it
    assert loaded(S.load_spec(layout)["network"]["allow"]) == wanted([CONTROL, SECOND])


def test_a_removal_saved_alone_and_the_addition_after_it(layout):
    save(layout, [FIRST, CONTROL])
    assert save(layout, [CONTROL]) == [CONTROL]
    assert save(layout, [CONTROL, SECOND]) == [CONTROL, SECOND] == S.load_spec(layout)["network"]["allow"]


def test_a_wildcard_replaced_by_its_bare_domain_is_gone(layout):
    wide, narrow = site("**.example.com"), site("example.com")
    save(layout, [wide])
    save(layout, [wide, narrow])
    assert save(layout, [narrow]) == [narrow] == S.load_spec(layout)["network"]["allow"]
    assert loaded(S.load_spec(layout)["network"]["allow"]) == wanted([narrow])


def test_the_same_destination_twice_is_one_rule(layout):
    spec = S.load_spec(layout)
    spec["network"] = {"egress": "deny", "allow": [FIRST, dict(FIRST), SECOND]}
    S.save_spec(layout, spec)
    assert S.load_spec(layout)["network"]["allow"] == [FIRST, SECOND]


def test_the_launcher_answers_stores_and_loads_the_list_it_was_sent(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch)
    routes = HostRoutes(sup, lambda: None)
    put = routes.match("PUT", "/api/plugins/openshell/network")
    get = routes.match("GET", "/api/plugins/openshell/config")

    def live():
        return sorted(ep["host"] for rule in api.revisions["hermes-work"][-1]["policy"]["network_policies"].values()
                      for ep in rule["endpoints"])

    async def scenario():
        await sup.start()
        try:
            for allow in ([FIRST, CONTROL], [FIRST, CONTROL, SECOND], [CONTROL, SECOND]):
                before = len(api.revisions["hermes-work"])
                status, payload, _ = await put(LD._req(), json.dumps({"egress": "deny", "allow": allow}).encode())
                assert status == 200 and payload["network"]["allow"] == allow
                assert (await get(LD._req(), b""))[1]["network"]["allow"] == allow
                assert sup.status()["applied"]["network"]["allow"] == allow and not sup.status()["pending"]["network"]
                assert S.load_spec(layout)["network"]["allow"] == allow
                assert live() == sorted(e["host"] for e in allow)
                assert len(api.revisions["hermes-work"]) == before + 1
            await sup.restart()
            created = [call for call in api.calls if call[0] == "create"][-1][2]["policy"]["network_policies"]
            assert sorted(ep["host"] for rule in created.values() for ep in rule["endpoints"]) == [
                "api.one.example", "unrelated.example"]
        finally:
            await sup.stop()

    asyncio.run(scenario())


# -- the page's edits through the route of a profile that is off -----------------------------------------------

REPORTS, OTHER_PORT = site("reports.example"), site("api.one.example", 8443)
ONE_A, ONE_B = site("download.example", 443, A), site("download.example", 443, B)
BACKUP_B, PLAIN = site("backup.example", 443, B), site("control.example")
EDITS = [
    ("punctuation", [[FIRST], [FIRST, SECOND]]),
    ("reverse", [[SECOND], [SECOND, FIRST]]),
    ("long prefix", [[EAST], [EAST, WEST]]),
    ("another name", [[FIRST], [FIRST, REPORTS]]),
    ("another port", [[FIRST], [FIRST, OTHER_PORT]]),
    ("two programs at one host, one removed", [[ONE_A, ONE_B, PLAIN], [ONE_B, PLAIN]]),
    ("two programs at two hosts, one removed", [[ONE_A, BACKUP_B], [BACKUP_B]]),
    ("cleared, then added", [[FIRST], [], [SECOND]]),
]


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(_plugin_api().router, prefix="/api/plugins/openshell")
    return TestClient(app)


@pytest.mark.parametrize("case, edits", EDITS, ids=[edit[0] for edit in EDITS])
def test_every_edit_of_the_page_is_what_is_saved(fake_home, case, edits):  # noqa: F811
    client, layout = _client(), current_profile()
    try:
        for allow in edits:
            answer = client.put("/api/plugins/openshell/network", json={"egress": "deny", "allow": allow})
            assert answer.status_code == 200 and answer.json()["network"]["allow"] == allow
            assert client.get("/api/plugins/openshell/config").json()["network"]["allow"] == allow
            assert S.load_spec(layout)["network"]["allow"] == allow
            assert loaded(S.load_spec(layout)["network"]["allow"]) == wanted(allow)
    finally:
        S.update_spec(layout, network={"egress": "deny", "allow": []})


# -- a policy saved under the short rule names -----------------------------------------------------------------

L7 = {"host": "api-one.example", "port": 443, "protocol": "rest", "access": "read-only"}
SHORT = {
    "hermes_site_api_one_example_443": {"name": "hermes_site_api_one_example_443", "endpoints": [dict(L7)],
                                        "binaries": [{"path": "/store/python-*/bin/python3*"}]},
    "hermes_site_download_example_443_53c22190": {"name": "hermes_site_download_example_443_53c22190",
                                                  "endpoints": [{"host": "download.example", "port": 443}],
                                                  "binaries": [{"path": A}]},
    "hermes_addr_10_0_0_0_8_443": {"name": "hermes_addr_10_0_0_0_8_443",
                                   "endpoints": [{"port": 443, "allowed_ips": ["10.0.0.0/8"]}],
                                   "binaries": [{"path": "/store/python-*/bin/python3*"}]},
    "allow_example_com_443": {"name": "allow_example_com_443", "endpoints": [{"host": "example.com", "port": 443}],
                              "binaries": [{"path": "/usr/bin/curl"}]},
}
SHORT_LIST = [FIRST, ONE_A, block("10.0.0.0/8")]


def _write(layout, rules):
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    layout.spec_path.write_text(hermes_yaml.safe_dump(
        {"driver": "openshell", "egress": "deny", "policy": {"version": 1, "network_policies": copy.deepcopy(rules)}},
        sort_keys=False), encoding="utf-8")


def test_a_policy_saved_under_the_short_names_reads_as_it_stands_and_is_saved_under_the_full_names(layout):
    _write(layout, SHORT)
    network = S.load_spec(layout)["network"]
    assert network["allow"] == SHORT_LIST and set(network["approved"]) == {"allow_example_com_443"}
    assert loaded(network["allow"]) == wanted(SHORT_LIST)  # the sandbox loads the three under their full names
    assert stored(layout) == SHORT  # reading changes nothing in the file
    # the first save, here a folder edit that leaves the network as it is
    answered = S.update_spec(layout, folders=[])
    assert answered["network"]["allow"] == SHORT_LIST and set(answered["network"]["approved"]) == {"allow_example_com_443"}
    rules = stored(layout)
    assert set(rules) == {name_of(FIRST), name_of(ONE_A), name_of(block("10.0.0.0/8")), "allow_example_com_443"}
    kept = rules[name_of(FIRST)]
    assert kept == {"name": name_of(FIRST), "endpoints": [L7], "binaries": SHORT["hermes_site_api_one_example_443"]["binaries"]}
    assert rules[name_of(ONE_A)]["binaries"] == [{"path": A}]
    assert rules["allow_example_com_443"] == SHORT["allow_example_com_443"]
    assert S.load_spec(layout)["network"] == answered["network"]
    # and the page's next edits act on single destinations
    assert save(layout, [FIRST, SECOND, ONE_A]) == [FIRST, SECOND, ONE_A]
    assert stored(layout)[name_of(FIRST)]["endpoints"] == [L7]  # the rule's own settings stay with its destination
    assert save(layout, [SECOND]) == [SECOND] == S.load_spec(layout)["network"]["allow"]


def test_a_short_name_that_holds_the_other_site_is_read_as_the_site_it_holds(layout):
    """Two sites shared one short name, and the file kept one of them under it: that one is what is shown."""
    held = {"name": "hermes_site_api_one_example_443", "endpoints": [{"host": "api.one.example", "port": 443}],
            "binaries": [{"path": "/store/python-*/bin/python3*"}]}
    _write(layout, {"hermes_site_api_one_example_443": held})
    assert S.load_spec(layout)["network"]["allow"] == [SECOND]
    assert save(layout, [SECOND, FIRST]) == [SECOND, FIRST]
    assert set(stored(layout)) == {name_of(FIRST), name_of(SECOND)}


# -- sites a chat card saved ------------------------------------------------------------------------------------

def _always_allowed(*hosts):
    """What "Always allow" on a website card saves for each host, one after the other."""
    approved = {}
    for host in hosts:
        rule = C.host_rule(host, {80, 443})
        approved[rule["name"]] = C._merge_rule(approved.get(rule["name"]), rule)
    return approved


def _rows(layout):
    return [row["target"] for row in SV.saved_grants(layout)]


def test_two_sites_in_one_saved_rule_are_removed_one_at_a_time(harness):  # noqa: F811
    layout = harness["layout"]
    approved = _always_allowed("api-one.example", "api.one.example", "www.example.org")
    assert len(approved) == 2  # the first two share a saved rule
    S.update_spec(layout, network={"egress": "deny", "allow": [], "approved": approved})
    assert _rows(layout) == ["api-one.example", "api.one.example", "www.example.org"]

    async def main():
        cards, conn = await TC._setup(harness)
        assert (await cards.remove_grant("network:always:api-one.example"))[0] == 200
        assert _rows(layout) == ["api.one.example", "www.example.org"]
        (rule,) = [r for r in S.load_spec(layout)["network"]["approved"].values() if "api.one.example" in json.dumps(r)]
        assert rule["endpoints"] == [{"host": "api.one.example", "port": 80}, {"host": "api.one.example", "port": 443}]
        assert (await cards.remove_grant("network:always:api-one.example"))[0] == 404
        assert (await cards.remove_grant("network:always:api.one.example"))[0] == 200
        assert _rows(layout) == ["www.example.org"] and len(S.load_spec(layout)["network"]["approved"]) == 1
        await cards.stop()

    asyncio.run(main())


def test_the_page_of_a_profile_that_is_off_removes_one_saved_site_too(fake_home):  # noqa: F811
    client, layout = _client(), current_profile()
    S.update_spec(layout, network={"egress": "deny", "allow": [],
                                   "approved": _always_allowed("*.example.com", "example.com")})
    try:
        assert _rows(layout) == ["*.example.com", "example.com"]
        done = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:*.example.com"})
        assert done.status_code == 200 and [row["target"] for row in done.json()["grants"]] == ["example.com"]
        again = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:*.example.com"})
        assert again.status_code == 404
        done = client.request("DELETE", "/api/plugins/openshell/grants", json={"id": "network:always:example.com"})
        assert done.status_code == 200 and done.json()["grants"] == []
        assert "approved" not in S.load_spec(layout)["network"]
    finally:
        S.update_spec(layout, network={"egress": "deny", "allow": []})


# -- names of any length ----------------------------------------------------------------------------------------

LONG = 200_000


@pytest.mark.parametrize("text", ["-." * (LONG // 2), "a" * LONG, "*." * (LONG // 2), "\\_/:" * (LONG // 4)],
                         ids=["punctuation", "one label", "wildcards", "separators"])
def test_a_name_of_any_length_gets_a_short_name_of_its_own_in_bounded_time(text):
    started = time.monotonic()
    one, other = OD.rule_name("site", text + "x", 443, "/opt/" + text), OD.rule_name("site", text + "y", 443, "/opt/" + text)
    assert one != other and len(one) <= 63 and len(other) <= 63
    assert one == OD.rule_name("site", text + "x", 443, "/opt/" + text)
    # a stored rule whose host is no host name is no destination of the page's: it is kept as it stands
    rule = {"name": "hermes_site_x_443", "endpoints": [{"host": text, "port": 443}], "binaries": [{"path": PY}]}
    block_rule = {"name": "hermes_addr_x_443", "endpoints": [{"port": 443, "allowed_ips": [text]}], "binaries": [{"path": PY}]}
    doc = {"version": 1, "network_policies": {"hermes_site_x_443": rule, "hermes_addr_x_443": block_rule}}
    folders, network = S.view_from_policy(doc)
    assert network["allow"] == [] and set(network["approved"]) == {"hermes_site_x_443", "hermes_addr_x_443"}
    assert S.policy_document({"network": network, "policy": doc})["network_policies"] == doc["network_policies"]
    # a saved website whose name is that long is found and removed by its exact name
    approved = {"allowed_host_x": {"name": "allowed_host_x", "endpoints": [{"host": text, "port": 443},
                                                                           {"host": "example.com", "port": 443}]}}
    assert C.without_grant(approved, text)["allowed_host_x"]["endpoints"] == [{"host": "example.com", "port": 443}]
    assert C.without_grant(approved, text + "x") is None
    assert time.monotonic() - started < 5
