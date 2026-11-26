"""The Network section's rows (desktop/plugin.js) in the Node harness (tests/js/switch_harness.mjs): what the row
of a model's address says about how the sandbox reaches it, and the rows of destinations that are for one program."""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

LOCAL_TIP = "This profile's model on this computer is reachable from the sandbox."
PROVIDER_TIP = "A key or sign-in of this profile is used at this address."


def test_the_row_of_a_model_address_says_how_the_sandbox_reaches_it(run):  # noqa: F811
    rows = run["modelReach"]
    assert "error" not in rows
    assert rows["local"] == {"title": "Model", "sub": "http://127.0.0.1:11434/v1", "text": "Allowed", "tip": LOCAL_TIP}
    assert (rows["provider"]["text"], rows["provider"]["tip"]) == ("Allowed", PROVIDER_TIP)
    assert (rows["blocked"]["text"], rows["blocked"]["tip"]) == ("Blocked", "Not reachable from the sandbox.")


A, B = "/opt/test/client-a", "/opt/test/client-b"
ONE_A = {"host": "download.example", "port": 443, "binary": A}
ONE_B = {"host": "download.example", "port": 443, "binary": B}
EVERY = {"host": "download.example", "port": 443}
CONTROL = {"host": "control.example", "port": 443}


def _put(allow):
    return ["/network", "PUT", {"egress": "deny", "allow": allow}]


def test_a_destination_for_one_program_is_a_row_of_its_own_that_names_the_program(run):  # noqa: F811
    found = run["programRules"]
    assert "error" not in found
    rows = found["rows"]
    assert [row["title"] for row in rows] == ["download.example", "download.example", "download.example", "control.example"]
    assert [row["note"] for row in rows] == [f"Only for {A}", f"Only for {B}", None, None]
    assert len({row["key"] for row in rows}) == 4 and all(row["port"] == "Port 443" for row in rows)
    # a rule the running sandbox does not have yet is marked by itself, not with the other program's
    assert found["pending"] == [True, False, False]


def test_remove_on_one_programs_row_leaves_the_other_rules_of_that_host(run):  # noqa: F811
    found = run["programRules"]
    assert found["removeFirst"] == _put([ONE_B, EVERY, CONTROL])
    assert found["removeEveryProgram"] == _put([ONE_A, ONE_B, CONTROL])
    assert found["twoHosts"] == _put([{"host": "backup.example", "port": 443, "binary": B}])
