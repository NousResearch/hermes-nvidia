"""The Network section's rows (desktop/plugin.js) in the Node harness (tests/js/switch_harness.mjs): what the row
of a model's address says about how the sandbox reaches it."""
from test_desktop_switch_js import run  # noqa: F401  (the Node run, once per module)

LOCAL_TIP = "This profile's model on this computer is reachable from the sandbox."
PROVIDER_TIP = "A key or sign-in of this profile is used at this address."


def test_the_row_of_a_model_address_says_how_the_sandbox_reaches_it(run):  # noqa: F811
    rows = run["modelReach"]
    assert "error" not in rows
    assert rows["local"] == {"title": "Model", "sub": "http://127.0.0.1:11434/v1", "text": "Allowed", "tip": LOCAL_TIP}
    assert (rows["provider"]["text"], rows["provider"]["tip"]) == ("Allowed", PROVIDER_TIP)
    assert (rows["blocked"]["text"], rows["blocked"]["tip"]) == ("Blocked", "Not reachable from the sandbox.")
