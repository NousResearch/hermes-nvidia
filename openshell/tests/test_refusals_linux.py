"""Refusals as OpenShell's Linux (Docker driver) sandboxes produce them: no proxy, a refused connection."""
import json

import os
from pathlib import Path

from openshell.launcher.refusals import (SOURCE_REFUSAL, SOURCE_TEXT, maybe_refused, refused_destinations,
                                         refused_paths)


def _result(output, code=7):
    return json.dumps({"output": output, "exit_code": code, "error": None})


def test_curl_in_the_linux_sandbox_names_the_refused_host():
    out = _result("curl: (7) Failed to connect to httpbin.org port 443 after 3 ms: Could not connect to server\nHTTP 000")
    assert maybe_refused(out)
    hosts, strength = refused_destinations("terminal", {"command": "curl -sS https://httpbin.org/get"}, out)
    assert strength == "strong" and hosts[0] == ("httpbin.org", 443, SOURCE_REFUSAL)


def test_python_requests_and_pip_name_the_host_they_could_not_reach():
    out = _result("HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded with url: /simple/ (Caused by "
                  "NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x7f>: Failed to establish a new "
                  "connection: [Errno 111] Connection refused'))", 1)
    hosts, strength = refused_destinations("terminal", {"command": "pip download requests"}, out)
    assert strength == "strong" and hosts[0] == ("pypi.org", 443, SOURCE_REFUSAL)


def test_wget_and_node_refusals():
    out = _result("Connecting to example.org (example.org)|198.18.0.7|:443... failed: Connection refused.", 4)
    hosts, _ = refused_destinations("terminal", {"command": "wget https://example.org/"}, out)
    assert hosts[0] == ("example.org", 443, SOURCE_REFUSAL)
    out = _result("Error: connect ECONNREFUSED 198.18.0.3:443", 1)
    hosts, strength = refused_destinations("terminal", {"command": "node fetch.js https://registry.npmjs.org/x"}, out)
    assert strength == "strong" and ("registry.npmjs.org", 443, SOURCE_TEXT) in hosts


def test_the_model_endpoint_and_loopback_never_become_candidates():
    out = _result("httpx.ConnectError: [Errno 111] Connection refused (http://host.openshell.internal:18530/v1)", 1)
    assert refused_destinations("terminal", {}, out)[0] == []
    out = _result("curl: (7) Failed to connect to localhost port 8080 after 0 ms: Connection refused")
    assert refused_destinations("terminal", {"command": "curl http://localhost:8080"}, out)[0] == []


def test_an_ordinary_result_stays_cheap():
    assert not maybe_refused(_result("HTTP 200", 0))


def test_python_connect_refused_with_eacces_is_a_network_refusal():
    """v0.1.6 answers a Python connect() to a refused destination with EACCES: urllib and Hermes's keyless web
    tools report "[Errno 13] Permission denied" and nothing else (measured live: Keyless Firecrawl extract)."""
    out = json.dumps({"results": [{"url": "https://www.mozilla.org/", "title": "", "content": "",
                                   "error": "Keyless Firecrawl extract failed: [Errno 13] Permission denied. Set "
                                            "FIRECRAWL_API_KEY (https://firecrawl.dev) for reliable service."}]})
    assert maybe_refused(out)
    hosts, strength = refused_destinations("web_extract", {"urls": ["https://www.mozilla.org/"]}, out)
    assert strength == "strong" and ("www.mozilla.org", 443, SOURCE_TEXT) in hosts
    out = _result("urllib.error.URLError: <urlopen error [Errno 13] Permission denied>", 1)
    hosts, strength = refused_destinations(
        "terminal", {"command": "python3 -c \"import urllib.request as u; u.urlopen('https://pypi.org/simple/')\""}, out)
    assert strength == "strong" and ("pypi.org", 443, SOURCE_TEXT) in hosts


def test_a_file_permission_error_is_not_a_network_refusal():
    for out in (_result("PermissionError: [Errno 13] Permission denied: '/home/u/.ssh/id_ed25519'", 1),
                _result("cat: /etc/shadow: Permission denied", 1)):
        assert refused_destinations("terminal", {"command": "python3 read.py"}, out) == ([], None)


def test_a_network_eacces_names_no_refused_path_even_beside_paths():
    """execute_code printed the sandbox CA variables, then requests failed with EACCES; the JSON result keeps it
    all on one line, and the CA bundle's path became a folder card for /run (measured live on Linux)."""
    ca = r"C:\ProgramData\openshell\ca-bundle.crt" if os.name == "nt" else "/run/openshell-supervisor-ca/material/ca-bundle.crt"
    out = json.dumps({"status": "error", "output": (
        f"{{'SSL_CERT_FILE': '{ca}'}}\nTraceback (most recent call last):\n  File "
        "\"/srv/venv/lib/python3.14/site-packages/urllib3/connection.py\", line 204, in _new_conn\n"
        "PermissionError: [Errno 13] Permission denied\n\nrequests.exceptions.ConnectionError: "
        "HTTPSConnectionPool(host='example.com', port=443): Max retries exceeded with url: / (Caused by "
        "NewConnectionError(\"HTTPSConnection(host='example.com', port=443): Failed to establish a new connection: "
        "[Errno 13] Permission denied\"))")})
    assert refused_paths("execute_code", {"code": "import requests"}, out) == []
    hosts, strength = refused_destinations("execute_code", {"code": "requests.get('https://example.com/')"}, out)
    assert strength == "strong" and ("example.com", 443, SOURCE_REFUSAL) in hosts


def test_a_file_permission_error_in_a_json_result_still_names_its_path():
    path = "C:/Users/u/notes/a.txt" if os.name == "nt" else "/home/u/notes/a.txt"
    out = json.dumps({"status": "error", "output": f"PermissionError: [Errno 13] Permission denied: '{path}'"})
    assert [p for p, _, _ in refused_paths("execute_code", {}, out)] == [Path(path)]
