"""What ``openshell sandbox provider status <sandbox> <provider> -o json`` prints, for the tests of the Windows
driver: the output of the 0.1.8 Windows package for a provider the sandbox has installed, with the names, ids and
times replaced by made-up ones of the same form. The state is under ``targets``, never at the top level."""
import json

READY_OUTPUT = """{
  "mutation_id": "00000007-aaaa-4aaa-8aaa-000000000007",
  "targets": [
    {
      "receipt": {
        "receipt_id": "00000004-aaaa-4aaa-8aaa-000000000004",
        "mutation_id": "00000007-aaaa-4aaa-8aaa-000000000007",
        "provider": "hermes-work-model-key-70bb24d9",
        "workspace": "default",
        "kind": "observe",
        "desired": {
          "sandbox_id": "00000005-aaaa-4aaa-8aaa-000000000005",
          "sandbox": "hermes-work",
          "attachment_epoch": "00000008-aaaa-4aaa-8aaa-000000000008",
          "provider_id": "00000003-aaaa-4aaa-8aaa-000000000003",
          "provider_resource_version": "1",
          "provider_env_revision": "51108027429830355",
          "config_revision": "10184604424732175967",
          "policy_hash": "abababababababababababababababababababababababababababababababab"
        },
        "persisted_time": "2025-01-02T02:12:11.713282500Z"
      },
      "state": "ready",
      "reason": "unspecified",
      "observed": {
        "session_id": "00000006-aaaa-4aaa-8aaa-000000000006",
        "sequence": "9",
        "attachment_epoch": "00000008-aaaa-4aaa-8aaa-000000000008",
        "provider_env_revision": "51108027429830355",
        "config_revision": "10184604424732175967",
        "policy_hash": "abababababababababababababababababababababababababababababababab",
        "credentials_installed": true,
        "policy_active": true,
        "launch_environment_installed": true,
        "process_instance_id": "00000002-aaaa-4aaa-8aaa-000000000002",
        "reason": "unspecified"
      },
      "network_instance_id": "00000001-aaaa-4aaa-8aaa-000000000001",
      "observed_time": "2025-01-02T02:12:10.536147500Z",
      "evaluated_time": "2025-01-02T02:12:11.717247700Z",
      "wait_outcome": "not_requested"
    }
  ]
}
"""


def status_output(sandbox: str, provider: str, state: str = "ready", reason: str = "unspecified") -> str:
    """The same output for another sandbox, provider, state and reason, printed the way the CLI prints it. A
    target that is not installed yet carries no observation."""
    doc = json.loads(READY_OUTPUT)
    target = doc["targets"][0]
    target["receipt"]["provider"] = provider
    target["receipt"]["desired"]["sandbox"] = sandbox
    target["state"], target["reason"] = state.lower(), reason.lower()
    if state.lower() != "ready":
        target["observed"] = None
        target["observed_time"] = None
    return json.dumps(doc, indent=2) + "\n"
