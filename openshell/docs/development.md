# Development

This page is for people who change the plugin: where the code is, how to run the tests, and how
the pinned OpenShell builds are changed.

## Code layout

| Path | What it holds |
|---|---|
| `plugin.yaml`, `__init__.py` | The plugin's manifest and its entry point |
| `launcher_cli.py` | The `hermes sandbox` commands |
| `launcher/` | The host launcher: the switch, the proxy, the drivers, the gateway, cards, keys and sign-ins, the review at switch-off, the activity log |
| `sandbox_hook.py`, `inside/` | What runs inside the sandbox: the tool-result hook and the start-up step |
| `busybox_env.py`, `loopback_env.py` | Windows only: the busybox terminal backend and the loopback names |
| `desktop/plugin.js` | The desktop half: the Sandbox page |
| `dashboard/` | The routes the host backend answers for a profile whose sandbox is off |
| `runtime/pins.json` | The OpenShell builds the plugin installs, with their hashes |
| `runtime/Containerfile` | The Linux sandbox's base image |
| `tests/` | The test suite |
| `docs/` | These pages |

The modules of `launcher/` explain themselves in their docstrings. A few to start with:

| Module | Topic |
|---|---|
| `launcher/switch.py` | The order of a switch-on and a switch-off |
| `launcher/layout.py` | What the sandbox may touch, and where the launcher keeps its state |
| `launcher/openshell_windows.py`, `launcher/openshell_driver.py` | The Windows and the Linux driver |
| `launcher/cards.py` | Cards, and how an answer is applied |
| `launcher/pins.py`, `launcher/signins.py` | The launcher's copies of keys and sign-ins |
| `launcher/handback.py` | The review at switch-off |
| `launcher/compat.py` | The host check |
| `launcher/openshell_install.py` | Installing and verifying OpenShell |

## Run the tests

Run the suite from the repository root with the Python environment of a Hermes checkout.

Linux:

```bash
PYTHONPATH="<hermes checkout>:<this repository>" <hermes python> -m pytest openshell/tests -q -p no:cacheprovider
```

Windows (PowerShell):

```powershell
$env:PYTHONPATH = "<hermes checkout>;<this repository>"
& "<hermes python>" -m pytest openshell/tests -q -p no:cacheprovider
```

What the suite does for you:

- `tests/conftest.py` points `HERMES_HOME` at a temporary folder before any test imports Hermes.
  It refuses to run if Hermes still resolves to another root, so the tests never touch your own
  profiles.
- The tests fake OpenShell, MXC, Docker and the operating system's service managers.

A few tests run against real tools when they are present, and skip otherwise:

| Tool | Where | What the test covers |
|---|---|---|
| `OPENSHELL_BUSYBOX`, or busybox-w32 on `PATH` | Windows | The busybox terminal backend |
| `OPENSHELL_WXC_EXEC_PATH` | Windows | The launcher's MXC check (`--probe` and a `--dry-run`, no container) against a real `wxc-exec` |
| `curl.exe` in `System32` | Windows | curl reads the config file the launcher writes (a local file, no network) |
| `node` on `PATH` | Any | The Sandbox page's switch logic in `tests/js/switch_harness.mjs` |

## Change a pin

`runtime/pins.json` names what the plugin installs and runs.
Each field is explained by a comment key beside it (`_comment`, `_version`, `_features`, ...).

> [!WARNING]
> Changing an `id` makes every Hermes installation upgrade its OpenShell and restart its gateway,
> once no sandbox runs on it. Edit the file only with fresh verification evidence.

| Block | What it pins |
|---|---|
| `linux` | The OpenShell v0.1.9 release: its four checksum files by sha256, the asset names per architecture, the Python SDK and its dependencies by sha256, and the two Docker images by digest |
| `windows` | NVIDIA's signed Windows package from the OpenShell v0.1.9 release: the zip and each of the four programs by sha256, the publisher (`signer`), and the `features` the build has. The `aarch64` block inside it is the Arm64 package. |
| `windows_previous` | The pin of the package before it, from the v0.1.8 release. Nothing reads it unless it is put back under the name `windows`. |
| `windows_programs` | Windows only: MXC's `wxc-exec` (the npm package by its integrity value, the file for each architecture by sha256, and its publisher) and the sandbox's shell, busybox-w32 (the file for each architecture by its address and sha256) |
| `base_image` | The Linux base image's repository name and its base, by digest |

Facts about the Windows package that the pin records:

- The plugin reads what the Windows build can do from the pin's `features` list, never from the
  version number.
- The programs carry the C runtime and Z3 inside them, so the package needs no Microsoft Visual
  C++ Redistributable.
- The release is at `github.com/ai-openshell/openshell`.

When a pin's version changes, update the versions these pages name: [Install](install.md),
[Set up Windows](setup-windows.md) and this page.

## What the plugin needs from Hermes

The plugin needs Hermes core and desktop support for a profile that runs elsewhere:

| Needed | Where |
|---|---|
| The run-elsewhere marker (`hermes_cli.profiles_run_elsewhere`) | Hermes core |
| The per-profile backend override (`host.setProfileBackend` and `host.clearProfileBackend`) | The desktop app |
| The `access` and `network` kinds on approval cards | The desktop app |
| On Linux: `security.fake_ip_ranges` and `terminal.env_passthrough` read from the managed scope | Hermes core. See [Programs inside the sandbox](inside-the-sandbox.md#linux-web-tools-and-execute_code). |
| On Windows: `HERMES_INSTALL_STATE_DIR`, which names the folder Hermes in the sandbox keeps its install state in | Hermes core |

How to get a Hermes build that has them is in
[Install](install.md#get-a-hermes-build-with-sandbox-support).
