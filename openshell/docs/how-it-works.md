# How it works

This page describes the parts of the plugin, what the switch does in which order, and how the
sandbox is kept away from the profile's credentials.

## The parts

| Part | Where it runs | What it does |
|---|---|---|
| Launcher (`hermes sandbox serve`) | On the host, one per sandboxed profile, as a per-user login service | Starts the sandbox, answers the plugin's own routes and the profile's credential writes, raises cards |
| The launcher's proxy | On the host, on a loopback port | Checks a token, then forwards requests to the backend in the sandbox |
| OpenShell gateway | On the host, one for all sandboxed profiles, as a login service | Creates and manages the sandboxes |
| OpenShell's supervisor and proxy | Outside the sandbox | Enforce the policy, put real keys into allowed requests, write the audit records |
| The sandbox | An MXC process container on Windows, a Docker container on Linux | Runs the profile's Hermes backend: chats, tools and terminal |
| The Sandbox page (`desktop/plugin.js`) | In the desktop app | The switch, the settings, the Activity tab |
| Host routes (`dashboard/plugin_api.py`) | In the host's Hermes backend | Answer the Sandbox page for a profile whose sandbox is off |

Because the launcher answers credential writes on the host, the sandbox never holds the profile's
keys or the proxy's token.

## What turning on does

Three things change together: the login service that runs the launcher, Hermes core's
run-elsewhere marker for the profile, and the desktop's route for the profile.
The order makes a half-finished switch fail closed.

1. The host check must pass. See [Troubleshooting](troubleshooting.md#the-switch-does-not-turn-on).
2. The desktop asks you first, so nothing starts before you agreed.
3. The plugin checks the sandbox driver, reviews the last session if it ended without a review,
   saves the settings, copies the profile's keys and model endpoints, records the profile folder,
   and starts the launcher as a login service.
4. The plugin waits until the launcher answers and its sandbox runs.
   A failure up to here undoes step 3. Nothing was marked.
   The Sandbox page asks for the result in short requests while it waits.
   If the page stops asking, the plugin undoes step 3 in the same way.
5. The plugin marks the profile as run elsewhere, last, in the request that tells the page the
   sandbox runs. From then on the host refuses to run it.
6. The desktop routes the profile to the launcher.

## What turning off does

1. The launcher compares the profile folder with the record it took at switch-on.
   While changes need an answer and none was given, nothing stops and nothing changes.
   See [Review changes at switch-off](switching-off.md).
2. The desktop asks you to confirm.
3. The launcher stops the sandbox.
4. The launcher puts back the env files and the sign-in files from its copies, deletes the
   copies, and applies your answer to the review.
5. The launcher removes the login service and clears the marker, last.
6. The desktop routes the profile back to the host.

The sandbox is gone before the marker is, so the host never runs the profile while a sandbox
might. A failure before the marker is cleared leaves the profile marked. A sandbox the gateway
did not delete is such a failure.
`hermes -p <profile> sandbox off` finishes the job from a terminal.

When no launcher answers, that command stops the login service and asks the gateway to delete
the profile's sandbox. It clears the marker only after that sandbox is gone from the gateway.
Another profile's sandbox on the same gateway keeps running.

## The launcher's proxy

- The proxy listens on `127.0.0.1` only.
- It authenticates callers with an outer token. That token never enters the sandbox: the proxy
  strips it from every forwarded header and query string and puts an inner token in its place.
- The inner token, which the sandbox holds, never authenticates at the proxy.
- Each client connection carries one request.
- The plugin's own routes (`/api/plugins/openshell/*`) and the Keys page's writes are answered on
  the host before anything is forwarded.
- The chat socket is relayed frame by frame. Frames from the sandbox that claim to be a launcher
  card are dropped, so the sandbox can neither raise nor answer a card.

## The gateway

All sandboxed profiles of a Hermes installation share one private OpenShell gateway.

- It listens on loopback only.
- It requires mTLS client certificates, which the plugin generates for it.
- It runs as a login service.
- It is removed when the last profile is switched off.

`hermes sandbox gateway status` shows it, and `hermes sandbox gateway remove` removes it.
Its files are in `openshell/runtime/gateway/` in the Hermes data folder:

| Entry | Holds |
|---|---|
| `gateway.json`, `gateway.toml` | The gateway's name, port and configuration |
| `pki/` | The generated certificate authority, server and client certificates |
| `state/`, `data/`, `xdg-config/` | The gateway's own database and settings |
| `cli/`, `cli-state/` | The registration and client certificate the launcher uses |
| `service/` | What the login service runs |
| `logs/`, `ocsf/` | The gateway's log and its audit log |

## The sandbox on each system

| | Windows | Linux |
|---|---|---|
| Isolation | MXC process container, through OpenShell's MXC driver | Docker container, through OpenShell's Docker driver |
| Hermes inside | The host's own Hermes runtime, under read-only grants. No image and no mounts. | The host's own Hermes runtime, mounted read-only into a small base image that is built on your computer |
| The profile folder and your folders | Granted at their real paths | Mounted at their host paths |
| The shell | busybox-w32, because Git Bash can't start inside MXC | The base image's shell |
| How credential files are hidden | MXC denied paths | Empty read-only mounts |
| How the audit is kept | The launcher polls the driver's events | The driver follows the supervisor's records |

## Inside the sandbox

| Piece | File | What it does |
|---|---|---|
| Start-up step | `inside/standin.py` | Writes the stand-in sign-in files before Hermes starts. See [Provider sign-ins](sign-ins.md). |
| Tool-result hook | `sandbox_hook.py` | When a tool result shows a refusal, tells the launcher and waits for your answer to the card, so the card resolves in the same turn |
| Terminal backend (Windows) | `busybox_env.py` | Runs the terminal and file tools on busybox-w32 |
| Loopback names (Windows) | `loopback_env.py` | Lists `127.0.0.1`, `localhost` and `::1` in `NO_PROXY` |

What differs for programs that run inside is in
[Programs inside the sandbox](inside-the-sandbox.md).

## How credential files are hidden

The profile's credential files stay hidden from the sandbox, whether or not they exist yet.
The sign-in files `auth.json` and `.anthropic_oauth.json` are hidden the same way, unless the
profile is signed in to a provider the sandbox can use. See [Provider sign-ins](sign-ins.md).

### On Windows

- The launcher lists the files as MXC denied paths (`driver_config.mxc.denied_paths`).
- Every hidden path sits directly under a folder the sandbox cannot rename.
- The launcher refuses to start while a credential file exists below a folder the sandbox writes,
  because renaming that folder would expose the file.
- When Hermes keeps its secret-manager caches at the top of the profile folder, the launcher
  deletes copies of them left in the profile's `cache` and `runtime` folders before the sandbox
  starts.

### On Linux

- The launcher covers each existing credential folder with an empty read-only mount.
- Credential files at the top of the profile folder are kept in one folder there,
  `.openshell-held`, while the sandbox runs. That folder is covered the same way, and a link
  stands under each file's name.
- `.env` and `.op.env` get the link even when they don't exist yet. So does `auth.json`, unless it
  holds a stand-in.
- Hermes's own writers follow the link. A key saved, a sign-in or a token refresh on this computer
  is written inside that folder and never under a name the sandbox can read.
- The files are moved back when the sandbox stops.
- A store the sandbox creates, or anything it puts where one of those links was, is moved out of
  the profile.

### A copy that appears while the sandbox is on

What a sandbox may not read is fixed when it starts.
The launcher therefore looks at the top of the profile folder about once a second.

When a copy of a credential file appears there while the sandbox is on (for example
`.env.bak-<stamp>`), the launcher restarts the sandbox, so that the sandbox cannot read the copy.
The page then says "Restarting the sandbox to hide" and the file's name.

## Host-only state

The Hermes data folder is `%LOCALAPPDATA%\hermes` on Windows and `~/.hermes` on Linux.
No sandbox is given these folders, with one exception: a Windows sandbox may read the folder
that holds its shell.

| Folder in the Hermes data folder | Holds |
|---|---|
| `openshell/<profile>/` | The launcher's state for one profile: the saved folders and sites (`spec.yaml`), the token, the card log, the logs |
| `openshell/<profile>/pins` | The launcher's copies of keys, sign-ins, secret sources and model endpoints |
| `openshell/<profile>/handback` | The record for the review at switch-off |
| `openshell/<profile>/quarantine` | Files the launcher took out of the profile folder |
| `openshell/<profile>/audit` | The audit log |
| `openshell/runtime/` | The installed OpenShell and the gateway. On Windows also `programs/`, with MXC's `wxc-exec` and the sandbox's shell, each alone in a folder. |
