# Command reference

This page lists every `hermes sandbox` command with its flags, its output and its exit status.

## Synopsis

```text
hermes [-p NAME] sandbox serve [--port N] [--folder PATH[:ro|rw]]... [--wxc-exec PATH] [--busybox PATH]
                               [--openshell-gateway NAME] [--openshell-image REF] [--egress deny|allow]
                               [--rotate-token] [--service] [--revert | --keep] [--move-keys]
hermes [-p NAME] sandbox on [--revert | --keep] [--move-keys]
hermes [-p NAME] sandbox off [--revert | --keep]
hermes [-p NAME] sandbox handback [--json]
hermes [-p NAME] sandbox status | check | policy | stop
hermes [-p NAME] sandbox requests [--status pending|approved|rejected|all]
hermes [-p NAME] sandbox approve ID
hermes [-p NAME] sandbox reject ID --reason TEXT
hermes [-p NAME] sandbox revisions
hermes [-p NAME] sandbox rollback VERSION
hermes [-p NAME] sandbox events [--since UNIX] [--class NET,HTTP,...] [--limit N]
hermes sandbox gateway status | ensure | remove [--force]
hermes sandbox runtime status | install [--build-dir DIR] | remove
```

- `-p NAME` names the profile. Without it, a command acts on the active profile.
- The commands print JSON on stdout unless a section says otherwise.
- A failure prints `hermes sandbox: <reason>` on stderr.
- A profile named `runtime` can't be sandboxed: `openshell/runtime` in the Hermes data folder
  holds the installed OpenShell.

## Exit statuses

| Status | Meaning |
|---|---|
| 0 | The command did what it was asked. |
| 1 | The command failed. For `check`: this computer cannot run the sandbox. |
| 2 | For `check`: the computer can run the sandbox, but the switch is refused for this profile. Also the status of a missing or unknown subcommand. |
| 3 | For `on`, `off` and `serve`: changes need an answer, and nothing was changed. Run the command again with `--revert` or `--keep`. |
| 130 | For `serve`: interrupted from the keyboard. |

## on

Turns the sandbox on: starts the launcher as a login service and marks the profile as run
elsewhere.

| Flag | Meaning |
|---|---|
| `--revert` | Put back what the last sandbox session changed among the settings and files that run on this computer |
| `--keep` | Keep those changes |
| `--move-keys` | First move keys written in `config.yaml` to `.env` |

| Output field | Meaning |
|---|---|
| `profile` | The profile's name |
| `url` | The launcher's address, `http://127.0.0.1:<port>` |
| `service` | The login service that runs the launcher |
| `token_file` | The file that holds the launcher's token. The token itself is never printed. |
| `state` | The sandbox's state |
| `handback` | What a review did, when one ran |

On stderr, `on` also says what it moved (`Moved to .env: ...`), what a review kept or reverted,
and one line when the profile's model has no key.

With exit status 3, `on` prints the list "Changed in the sandbox" first.
See [Review changes at switch-off](switching-off.md#a-session-that-ended-without-a-review).

## off

Turns the sandbox off: stops the launcher and its sandbox, removes its login service and unmarks
the profile.

When no launcher answers, `off` stops the login service and asks the gateway to delete the
profile's sandbox. It unmarks the profile only after that sandbox is gone from the gateway.

Until then `off` exits with status 1 and prints "The sandbox couldn't be stopped (...). It stays
switched on."
See [The sandbox couldn't be stopped](troubleshooting.md#the-sandbox-couldnt-be-stopped).

| Flag | Meaning |
|---|---|
| `--revert` | Put back what the sandbox changed among the settings and files that run on this computer |
| `--keep` | Keep those changes |

| Output field | Meaning |
|---|---|
| `stopped` | `launcher` when a running launcher did the work, `service` when the command stopped and removed the service itself |
| `state` | `off` |
| `marker_cleared` | Whether the run-elsewhere marker was cleared |
| `handback` | What the review did: `reverted`, `kept`, `held`, or `error` when the review could not run |

`off` waits for a running launcher to finish. With exit status 3 it prints the list first.

## handback

Lists what the sandbox changed among the settings and files that run on this computer.

| Flag | Meaning |
|---|---|
| `--json` | Print the list as JSON |

Without `--json` the command prints text:

| Line | Meaning |
|---|---|
| `Changed in the sandbox (profile NAME)` | Heading of the numbered rows: label, name, detail |
| `Always reverted` | Heading of the rows that are put back whatever you answer |
| `Also changed: ...` | Counts of changed skills, memories, `SOUL.md` and other settings |
| `Not fully checked: ...` | Folders the comparison could not walk completely |
| `Kept from the sandbox: N items` | Changes you kept earlier that are still in the profile |
| `No sandbox changes to review for profile 'NAME'.` | Nothing to answer |

## status

Shows the running sandbox's state. It fails with status 1 when no sandbox runs for the profile.

| Output field | Meaning |
|---|---|
| `profile`, `sandboxed`, `driver`, `url`, `started_at` | Which sandbox this is |
| `state` | `starting`, `running`, `restarting`, `stopping`, `stopped` or `failed` |
| `error` | The last error, when there is one |
| `applied` | What the running sandbox got |
| `saved` | The saved settings, which the next start uses |
| `temporary` | What was allowed until the sandbox is switched off |
| `pending`, `restart_required`, `restart_queued` | Changes that wait for a restart, and whether the launcher restarts by itself |
| `builtin` | What the launcher keeps open by itself |
| `opened` | Every address a sign-in or a key is used at |
| `endpoint_changed` | Keys withheld because a model's endpoint was changed inside the sandbox |
| `pinned` | `false` when the launcher holds no copies of the profile's keys and model endpoints; turn the sandbox off and on |
| `handback` | Whether a record was taken at switch-on, and how many kept changes are still in the profile |
| `providers` | The profile's providers and whether each works in the sandbox |
| `capabilities`, `restarting`, `restart`, `switching_off` | Details the Sandbox page reads |

While kept changes are still in the profile, `status` also prints one line on stderr:
`Kept from the sandbox: N items. Run ... sandbox handback to list them.`

## check

Checks whether this computer can run the sandbox, and whether this profile's switch would turn
on. The check reads and probes only. It installs and starts nothing.

| Output field | Meaning |
|---|---|
| `ok` | This computer can run the sandbox |
| `ready` | This profile's switch would turn on now. Always `true` while its sandbox is on. |
| `switch_refused` | The reason, when the switch is refused. Also printed on stderr. |
| `note` | What to know about a switch-on that goes ahead, for example a model without a key |
| `platform` | `windows`, `linux` or `macos` |
| `code`, `reason`, `action` | Why the computer cannot run the sandbox, in one line, and what to do |
| `detail`, `facts` | Technical detail: the Windows build, the probe's answer, the kernel, Docker |
| `checked_at` | When the check ran |
| `providers` | The profile's providers: `id`, `label`, `kind`, `state`, `detail`, `main` |
| `providers_error` | Why the providers could not be read |
| `programs` | Windows only: the `wxc-exec` and the shell the launcher uses. See [Set up Windows](setup-windows.md#see-which-files-are-used). |

The exit status is 0 when ready, 1 when this computer cannot run the sandbox, and 2 when it can
but the switch is refused for this profile.

## serve

Starts the sandboxed backend and its proxy in the foreground.
`on` runs the same command as a login service, with `--service`.

Once the sandboxed backend answers, `serve` prints two lines:

```text
HERMES_SANDBOX_READY port=N profile=NAME
Sandboxed backend for profile 'NAME' at http://127.0.0.1:N (driver openshell); token file: PATH
```

Point a client at `http://127.0.0.1:N` with the token stored in the file `serve` names.

| Flag | Meaning |
|---|---|
| `--port N` | Fixed outer loopback port. Without it, `serve` picks a free port the first time. |
| `--folder PATH[:ro\|rw]` | A folder the sandbox may use, read-only or read & write. Repeat it for more folders. It replaces the saved list. |
| `--wxc-exec PATH` | Windows: the `wxc-exec.exe` (MXC 1.0 or newer) to check the host's MXC with |
| `--busybox PATH` | busybox-w32 for the sandbox's shell |
| `--openshell-gateway NAME` | A registered OpenShell gateway (mTLS) to run the sandbox on. Without it, `serve` uses the plugin's private gateway. |
| `--openshell-image REF` | Hermes image for the OpenShell sandbox |
| `--egress deny\|allow` | Internet access from the sandbox. `allow` is refused and nothing is saved: OpenShell has no rule for all internet access. |
| `--rotate-token` | Mint a new outer token |
| `--service` | Run as the profile's login service. It exits at once if the switch is off. |
| `--revert`, `--keep` | Answer the review of the last sandbox session |
| `--move-keys` | First move keys written in `config.yaml` to `.env` |

- Flags marked "saved" in `serve --help` are stored in the profile's host-only settings once the
  sandbox driver accepts them. That covers every flag above except `--rotate-token`, `--service`,
  `--revert`, `--keep` and `--move-keys`.
- On a profile's first `serve` without `--folder`, the command creates a folder named `Hermes` in
  your home folder and gives the sandbox read & write access to it.
- A foreground `serve` is the only way to sandbox the default profile. It does not mark the
  profile as run elsewhere.

## policy and stop

| Command | What it does |
|---|---|
| `policy` | Prints the policy handed to the sandbox driver: `driver`, `grants`, `enforced` |
| `stop` | Stops the sandbox and its proxy |

## requests, approve and reject

These commands need a running sandbox.

| Command | What it does |
|---|---|
| `requests [--status pending\|approved\|rejected\|all]` | Lists network requests the sandbox blocked. The default is `pending`. |
| `approve ID` | Allows a blocked request. It applies live. |
| `reject ID --reason TEXT` | Refuses a blocked request. The agent sees the reason. `--reason` is required. |

## revisions, rollback and events

These commands need a running sandbox.

| Command | What it does |
|---|---|
| `revisions` | Lists the enforcer's policy revisions |
| `rollback VERSION` | Restores an earlier policy revision, as a new revision |
| `events [--since UNIX] [--class NET,HTTP,CONFIG,...] [--limit N]` | Prints recent audit events (OCSF) from the enforcer. `--since` is in Unix seconds. `--limit` defaults to 100. |

## gateway

Manages this Hermes installation's private OpenShell gateway, which all sandboxed profiles share.

| Command | What it does |
|---|---|
| `gateway status` | Shows the gateway and the installed OpenShell |
| `gateway ensure` | Runs the profile's driver checks, then installs and starts the gateway. It refuses for a profile whose settings name a gateway of its own. |
| `gateway remove [--force]` | Removes the gateway. It refuses while a profile is switched on, unless `--force` is given. |

| `gateway status` field | Meaning |
|---|---|
| `root` | The Hermes data folder |
| `runtime` | The installed OpenShell: `id`, `version`, `platform`, `arch`, `source`, `signer`, `signature` |
| `pinned` | The id of the OpenShell build the plugin pins |
| `profiles_in_use` | The profiles that are switched on |
| `base_image` | Linux: the sandbox's base image that was built |
| `gateway` | `name`, `port`, `kind`, `runtime_id`, `service`, `service_state`, `healthy`, `detail`, `dir`, `openshell_telemetry`, and `sandboxes` when the gateway answers |

`"openshell_telemetry": "off"` confirms that OpenShell's usage telemetry is off.
See [Telemetry](security.md#telemetry).

## runtime

Manages the installed OpenShell programs.

| Command | What it does |
|---|---|
| `runtime status` | Shows `installed` (what is installed), `pinned` (`id`, `version`, `arch`, `source`, `signer`) and `dir`. On Windows also `programs`. |
| `runtime install [--build-dir DIR]` | Installs the pinned OpenShell and checks it. On Windows it then installs MXC's `wxc-exec` and the sandbox's shell, and prints `programs`. `--build-dir` (Windows) names a folder that already holds the pinned OpenShell files; without it the pinned package is downloaded. |
| `runtime remove` | Removes the installed OpenShell, and on Windows the two programs with it. It refuses while the gateway is still installed: run `gateway remove` first. |

`programs` is described in [Set up Windows](setup-windows.md#see-which-files-are-used).

## Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `OPENSHELL_WXC_EXEC_PATH` | The launcher, on Windows | Optional: a `wxc-exec.exe` of your own, used in place of the plugin's copy when the profile's settings name none |
| `OPENSHELL_BUSYBOX` | The launcher, on Windows | Optional: a busybox-w32 of your own, used in place of the plugin's copy when the profile's settings name none |
| `HERMES_OPENSHELL_BUILD_DIR` | `runtime install`, on Windows | A folder that already holds the pinned OpenShell programs |
