# Set up Windows

This page lists what a Windows PC needs before the sandbox can run: the Windows version to check,
and the two programs the plugin installs for you.

Run the commands in PowerShell as your normal user. No administrator rights are needed.

## Check the Windows version

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object DisplayVersion, CurrentBuild, UBR
```

| `CurrentBuild` | Windows 11 release | Lowest `UBR` | Update |
|---|---|---|---|
| 26100 | 24H2 | 9550 | KB5124010 (September 2026) |
| 26200 | 25H2 | 9550 | KB5124010 (September 2026) |
| 26300 | 26H2 | 9550 | KB5124010 (September 2026) |
| 28000 | 26H1 | 3086 | KB5124006 (September 2026) |

If `UBR` is lower, install every update in Settings > Windows Update and restart.
Windows 10, Windows 11 releases older than 24H2 and Windows Server are not supported.

## MXC and the sandbox's shell

On Windows the sandbox needs two more programs.
The plugin downloads, checks and installs both itself.

| Program | What it is for | Where it comes from | What is checked |
|---|---|---|---|
| `wxc-exec.exe` | MXC, which starts the sandbox | Microsoft's MXC SDK package 1.0.1 on the npm registry (`registry.npmjs.org`, about 38 MB). Only `wxc-exec.exe` for the PC's architecture is kept. | The package's pinned integrity value, the file's pinned sha256, and a valid signature by Microsoft Corporation |
| `busybox64u.exe` (on Arm64 `busybox64a.exe`) | The sandbox's shell, because Git Bash can't start inside MXC | `frippery.org/files/busybox/` (under 1 MB) | The file's pinned sha256. busybox-w32 is not code-signed. |

Both are installed by the commands you run anyway:

- `hermes -p <profile> sandbox runtime install` installs OpenShell and then the two programs.
  A second run downloads nothing.
- Switching the sandbox on installs whatever is missing, in this order: `wxc-exec`, the shell,
  then OpenShell and its gateway. Before it installs OpenShell, it asks `wxc-exec` about this PC.
  A download that cannot be made stops the switch with its message before anything is started.

Running `runtime install` first shows the result, or the error, in the terminal.
It prints nothing while it downloads.
See [Install](install.md#install-openshell) for what a first switch-on downloads and shows.

If the install of one of the two programs fails, see
[Troubleshooting](troubleshooting.md#the-plugin-could-not-install-wxc-exec-or-the-shell).

## Where the two programs are

Each file sits alone in a folder of the Hermes data folder (`%LOCALAPPDATA%\hermes`).
The folder is named for the pinned build and the PC's architecture.

| Program | x64 | Arm64 |
|---|---|---|
| MXC's `wxc-exec` | `openshell\runtime\programs\mxc-sdk-1.0.1-x64\wxc-exec.exe` | `openshell\runtime\programs\mxc-sdk-1.0.1-arm64\wxc-exec.exe` |
| The sandbox's shell | `openshell\runtime\programs\busybox-w32-FRP-6075-g169694ebd-x64\busybox64u.exe` | `openshell\runtime\programs\busybox-w32-FRP-6075-g169694ebd-arm64\busybox64a.exe` |

- Nothing else of Microsoft's package is written to disk, and the download itself is not kept.
- Of `openshell\runtime` the sandbox can read the shell's folder and one OpenShell program,
  `openshell-windows-sandbox.exe`, which runs inside the sandbox. Nothing else.
- The plugin compares each file with its pinned sha256 again before every use, and installs it
  again if it no longer matches.
- A plugin update that pins another build installs it beside the old one at the next switch-on.
  The old build's folder is removed when the last sandboxed profile is switched off.

## See which files are used

`hermes -p <profile> sandbox check` and `sandbox runtime status` print the same `programs` object.
It has one row for `wxc-exec` and one for `busybox`:

| Field | Meaning |
|---|---|
| `file` | The file the launcher uses now, or `null` when the plugin's copy is missing or no longer matches its pinned sha256 |
| `source` | `pinned install` (the plugin's own copy), `variable OPENSHELL_WXC_EXEC_PATH` or `variable OPENSHELL_BUSYBOX`, `spec` (the profile's saved `--wxc-exec` or `--busybox`), `PATH` (only on a PC the plugin has no pinned build for), or `null` |
| `installed` | Only for `pinned install`: whether the file is there with its pinned sha256 |
| `pinned` | The build the plugin installs: `id`, `version`, `arch`, `file`, `sha256`, `signer` |
| `sha256` | The sha256 of the file in use |
| `is_pinned_build` | Whether the file in use has the pinned sha256 |
| `signature`, `signer` | What Windows says of the file in use: `valid` with the publisher's name, `unsigned`, `invalid` or `not checked` |
| `note` | `not installed yet: ...` when the plugin's copy is missing or no longer matches its pinned sha256. `not found` when there is no file on a PC the plugin has no pinned build for. |
| `ignored` | Named files that were skipped: `source`, `file`, `reason` |

Neither command installs or downloads anything.

> [!NOTE]
> Run `sandbox check` after `sandbox runtime install`, or run it twice.
> Before the install the check has no `wxc-exec` to ask. It then answers from the Windows version
> alone and prints `"probe": "skipped: wxc-exec not found"`.

## Use a copy of your own

`OPENSHELL_WXC_EXEC_PATH` and `OPENSHELL_BUSYBOX` are optional. Leave them unset to use the
plugin's own copies. The launcher takes the first of these that names a file:

1. The profile's saved `hermes sandbox serve --wxc-exec PATH` or `--busybox PATH`.
   The row shows `"source": "spec"`.
2. The variable, set to the full path of a file that exists.
   The row shows `"source": "variable OPENSHELL_WXC_EXEC_PATH"` or `"variable OPENSHELL_BUSYBOX"`.
3. The plugin's own copy.

What to know about a copy of your own:

- The file is used as it is. The installer checks neither its hash nor its signature, and the
  plugin does not install its own copy of that program.
- The launcher still checks a `wxc-exec` of your own before it uses it: it must be MXC 1.0 or
  newer and built for the PC's architecture.
- A variable that names a file that does not exist is skipped. The plugin's own copy is used, and
  the row lists the variable under `ignored`.
- A `wxc-exec` or busybox that merely sits on `PATH` is not used on a PC the plugin has a pinned
  build for.
- A changed variable takes effect in the desktop app and in a terminal after a restart, and in a
  running sandbox after it is switched off and on.

## Remove the Windows prerequisites

When you uninstall the plugin:

1. Run `sandbox gateway remove` and then `sandbox runtime remove`, as
   [Uninstall](install.md#uninstall) shows.
   `runtime remove` removes the two programs together with OpenShell.
2. Delete `C:\var\log\openshell*.log`.
