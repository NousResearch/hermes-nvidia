# Set up Windows

This page lists what a Windows PC needs before the sandbox can run: two checks to make, and the two
programs the plugin installs for you.

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

## Check Smart App Control

The beta needs Smart App Control off or in evaluation mode.
The reason is Hermes itself. Installed from source, it has parts that are not code-signed, with or
without this plugin. Hermes's own issue tracker has reports of Smart App Control blocking each:

| Part of Hermes | Report |
|---|---|
| The Python that Hermes installs for itself | [hermes-agent#148950](https://github.com/NousResearch/hermes-agent/issues/148950) |
| The `hermes.exe` launchers, which Hermes writes on each PC | [hermes-agent#154847](https://github.com/NousResearch/hermes-agent/issues/154847) |
| The desktop app built from source | [hermes-agent#125601](https://github.com/NousResearch/hermes-agent/issues/125601) |

Nobody has run this plugin with Smart App Control on.

Read the state with this command:

```powershell
Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' VerifiedAndReputablePolicyState
```

| Value | State | For the beta |
|---|---|---|
| `0` | Off | Supported |
| `1` | On | Not supported |
| `2` | Evaluation | Supported |

What Microsoft's pages say:

| About | Microsoft says |
|---|---|
| Evaluation mode | Windows blocks nothing in this mode. It ends the mode by itself and turns Smart App Control on or off. ([App & browser control](https://support.microsoft.com/en-us/windows/security/windows-security/app-browser-control-in-the-windows-security-app)) |
| A company-managed PC | Windows switches Smart App Control off within 48 hours, unless the user turned it on first. ([App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)) |
| Turning it on again after Off | The pages disagree: [the FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions) says recent Windows updates allow it, and [the page for developers](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control) calls a switch to Off a one-way operation. |
| A second way to read the state | `citool.exe -lp` lists the policy `VerifiedAndReputableDesktop` when Smart App Control is on and `VerifiedAndReputableDesktopEvaluation` in evaluation mode. ([the same page](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control#verify-smart-app-controls-current-mode)) |

Without administrator rights, `citool.exe -lp` answers "An error occurred: 0x80070005".
The command above needs none.

> [!WARNING]
> Treat a switch to Off as permanent: Microsoft's pages disagree on whether it can be undone.

The sandbox's own programs:

| Program | Code-signed |
|---|---|
| OpenShell's four programs | Yes, by NVIDIA Corporation |
| MXC's `wxc-exec.exe` | Yes, by Microsoft Corporation |
| busybox-w32 (`busybox64u.exe`, on Arm64 `busybox64a.exe`) | No. It is not signed by anyone. The plugin checks it by its pinned sha256 only. |

## MXC and the sandbox's shell

On Windows the sandbox needs two more programs.
The plugin downloads, checks and installs both itself.
You install nothing by hand, and no environment variable is needed.

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

## After an earlier beta that was set up by hand

Testers of the earlier beta set the two user variables themselves.
Those copies stay in use until you remove the variables in Settings > System > About > Advanced
system settings > Environment Variables.

- `sandbox runtime status` shows a variable that is still in use, in `source`.
- A running desktop app and open terminals keep the old values until they are restarted.
- A sandbox that is switched on keeps them until it is switched off and on.

## Remove the Windows prerequisites

When you uninstall the plugin:

1. Run `sandbox gateway remove` and then `sandbox runtime remove`, as
   [Uninstall](install.md#uninstall) shows.
   `runtime remove` removes the two programs together with OpenShell.
2. Delete `C:\var\log\openshell*.log`.
3. Only after an earlier beta that was set up by hand: delete
   `%LOCALAPPDATA%\Programs\mxc-1.0.1` and `%LOCALAPPDATA%\Programs\busybox-w32`, and remove the
   user variables `OPENSHELL_WXC_EXEC_PATH` and `OPENSHELL_BUSYBOX`.
