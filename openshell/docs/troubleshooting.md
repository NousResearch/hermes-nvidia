# Troubleshooting

This page helps when the switch does not turn on or the sandbox stops answering, and shows where
the logs are and how to report a problem.

## The switch does not turn on

The Sandbox page says why, with **Check again**.
`hermes -p <profile> sandbox check` prints the same reason in `"reason"` and what to do in
`"action"`.

### Reasons on Windows

| The page says | What to do |
|---|---|
| "Not supported on Windows Server." | Use Windows 11 |
| "Needs Windows 11." | Use Windows 11 |
| "Needs a 64-bit PC (x64 or Arm)." | Use a 64-bit PC |
| "Needs Windows 11 24H2 or newer. This PC has ..." | Update in Settings > Windows Update, then check again |
| "Needs the September 2026 Windows update. This PC has ..." | Install it in Settings > Windows Update, then check again |
| "Couldn't read this PC's Windows version." | Check again |
| "wxc-exec is the x64 build. This PC needs the Arm64 one." (or the reverse) | This concerns a `wxc-exec.exe` of your own. Use the one for the PC's architecture from the MXC package, or remove `OPENSHELL_WXC_EXEC_PATH` to use the plugin's copy, then check again. |
| "Couldn't check process isolation on this PC." | Check again |
| "Process isolation isn't available on this PC." | Install the latest updates in Settings > Windows Update and restart, then check again |
| "Process isolation is turned off on this PC." | Install the latest updates in Settings > Windows Update and restart, then check again |

### Reasons on Linux

| The page says | What to do |
|---|---|
| "Needs a 64-bit x86 or Arm computer." | Use an x86_64 or aarch64 computer |
| "Needs a Linux distribution with glibc." | Use a distribution with glibc |
| "Needs Linux 6.2 or newer. This computer has Linux ..." | Update the kernel, then check again |
| "Landlock is turned off in this Linux kernel." | Add `landlock` to the kernel's `lsm=` boot option, restart, then check again |
| "Landlock is blocked here." | Run Hermes directly on this computer, not inside a container |
| "This Linux kernel has no Landlock." | Use a kernel built with Landlock (`CONFIG_SECURITY_LANDLOCK`), then check again |
| "This Linux kernel can't hand system calls to the sandbox's broker." | Use a kernel with seccomp user notification (`CONFIG_SECCOMP_FILTER`), then check again |
| "Needs Docker." | Install Docker Engine, then check again |
| "This user can't use Docker." | Add this user to the `docker` group, sign in again, then check again |
| "Docker isn't running." | Start Docker, then check again |

### The sandbox did not start

| The page says | What to do |
|---|---|
| "The sandbox didn't start within 240 seconds." | Turn the switch on again. On Windows, run `hermes -p <profile> sandbox runtime install` first if the sandbox's programs are not installed yet |
| "The sandbox didn't finish starting. Turn it on again." | Turn the switch on again. Hermes was restarted while the sandbox was starting |

In both cases the plugin has stopped the launcher and removed the login service, and the profile
runs on the host.

### Other reasons

| The page says | What to do |
|---|---|
| "Not supported on macOS yet." | Use Windows 11 or Linux |
| "Not available for the default profile yet." | Use another profile |
| "Needs a newer version of Hermes." or "Needs a newer version of the desktop app." | [Get a Hermes build with sandbox support](install.md#get-a-hermes-build-with-sandbox-support) |
| "Couldn't check this computer." | Check again |
| A reason about a key, a provider, a sign-in or a file that can't be read | See [What keeps the switch off](credentials.md#what-keeps-the-switch-off) |

## The plugin could not install wxc-exec or the shell

On Windows the plugin installs MXC's `wxc-exec.exe` and the sandbox's shell itself
(see [Set up Windows](setup-windows.md#mxc-and-the-sandboxs-shell)).
When that fails, the message shows in one of three places:

- `sandbox runtime install` prints `hermes sandbox: <message>` and exits with status 1.
- A switch-on shows the message as the reason the switch did not turn on, for either program.
  On the Sandbox page it is a notice that stays until you close it, also after a later switch-on
  worked.
- A later sandbox start that finds the shell gone and cannot install it again shows the message
  as the sandbox's start error.

| The message says | When | What to do |
|---|---|---|
| "... is not installed and could not be downloaded: could not download ..." | The PC cannot reach `registry.npmjs.org` (for `wxc-exec.exe`) or `frippery.org` (for the shell) | Check the connection, proxy or firewall and run the command again. Or set `OPENSHELL_WXC_EXEC_PATH` or `OPENSHELL_BUSYBOX` to a copy you already have. |
| "... does not match its pinned integrity ...; refused" or "... has sha256 ..., pinned ...; refused" | The file that arrived is not the pinned one, for example behind a proxy that rewrites downloads or a network's sign-in page | Try again on another network. If it repeats, report it with the two values. |
| "the downloaded MXC package is not a readable .tgz file ...; refused" | A damaged download | Run the command again |
| "... is not signed ...", "Windows does not accept the signature on wxc-exec.exe ...", "... is signed by '...', not by Microsoft Corporation. Refused." | The signature on `wxc-exec.exe` is missing, not accepted on this PC, or another publisher's | Report it, with the message |
| "... has no build for Windows on ...; this version of the plugin supports x64, Arm64 Windows PCs" | A PC that is neither x64 nor Arm64 | Not supported |
| "could not put ... in place at ...; if a sandbox is running, switch it off and try again" | The folder could not be replaced, usually because the old file is in use | Switch every sandbox off, then run the command again |
| "... changed while it was installed; refused" | The file changed between the check and the install | Run the command again. If it repeats, look for a program that rewrites files in the Hermes data folder. |
| "the MXC package has ...; refused", "... is built for ..., but this PC is ...; refused", "... is not a Windows program; refused" | The package or file is not laid out as the pinned one. This cannot happen with the pinned package. | Report it |
| "this version of the plugin pins no wxc-exec for Windows" (or `busybox`), "the pin of ... must name ..." | The plugin's `runtime/pins.json` is damaged | Reinstall the plugin: run its install command with `--force` |
| "busybox not found at ..." | The profile's saved `--busybox` names a file that is gone | Give `sandbox serve` a `--busybox` that exists, or remove `busybox:` from `openshell\<profile>\spec.yaml` |

When Windows cannot run the signature check at all, the install continues on the pinned sha256
checksums and writes one line to the launcher's log. That is the rule for OpenShell's own programs
too.

## The sandbox isn't answering

If the launcher stops by itself, the profile stays switched on for the sandbox.
Hermes does not run the profile on this computer either.
The Sandbox page says "The sandbox isn't answering." and cannot turn such a sandbox off.

1. Run `hermes -p <profile> sandbox off` in a terminal.
2. Press **Switch back** on the page.

## The sandbox's gateway stopped

If the OpenShell gateway's process ends while the sandbox is on, the plugin starts the gateway and
the sandbox again, once.

- Meanwhile the page says "Restarting the sandbox after its gateway stopped".
- A reply that was streaming is cut and is not continued. Send the message again.

If the gateway stops again within ten minutes, the sandbox stays stopped.
The page then says "The sandbox's gateway stopped. Turn the sandbox off, then on again."
`hermes -p <profile> sandbox status` prints the same sentence.

## Find the logs

The Hermes data folder is `%LOCALAPPDATA%\hermes` on Windows and `~/.hermes` on Linux.
Inside it:

| What | Where |
|---|---|
| The profile's launcher, sandbox start and card log | `openshell/<profile>/launcher.log`, `serve.log`, `serve.log.1`, `cards.jsonl` |
| The OpenShell gateway's log and audit log | `openshell/runtime/gateway/logs/`, `openshell/runtime/gateway/ocsf/` |
| The sandboxed backend's log (and launcher warnings) | `profiles/<profile>/logs/agent.log`, `errors.log` |
| The desktop | `logs/desktop.log`, `logs/gateway.log` |
| Windows only: the OpenShell host supervisor | `C:\var\log\openshell*.log` |
| Linux only: the services | `journalctl --user -u 'hermes-*' --since today` |

> [!NOTE]
> Collect the logs before you switch the sandbox off.
> Switching off removes the sandbox and some of its logs.

## Collect the logs

These blocks copy the logs that are safe to share into one archive.
Set the profile's name in the first line.

Windows (PowerShell):

```powershell
$h = "$env:LOCALAPPDATA\hermes"; $p = 'sbtest'; $out = "$env:USERPROFILE\Desktop\openshell-beta-logs"
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item "$h\openshell\$p\*.log*", "$h\openshell\$p\cards.jsonl" $out -ErrorAction SilentlyContinue
Copy-Item -Recurse "$h\openshell\runtime\gateway\logs", "$h\openshell\runtime\gateway\ocsf" $out -ErrorAction SilentlyContinue
Copy-Item "$h\profiles\$p\logs\agent.log*", "$h\profiles\$p\logs\errors.log*", "$h\logs\desktop.log*", "$h\logs\gateway.log*" $out -ErrorAction SilentlyContinue
Copy-Item 'C:\var\log\openshell*.log' $out -ErrorAction SilentlyContinue
Compress-Archive -Force "$out\*" "$out.zip"
```

Linux:

```bash
h=~/.hermes; p=sbtest; out=~/openshell-beta-logs; mkdir -p "$out"
cp "$h/openshell/$p/"*.log* "$h/openshell/$p/cards.jsonl" "$out/" 2>/dev/null
cp -r "$h/openshell/runtime/gateway/logs" "$h/openshell/runtime/gateway/ocsf" "$out/" 2>/dev/null
cp "$h/profiles/$p/logs/"{agent,errors}.log* "$h/logs/"{desktop,gateway}.log* "$out/" 2>/dev/null
journalctl --user -u 'hermes-*' --since today --no-pager > "$out/journal.txt"
tar -czf "$out.tar.gz" -C "$out" .
```

> [!WARNING]
> Never attach `.env`, `auth.json`, `gateway-connection-tokens.json`, `openshell/<profile>/token`,
> or the gateway's `pki`, `cli`, `cli-state`, `state`, `data` and `xdg-config` folders.
> They hold your keys and the sandbox's certificates.

Logs can contain your prompts, file names and site names. Read them before you send them.

## Report a problem

Report through the channel you got this beta from, or open an issue in this repository.
Include:

- what you did, what you expected, what happened, and the time it happened;
- a screenshot of the chat or the Sandbox page, if the problem shows there;
- the output of `hermes --version`;
- the output of these four commands:

  ```bash
  hermes -p sbtest sandbox check
  hermes -p sbtest sandbox status
  hermes -p sbtest sandbox runtime status
  hermes -p sbtest sandbox gateway status
  ```

- the logs, collected as shown above.

Check [Known issues](known-issues.md) first: the problem may be listed there.
