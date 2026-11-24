# Install, update and uninstall

This page takes you from a computer without the plugin to a profile that is ready to switch on,
and back again.

## The steps

Do these in order. Each one links to its section.

1. [Set up your system](#supported-platforms): the Windows version, or Docker on Linux.
2. [Install Hermes on its main channel](#get-a-hermes-build-with-sandbox-support), with the desktop.
3. [Set up a model and create a profile](#choose-a-profile).
4. [Install the plugin for the profile](#install-the-plugin).
5. [Check the computer](#check-the-computer) and [install OpenShell](#install-openshell).
6. [Turn on the plugin in the desktop](#turn-on-the-plugin-in-the-desktop).
7. [Turn the sandbox on](using.md#turn-the-sandbox-on).

Steps 2 to 5 are typed in a terminal. Steps 6 and 7 are done in the desktop app.

The `hermes` commands on these pages are the same in PowerShell and in a Linux shell.
Commands that differ are shown once for each.

## Supported platforms

| Platform | Tested | Notes |
|---|---|---|
| Windows 11 x64 | Yes | 24H2, 25H2 or 26H2 with the September 2026 update (build 26100, 26200 or 26300 at `.9550` or later), or 26H1 (build 28000 at `.3086` or later). Windows 10 and Windows Server aren't supported. |
| Windows 11 on Arm64 | Not yet run on hardware | Same Windows versions. Every Arm64 program must be the Arm64 build. |
| Linux x86_64 | Yes | Linux 6.2 or newer (Landlock ABI 3), glibc, seccomp user notification, Docker, systemd. Tested on Ubuntu 26.04, and on Ubuntu 24.04 in WSL2. |
| Linux aarch64 | Built, not yet run on hardware | Same as x86_64. |
| macOS | No | Not supported. |

Finish the setup for your system before you go on:

- [Set up Windows](setup-windows.md)
- [Set up Linux](setup-linux.md)

## Get a Hermes build with sandbox support

Until a published Hermes release has the changes the plugin needs, Hermes must be on its `main`
channel. The default channel is `stable`, the latest published release. `main` follows every commit.

### Install Hermes on the main channel

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1))) -Channel main -IncludeDesktop
```

If PowerShell answers `The assignment expression is not valid`, run the installer from a file:

```powershell
irm https://hermes-agent.nousresearch.com/install.ps1 -OutFile "$env:TEMP\hermes-install.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\hermes-install.ps1" -Channel main -IncludeDesktop
```

Linux:

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --channel main --include-desktop
```

Leave out `--include-desktop` on a machine without a desktop session.

### Move an existing install to the main channel

```bash
hermes update --set-channel main
hermes update
hermes desktop
```

- `--set-channel` saves the channel for this install. It does not update.
- The `hermes update` after it moves Hermes to `main`.
- `hermes desktop` builds the desktop app from this install and starts it.

### Check the build

1. Open a new terminal, so that it finds the `hermes` command, and run `hermes --version`.
2. Use the desktop that `hermes desktop` (or `-IncludeDesktop`) builds from this install.
   A Hermes Desktop download from the website or the Microsoft Store does not have the sandbox
   support until a published release includes it.

The installer and `--set-channel` both save the channel.
A later `hermes update` stays on `main`.

If the Sandbox page or `hermes sandbox check` says "Needs a newer version of Hermes.", run
`hermes update`.

## Choose a profile

The switch does not turn on for the default profile yet. Use another profile.

1. On a new Hermes install, set up a model first:

   ```bash
   hermes setup
   ```

2. Create a profile and check that its model answers:

   ```bash
   hermes profile create sbtest --clone
   hermes -p sbtest -z "say hi"
   ```

- `--clone` copies the active profile's model settings and keys.
- Hermes needs a model context of at least 64K tokens.
- The commands on these pages use `sbtest` as the profile's name.

The model can use an API key stored in the profile's `.env`, a provider the profile is signed in
to, or a model server on this computer.
[API keys and providers](credentials.md) lists what works in the sandbox.

## Install the plugin

The plugin is on the `feat/openshell` branch of this repository, in the `openshell` folder.
`--ref` takes a full commit hash, so look up the branch's current commit first.
Without `--ref`, `hermes plugins install` reads the repository's default branch, which does not
hold the plugin yet.

Windows (PowerShell):

```powershell
$ref = (Invoke-RestMethod https://api.github.com/repos/NousResearch/hermes-nvidia/commits/feat/openshell).sha
hermes -p sbtest plugins install NousResearch/hermes-nvidia/openshell --ref $ref --enable
```

Linux:

```bash
ref=$(git ls-remote https://github.com/NousResearch/hermes-nvidia refs/heads/feat/openshell | cut -f1)
hermes -p sbtest plugins install NousResearch/hermes-nvidia/openshell --ref "$ref" --enable
```

The plugin is not in the Hermes catalog, so the command first prints
`Warning: custom (unreviewed) source — not from the Hermes catalog.`
The first install in a new Hermes root takes about a minute, because Hermes sets up its plugin
environment before it installs.

`--enable` turns the plugin on for the profile: it adds `openshell` to `plugins.enabled` in the
profile's `config.yaml`.
The plugin's page in the desktop app is turned on separately, in
[Turn on the plugin in the desktop](#turn-on-the-plugin-in-the-desktop).

## Check the computer

```bash
hermes -p sbtest sandbox check
```

| Field | Meaning |
|---|---|
| `"ok": true` | This computer can run the sandbox. Otherwise `"reason"` is the one reason it can't, and `"action"` says what to do about it. |
| `"ready"` | Whether the switch would turn on for this profile now. |
| `"switch_refused"` | The reason, when `"ready"` is `false`. The exit status is then 2. |

A profile that has no model yet also answers `"ready": true`.
Set up the model before the first chat: see [Choose a profile](#choose-a-profile).

The other fields and exit statuses are in the [command reference](cli.md#check).
What each reason means is in [Troubleshooting](troubleshooting.md#the-switch-does-not-turn-on).

On Windows, run the check again after the next step.
Before `wxc-exec` is installed, the check answers from the Windows version alone.
See [Set up Windows](setup-windows.md#see-which-files-are-used).

## Install OpenShell

Switching the sandbox on installs the pinned OpenShell build too.
Running the install here first shows the result, or the error, in the terminal.
The command prints nothing while it downloads, then one JSON result:

```bash
hermes -p sbtest sandbox runtime install
hermes -p sbtest sandbox runtime status
```

The files are installed in `openshell/runtime/` in the Hermes data folder.
That folder is `%LOCALAPPDATA%\hermes` on Windows and `~/.hermes` on Linux.
The plugin checks every file against the hashes pinned in `runtime/pins.json`.

| | Windows | Linux |
|---|---|---|
| What is installed | The four OpenShell programs from NVIDIA's signed Windows package for the PC's architecture (a download of about 60 MB from the OpenShell v0.1.9 release on GitHub) | The OpenShell v0.1.9 release for your architecture, its two Docker images, the OpenShell Python SDK, and the sandbox's base image, which is built on your computer (a few minutes the first time) |
| `runtime status` shows | `openshell-windows-0.1.9` on x64, `openshell-windows-0.1.9-arm64` on Arm64, with `"signer": "NVIDIA Corporation"` and `"signature": "valid"` | `openshell-v0.1.9` |

What the plugin checks before it accepts a file is in
[Security](security.md#what-is-verified-at-install).

Notes for Windows:

- If you skip this step, the first switch-on downloads about 100 MB in all: OpenShell (about
  60 MB), Microsoft's MXC package (about 38 MB) and the shell (under 1 MB).
  The Sandbox page shows only "Starting sandbox…" meanwhile.
  Running `sandbox runtime install` first moves that wait into the terminal.
- The same command installs MXC's `wxc-exec` and the sandbox's shell.
  See [Set up Windows](setup-windows.md#mxc-and-the-sandboxs-shell).
- The plugin installs the package for the PC's own architecture, also when Hermes runs an
  emulated x64 Python on an Arm64 PC.
- To install from a folder that already holds the four programs, use
  `hermes sandbox runtime install --build-dir <dir>` or set `HERMES_OPENSHELL_BUILD_DIR`.
  The same checks apply.

OpenShell's own usage telemetry is turned off for every OpenShell program the plugin starts.
See [Telemetry](security.md#telemetry).

## Turn on the plugin in the desktop

The Sandbox page belongs to the desktop app. It is turned on once for the app, whichever profile
the window shows.

1. Start the desktop:

   ```bash
   hermes desktop
   ```

2. Go to **Capabilities** > **Plugins**.
3. Type `openshell` in the search box, or choose **Filters** > **Installed**.
4. Open **OpenShell** and turn on **Desktop: OpenShell**.
   **Sandbox** appears in the sidebar.

Then select the profile in the profile rail and turn the sandbox on:
[Use the sandbox](using.md#turn-the-sandbox-on).

## Update

| What | Command |
|---|---|
| Hermes | `hermes update` |
| The plugin | The install command from [Install the plugin](#install-the-plugin), with `--force` added |
| OpenShell | Nothing to run. After a plugin update that changes the pinned build, the new build is installed the next time a sandbox starts. |

When the pinned build changes, the plugin restarts the gateway on the new build once no sandbox
runs on it. Sandboxes that are running keep the build they started with until then.

## Uninstall

1. Switch the sandbox off for every profile that uses it, on the Sandbox page or with
   `hermes -p <profile> sandbox off`.
   When the last one is off, the plugin stops the OpenShell gateway too.
2. Remove the gateway's files and the installed OpenShell:

   ```bash
   hermes -p sbtest sandbox gateway remove
   hermes -p sbtest sandbox runtime remove
   ```

3. Turn off **Desktop: OpenShell** in Capabilities > Plugins.
4. Remove the plugin: `hermes -p <profile> plugins remove openshell`.
5. Optional: delete `openshell/<profile>/` in the Hermes data folder. It holds the saved folders,
   sites and card log. Delete the profile itself with `hermes profile delete sbtest`.
6. Windows: remove what [Set up Windows](setup-windows.md#remove-the-windows-prerequisites) lists.
7. Linux: remove the images if you don't need them. See
   [Set up Linux](setup-linux.md#remove-the-images).
8. Optional: put Hermes back on its `stable` channel with `hermes update --set-channel stable`.
   Later updates then follow published releases.
