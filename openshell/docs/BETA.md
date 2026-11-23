# OpenShell sandbox beta: tester guide

This guide is for people testing the openshell plugin before its Hermes support is released. The plugin runs one Hermes profile's backend inside an [NVIDIA OpenShell](https://github.com/ai-openshell/openshell) sandbox: the profile's chats, tools and terminal run in the sandbox, and the sandbox reaches only the folders and websites you allow. What the plugin does is described in [the plugin README](../README.md).

The beta needs a Hermes build from the `beta/openshell` branch of hermes-agent (main plus the core and desktop changes the plugin needs, which are still in review). Use a test profile, not the profile you rely on every day.

## Supported platforms

| Platform | Tested | Notes |
|---|---|---|
| Windows 11 x64 | Yes | 24H2, 25H2 or 26H2 with the September 2026 update (build 26100, 26200 or 26300 at `.9550` or later), or 26H1 (build 28000 at `.3086` or later). Windows 10 isn't supported. |
| Windows 11 on Arm64 | Not yet run on hardware | Same Windows versions. Every Arm64 program must be the Arm64 build. |
| Linux x86_64 | Yes | Linux 6.2 or newer (Landlock ABI 3), Docker, systemd. Tested on Ubuntu 24.04 in WSL2. |
| Linux aarch64 | Built, not yet run on hardware | Same as x86_64. |
| macOS | No | Not supported in this beta. |

On Windows the sandbox uses Microsoft MXC process containers. Treat it as defense in depth, not a security boundary: MXC is itself a preview.

## 1. Prerequisites

### Windows

Run these in PowerShell as your normal user (no administrator rights needed).

1. **Windows version.** Check the build and update level:

   ```powershell
   Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object DisplayVersion, CurrentBuild, UBR
   ```

   `CurrentBuild` must be 26100, 26200 or 26300 with `UBR` 9550 or more, or 28000 with `UBR` 3086 or more. If it is lower, install every update in Settings > Windows Update and restart.

2. **Smart App Control.** Smart App Control can block programs that aren't code-signed. The OpenShell programs are signed by NVIDIA, and MXC's `wxc-exec.exe` (step 4) is signed by Microsoft. Two things this beta runs are not signed: busybox-w32 (step 5), and Hermes's own programs: the launchers `hermes.exe` and `hermes-acp.exe` (in the `bin` folder of the Hermes data folder, section 8) and the Python that Hermes installs for itself. Nobody has run this beta with Smart App Control on yet, so it isn't known whether it works there.

   ```powershell
   Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' VerifiedAndReputablePolicyState
   ```

   `0` is off, `1` is on, `2` is evaluation. Off works. In evaluation Windows blocks nothing yet, but it can turn itself on later; if programs suddenly stop starting, check again. If it is on, Windows may block the unsigned programs above, and then Hermes or the sandbox's shell won't start. The only way around that is turning Smart App Control off in Windows Security > App & browser control. **Turning Smart App Control off can't be undone without reinstalling Windows.** Decide that for yourself; a spare or test PC is the better place for this beta.

3. **Your PC's architecture.** The next steps use it:

   ```powershell
   $arch = if ((Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' PROCESSOR_ARCHITECTURE) -eq 'ARM64') { 'arm64' } else { 'x64' }
   $arch
   ```

4. **MXC (`wxc-exec`).** The sandbox needs MXC 1.0.1's `wxc-exec.exe`, from the npm package `@microsoft/mxc-sdk`. This downloads the package, checks it, and keeps the build for your architecture in a folder of its own:

   ```powershell
   $dir = "$env:LOCALAPPDATA\Programs\mxc-1.0.1"
   New-Item -ItemType Directory -Force $dir | Out-Null
   $tgz = "$dir\mxc-sdk-1.0.1.tgz"
   Invoke-WebRequest https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.1.tgz -OutFile $tgz
   $sri = 'sha512-' + [Convert]::ToBase64String([Security.Cryptography.SHA512]::Create().ComputeHash([IO.File]::ReadAllBytes($tgz)))
   if ($sri -ne 'sha512-2cP925G5+lQyKzjBVha8uNtVd7XESgDBtgi1yCYYSo9M3xiFyZWtCO4SWPGTk509rdI6nqjyGcZxvEP3t6l8Hg==') { throw 'mxc-sdk download does not match' }
   & "$env:SystemRoot/System32/tar.exe" -xzf $tgz -C $dir "package/bin/$arch/wxc-exec.exe"
   Move-Item -Force "$dir\package\bin\$arch\wxc-exec.exe" "$dir\wxc-exec.exe"
   Remove-Item -Recurse -Force "$dir\package", $tgz
   (Get-FileHash "$dir\wxc-exec.exe").Hash
   [Environment]::SetEnvironmentVariable('OPENSHELL_WXC_EXEC_PATH', "$dir\wxc-exec.exe", 'User')
   & "$dir\wxc-exec.exe" --probe
   ```

   The sha256 must be `090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a` (x64) or `91aa4171e8809f33f19622c381116188eab7d8c8cffad231230a31b58146ee77` (Arm64). The probe must report `"tier": "base-container"` and `"needsDaclAugmentation": false`. Any other tier means process isolation isn't available on this PC yet: update Windows, restart, and probe again.

5. **busybox-w32** for the sandbox's shell (Git Bash can't start inside MXC). Save it in a folder that holds nothing else, because the sandbox gets read access to that whole folder:

   ```powershell
   $bb = "$env:LOCALAPPDATA\Programs\busybox-w32"
   New-Item -ItemType Directory -Force $bb | Out-Null
   if ($arch -eq 'arm64') {
     $url = 'https://frippery.org/files/busybox/busybox-w64a-FRP-6075-g169694ebd.exe'; $exe = "$bb\busybox64a.exe"
     $want = 'e67f873d19d58c535cc9f0c4965ffd622e19b7bab87e3da89cb2185fb54464d7'
   } else {
     $url = 'https://frippery.org/files/busybox/busybox-w64u-FRP-6075-g169694ebd.exe'; $exe = "$bb\busybox64u.exe"
     $want = '6e263d154d8548d1eb936f65d1d8312c80df31c45974e48d6335e4dcc0f4f34c'
   }
   Invoke-WebRequest $url -OutFile $exe
   if ((Get-FileHash $exe).Hash -ne $want) { Remove-Item $exe; throw 'busybox download does not match' }
   [Environment]::SetEnvironmentVariable('OPENSHELL_BUSYBOX', $exe, 'User')
   ```

6. Open a new PowerShell window, and quit the Hermes desktop app completely if it is running (tray icon > Quit), so both pick up the two new variables.

### Linux

1. **Kernel.** `uname -r` must be 6.2 or newer, and `cat /sys/kernel/security/lsm` must list `landlock`. The plugin's own check (step 4) confirms the Landlock ABI and seccomp support.

2. **Docker Engine**, usable without `sudo`:

   ```bash
   sudo usermod -aG docker "$USER"     # then sign out and back in
   docker run --rm hello-world
   ```

   Install Docker first if you don't have it (for example `curl -fsSL https://get.docker.com | sudo sh`).

3. **A systemd user session.** The sandbox and its gateway run as `systemd --user` services:

   ```bash
   systemctl --user status --no-pager | head -3
   ```

   To keep the sandbox running after you sign out, also run `sudo loginctl enable-linger "$USER"`. In WSL2, systemd must be on: `/etc/wsl.conf` needs `[boot]` with `systemd=true` (then `wsl --shutdown` from Windows and reopen the distro).

## 2. Install Hermes from the beta branch

### New install

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1))) -Branch beta/openshell -IncludeDesktop
```

If PowerShell answers `The assignment expression is not valid`, run the installer from a file instead:

```powershell
irm https://hermes-agent.nousresearch.com/install.ps1 -OutFile "$env:TEMP\hermes-install.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\hermes-install.ps1" -Branch beta/openshell -IncludeDesktop
```

Linux:

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --branch beta/openshell --include-desktop
```

Leave out `--include-desktop` on a machine without a desktop session.

### Existing install

Rerunning the installer keeps an existing checkout on its update channel, so move it to the branch with Hermes itself, then build the desktop from it:

```
hermes update --branch beta/openshell
hermes desktop
```

### Check

Open a new terminal and run `hermes --version`. Use the desktop that `hermes desktop` (or `-IncludeDesktop`) builds from this install, not a Hermes Desktop download from the website or the Microsoft Store: those don't have the sandbox support yet.

Stay on the branch when you update: run `hermes update --branch beta/openshell`. A plain `hermes update`, or the desktop's update prompt, moves Hermes back to the regular release, which can't run the plugin.

## 3. Create a test profile and install the plugin

A test profile with a working model keeps your own profiles out of the test. `--clone` copies the active profile's model settings and keys; on a new install, set up a model first with `hermes setup`:

```
hermes profile create sbtest --clone
hermes -p sbtest -z "say hi"
```

The model can use an API key stored in the profile (its `.env`), a provider the profile is signed in to (Nous Portal, OpenAI Codex, xAI, MiniMax, Anthropic), or a model server on this computer. Before you switch on, the Sandbox page lists the profile's providers and says which of them work in the sandbox; sign in to a provider with the sandbox off. Hermes needs a model context of at least 64K tokens.

Install the plugin at the current commit of its beta branch (`--ref` takes a full commit hash):

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

`--enable` turns on the plugin's Python half for `sbtest`. Then turn on its desktop half: start the desktop (`hermes desktop`), go to Capabilities > Plugins, search for `openshell`, open **Sandbox** and turn on **Desktop: Sandbox**. **Sandbox** then appears in the sidebar.

To move to a newer plugin commit later, run the same install command with `--force`.

## 4. Check the computer and install OpenShell

```
hermes -p sbtest sandbox check
hermes -p sbtest sandbox runtime install
hermes -p sbtest sandbox runtime status
```

`check` prints `"ok": true` when this computer can run the sandbox, or the one reason it can't, with what to do about it. `"ready"` says whether the switch would turn on for this profile now; when it would not, `"switch_refused"` is the reason and the exit status is 2. `runtime install` installs the pinned OpenShell build and checks every file against the plugin's pinned sha256 hashes:

- Windows: it downloads NVIDIA's signed Windows package for your PC's architecture (about 60 MB) from the OpenShell v0.1.9 release on GitHub, installs the four OpenShell programs from it and checks that each is signed by NVIDIA Corporation. `runtime status` shows `openshell-windows-0.1.9` on x64 and `openshell-windows-0.1.9-arm64` on Arm64, with `"signer": "NVIDIA Corporation"` and `"signature": "valid"`. The package prints version 0.1.9 but is built from OpenShell's `windows` branch, so it isn't the same code as OpenShell 0.1.9 on Linux. It needs no Microsoft Visual C++ Redistributable: if you installed one for an earlier beta, you can keep it.
- Linux: it downloads the OpenShell v0.1.9 release for your architecture, pulls its two Docker images by digest and builds the sandbox's base image (a few minutes the first time). `runtime status` shows `openshell-v0.1.9`.

Switching the sandbox on installs it too; running it here first shows progress and errors in the terminal.

OpenShell normally sends anonymous usage counts (sandbox starts and stops, policy decisions, provider changes; no names, paths, prompts or keys) to NVIDIA. The plugin turns that off for every OpenShell program it starts. To confirm once the sandbox is on, run `hermes -p sbtest sandbox gateway status` and look for `"openshell_telemetry": "off"`.

## 5. Turn the sandbox on and off

### From the desktop

1. Select `sbtest` in the profile rail.
2. Open **Sandbox** from the sidebar (or "Open sandbox settings" in the command palette). If the computer can't run the sandbox, the page says why and the switch stays off.
3. Flip the switch and confirm ("Let the openshell plugin run the “sbtest” profile?" > **Switch to openshell**). The page shows "Starting sandbox…", then **Running**, usually after 10 to 25 seconds. The status bar shows **Sandboxed**.
4. To turn it off, flip the switch again and choose **Switch back**. The profile runs on the host again, with its keys and chat history.

The default profile can't be sandboxed in this beta; use another profile.

### From a terminal

```
hermes -p sbtest sandbox on
hermes -p sbtest sandbox status
hermes -p sbtest sandbox off
```

Use these only while the desktop is closed or shows another profile (see known issues). While the sandbox is on, Hermes refuses to run `sbtest` on the host: `hermes -p sbtest chat` says the profile runs elsewhere. The sandbox is a login service (Task Scheduler on Windows, `systemd --user` on Linux), so it starts again after you sign in until you switch it off.

## 6. What the sandbox can reach

- **Folders:** the profile's own folder (read and write), the installed Hermes (read only), and the folders you add on the Sandbox page (**Add folder…**, read only or read & write). The page refuses drive roots, your home folder, the Hermes data folder and credential folders.
- **Credentials:** the profile's `.env` and Hermes's other credential stores are hidden from the sandbox. Keys reach it as placeholders that OpenShell's proxy replaces only on requests to the key's own address. A provider you are signed in to stays signed in on your computer: the sandbox gets a stand-in sign-in without the token or the grant that renews it, and the launcher renews the real one. When you switch the sandbox on, a key or sign-in is used only at the addresses your profile's model needs; what a tool needs opens when you allow that tool in a chat (section 7). The Sandbox page lists every provider with its state and the addresses it is used at under "Providers", and the same addresses among its allowed destinations. If a model's endpoint is changed from inside the sandbox, its key is withheld until you choose **Allow** on the Sandbox page. Switch the sandbox off before you edit `.env` by hand or sign in to a provider: an edit made while it is on is not used and is undone at switch-off.
- **Switching off:** when the sandbox changed settings or files that run on your computer (a cron job, an MCP server, a shell hook, a secret source, a model's endpoint), the Sandbox page lists them under "Changed in the sandbox" before it turns off. **Revert and turn off** puts them back as they were when you switched the sandbox on; **Keep and turn off** leaves them. In a terminal, `hermes -p <profile> sandbox off` prints the same list and waits for `--revert` or `--keep`. After a Keep the page shows "Kept from the sandbox: N items" for as long as those changes are in the profile. If a sandbox session ended without that step, the next switch-on asks first: the page shows the list with **Revert and turn on** and **Keep and turn on**, and `hermes -p <profile> sandbox on` waits for the same two flags.
- **Websites:** blocked by default. Add destinations on the Sandbox page (**Add destination…**: a hostname or address range, and a port), or answer the cards below. Leave **Internet access** set to Blocked: OpenShell has no rule for the whole internet, and a sandbox set to Allowed won't start.
- **Windows only:** MXC lets the sandbox reach every port on this computer's own addresses, so services running on this PC are reachable from the sandbox. Only run local services that check who calls them. Programs in the sandbox reach them at `127.0.0.1` or `localhost` directly; every other address goes through the sandbox's proxy.
- **Usage data:** if the profile shares usage data with Nous (the "Help improve Hermes?" question, or `hermes -p sbtest setup telemetry`), the Sandbox page lists `telemetry.nousresearch.com` under **Allowed destinations** with "Usage data this profile shares with Nous". The plugin keeps that one destination open while sharing is on and takes it out when you turn sharing off; it has no Remove button.

Hermes's own background lookups (update checks, model catalogs) stay blocked inside the sandbox and never raise a card; they show in Activity as refused.

## 7. Cards: answering the sandbox's questions

When the sandbox refuses a folder or a website during a chat, the plugin shows one card in that chat:

- **Website access** names one host and covers http and https for any program in the sandbox.
- **A tool's card** (for example "Web extract") comes the first time a tool of that kind is used: Web search, Web extract, Browser, Image generation, Video generation, Speech, Connected apps or Remote terminal. It covers every service that kind of tool uses for your profile and names each host. If you are signed in to Nous Portal, that includes the Nous tool gateway's host for it, where your sign-in is then used. Web extract and Browser fetch pages for the agent, so after Allow the agent can read any public page, not one site; the card says so.
- **Folder access** names the nearest existing folder and the access asked for (**Read only** or **Read and write**).

Each card has three answers:

- **Allow:** until the sandbox is switched off. Not saved.
- **Always allow:** after you confirm, the folder or site is added to the profile's sandbox settings; Hermes doesn't ask again for it in any chat.
- **Deny:** refuses it. You can add a reason, which the agent reads.

The answer applies to the reply in progress. For a website, the plugin pauses the reply at the refused step, loads the rule and the reply continues by itself, usually within a few seconds. For a folder, the sandbox restarts first ("Restarting sandbox…", 10 to 20 seconds), then the reply continues. A tool's card does the same when one of its services uses your sign-in or a key; a tool that only uses services without a key applies like a website. You can open another page meanwhile: the reply continues all the same. If no Hermes window was open during the restart, the chat says "This reply stopped when the sandbox restarted. Send your message again." when you open it; send it again, and nothing asks a second time.

The Sandbox page lists what you allowed from cards under **Allowed from chat**, each with **Remove**. What you saved with **Always allow** stays listed while the sandbox is off, and can be removed there. The **Activity** tab shows what the sandbox allowed and refused (network, files, your answers), the policy history with **Restore**, and **Export OCSF JSON…**.

## 8. Logs

The Hermes data folder is `%LOCALAPPDATA%\hermes` on Windows and `~/.hermes` on Linux. Inside it:

| What | Where |
|---|---|
| The profile's launcher, sandbox start and card log | `openshell/<profile>/launcher.log`, `serve.log`, `serve.log.1`, `cards.jsonl` |
| The OpenShell gateway's log and audit log | `openshell/runtime/gateway/logs/`, `openshell/runtime/gateway/ocsf/` |
| The sandboxed backend's log (and launcher warnings) | `profiles/<profile>/logs/agent.log`, `errors.log` |
| The desktop | `logs/desktop.log`, `logs/gateway.log` |
| Windows only: the OpenShell host supervisor | `C:\var\log\openshell*.log` |
| Linux only: the services | `journalctl --user -u 'hermes-*' --since today` |

Collect them before you switch the sandbox off: switching off removes the sandbox and some of its logs.

## 9. Reporting a problem

Report through the channel you got this beta from, or open an issue in this repository. Include:

- what you did, what you expected, what happened, and the time it happened;
- a screenshot of the chat or Sandbox page, if the problem shows there;
- the output of `hermes --version` and of `hermes -p <profile> sandbox check`, `sandbox status`, `sandbox runtime status` and `sandbox gateway status`;
- the logs in section 8.

This copies the logs that are safe to share into one zip on Windows:

```powershell
$h = "$env:LOCALAPPDATA\hermes"; $p = 'sbtest'; $out = "$env:USERPROFILE\Desktop\openshell-beta-logs"
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item "$h\openshell\$p\*.log*", "$h\openshell\$p\cards.jsonl" $out -ErrorAction SilentlyContinue
Copy-Item -Recurse "$h\openshell\runtime\gateway\logs", "$h\openshell\runtime\gateway\ocsf" $out -ErrorAction SilentlyContinue
Copy-Item "$h\profiles\$p\logs\agent.log*", "$h\profiles\$p\logs\errors.log*", "$h\logs\desktop.log*", "$h\logs\gateway.log*" $out -ErrorAction SilentlyContinue
Copy-Item 'C:\var\log\openshell*.log' $out -ErrorAction SilentlyContinue
Compress-Archive -Force "$out\*" "$out.zip"
```

and on Linux:

```bash
h=~/.hermes; p=sbtest; out=~/openshell-beta-logs; mkdir -p "$out"
cp "$h/openshell/$p/"*.log* "$h/openshell/$p/cards.jsonl" "$out/" 2>/dev/null
cp -r "$h/openshell/runtime/gateway/logs" "$h/openshell/runtime/gateway/ocsf" "$out/" 2>/dev/null
cp "$h/profiles/$p/logs/"{agent,errors}.log* "$h/logs/"{desktop,gateway}.log* "$out/" 2>/dev/null
journalctl --user -u 'hermes-*' --since today --no-pager > "$out/journal.txt"
tar -czf "$out.tar.gz" -C "$out" .
```

**Never attach** `.env`, `auth.json`, `gateway-connection-tokens.json`, `openshell/<profile>/token`, or the gateway's `pki`, `cli`, `cli-state`, `state`, `data` and `xdg-config` folders: they hold your keys and the sandbox's certificates. Logs can contain your prompts, file names and site names; read them before you send them.

## 10. Turning it off and uninstalling

1. Switch the sandbox off for every profile that uses it (Sandbox page, or `hermes -p <profile> sandbox off`). When the last one is off, the plugin stops the OpenShell gateway too.
2. Remove the gateway's files and the installed OpenShell:

   ```
   hermes -p sbtest sandbox gateway remove
   hermes -p sbtest sandbox runtime remove
   ```

3. Turn off **Desktop: Sandbox** in Capabilities > Plugins, then remove the plugin: `hermes -p <profile> plugins remove openshell`.
4. Optional: delete `openshell/<profile>/` in the Hermes data folder (the saved folders, sites and card log), and the test profile itself (`hermes profile delete sbtest`).
5. Windows: delete `%LOCALAPPDATA%\Programs\mxc-1.0.1`, `%LOCALAPPDATA%\Programs\busybox-w32` and `C:\var\log\openshell*.log`, and remove the user variables `OPENSHELL_WXC_EXEC_PATH` and `OPENSHELL_BUSYBOX` (Settings > System > About > Advanced system settings > Environment Variables).
6. Linux: remove the sandbox's base image and OpenShell's images if you don't need them. List them with `docker image ls hermes-sandbox-base` and `docker image ls --digests --filter 'reference=ghcr.io/nvidia/openshell/*'`, then `docker image rm` the ones listed.
7. Leave the beta branch: `hermes update --branch main`. Later updates follow your usual channel again.

## Known issues

- **`sandbox on` from a terminal while the desktop shows the profile.** `hermes -p <profile> sandbox off` in a terminal is followed by the open page, which offers **Switch back**. `hermes -p <profile> sandbox on` in a terminal while the desktop shows that profile is not: the window keeps saying that the sandbox is stopping and that the backend is offline until the sandbox is switched off again. Use the page's own switch to turn it on.
- **`[Sandbox]` notes appear inside your next message.** Notes from the plugin (for example that a rule change closed open connections) are shown in your next message bubble, as if you had typed them. The agent reads them as the plugin's notes.
- **"Response stopped" can flash when a paused reply goes on.** While the plugin applies your answer to a card, and during a folder restart, the reply shows that it is continuing. As it goes on, "Response stopped" can show for an instant (seen once in eleven folder restarts). A reply you stopped yourself keeps it.
- **A late Allow can take up to about 35 seconds.** If the agent has meanwhile hit a second refusal in the same chat (it often tries curl next), your answer to the first card applies only when the second card's wait ends. Answer the second card too, or wait.
- **Deny on a web tool card covers the tool, not the site.** After Deny on a "Web extract" card, web extract stays refused for every site in that chat. The site itself is not denied: when the agent then tries it another way (curl, say), a **Website access** card asks about that.
- **The first folder restart is slower.** The first restart for a folder grant in a session takes about 15 seconds longer than later ones.
- **The sandbox's gateway stopped.** If the OpenShell gateway's process ends while the sandbox is on, the plugin starts the gateway and the sandbox again, once; the page says "Restarting the sandbox after its gateway stopped" meanwhile. A reply that was streaming is cut and is not continued: send the message again. If the gateway stops again within ten minutes, the sandbox stays stopped and the page says "The sandbox's gateway stopped. Turn the sandbox off, then on again."; `hermes -p <profile> sandbox status` prints the same sentence.
- **Some providers are not available in the sandbox.** Providers that are a program with their own sign-in, Qwen OAuth, Anthropic through Claude Code's sign-in, Azure with Entra ID, Vertex and Bedrock. The Sandbox page names them before the switch, and the switch stays off while the profile's model uses one.
- **Sign in with the sandbox off.** Signing in or out of a provider is refused while the sandbox is on. When a sign-in expires for good, the Sandbox page says "Sign-in expired" and a notice says the same once, whichever page is open: turn the sandbox off, sign in, turn it on. A message sent after that can show Hermes's "Provider temporarily unavailable" and retry for several minutes before it fails.
- **A key written in `config.yaml` keeps the switch off.** The Sandbox page names it and offers **Move to .env**; in a terminal, `hermes -p <profile> sandbox on --move-keys` moves it and turns the sandbox on. After the move the key is in `.env` only; no copy of either file is kept.
- **A file that can't be read keeps the switch off.** While another program has the profile's `config.yaml`, `.env` or a sign-in file open so that it can't be read, the Sandbox page says "Can't read this profile's config.yaml. Another program may have it open.", keeps the rows it last read, and the switch reads "Can't turn on". Close the program; the page follows by itself.
- **A model with no key does not keep the switch off.** Its row says "No key found" and that the model won't answer in the sandbox without it, and the confirm says so before the sandbox starts.
- **A long reply can be cut when a sign-in is renewed.** The launcher renews a sign-in between replies. If replies stream until shortly before the token expires, the renewal cuts the reply that is streaming; Hermes asks the model again by itself and the chat shows no error. This was seen on Linux; in the one run on Windows the reply was not cut.
- **Sign-ins have been run with Nous Portal and OpenAI Codex only.** Both on Linux; on Windows a Nous Portal sign-in against a stand-in issuer, with a model entry that names the sign-in's token. xAI, MiniMax and Anthropic sign-ins are covered by tests. Reports are welcome.
- **The default profile can't be sandboxed.** Use another profile.
- **macOS isn't supported**, and Windows on Arm64 and Linux aarch64 have not been run on real hardware yet. Reports from those machines are especially welcome.
