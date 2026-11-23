# Use the sandbox

This page shows how to turn a profile's sandbox on and off, and how to give it folders and
websites.

## Turn the sandbox on

1. Select the profile in the desktop's profile rail.
2. Open **Sandbox** from the sidebar, or run "Open sandbox settings" from the command palette.
   The page first checks that the computer can run the sandbox.
   If it can't, the page says why and the switch stays off.
3. Flip the switch and confirm.
   The desktop asks "Let the openshell plugin run the “sbtest” profile?"; choose
   **Switch to openshell**.
4. Wait for the page to go from "Starting sandbox…" to **Running**, usually 10 to 25 seconds.
   The status bar then shows **Sandboxed**.

The switch does not turn on for the default profile yet.
Other reasons the switch stays off are in
[Troubleshooting](troubleshooting.md#the-switch-does-not-turn-on) and
[API keys and providers](credentials.md#what-keeps-the-switch-off).

What the switch does:

1. The plugin starts the profile's launcher as a per-user login service (Task Scheduler on
   Windows, `systemd --user` on Linux). The launcher starts the sandbox.
2. The plugin marks the profile as run elsewhere, so the host stops running it.
3. The desktop routes the profile to the launcher.

Because the launcher is a login service, the sandbox starts again after you sign in, until you
switch it off.

## Turn the sandbox off

1. Flip the switch again and choose **Switch back**.
2. If the page lists changes under "Changed in the sandbox", answer the list.
   See [Review changes at switch-off](switching-off.md).

Turning off stops the sandbox, removes the login service and clears the marker.
The desktop then routes the profile back to the host, and the profile runs there again with its
keys and chat history.

## Use a terminal instead

```bash
hermes -p sbtest sandbox on
hermes -p sbtest sandbox status
hermes -p sbtest sandbox off
```

> [!NOTE]
> Use `sandbox on` only while the desktop is closed or shows another profile. See
> [Known issues](known-issues.md#sandbox-on-from-a-terminal-while-the-desktop-shows-the-profile).

While the sandbox is on, Hermes refuses to run the profile on the host.
`hermes -p sbtest chat`, for example, says that the profile runs elsewhere.

All commands and flags are in the [command reference](cli.md).

## What the sandbox can reach

| | Reachable without asking | Reachable after you allow it |
|---|---|---|
| Folders | The profile's own folder (read and write), the installed Hermes runtime (read only), the sandbox's own scratch folders | Folders you add, each read only or read and write |
| Websites | The addresses the profile's model uses | Destinations you add, and what you allow from a card |
| Credentials | None. Keys reach the sandbox as placeholders. | See [API keys and providers](credentials.md) |

Network access is blocked by default.
Hermes's own background lookups (update checks, model catalogs) stay blocked inside the sandbox.
They never raise a card, and they show in Activity as refused.

## Add a folder

1. On the Sandbox page, choose **Add folder…**.
2. Enter the folder's path and choose its access: **Read only** or **Read & write**.
3. Confirm. While the sandbox is on, a folder change applies after a restart: the page shows
   "Changes apply after restart." with **Restart**.

The page refuses these folders:

- a drive root;
- your home folder, or a folder above it;
- the Hermes data folder;
- credential folders.

The agent can also ask for a folder during a chat. See [Approval cards](cards.md).

## Allow a website

1. On the Sandbox page, choose **Add destination…**.
2. Enter a hostname or an address range (CIDR), and a port.
3. Confirm.

A destination you add on the page is open for Hermes's interpreter.
A site you allow from a card is open for any program in the sandbox.

Leave **Internet access** set to **Blocked**.
OpenShell has no rule for the whole internet, and a sandbox set to **Allowed** won't start.

The agent can also ask for a website during a chat. See [Approval cards](cards.md).

## See what is allowed

The Sandbox page lists everything the running sandbox may reach:

| Section | What it lists |
|---|---|
| **Folders** | The profile folder and the folders you added |
| **Allowed destinations** | The destinations you added, and every address a sign-in or a key is used at, with what it is for ("Model", or the tool category that opened it) |
| **Allowed from chat** | What you allowed from cards, each with **Remove** |
| **Providers** | The profile's providers and what each does in the sandbox |

- The page's header counts the addresses a sign-in or a key is used at together with your own.
- A model's address that is listed among the allowed destinations has no second row above the
  list.
- The open page follows what the launcher changes by itself (a card answered in a chat, a removal,
  a restart, a renewed sign-in) within a few seconds.
  It does so also in a window that is covered, minimized or without focus.

## Services on this computer (Windows)

On Windows, MXC lets the sandbox reach every port on the computer's own addresses, loopback
included. The Sandbox page says so: "Services on this computer are always reachable from the
sandbox."

- Only run local services that check who calls them.
- Programs in the sandbox reach those services at `127.0.0.1` or `localhost` directly.
  Every other address goes through the sandbox's proxy and the allowed destinations.

See [Security](security.md#services-on-this-computer-windows).

## Usage data shared with Nous

A profile can share usage data with Nous. That is the answer to Hermes's "Help improve Hermes?"
question, and `hermes -p sbtest setup telemetry` changes it.

While sharing is on, the launcher keeps one destination open by itself:
`telemetry.nousresearch.com` on port 443.

- The page lists it under **Allowed destinations** with "Usage data this profile shares with
  Nous". It has no **Remove** button.
- It is open for Hermes's interpreter only. Another program the agent runs, `curl` for example,
  is still refused for that host and raises the usual website card.
- It is removed when you turn sharing off.

The details are in [Security](security.md#usage-data-shared-with-nous).
