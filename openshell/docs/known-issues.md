# Known issues

This page lists the limits and open problems of the beta, with what to do about each.

## Platforms

### macOS, Arm64 and aarch64

- macOS isn't supported.
- Windows on Arm64 and Linux aarch64 have not been run on real hardware yet.

### The default profile can't be switched on

The switch refuses the default profile. Use another profile.

### Smart App Control (Windows)

The plugin is not tested with Smart App Control on.

Hermes itself has open reports of Smart App Control blocking parts of a source install:
[hermes-agent#148950](https://github.com/NousResearch/hermes-agent/issues/148950),
[hermes-agent#154847](https://github.com/NousResearch/hermes-agent/issues/154847) and
[hermes-agent#125601](https://github.com/NousResearch/hermes-agent/issues/125601).

The sandbox's shell, busybox-w32, is not code-signed.

## Switching on and off

### `sandbox on` from a terminal while the desktop shows the profile

- `hermes -p <profile> sandbox off` in a terminal is followed by the open page, which offers
  **Switch back**.
- `hermes -p <profile> sandbox on` in a terminal, while the desktop shows that profile, is not.
  The window keeps saying that the sandbox is stopping and that the backend is offline, until the
  sandbox is switched off again.

Use the page's own switch to turn the sandbox on.

### A sandbox whose launcher has stopped

If the launcher stops by itself, the profile stays switched on for the sandbox, and the page
cannot turn it off.
See [Troubleshooting](troubleshooting.md#the-sandbox-isnt-answering).

### The sandbox's gateway stopped

The plugin starts the gateway and the sandbox again, once. A reply that was streaming is cut.
See [Troubleshooting](troubleshooting.md#the-sandboxs-gateway-stopped).

### The first folder restart is slower

The first restart for a folder grant in a session takes about 15 seconds longer than later ones.

## Windows: the sandbox's programs

### The first switch-on shows only "Starting sandbox…"

Unless `sandbox runtime install` ran before it, the first switch-on downloads and installs the
sandbox's programs, about 100 MB in all. Until it is done, the page and the status bar show only
"Starting sandbox…", with no word of a download.

Wait for it, or run `hermes -p <profile> sandbox runtime install` in a terminal first.
See [Install](install.md#install-openshell).

### A failed download leaves a long notice on the page

If the PC cannot reach `registry.npmjs.org` or `frippery.org` during a switch-on, the switch turns
itself off and the page shows a notice with the terminal's message. It names `wxc-exec.exe` or the
shell, says it "could not be downloaded", and carries the address, the raw error and the name of an
environment variable. The notice stays until you close it, also after a later switch-on worked.

Check the connection, turn the switch on again, and close the notice yourself.
See [Troubleshooting](troubleshooting.md#the-plugin-could-not-install-wxc-exec-or-the-shell).

### A changed program file is replaced without a message

The plugin compares `wxc-exec.exe` and the shell with their pinned sha256 before every use.
A copy that was changed or damaged is downloaded and installed again at the next switch-on.
No message says so, and no log file records it or any other install of the two programs.

To see what is installed now, run `hermes -p <profile> sandbox runtime status`.

### A changed program file is reported as "not installed yet"

`sandbox check` and `sandbox runtime status` report a `wxc-exec.exe` or shell file that no longer
matches its pinned sha256 as if it were missing: `"file": null`, `"installed": false` and the note
"not installed yet: ...". The file is still at its path.
The next switch-on or `sandbox runtime install` installs it again.

## Cards and replies

### `[Sandbox]` notes appear inside your next message

Notes from the plugin (for example that a rule change closed open connections) are shown in your
next message bubble, as if you had typed them. The agent reads them as the plugin's notes.

### "Response stopped" can flash when a paused reply goes on

While the plugin applies your answer to a card, and during a folder restart, the reply shows that
it is continuing. As it goes on, "Response stopped" can show for an instant.
A reply you stopped yourself keeps it.

### A late Allow can take up to about 35 seconds

If the agent has meanwhile hit a second refusal in the same chat (it often tries curl next), your
answer to the first card applies only when the second card's wait ends.
Answer the second card too, or wait.

### Deny on a web tool card covers the tool

After Deny on a "Web extract" card, web extract stays refused for every site in that chat.
The site itself is not denied. When the agent then tries it another way (curl, say), a
**Website access** card asks about that.

### After a Deny, the same chat is not asked again

After a Deny on a site's card, later refused calls for that site in the same chat get no second
card. Each result carries the reason you gave.

### A connection refused outside a tool call is not asked about

A connection that is refused while no tool call is open raises no card.
The next tool call that names that host is asked about the site first.

### A folder refused in a command that did not fail needs its full path

When a command does not fail although a folder was refused (`ls A; ls B`), the **Folder access**
card comes only if the command names the folder by its full path.

A relative path, `~`, a variable or a path that only a script names raises no card. Neither does
a line that says only "No such file or directory". The agent reads the refusal in the command's
output.

### Windows: a program that connects without the proxy

A program that connects directly, without the sandbox's proxy, is refused and leaves no record.
No card can come for it.

## Keys and providers

### Keys set from a terminal

A key set with `hermes config set` for a profile whose sandbox is on does not stay.
The launcher puts the profile's `.env` back as it was and keeps the changed file in
`openshell/<profile>/quarantine`. The command itself reports success.

Save keys on the Sandbox page or the desktop's Keys page, or switch the sandbox off first.

### Keys that stay on this computer

Keys for image, video, speech and browser tools, tokens of MCP servers and keys of memory
providers are not handed to the sandbox. Those tools report a missing key there.

### Providers that are not available in the sandbox

Some providers cannot work in a sandbox. The Sandbox page names each one before the switch, and
the switch stays off while the profile's model uses one.
The list is in [API keys and providers](credentials.md#providers-that-work-in-the-sandbox).

### Nous Portal on an inference address of your own

For a Nous Portal model, Hermes inside the sandbox asks Nous's own inference address.
An address set with `NOUS_INFERENCE_BASE_URL` in the profile's `.env` is used on this computer and
is not handed in. Such a profile's Nous Portal model does not answer in the sandbox.

## Sign-ins

### Sign in with the sandbox off

Signing in or out of a provider is refused while the sandbox is on.
See [Provider sign-ins](sign-ins.md#sign-in-with-the-sandbox-off).

### A reply that is streaming when a sign-in must be renewed

The launcher renews a sign-in between replies. On Linux, if replies stream until shortly before
the token expires, the renewal cuts the reply that is streaming. Hermes asks the model again by
itself, and the chat shows no error.

See [Sign-in renewal](sign-in-renewal.md#a-reply-that-is-streaming-when-a-renewal-is-due).

### A sign-in that the provider no longer renews

The Sandbox page says "Sign-in expired", and a notice says the same once, whichever page is open.
Turn the sandbox off, sign in, turn it on.

A message sent after the sign-in ended can show Hermes's "Provider temporarily unavailable" and
retry for several minutes before it fails.
See [Sign-in renewal](sign-in-renewal.md#a-sign-in-that-the-provider-no-longer-renews).

### A provider that answers a renewal with a token that does not last

The launcher limits how often it asks a provider to renew a sign-in. A sign-in whose renewal was
tried 150 times within an hour is left alone until the sandbox is turned off and on, and the page
shows "Sign-in expired" for it.
See [Sign-in renewal](sign-in-renewal.md#how-often-the-launcher-asks-a-provider).

## Credential files

### Linux: a credential file replaced by hand

A program that renames a new file over a credential file at the top of the profile folder puts a
plain file where the launcher's link was. Examples are an editor that saves by rename, and `mv`.
The files concerned are `.env`, `.op.env`, `auth.json` (when it is not a stand-in) and the other
credential files there.

- The sandbox can read that file until the launcher looks again, which it does four times a
  second. Then the file is moved to the quarantine folder and the link is put back.
- Hermes's own writers are not affected.

Switch the sandbox off before you edit or replace a credential file by hand.

### Linux: a credential store that first appears while the sandbox runs

`.env`, `.op.env` and, for a profile without a sign-in the sandbox can use, `auth.json` are hidden
even when they don't exist at the start.

Any other credential store that does not exist when the sandbox starts and is created on this
computer while it runs can be read inside until the sandbox stops.
It is then moved to the quarantine folder.

Create such a file with the sandbox off.

### Windows: names and sizes

A hidden credential file cannot be opened inside the sandbox, but its name and size can be seen
there.

## Review at switch-off

### Large files in the review

The launcher keeps a copy of each script, hook file and named program for Revert only up to 8 MB a
file and 128 MB in all. A larger file that the sandbox changed is listed as "No copy kept".
See [Review changes at switch-off](switching-off.md#limits).

### A sandboxed agent can turn usage sharing on

A sandboxed agent can edit its own profile's `config.yaml` and so turn usage sharing on.
That opens `telemetry.nousresearch.com` on port 443 and nothing else.
See [Security](security.md#usage-data-shared-with-nous).
