# Security

This page says what the sandbox limits, what it does not protect against, what the plugin verifies
before it runs OpenShell, and what leaves the computer.

## What the sandbox limits

| Area | What the sandbox gets |
|---|---|
| Files | The profile's own folder (read and write), the installed Hermes runtime (read only), its own scratch folders, and the folders you add |
| Network | Nothing by default. Only the destinations you allowed, and the addresses the profile's model uses. |
| Keys and sign-in tokens | None. The sandbox holds placeholders. OpenShell's proxy puts the real value into a request to the key's own address. |
| Credential files | Hidden, whether or not they exist yet |
| The launcher's own state | Not given to any sandbox: the token, the saved settings, the copies of keys, the logs |

While the sandbox is on, the host does not run the profile.
The plugin marks the profile as run elsewhere, and Hermes on this computer refuses to run it.

## What the sandbox does not protect against

- **Services on this computer (Windows).** The sandbox reaches every port on the computer's own
  addresses. See [below](#services-on-this-computer-windows).
- **The profile folder.** The sandbox can write most of it, `config.yaml` included. Hermes on
  this computer runs what the folder holds once the sandbox is off.
  The [review at switch-off](switching-off.md) lists those changes.
- **Public pages.** After you allow Web search, Web extract or Browser, the agent can read any
  public page through the service that fetches pages for the tool.
- **Names and sizes (Windows).** A hidden credential file cannot be opened inside the sandbox,
  but its name and size can be seen there.
- **A foreground `hermes sandbox serve`.** It does not mark the profile, so Hermes on this
  computer reads the profile folder while such a sandbox runs.

More limits are in [Known issues](known-issues.md).

## What the plugin checks on Windows before it starts

Before the launcher installs or starts anything on Windows, it runs `wxc-exec --probe` and a
`--dry-run`. Both are read-only: neither creates a container. The launcher refuses to go on
unless the probe reports all of these:

- the `base-container` tier;
- `needsDaclAugmentation: false`. MXC would otherwise enforce grants by rewriting host file
  permissions;
- support for host loopback and for denied paths.

## Services on this computer (Windows)

On Windows, MXC lets the sandbox reach every port on the computer's own addresses, loopback
included, whatever the allowed destinations say.

- Services on the computer are always reachable from the sandbox. They must authenticate their
  callers. The Sandbox page says so.
- The plugin's own services do: the gateway requires mTLS client certificates, and the launcher's
  proxy requires a token that never enters the sandbox.

OpenShell's proxy refuses loopback addresses.
So inside a Windows sandbox the plugin lists `127.0.0.1`, `localhost` and `::1` in `NO_PROXY`.

- Programs that follow the proxy variables (curl, Python, Node) connect to those three names
  directly, as a program that opens its own socket already could.
- Every other destination still goes through the proxy and the allowed destinations.

## Credentials

- Keys reach the sandbox as placeholders. See
  [API keys and providers](credentials.md#how-a-key-reaches-the-sandbox).
- Sign-in tokens stay on the host. The sandbox gets a stand-in file with no token and no refresh
  grant. See [Provider sign-ins](sign-ins.md#what-the-sandbox-gets).
- Credential files are hidden with MXC denied paths on Windows and with read-only mounts on Linux.
  See [How it works](how-it-works.md#how-credential-files-are-hidden).
- A key written in `config.yaml`, which the sandbox reads, keeps the switch off until it is moved
  to `.env`.

## What is verified at install

The plugin installs only what `runtime/pins.json` pins, and checks every file against it.

| | Windows | Linux |
|---|---|---|
| Download | The release zip must match its pinned sha256 | Each release asset must match its line in the pinned checksum files |
| Programs | Each of the four programs must match its own pinned sha256 | The Docker driver's images are pulled by pinned digest |
| Publisher | Each program must carry a valid signature by NVIDIA Corporation (`windows.signer` in the pin) | |
| Python packages | | The OpenShell SDK and its dependencies are pinned by sha256 |

On Windows the plugin also installs MXC's `wxc-exec.exe` and the sandbox's shell, pinned in the
same file:

| Program | What is checked |
|---|---|
| `wxc-exec.exe` | The npm package must match its pinned integrity value, the file its pinned sha256, and the file must carry a valid signature by Microsoft Corporation. Nothing else of the package is written to disk. |
| The shell (busybox-w32) | The file must match its pinned sha256. It is not code-signed. |

The plugin compares both files with their pinned sha256 again before every use.
A copy of your own that you name with a variable or a flag is used as it is.
See [Set up Windows](setup-windows.md#use-a-copy-of-your-own).

- An install that fails a check is refused.
- If Windows can't check the signatures at all, the install continues on the checksums and logs
  one line.
- Only the four pinned programs are unpacked, from the Windows zip's `bin` folder. The package's
  scripts, SDKs and documents are never written to disk.
- The Linux base image is built on your computer, on a base that is pinned by digest.

## Telemetry

### Relay response receipts

To link native model calls to OpenShell's HTTP records, enable receipts in the profile's
`config.yaml`:

```yaml
plugins:
  enabled: [openshell]
  entries:
    openshell:
      settings:
        relay_receipts: true
```

Requires Hermes's `llm_http_response` hook and a compatible Relay build. The version bundled
with Hermes may not yet have the required APIs; the plugin warns and skips capture if they
are missing. This works inside the sandbox with in-process plugins, not plugin-host isolation.

Receipts contain only the request ID and HTTP status, not other headers, bodies, prompts or
credentials. Use Relay's `full` or `openinference` export mode to retain them. The plugin does
not configure exporters or open network destinations.

A receipt means response headers arrived, not that a stream completed or a policy allowed
the request. It is not an authorization token. Tool-subprocess requests are not covered.
Capture is off by default; a recording failure does not change the model request's result.

### OpenShell's usage telemetry is off

OpenShell sends anonymous usage counts to NVIDIA unless it is told not to.
The counts cover sandbox starts and stops, policy decisions and provider changes.
They hold no names, paths, prompts or keys.

The plugin always tells OpenShell not to send them:

- Every OpenShell program the plugin starts runs with `OPENSHELL_TELEMETRY_ENABLED=false`.
- The plugin sets that whatever your own environment says.
- The gateway passes the setting on to each sandbox.

To confirm it:

```bash
hermes -p sbtest sandbox gateway status
```

Look for `"openshell_telemetry": "off"`.
The setting is the `OPENSHELL_TELEMETRY_ENABLED` line in
`openshell/runtime/gateway/service/gateway-service.json` in the Hermes data folder.

### Usage data shared with Nous

A profile shares usage data with Nous while `telemetry.shared_metrics.enabled` and `send` are both
on in its `config.yaml`. That is the answer to Hermes's "Help improve Hermes?" question, and
`hermes setup telemetry` changes it.

While sharing is on, the launcher keeps one destination open by itself:
`telemetry.nousresearch.com` on port 443, for Hermes's interpreter.

| Property | Detail |
|---|---|
| Where you see it | Among the allowed destinations on the Sandbox page, with its reason |
| Can you remove it there | No. It is not one of your destinations or card grants. Edits and card answers leave it in place. |
| When it goes | When sharing is turned off |
| Who can use it | Hermes's interpreter only. Another program the agent runs (for example `curl`) is still refused for that host and raises the usual website card. |
| When the launcher decides | When the sandbox starts and at every network update. It picks up an answer given while the sandbox runs a few seconds later, once no turn is running. |
| Which host | The host is fixed in the plugin. The `endpoint` key in `config.yaml` is never opened. A profile whose config names another endpoint sends no usage data from inside the sandbox. |

Known limit: a sandboxed agent can edit its own profile's `config.yaml` and so turn sharing on.
That opens this one host and nothing else.
