---
name: nvidia-app
description: Use NVIDIA App's local MCP tools for application, driver, game-optimization, laptop-feature, and restricted In-Game Overlay operations and troubleshooting.
metadata:
  author: Sahil Singh <sahils@nvidia.com>
  tags: nvidia-app, mcp, in-game-overlay, recording
  domain: system-tools
  team: nvidia-app
  version: 1.1.4
  hermes_adaptation: Connection guidance rewritten for Hermes, which connects the server from this plugin; tool contracts unchanged from upstream 1.1.4
---

# NVIDIA App MCP Overlay

## Purpose

Use this skill for one product integration: operating NVIDIA App through its local MCP server. It has two routed modes:

- General NVIDIA App operations cover application listing and launch, driver status and release notes, per-game optimization, and laptop features.
- In-Game Overlay operations use the deliberately restricted workflow below.

The restricted Overlay workflow supports:

- Read high-level Overlay status.
- Start or stop gameplay recording.
- Enable, disable, or save Instant Replay.
- Enable or disable Highlights.
- Capture a screenshot to the Overlay gallery.
- Show or hide the Statistics Overlay.
- Enable or disable the RTX Dynamic Vibrance filter.
- Identify the currently running game.

Connection setup supports both modes but does not authorize additional actions.

## When to use this skill

Use this skill when the user asks for one of the supported application, driver, game-optimization, laptop-feature, Overlay, or connection workflows.

Do not select this skill for Desktop Capture, other Overlay filter mutations, NVIDIA Broadcast, OBS, Xbox Game Bar, or other capture software.

## Inputs

- **Required:** A user request for a supported NVIDIA App query, mutation, or connection diagnostic.
- **Optional:** An explicit target state, game or program identifier, and tool-specific values. Authentication tokens are Hermes's concern; never accept, read, or expose them.

Resolve information in this order: explicit user instructions, fresh live MCP schema or state, then the applicable self-contained skill reference for static contract details. Never treat a previous tool result as current state.

## Prerequisites

- Windows host with NVIDIA App installed and its NvContainer-hosted MCP plugin running.
- Standard NVIDIA App executable path: `%ProgramFiles%\NVIDIA Corporation\NVIDIA App\CEF\NVIDIA App.exe`.
- Hermes has connected the `nvidia-app` server from this plugin: its tools appear as `mcp__nvidia_app__nvapp_*` in the deferred tool catalog. See [references/connection.md](references/connection.md).
- NVIDIA In-Game Overlay is enabled, running, and ready before any `nvapp_overlay_` call.

MCP server readiness and Overlay readiness are separate. A successful MCP connection does not establish that Overlay tools are ready.

## Instructions

1. **Classify the request.** Route general NVIDIA App requests through live tool discovery. Route `nvapp_overlay_` requests through the restricted Overlay workflow. Read-only Overlay status can include fields for excluded features, but that does not authorize changing them.
2. **Use the tools Hermes connected.** Pick the `mcp__nvidia_app__nvapp_*` tool from the deferred tool catalog, read its live schema with `tool_describe`, and call it with `tool_call`, one tool per call. Never register another NVIDIA App MCP entry, and never open a connection yourself: no loopback HTTP requests, no stdio bridge, no reading `server.json`.
3. **When no `nvapp_` tools are listed, say so and stop.** Relay the sentence Hermes gives for the server (the unavailable line in the catalog or `tool_search` result, the same one the Plugins tab shows). Do not search NVIDIA's folders for ports or tokens, and do not name a cause Hermes did not report. See [references/connection.md](references/connection.md).
4. **Discover general tools.** For a non-Overlay request, read [references/general-tools.md](references/general-tools.md) before selecting or calling one of its seven documented public tools, and confirm the live schema with `tool_describe`. Select only a listed tool whose description, schema, and annotations most narrowly match the user's in-scope intent, and follow any narrower live schema and annotations.
5. **Resolve an Overlay target state.** For an explicit start, stop, enable, disable, show, or hide request, call the mapped mutation directly. For a true toggle with no target state, read status once and invert only the corresponding Boolean.
6. **Validate the arguments.** For general tools, follow [references/general-tools.md](references/general-tools.md) and any narrower live schema. For restricted Overlay tools, use exactly the mapped fields below. Never invent unsupported arguments.
7. **Execute in request order.** Fulfill compound requests by issuing each supported operation as its own tool call in the user's order. Make only the calls needed for the requested operations. Respect the access tier and any consent decision; never raise access or enable another feature as a workaround.
8. **Interpret the result literally.** Report only returned fields and outcomes. Overlay mutations return a human-readable message; report that message without inventing structured success fields. If a mutation message is ambiguous, state that the outcome is not independently confirmed instead of making a follow-up Overlay status call solely to verify it.

## Connecting

Hermes connects NVIDIA App's MCP server from this plugin. It reads the current URL and token from `%LOCALAPPDATA%\NVIDIA Corporation\NVIDIA App\McpServer\server.json` on every connection, so a new port or token after an NVIDIA App restart needs nothing from you. There is no other connection path in Hermes: no client entry to add, no direct HTTP, no stdio bridge.

If NVIDIA App restarts its MCP server while a call is in flight, that call fails with a session-expired error and an unknown outcome; Hermes has already reconnected. Repeat a read once. Ask before repeating a mutation.

## General NVIDIA App operations

Read [references/general-tools.md](references/general-tools.md) before selecting or calling a general NVIDIA App tool. It contains the seven supported tool names, exact arguments, enums, conditional schemas, and prerequisite checks.

Use only a documented tool that Hermes lists for this session. The packaged instructions are self-contained and do not depend on repository-internal schema sources.

## Restricted Overlay operations

Use only the tools in this table and the authorized arguments shown here:

| User intent | Tool | Arguments |
|---|---|---|
| Read overall Overlay status | `nvapp_overlay_get_status` | `{}` |
| Start recording | `nvapp_overlay_capture` | `{ "action": "toggle_recording", "enable": true }` |
| Stop and save recording | `nvapp_overlay_capture` | `{ "action": "toggle_recording", "enable": false }` |
| Enable Instant Replay | `nvapp_overlay_capture` | `{ "action": "toggle_instant_replay", "enable": true }` |
| Disable Instant Replay | `nvapp_overlay_capture` | `{ "action": "toggle_instant_replay", "enable": false }` |
| Save Instant Replay | `nvapp_overlay_capture` | `{ "action": "save_instant_replay" }` |
| Enable Highlights | `nvapp_overlay_capture` | `{ "action": "toggle_highlights", "enable": true }` |
| Disable Highlights | `nvapp_overlay_capture` | `{ "action": "toggle_highlights", "enable": false }` |
| Capture a screenshot | `nvapp_overlay_capture` | `{ "action": "capture_screenshot" }` |
| Show Statistics Overlay | `nvapp_overlay_configure_stats` | `{ "enable": true }` |
| Hide Statistics Overlay | `nvapp_overlay_configure_stats` | `{ "enable": false }` |
| Enable RTX Dynamic Vibrance | `nvapp_overlay_configure_filters` | `{ "filter": "rtx_dvc", "enable": true }` |
| Disable RTX Dynamic Vibrance | `nvapp_overlay_configure_filters` | `{ "filter": "rtx_dvc", "enable": false }` |
| Get current game | `nvapp_overlay_get_current_game_info` | `{}` |

Never invoke `toggle_desktop_capture`. For `nvapp_overlay_configure_filters`, use only the `rtx_dvc` filter value.

## Decision rules

- If this session's catalog has no `nvapp_` tools, relay Hermes's sentence for the server and stop; never connect by another path.
- If a tool returns an error, report it with its code. Never look for the same data in NVIDIA's files, caches, or databases.
- For a true request to toggle recording, Instant Replay, Highlights, Statistics Overlay, or RTX Dynamic Vibrance, call `nvapp_overlay_get_status` once and invert only `recordingActive`, `instantReplayEnabled`, `highlightsEnabled`, `statsOverlayEnabled`, or `rtxDvc`, respectively.
- If the required status field is absent, ask whether to enable or disable instead of guessing. Never convert an omitted field to `false`.
- `nvapp_overlay_capture` accepts one action, not an action list.
- Do not add `enable` to `save_instant_replay` or `capture_screenshot`.
- Do not omit `enable` from `toggle_recording`, `toggle_instant_replay`, `toggle_highlights`, or `nvapp_overlay_configure_stats`.
- Pass both `filter: "rtx_dvc"` and `enable` to `nvapp_overlay_configure_filters`; never invent another filter value.
- For a mixed request, execute independent supported operations in order and explain or skip unsupported operations; an unsupported sibling request must not block a fully specified supported action.
- When an unsupported qualifier modifies an otherwise supported state-changing operation, explain the limitation and ask whether to proceed with that supported subset before making its mutation call.
- `running: false` means no current game was identified. Do not invent `gameName` or `processId`. Report `fullscreen` only when it is returned.

## Output Format

- Follow the user's requested format; otherwise give a concise human-readable result.
- For reads, report only structured fields that are present and distinguish an omitted field from `false` or `null`.
- For failures, state that the operation failed and preserve the returned error code, retryability, and useful guidance.
- Never expose authentication material. When protocol-level detail is needed, show only the request or response shape and replace tokens, authorization headers, and other secrets with placeholders such as `<redacted-token>`.

## Limitations

- Installed NVIDIA App versions and access levels can expose different general tools and output contracts; the tools Hermes lists for this session and their live schemas are authoritative.
- MCP readiness does not guarantee Overlay readiness, and a successful mutation message does not prove more than the returned result.
- The restricted workflow cannot mutate Desktop Capture or filters other than RTX Dynamic Vibrance, choose screenshot format or destination, or configure Statistics Overlay layout and styling.
- Missing fields are unknown, not implicit false values, and unavailable tools or backend timeouts must not be replaced with inferred data.

## Examples

### Get driver status

For a request such as "Show my NVIDIA driver status," find `mcp__nvidia_app__nvapp_client_get_driver_status` in the deferred tool catalog and confirm with `tool_describe` that its input schema is an empty object. If no `nvapp_` tools are listed, relay Hermes's sentence for the server and stop. If the other `nvapp_` tools are listed but this one is not, explain that the connected NVIDIA App version or access level does not expose this workflow; do not substitute a similarly named tool without validating its live schema.

Invoke:

```json
{
  "name": "nvapp_client_get_driver_status",
  "arguments": {}
}
```

Use the returned structured fields literally:

- Report `systemType`, `installedDriver.version`, optional `installedDriver.channel`, and `installedDriver.availableActions`.
- Report `preferredChannel`.
- For each item in `recommendedDrivers`, report `name`, `version`, `channel`, `releaseDate`, `isUpdateAvailable`, and `availableActions`.
- If `previouslyInstalledDriver` is `null`, state that NVIDIA App reports no rollback driver is available. Otherwise, report its `name`, `version`, `releaseDate`, and `availableActions`.

This tool is read-only. Do not invoke a driver mutation; none is included in this seven-tool scope.

### Start recording with an explicit target state

Call the mutation directly because the requested target state is already known:

```json
{ "name": "nvapp_overlay_capture", "arguments": { "action": "toggle_recording", "enable": true } }
```

Do not read status before the call or issue a verification read afterward.

### Toggle Instant Replay without a target state

First call `nvapp_overlay_get_status` with `{}`. If `instantReplayEnabled` is present, call `nvapp_overlay_capture` once with `enable` set to its opposite. If the field is absent, ask whether to enable or disable Instant Replay and make no mutation yet.

### Handle an unsupported screenshot qualifier

For “Take a PNG screenshot in `D:\Shots`,” explain that the tool cannot select the format or destination. Ask whether to capture to the Overlay gallery. After confirmation, call:

```json
{ "name": "nvapp_overlay_capture", "arguments": { "action": "capture_screenshot" } }
```

## Troubleshooting

| Error or symptom | Likely cause | Response |
|---|---|---|
| No `nvapp_` tools in the catalog | Hermes has not connected the server in this session | Relay Hermes's sentence for the server; do not connect manually or search NVIDIA's folders. |
| Session-expired transport error, outcome unknown | NVIDIA App restarted its MCP server; Hermes reconnected | Repeat a read once; ask before repeating a mutation. |
| `service_disabled` | Persistent MCP server access is disabled | Ask the user to enable MCP server access in NVIDIA App Settings. |
| `overlay_not_available` | MCP is connected but In-Game Overlay is not ready | Ask the user to enable or start In-Game Overlay, then retry only if requested. |
| `overlay_timeout` | Overlay did not answer before the deadline | Preserve `retriable`; retry at most once when the result allows retrying and the retry remains within the request, then report the failure and ask before trying again. |
| `access_level_restricted` | Current MCP access ceiling blocks the tool | Report the restriction; do not raise access implicitly. |
| `isError: true` or another backend/validation failure | The requested operation did not succeed | Preserve the message and error code; do not infer data or report success. |

Overlay mutations return a human-readable message rather than structured success fields. Report that message literally and do not infer additional state. If saving Instant Replay reports that it is disabled, ask before enabling it. If capture requires Desktop Capture, report the limitation rather than enabling Desktop Capture.

## References

- Read [references/connection.md](references/connection.md) for how Hermes connects the server, what to do when its tools are missing or a call hits a restart, readiness, and connection troubleshooting.
- Read [references/general-tools.md](references/general-tools.md) for live discovery, schema use, routing, and result handling for non-Overlay NVIDIA App operations.
- Read [references/overlay-capture.md](references/overlay-capture.md) for recording, Instant Replay, Highlights, screenshots, unsupported qualifiers, access, and capture errors.
- Read [references/overlay-state.md](references/overlay-state.md) for status fields, true toggles, Statistics Overlay visibility, RTX Dynamic Vibrance, and current-game lookup.
- Read [references/mcp-tool-contract.md](references/mcp-tool-contract.md) when exact restricted schemas, outputs, access tiers, or error forms are needed.
