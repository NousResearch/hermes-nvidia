# NVIDIA App MCP Connection (Hermes)

## Hermes owns the connection

The `nvidia-app` plugin declares NVIDIA App's MCP server, and Hermes connects it. You never register, configure, or open a connection yourself.

- Hermes reads `%LOCALAPPDATA%\NVIDIA Corporation\NVIDIA App\McpServer\server.json` on every connection and uses its `http` URL and `token`. The URL in the plugin's `mcp.json` is a placeholder; the port NVIDIA App publishes can differ between builds and machines.
- The connected tools are named `mcp__nvidia_app__nvapp_*`. Find them in the deferred tool catalog, read a schema with `tool_describe`, and call one with `tool_call`.
- The token never appears in a tool argument, a transcript, or a log, and you never need it.

## When no `nvapp_` tools are listed

Hermes lists only what is connected and offerable. When the catalog has no `nvapp_` tools:

1. Report the sentence Hermes gives for the server: the unavailable line in the tool catalog or `tool_search` result, which is the same sentence the Plugins tab in Settings shows. It names one user action, such as starting NVIDIA App.
2. Stop there. Do not connect to a loopback port, do not run the stdio bridge, do not script HTTP requests, do not read `server.json`, and do not search NVIDIA's folders for ports, tokens, or databases. None of these makes the tools appear in this session, and a manual transport bypasses the approvals Hermes applies to these tools.
3. Do not name a cause Hermes did not report. In particular, do not tell the user to change an NVIDIA App setting unless a tool returned `service_disabled` or `overlay_not_available`.

## When a tool call fails

- **NVIDIA App restarted its MCP server.** The server's host process can restart on its own; each restart issues a new token on the same port. Hermes reconnects with the new token. The call in flight at that moment fails with a message that the transport session expired and the outcome is unknown. For a read (status, driver, applications, laptop features, current game), call it again once. For a mutation, tell the user the outcome is unknown and ask before repeating it.
- **The tool returned an error** (for example `Application_GetState_4 failed with 4`). Report the error and its code. Do not look for the same information in NVIDIA's files, caches, or databases.

## Readiness sequence

Connection success and Overlay success are separate:

1. NVIDIA App's NvContainer-hosted MCP plugin runs.
2. Its HTTP transport starts and `server.json` is written.
3. The MCP server readiness event is signaled.
4. NVIDIA In-Game Overlay independently signals its own readiness event.

The restricted Overlay tools in this skill can return `overlay_not_available` even after the MCP connection succeeds. Non-Overlay NVIDIA App tools do not depend on Overlay readiness.

## Troubleshooting

| Symptom | Likely cause | Response |
|---|---|---|
| No `nvapp_` tools, and Hermes reports NVIDIA App is not running | NVIDIA App or its MCP host is stopped | Relay Hermes's sentence: start NVIDIA App, then try again. |
| No `nvapp_` tools, and Hermes reports nothing about `nvidia-app` | The server is not connected in this session | Say the NVIDIA App tools are not available in this chat and suggest a new chat; do not connect manually. |
| A call fails with a session-expired transport error | NVIDIA App restarted its MCP server | Repeat a read once; ask before repeating a mutation. |
| A tool returns `service_disabled` | NVIDIA App's MCP server access is disabled | Ask the user to enable MCP server access in NVIDIA App Settings. |
| Overlay calls return `overlay_not_available` | In-Game Overlay is disabled or not running | Ask the user to enable NVIDIA App Settings > Features > In-Game Overlay, then retry if they ask. |
| A tool returns `access_level_restricted` | The MCP access ceiling blocks the tool | Report the restriction; do not raise access. |
