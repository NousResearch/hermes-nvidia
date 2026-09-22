# Evidence

One table per machine per Hermes change, measured on hardware with a temporary `HERMES_HOME`.

## Baseline: this repo against Hermes main (no declaration support yet)

| machine | install | nvidia-app connects | nvidia-broadcast connects | skills listed | notes |
|---|---|---|---|---|---|
| macOS arm64 (dev laptop), Hermes main 969872ebaa | `plugins validate` passed (scan caution: `dump_all_env` strings in vendor evals.json); `enable` ok; `plugins list` shows `hermes-nvidia · enabled · 0.1.0 · user` | not attempted (no app; loopback refused) | not attempted (no app) | registered via portable loader | `extensions["com.nousresearch.hermes"]` ignored by main without warning, as the spec requires. Temp HERMES_HOME, removed after. |

## Stack tip (PR1 → PR2 → PR4 → PR5 → PR6) against this repo at d7abde1

Hermes tip `76d568c80a` (PR6 head; PR5 at `17e019e0d7`). Fresh `HERMES_HOME`, `uv run hermes --extra mcp`, session model `xiaomi/mimo-v2.6-pro-ultraspeed`, machines over SSH (session 0).

| machine | host facts | validate | install | session start | tool_search (model) | token | notes |
|---|---|---|---|---|---|---|---|
| ARM64 laptop, drop builds (App 11.0.9.535, Broadcast 2.3.0.12594), 2026-09-22 16:51 | `win32 / arm64 / soc=True / interactive=False` | both servers `available` with real versions (registry + PE) | accepted | `nvidia-app: connecting to http://127.0.0.1:13508/mcp` (port from `server.json`, not the mcp.json placeholder) → **12 tools**; `nvidia-broadcast` on `:18100` → **10 tools**; `MCP: registered 22 tool(s) from 2 server(s)` | listed both sources with counts; relayed the catalog line verbatim: *"nvidia-broadcast needs an interactive desktop session. Open an interactive desktop session and start nvidia-broadcast, then try again."* | `server.json` has no token on this build; connected without `Authorization` | Broadcast connected yet flagged unavailable because Hermes ran in session 0 while the UI ran in session 1: `interactive_session` is stricter than the loopback reality. Open design question for PR5. Two PR5 bugs found and fixed by this run: `fields` was required (now defaults), a malformed liveness block crashed the server task (now degrades to static with a warning). |
| macOS arm64 (dev laptop), same tip | `darwin` | both servers `unsupported_os` | **refused**: `Plugin 'hermes-nvidia' server 'nvidia-app' is unavailable: unsupported_os.` nothing on disk | n/a | n/a | n/a | the negative case |

