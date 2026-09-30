Layout split into nvidia-app/ and nvidia-broadcast/ on 2026-09-22; rows below predate the split.
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
| x64 desktop, App 11.0.9.528 (= drop x64 build), Broadcast 2.3.0.12830 (drop installer 2.3.0.67997638 not yet applied), 2026-09-22 16:54 | `win32 / amd64 / soc=False / interactive=False` | both servers `available` with real versions | accepted | `nvidia-app: connecting to http://127.0.0.1:47985/mcp` (from `server.json`) → **12 tools**; `nvidia-broadcast` on `:18100` → **10 tools**; `MCP: registered 22 tool(s) from 2 server(s)` | query matched one nvidia-app tool (overlay stats); catalog preamble carried the broadcast unavailable line | **`server.json` has a token; connected with `Authorization: Bearer`; occurrences of the token value in the session logs: 0** | redaction path proven on hardware. Same `interactive_session` note as the laptop (Hermes in session 0, UI in session 1, port reachable). |

## rtx-remix against the Sep 28 drop build

Toolkit `rtx_remix@1.5.2-0+mr1420.29126.d6f84ac2` (mcp.core 1.3.0), unmodified, `lightspeed.app.trex.stagecraft.headless.bat` in session 1 on the ARM64 laptop (x64 emulation, renderer on the laptop's NVIDIA GPU, `SERVICE_READY … port=8012` at 23.9 s). Hermes upstream main `9cbc6a5ac0` over SSH (session 0), fresh `HERMES_HOME`, Nous OAuth, `anthropic/claude-opus-5.5`. Plugin files as in this change, except one skill line (the tool prefix), corrected after these runs; the model did not load the skill in any run. Test project: a scratch copy of the Toolkit's own `lightspeed.project_manager.service/data/tests/usd/full_project`.

| check | result | notes |
|---|---|---|
| protocol smoke (MCP Inspector over `ssh -L 8012`) | 35 tools; open → get_layers → create_layer → present → remove_layer → absent → tree identical → close | `create_layer` writes the layer file and `remove_layer` leaves it on disk. `remix_create_layer` has a dangling `$ref` to `#/components/schemas/LayerType`. |
| `plugins validate` / `doctor --ci` (macOS, same main) | pass | static only; no Mac install run for this build |
| install (`file://` git repo) | installed to `plugins/rtx-remix` | `plugins enable` in a fresh ARM64 home made PM provision native build tools and installed VS 2022 Build Tools machine-wide; enabled via `plugins.enabled` in `config.yaml` instead |
| session start, Toolkit up | `MCP server 'rtx-remix' (HTTP): registered 39 tool(s)`, prefix `mcp__rtx_remix__` | 35 Remix tools + 4 MCP utility wrappers. Startup prints `Unknown toolsets: rtx-remix` (upstream #119457). |
| read turn | `tool_search` → `tool_call → mcp__rtx_remix__remix_get_loaded_project` → relayed `404 No project is currently loaded` verbatim | session `20260930_205314_e86b13` |
| write turn | `tool_describe` + 7 `tool_call`s (open, get_layers, create_layer, get_layers, remove_layer, get_layers, close); all OK, tree restored | the model noted the layer file may remain on disk (it did; removed by hand). Session `20260930_205633_fbe852` |
| session start, Toolkit down | `failed initial connection after 3 attempts, parking until a reconnect is requested`; `registered 0 tool(s)` | no catalog line (no declaration) |
| turn, Toolkit down | correct answer: Toolkit not running, start it, then start a new Hermes session | after `tool_search`, 5 probing calls (search_files, reading the plugin's files, curl to 8012 and 8011, netstat); 226 s. The skill forbids this probing, but the model never loaded it in any turn: portable skills are not in the prompt index. |
