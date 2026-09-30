# hermes-nvidia

This repo holds three Hermes plugins, one per NVIDIA application: `nvidia-app`, `nvidia-broadcast` and `rtx-remix`. Each lives in its own subdirectory as a complete portable plugin (plugin.json, mcp.json, one skill) and is installed independently.

| Plugin | App and minimum version | Server |
|---|---|---|
| `nvidia-app` | NVIDIA App 11.0.0 | streamable-http on loopback; the runtime endpoint is published by the app in its McpServer `server.json` |
| `nvidia-broadcast` | NVIDIA Broadcast 2.3.0 | streamable-http on loopback; the gateway binds the first free port from 18100 and records it in `%APPDATA%/nvidia-broadcast/gateway.json` |
| `rtx-remix` | RTX Remix Toolkit with the MCP extension on port 8012 (tested: `1.5.2-0+mr1420`) | streamable-http on `127.0.0.1:8012/mcp/`, fixed in `mcp.json`; this Toolkit build publishes no endpoint file |

Install from the repo subdirectories:

```
hermes plugins install NousResearch/hermes-nvidia/nvidia-app
hermes plugins install NousResearch/hermes-nvidia/nvidia-broadcast
```

Desktop deep link form:

```
hermes://plugin/install?repo=NousResearch/hermes-nvidia/nvidia-app&enable=1
hermes://plugin/install?repo=NousResearch/hermes-nvidia/nvidia-broadcast&enable=1
```

Windows only. The corresponding application must be installed at the minimum version or the install refuses; its tools appear while the application is running.

`rtx-remix` differs. The Toolkit is a package you unpack anywhere, with no install record, so the install does not check for it: it succeeds on any OS, and the tools appear only while the Toolkit is running. Install it from the repo subdirectory:

```
hermes plugins install NousResearch/hermes-nvidia/rtx-remix
```

Start the Toolkit before the Hermes session: the windowed app, or `lightspeed.app.trex.stagecraft.headless.bat` from the package folder. Hermes connects at session start and stops retrying after three failed attempts. Builds from the current toolkit-remix `main` use port 18014 and an endpoint file; this plugin does not support them yet.

Evidence from real hardware per core change: `EVIDENCE.md`.
