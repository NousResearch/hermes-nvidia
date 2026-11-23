# hermes-nvidia

This repo holds three Hermes plugins. `nvidia-app` and `nvidia-broadcast` each connect Hermes to one NVIDIA application and are complete portable plugins (plugin.json, mcp.json, one skill). `openshell` runs a profile's Hermes backend in an NVIDIA OpenShell sandbox. Each lives in its own subdirectory and is installed independently.

| Plugin | App and minimum version | Server |
|---|---|---|
| `nvidia-app` | NVIDIA App 11.0.0 | streamable-http on loopback; the runtime endpoint is published by the app in its McpServer `server.json` |
| `nvidia-broadcast` | NVIDIA Broadcast 2.3.0 | streamable-http on loopback; the gateway binds the first free port from 18100 and records it in `%APPDATA%/nvidia-broadcast/gateway.json` |
| `openshell` | NVIDIA OpenShell v0.1.9 on Linux (Docker) or Windows 11 (MXC, NVIDIA's signed Windows package); the builds are pinned in `openshell/runtime/pins.json` | none; runs a profile's Hermes backend in an OpenShell sandbox (`openshell/README.md`) |

Install from the repo subdirectories:

```
hermes plugins install NousResearch/hermes-nvidia/nvidia-app
hermes plugins install NousResearch/hermes-nvidia/nvidia-broadcast
hermes plugins install NousResearch/hermes-nvidia/openshell
```

Desktop deep link form:

```
hermes://plugin/install?repo=NousResearch/hermes-nvidia/nvidia-app&enable=1
hermes://plugin/install?repo=NousResearch/hermes-nvidia/nvidia-broadcast&enable=1
```

`nvidia-app` and `nvidia-broadcast` are Windows only. The corresponding application must be installed at the minimum version or the install refuses; its tools appear while the application is running.

Evidence from real hardware per core change: `EVIDENCE.md`.
