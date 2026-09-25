# hermes-nvidia

This repo holds two Hermes plugins, one per NVIDIA application: `nvidia-app` and `nvidia-broadcast`. Each lives in its own subdirectory as a complete portable plugin (plugin.json, mcp.json, one skill) and is installed independently.

| Plugin | App and minimum version | Server |
|---|---|---|
| `nvidia-app` | NVIDIA App 11.0.0 | streamable-http on loopback; the runtime endpoint is published by the app in its McpServer `server.json` |
| `nvidia-broadcast` | NVIDIA Broadcast 2.3.0 | streamable-http on loopback; the gateway binds the first free port from 18100 and records it in `%APPDATA%/nvidia-broadcast/gateway.json` |

Install through the Hermes plugin catalog (Hermes 0.21.4 or newer), which pins each plugin to a reviewed commit:

```
hermes plugins install nvidia-app
hermes plugins install nvidia-broadcast
```

Desktop deep link form:

```
hermes://plugin/install?catalog=nvidia-app
hermes://plugin/install?catalog=nvidia-broadcast
```

To follow `main` instead, install from the repo subdirectory. Hermes treats this as a custom (unreviewed) source:

```
hermes plugins install NousResearch/hermes-nvidia/nvidia-app
hermes plugins install NousResearch/hermes-nvidia/nvidia-broadcast
```

Windows only. The corresponding application must be installed at the minimum version or the install refuses; its tools appear while the application is running.

Evidence from real hardware per core change: `EVIDENCE.md`.
