# hermes-nvidia

Hermes plugin carrying the NVIDIA App and NVIDIA Broadcast MCP servers and their skills. Portable Agent Plugin (agent-plugins.org 1.0.0): no code, two servers, two skills.

Windows only. Each server's tools are offered while its application is installed at the required version; the Broadcast server exists only while the Broadcast UI is open in a desktop session.

Hermes-specific gating lives under `extensions["com.nousresearch.hermes"]` in `plugin.json`; other Agent Plugins clients ignore it by spec. `mcp.json` is unmodified spec shape.

Evidence from real hardware per core change: `EVIDENCE.md`.
