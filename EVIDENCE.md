# Evidence

One table per machine per Hermes change, measured on hardware with a temporary `HERMES_HOME`.

## Baseline: this repo against Hermes main (no declaration support yet)

| machine | install | nvidia-app connects | nvidia-broadcast connects | skills listed | notes |
|---|---|---|---|---|---|
| macOS arm64 (dev laptop), Hermes main 969872ebaa | `plugins validate` passed (scan caution: `dump_all_env` strings in vendor evals.json); `enable` ok; `plugins list` shows `hermes-nvidia · enabled · 0.1.0 · user` | not attempted (no app; loopback refused) | not attempted (no app) | registered via portable loader | `extensions["com.nousresearch.hermes"]` ignored by main without warning, as the spec requires. Temp HERMES_HOME, removed after. |
