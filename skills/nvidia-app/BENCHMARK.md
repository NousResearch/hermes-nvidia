# Skill Benchmark: nvidia-app

> ⚠️ **Overall verdict: INCOMPLETE — Required evidence is missing**

One or more required evaluation tiers did not complete, so this benchmark is not publication-complete.

## Evaluation Metadata

- Skill: `nvidia-app`
- Evaluation date: 2026-09-08
- Evaluator version: `1.5.4`
- Agents: Claude Code (`aws/anthropic/bedrock-claude-opus-4-8`), Codex (`openai/openai/gpt-5.5`)
- Tasks: 29 evaluation tasks (26 positive, 3 negative)
- Dataset digest: `sha256:17a57f75be2bac7375a22afad8bfb6ca9349c1cd9681797ac4729ca7ef11daf1` (skill-evaluator-dataset-snapshot/1)
- Attempts per task: 1
- Environment: `k8s-sandbox`
- Tier 2 evidence: required for publication
- Tier 3 evidence: required for publication

Each task attempt ran in its own isolated sandbox pod.

## What This Report Answers

The three-tier evaluation checks whether the skill:

- is safe to use;
- produces correct answers;
- is discovered and activated when needed;
- helps the agent complete the user's goal and expected workflow; and
- avoids wasted skill and tool usage.

## Results at a Glance

| Measure | Claude Code (Baseline → Skill Uplift) | Codex (Baseline → Skill Uplift) |
|---|---:|---:|
| Overall | 81.6% — baseline ran, but no comparable score was available; uplift unavailable | 70.1% — baseline ran, but no comparable score was available; uplift unavailable |
| Security | 100.0% → 79.3% (-20.7 points) | 82.8% → 72.4% (-10.4 points) |
| Correctness | 13.8% → 90.3% (+76.5 points) | 17.2% → 60.7% (+43.5 points) |
| Discoverability | 100.0% — baseline ran, but no comparable score was available; uplift unavailable | 87.1% — baseline ran, but no comparable score was available; uplift unavailable |
| Effectiveness | 26.6% → 43.7% (+17.1 points) | 27.2% → 35.7% (+8.5 points) |
| Efficiency | 94.6% — baseline ran, but no comparable score was available; uplift unavailable | 94.5% — baseline ran, but no comparable score was available; uplift unavailable |

**How to read this table:** baseline is the same task attempted without the target skill. Scores are rounded to one decimal; threshold-adjacent values use additional precision so their displayed band matches the verdict. Uplift is derived from those displayed scores and shown in percentage points.

Example: `47.0% → 92.0% (+45.0 points)` means the skill-assisted run scored 92.0%, 45.0 percentage points above its 47.0% no-skill baseline.

A partial dimension was calculated from only the available configured signals; review the detailed report before relying on it.

## Token Usage

Actual Tier 3 execution usage is reported for every observed agent/case pair and both conditions.

| Agent | Dataset case | With skill | Without skill | Delta | Change | Coverage |
|---|---|---:|---:|---:|---:|---|
| claude-code | All cases | 4,905,846 | 2,229,367 | +2,676,479 | +120.06% | skill 29/29; base 29/29 |
| claude-code | nvidia-app-applications-list-024 | 279,526 | 152,672 | +126,854 | +83.09% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-compound-010 | 270,276 | 152,714 | +117,562 | +76.98% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-connection-auth-013 | 104,264 | 93,406 | +10,858 | +11.62% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-connection-default-012 | 104,258 | 30,198 | +74,060 | +245.25% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-current-game-008 | 150,011 | 29,495 | +120,516 | +408.60% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-driver-discovery-018 | 195,077 | 119,867 | +75,210 | +62.74% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-driver-release-notes-026 | 195,590 | 119,051 | +76,539 | +64.29% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-game-optimization-027 | 197,244 | 327,607 | -130,363 | -39.79% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-game-optimization-discovery-019 | 199,184 | 29,994 | +169,190 | +564.08% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-highlights-disable-020 | 146,989 | 60,565 | +86,424 | +142.70% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-highlights-enable-014 | 189,839 | 29,779 | +160,060 | +537.49% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-instant-replay-disable-023 | 189,572 | 29,592 | +159,980 | +540.62% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-instant-replay-enable-003 | 191,689 | 29,734 | +161,955 | +544.68% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-instant-replay-save-005 | 189,791 | 121,390 | +68,401 | +56.35% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-instant-replay-toggle-004 | 189,901 | 90,105 | +99,796 | +110.76% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-laptop-global-read-028 | 195,742 | 59,816 | +135,926 | +227.24% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-laptop-global-set-029 | 198,704 | 30,064 | +168,640 | +560.94% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-launch-025 | 197,421 | 29,242 | +168,179 | +575.13% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-negative-broadcast-016 | 65,705 | 29,917 | +35,788 | +119.62% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-negative-desktop-capture-015 | 65,009 | 30,403 | +34,606 | +113.82% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-negative-obs-017 | 30,199 | 59,991 | -29,792 | -49.66% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-record-start-001 | 191,149 | 29,292 | +161,857 | +552.56% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-record-stop-002 | 141,461 | 29,780 | +111,681 | +375.02% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-rtx-dvc-enable-021 | 189,940 | 60,435 | +129,505 | +214.29% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-rtx-dvc-toggle-022 | 153,047 | 121,618 | +31,429 | +25.84% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-screenshot-006 | 197,381 | 59,528 | +137,853 | +231.58% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-stats-007 | 191,884 | 90,938 | +100,946 | +111.01% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-status-009 | 192,629 | 122,142 | +70,487 | +57.71% | skill 1/1; base 1/1 |
| claude-code | nvidia-app-unsupported-qualifier-011 | 102,364 | 60,032 | +42,332 | +70.52% | skill 1/1; base 1/1 |
| codex | All cases | 4,009,246 | 3,015,907 | +993,339 | +32.94% | skill 29/29; base 29/29 |
| codex | nvidia-app-applications-list-024 | 132,296 | 559,143 | -426,847 | -76.34% | skill 1/1; base 1/1 |
| codex | nvidia-app-compound-010 | 110,111 | 89,560 | +20,551 | +22.95% | skill 1/1; base 1/1 |
| codex | nvidia-app-connection-auth-013 | 47,536 | 77,788 | -30,252 | -38.89% | skill 1/1; base 1/1 |
| codex | nvidia-app-connection-default-012 | 69,533 | 95,534 | -26,001 | -27.22% | skill 1/1; base 1/1 |
| codex | nvidia-app-current-game-008 | 333,577 | 179,732 | +153,845 | +85.60% | skill 1/1; base 1/1 |
| codex | nvidia-app-driver-discovery-018 | 130,185 | 46,159 | +84,026 | +182.04% | skill 1/1; base 1/1 |
| codex | nvidia-app-driver-release-notes-026 | 160,375 | 57,335 | +103,040 | +179.72% | skill 1/1; base 1/1 |
| codex | nvidia-app-game-optimization-027 | 147,536 | 740,168 | -592,632 | -80.07% | skill 1/1; base 1/1 |
| codex | nvidia-app-game-optimization-discovery-019 | 128,617 | 32,309 | +96,308 | +298.08% | skill 1/1; base 1/1 |
| codex | nvidia-app-highlights-disable-020 | 147,593 | 98,037 | +49,556 | +50.55% | skill 1/1; base 1/1 |
| codex | nvidia-app-highlights-enable-014 | 146,709 | 56,296 | +90,413 | +160.60% | skill 1/1; base 1/1 |
| codex | nvidia-app-instant-replay-disable-023 | 111,961 | 27,028 | +84,933 | +314.24% | skill 1/1; base 1/1 |
| codex | nvidia-app-instant-replay-enable-003 | 153,451 | 31,479 | +121,972 | +387.47% | skill 1/1; base 1/1 |
| codex | nvidia-app-instant-replay-save-005 | 108,191 | 27,353 | +80,838 | +295.54% | skill 1/1; base 1/1 |
| codex | nvidia-app-instant-replay-toggle-004 | 141,725 | 71,217 | +70,508 | +99.00% | skill 1/1; base 1/1 |
| codex | nvidia-app-laptop-global-read-028 | 129,638 | 42,007 | +87,631 | +208.61% | skill 1/1; base 1/1 |
| codex | nvidia-app-laptop-global-set-029 | 128,271 | 60,235 | +68,036 | +112.95% | skill 1/1; base 1/1 |
| codex | nvidia-app-launch-025 | 87,490 | 27,109 | +60,381 | +222.73% | skill 1/1; base 1/1 |
| codex | nvidia-app-negative-broadcast-016 | 55,046 | 17,827 | +37,219 | +208.78% | skill 1/1; base 1/1 |
| codex | nvidia-app-negative-desktop-capture-015 | 50,371 | 100,271 | -49,900 | -49.77% | skill 1/1; base 1/1 |
| codex | nvidia-app-negative-obs-017 | 142,692 | 136,967 | +5,725 | +4.18% | skill 1/1; base 1/1 |
| codex | nvidia-app-record-start-001 | 108,087 | 27,395 | +80,692 | +294.55% | skill 1/1; base 1/1 |
| codex | nvidia-app-record-stop-002 | 127,476 | 55,492 | +71,984 | +129.72% | skill 1/1; base 1/1 |
| codex | nvidia-app-rtx-dvc-enable-021 | 153,778 | 53,065 | +100,713 | +189.79% | skill 1/1; base 1/1 |
| codex | nvidia-app-rtx-dvc-toggle-022 | 212,014 | 45,530 | +166,484 | +365.66% | skill 1/1; base 1/1 |
| codex | nvidia-app-screenshot-006 | 104,941 | 72,723 | +32,218 | +44.30% | skill 1/1; base 1/1 |
| codex | nvidia-app-stats-007 | 468,387 | 41,127 | +427,260 | +1038.88% | skill 1/1; base 1/1 |
| codex | nvidia-app-status-009 | 129,752 | 105,257 | +24,495 | +23.27% | skill 1/1; base 1/1 |
| codex | nvidia-app-unsupported-qualifier-011 | 41,907 | 41,764 | +143 | +0.34% | skill 1/1; base 1/1 |
| ALL AGENTS | Dataset aggregate | 8,915,092 | 5,245,274 | +3,669,818 | +69.96% | skill 58/58; base 58/58 |

Prompt tokens include cached reads, so total tokens are `prompt + completion` (cached is not added twice). The Efficiency score uses `(prompt - cached) + completion`. N/A means the relevant trajectory counters were not available; coverage is never estimated.

## Tier Status

| Tier | Purpose | Status | Evidence |
|---|---|---|---|
| Tier 1 | Static validation | **PASSED** | 1 validator(s); 0 finding(s) |
| Tier 2 | Semantic deduplication | **NOT RUN** | No result was recorded |
| Tier 3 | Live agent evaluation | **PASS** | 2 agent(s); 29 task(s) |

## Findings and Observations

<details>
<summary>Show detailed findings and successful checks</summary>

- Schema & Repository Governance: Found skill manifest: SKILL.md
- AGENT_EVAL: Tier 3 evaluation complete: verdict PASS; best agent claude-code

</details>

## Scoring Methodology

<details>
<summary>Show dimension definitions, source signals, and thresholds</summary>

| Dimension | Question | Scored signals |
|---|---|---|
| Security | Is it safe to use? | `security` (100%) |
| Correctness | Is the answer correct? | `accuracy` (100%) |
| Discoverability | Was the right skill loaded when needed? | `skill_execution` (100%) |
| Effectiveness | Did the skill help complete the task? | `goal_accuracy` (50%) + `behavior_check` (50%) |
| Efficiency | Did it avoid wasted tool calls and token usage? | `skill_efficiency` (50%) + `token_efficiency` (50%) |

- Dimension bands: PASS at 50% or above; NEUTRAL from 40% to below 50%; FAIL below 40%.
- Overall Tier 3 lift: PASS at +5 points or more; FAIL at -10 points or less; values between those bands are NEUTRAL.
- Overall verdict: PASS only when every configured dimension passes for at least one supported agent. Lift is reported as diagnostic evidence and does not override this gate.
- The 50% attempt pass threshold is a separate per-task gate; it is not the dimension pass threshold.
- Effectiveness is the equal-weight mean of goal completion (`goal_accuracy`) and expected workflow adherence (`behavior_check`).
- Efficiency is 50% tool-call productivity (the backward-compatible `skill_efficiency` wire id) and 50% `token_efficiency`. Positive-case skill routing is scored under Discoverability, not Efficiency; a negative case without a routing target is N/A. N/A sources are omitted, remaining weights are renormalized, and the dimension is marked partial.

Signals present in this run:

- `security` (Security): unsafe operations, secret leakage, and unauthorized access.
- `skill_execution` (Skill Execution): whether the expected skill was selected, decoys were avoided, and the workflow executed.
- `skill_efficiency` (Tool Productivity): tool-call productivity (legacy wire id; routing is scored under Discoverability).
- `accuracy` (Accuracy): final-answer correctness against the reference answer.
- `goal_accuracy` (Goal Accuracy): whether the user's goal was achieved.
- `behavior_check` (Behavior Check): whether the expected workflow behavior was followed.
- `token_efficiency` (Token Efficiency): actual uncached prompt plus completion usage (50% of Efficiency).

</details>

## Freshness

Regenerate this benchmark when the skill, evaluation dataset, target agent/model, evaluator version, environment, or scoring policy changes.
