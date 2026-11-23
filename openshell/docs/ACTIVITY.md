# Activity: what the sandbox allowed and refused

The Sandbox page's **Activity** tab is one live timeline of a profile's sandbox, newest first, with
filters (All, Network, Files, Decisions; Denied only; a period), the enforcer's policy history with
Restore, and an export of the rows shown as OCSF JSON Lines. Code: `launcher/activity.py` (backend),
the `-- activity --` block in `desktop/plugin.js` (page), `tests/test_activity.py`.

## Sources

| Rows | Source | Where it is kept (host only) |
|---|---|---|
| Network: connections and HTTP requests (allowed, denied), policy loads, findings | OpenShell's audit (OCSF) | `<root>/openshell/<profile>/audit/ocsf-<sandbox>-<UTC date>.jsonl` |
| Files: refused reads and writes, and the file tools' writes | Hermes's tool results in the profile's `state.db` (read-only), only while the sandbox ran | read in place; run times in `<state>/activity/runs.jsonl` |
| Decisions: answers to the in-chat access cards, their outcome, removed grants | the launcher's card log | `<state>/cards.jsonl` |
| Sandbox started / stopped | the collector | `<state>/activity/runs.jsonl` |

`<state>` is the launcher's state dir, which the sandbox cannot read or write. OpenShell logs no
per-file events, so file rows come from what the agent's own tools reported; a file the agent changed
through the terminal (for example `echo > f`) shows only if a refusal was reported.

### Keeping the audit on the host

- **Linux:** the driver's `AuditArchive` follows the supervisor's `OCSF-JSON` stderr records and writes
  the archive itself (full OpenShell records, verbatim).
- **Windows:** nothing is saved by OpenShell: `openshell logs` is the gateway's in-memory tail (shorthand
  lines only; the full JSON records go only to the gateway's own stdout), and the supervisor writes no
  file on the host. The launcher's `AuditCollector` polls the driver's events every 3 s while the sandbox
  runs (and before answering the page when the last poll is older than 1.5 s), converts each shorthand
  line to an OCSF record of the class OpenShell uses for it, dedupes by `metadata.uid` (a hash of the
  line's time and text) and appends it. It polls once more just before the driver deletes the sandbox, so
  the tail survives a stop. A launcher killed outright loses at most the last poll interval.
- Both forms are read the same way, so the timeline and export look the same on both platforms, and
  history survives stops, restarts and the switch being turned off (the host backend answers the same
  routes from the same files while the profile runs unsandboxed).

### What the timeline leaves out

The archive keeps everything; the timeline shows rows a person reads: allowed or denied connections and
requests, policy loads and rejections, and findings. OpenShell's relay plumbing (unattributed loopback
opens and closes) and startup configuration chatter stay in the archive only. OpenShell logs one HTTP
request once per engine (L7 and OPA); the timeline shows one row and the export keeps both records.

### Links to chats

File and decision rows carry their chat. A network row links to a chat only when exactly one chat had a
turn running at that moment (from the message times in `state.db`); otherwise it has no link.

## Routes

`GET /api/plugins/openshell/activity` and `.../activity/export`, on the launcher (sandboxed) and the host
dashboard router (unsandboxed). Query: `since`, `until` (Unix seconds; default the last 24 h), `kinds`
(`network,files,decisions`), `denied=1`, `limit` (1 to 2000, default 500). The export answers
`{records, count, filename, truncated, format: "ocsf-jsonl", ocsf_version}`; the page writes one record per
line. Policy history uses the existing `policy/revisions`, `policy/revisions/<n>` and `policy/rollback`
routes (running sandbox only; Restore brings back the revision's network rules, folders are fixed at start).

## OCSF mapping (schema 1.8.0)

| Row | Class | Activity | Notes |
|---|---|---|---|
| Network (Linux) | OpenShell's record, verbatim | as logged | |
| Network (Windows) | NET 4001 Network Activity, HTTP 4002 HTTP Activity, SSH 4007, PROC 1007, FINDING 2004, CONFIG 5019 Device Config State Change | NET: Open 1, Close 2, Reset 3, Fail 4, Refuse 5, Traffic 6, Listen 7; HTTP: by method (Get 3, Post 6, ...); else Other 99 | Converted from the shorthand: `action`/`disposition` (Allowed 1 / Denied 2, Blocked), `status`, `status_detail` (OpenShell's reason), `firewall_rule` {name, type: engine}, `actor.process.name` (the program; pid as logged, 0 on Windows), `dst_endpoint` (domain or ip, port), `http_request` {http_method, url}. `metadata.product` OpenShell Sandbox Supervisor; `metadata.log_source` `openshell logs (shorthand)`; the original line in `unmapped.shorthand` |
| Files | 1001 File System Activity | Read 2, Update 3 | `action` Denied (refusal) or Allowed (file tool write), `file` {path, name}, `actor.app_name` Hermes Agent, `status_detail` the refusal line from the tool result, `unmapped.hermes` {profile, chat, tool, message_id, access}; product Hermes Agent |
| Decisions | 3005 User Access Management | Assign Privileges 1 (allowed until the sandbox is switched off / always), Revoke Privileges 2 (a grant removed on the Sandbox page), Other 99 "Deny" | `user` = the profile whose access changed, `actor.user` = the OS user who answered, `privileges` [`network:<host>:<port>` or `files:<access>:<path>`], `resource`, `unmapped.hermes` {chat, choice, label, card, program, reason, status, request_id, ...} |
| Sandbox started / stopped | 6002 Application Lifecycle | Start 3, Stop 4 | `app` {name: Hermes sandbox, uid: sandbox name} |

Every record has `class_uid`, `category_uid`, `activity_id`, `type_uid` (= class × 100 + activity),
`time` (ms), `severity_id` and `metadata` {version, product, uid, log_source}. Records are oldest first.
