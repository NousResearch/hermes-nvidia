# Activity log

This page describes the Sandbox page's **Activity** tab: where its rows come from, the routes
behind it, and how its export maps to OCSF.

The tab is one live timeline of a profile's sandbox, newest first. It shows what the sandbox
allowed and refused, and has:

- filters: All, Network, Files, Decisions; Denied only; a period;
- the enforcer's policy history, with Restore;
- an export of the rows shown as OCSF JSON Lines (**Export OCSF JSON…**).

Code: `launcher/activity.py` (backend), the `-- activity --` block in `desktop/plugin.js` (page),
`tests/test_activity.py`.

## Sources

| Rows | Source | Where it is kept (host only) |
|---|---|---|
| Network: connections and HTTP requests (allowed, denied), policy loads, findings | OpenShell's audit (OCSF) | `<root>/openshell/<profile>/audit/ocsf-<sandbox>-<UTC date>.jsonl` |
| Files: refused reads and writes, and the file tools' writes | Hermes's tool results in the profile's `state.db` (read-only), only while the sandbox ran | read in place; run times in `<state>/activity/runs.jsonl` |
| Decisions: answers to the in-chat access cards, their outcome, removed grants | the launcher's card log | `<state>/cards.jsonl` |
| Sandbox started / stopped | the collector | `<state>/activity/runs.jsonl` |

`<state>` is the launcher's state dir, which the sandbox cannot read or write.

OpenShell logs no per-file events, so file rows come from what the agent's own tools reported.
A file the agent changed through the terminal (for example `echo > f`) shows only if a refusal
was reported.

## How the audit is kept on the host

The audit log is kept on the host, so it stays readable after the sandbox stops.

**Linux.** The driver's `AuditArchive` follows the supervisor's `OCSF-JSON` stderr records and
writes the archive itself. The records are full OpenShell records, verbatim.

**Windows.** OpenShell saves nothing. `openshell logs` is the gateway's in-memory tail (shorthand
lines only; the full JSON records go only to the gateway's own stdout), and the supervisor writes
no file on the host. So the launcher's `AuditCollector` does this:

1. It polls the driver's events every 3 s while the sandbox runs.
   It also polls before answering the page when the last poll is older than 1.5 s.
2. It converts each shorthand line to an OCSF record of the class OpenShell uses for it.
3. It dedupes by `metadata.uid` (a hash of the line's time and text) and appends the record.
4. It polls once more just before the driver deletes the sandbox, so the last records are kept
   when the sandbox stops.

A launcher killed outright loses at most the last poll interval.

Both forms are read the same way, so the timeline and the export look the same on both platforms.
History is kept across stops, restarts and the switch being turned off.
The host backend answers the same routes from the same files while the profile runs unsandboxed.

## What the timeline leaves out

The archive keeps everything. The timeline shows the rows a person reads:

- allowed or denied connections and requests;
- policy loads and rejections;
- findings.

Two kinds of record stay in the archive only:

- OpenShell's relay plumbing (unattributed loopback opens and closes);
- startup configuration chatter.

OpenShell logs one HTTP request once per engine (L7 and OPA).
The timeline shows one row, and the export keeps both records.

## Links to chats

- File and decision rows carry their chat.
- A network row links to a chat only when exactly one chat had a turn running at that moment
  (from the message times in `state.db`). Otherwise it has no link.

## Routes

| Route | Answered by |
|---|---|
| `GET /api/plugins/openshell/activity` | The launcher (sandboxed) and the host dashboard router (unsandboxed) |
| `GET /api/plugins/openshell/activity/export` | The same two |

| Query parameter | Meaning |
|---|---|
| `since`, `until` | Unix seconds. Default: the last 24 h. |
| `kinds` | `network,files,decisions` |
| `denied=1` | Denied rows only |
| `limit` | 1 to 2000, default 500 |

The export answers `{records, count, filename, truncated, format: "ocsf-jsonl", ocsf_version}`.
The page writes one record per line.

Policy history uses the `policy/revisions`, `policy/revisions/<n>` and `policy/rollback` routes.
They answer for a running sandbox only.
Restore brings back the revision's network rules. Folders are fixed at start.

## OCSF mapping (schema 1.8.0)

| Row | Class | Activity | Notes |
|---|---|---|---|
| Network (Linux) | OpenShell's record, verbatim | as logged | |
| Network (Windows) | NET 4001 Network Activity, HTTP 4002 HTTP Activity, SSH 4007, PROC 1007, FINDING 2004, CONFIG 5019 Device Config State Change | NET: Open 1, Close 2, Reset 3, Fail 4, Refuse 5, Traffic 6, Listen 7; HTTP: by method (Get 3, Post 6, ...); else Other 99 | Converted from the shorthand: `action`/`disposition` (Allowed 1 / Denied 2, Blocked), `status`, `status_detail` (OpenShell's reason), `firewall_rule` {name, type: engine}, `actor.process.name` (the program; pid as logged, 0 on Windows), `dst_endpoint` (domain or ip, port), `http_request` {http_method, url}. `metadata.product` OpenShell Sandbox Supervisor; `metadata.log_source` `openshell logs (shorthand)`; the original line in `unmapped.shorthand` |
| Files | 1001 File System Activity | Read 2, Update 3 | `action` Denied (refusal) or Allowed (file tool write), `file` {path, name}, `actor.app_name` Hermes Agent, `status_detail` the refusal line from the tool result, `unmapped.hermes` {profile, chat, tool, message_id, access}; product Hermes Agent |
| Decisions | 3005 User Access Management | Assign Privileges 1 (allowed until the sandbox is switched off / always), Revoke Privileges 2 (a grant removed on the Sandbox page), Other 99 "Deny" | `user` = the profile whose access changed, `actor.user` = the OS user who answered, `privileges` [`network:<host>:<port>` or `files:<access>:<path>`], `resource`, `unmapped.hermes` {chat, choice, label, card, program, reason, status, request_id, ...} |
| Sandbox started / stopped | 6002 Application Lifecycle | Start 3, Stop 4 | `app` {name: Hermes sandbox, uid: sandbox name} |

Every record has `class_uid`, `category_uid`, `activity_id`, `type_uid` (= class × 100 +
activity), `time` (ms), `severity_id` and `metadata` {version, product, uid, log_source}.
Records are oldest first.
