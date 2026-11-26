# Review changes at switch-off

This page explains the list "Changed in the sandbox" that can appear when you turn the sandbox
off, and how to answer it.

## Why there is a review

The sandbox can write most of its profile folder.
Once the sandbox is off, Hermes on this computer runs what that folder holds again:

- cron jobs and their scripts;
- MCP servers;
- shell hooks;
- secret sources;
- model endpoints.

So the launcher records those settings and files when the sandbox is switched on.
It keeps the record in `openshell/<profile>/handback` in the Hermes data folder, which no sandbox
is given. Before it switches off, it compares the profile folder with the record.

With no such change, no list appears and the sandbox turns off.

## Answer the list

### On the Sandbox page

The page lists the changes under "Changed in the sandbox" with two buttons:

| Button | What it does |
|---|---|
| **Revert and turn off** | Puts every listed change back as it was at switch-on. The sandbox's versions are kept in `openshell/<profile>/handback/held`. |
| **Keep and turn off** | Leaves the changes as they are. |

While the list has no answer, the switch itself does not turn the sandbox off.
The page says "Changes need an answer first."

### In a terminal

```bash
hermes -p sbtest sandbox off
hermes -p sbtest sandbox off --revert
hermes -p sbtest sandbox off --keep
hermes -p sbtest sandbox handback
```

- `sandbox off` prints the list, changes nothing and exits with status 3 until you run it with
  `--revert` or `--keep`.
- `sandbox off --revert` exits with status 1 when the changes could not be reviewed and nothing was
  reverted. The sandbox is off all the same.
- `sandbox handback` prints the list at any time.

## What the review covers

| What changed | How the list shows it | What Revert does |
|---|---|---|
| Cron jobs, scripts, hook files | One row each | Puts each back as it was at switch-on |
| Programs in `bin`, `lsp/bin` and `node/bin`, and a program that a setting names | One row each | Moves a new program out, puts a changed one back |
| An MCP server install in `mcp-installs`, new or changed | One row for the install | Moves the install out. A changed one is not put back: install that server again. |
| A setting in `config.yaml`: an MCP server, a shell hook, a secret source, a provider, the model, the browser, delegation and every other key that is not in the list below | One row each | Puts each back as it was at switch-on |
| The settings in the list below | A count ("Also changed: N other settings") | Nothing. They are counted but not reverted. |
| Skills, memories and `SOUL.md` | A count ("Also changed: ...") | Nothing. They are counted but not reverted. |
| Env files and `auth.json` | Under "Always reverted" | They are always put back from the launcher's copies, whatever you answer |

A setting you changed yourself in the app while the sandbox was on is listed too, because the
sandboxed backend wrote it. Keep it.

A cron job is compared by what it runs and when: its prompt and script, its schedule, the next
run, the run limit, its time zone and where its output goes.
Revert puts those back. A job that was removed comes back, and so does a removed jobs file.

Runs that happened while the sandbox was on stay counted. They are not a change, and neither is a
next run that the scheduler moved along the schedule.

The settings under these keys can differ without a row. They change how Hermes looks, its
limits and its housekeeping:

- `display`, `streaming`, `human_delay`, `logging`, `tool_output` and the three
  `paste_collapse_*` keys;
- `sessions`, `session`, `compression`, `checkpoints`, `worktrees`, `database`, `runtime`,
  `prompt_caching`, `vision`, `goals`, `loops`, `doctor` and `bot_mode`;
- `file_read_max_chars`, `context_file_max_chars`, `context_file_read_timeout`,
  `max_concurrent_sessions` and `max_live_sessions`;
- `_config_version`, `onboarding` and `monitoring.install_id`, which Hermes writes by itself.

Under these keys a number or an on/off value differs without a row.
A text does so only when Hermes checks it against its own choices or only shows it: a theme, a
language, a display mode.
Any other text under these keys is a row, the log level among them.

A theme or a mode that holds a slash, a backslash or a colon, or is longer than 64 characters, is
a row too.

Only what the sandbox can write is compared:

- The `plugins` and `desktop-plugins` folders are read-only inside the sandbox, so a plugin you
  update while the sandbox is on is never listed.
- Python bytecode in a folder the sandbox can write, such as `scripts/__pycache__`, is listed.

A settings file or a cron jobs file that cannot be compared is one row, "could not be compared".
Revert puts the whole file back as it was at switch-on. The other rows stay as they are.

If no list can be made at all, the sandbox still turns off, and the page says that the changes
were not reviewed.

With **Revert**, the launcher then puts back every file it saved a copy of at switch-on, takes the
new files out of `scripts` and `hooks`, and names what it reverted.
The next switch-on reviews that session again.

## After a Keep

What you keep runs on this computer from then on like your own settings.
A kept secret source is what the next sandbox's keys are read with.

While kept changes are still in the profile:

- the Sandbox page shows one line, "Kept from the sandbox: N items", with **Show**;
- `hermes -p <profile> sandbox status` prints the same line;
- `hermes -p <profile> sandbox handback` lists them.

The line disappears when you change or remove the kept entries.

## A session that ended without a review

A sandbox session can end without the review: its launcher was stopped and the profile freed by
hand, or the comparison could not run.
Such a session is reviewed before the sandbox is switched on again, so that nothing it left behind
is taken for your own settings.

- The Sandbox page shows the same list with **Revert and turn on** and **Keep and turn on**.
- `hermes -p <profile> sandbox on` prints the list and exits with status 3 until you run it with
  `--revert` or `--keep`.
- `hermes -p <profile> sandbox off --revert` (or `--keep`) answers the list without switching on.

### A foreground `hermes sandbox serve`

A foreground `hermes sandbox serve` is the only way to sandbox the default profile.
It is compared too:

1. It records the folder when it starts.
2. It prints the list when it stops.
3. `sandbox off --revert` or `sandbox off --keep` answers the list. Its next start asks first.

> [!NOTE]
> A foreground `serve` does not mark the profile.
> Hermes on this computer reads the profile folder while such a sandbox runs.

### The first switch-on

The first time a profile is switched on there is nothing to compare with.
The launcher records the folder as it is.

## Limits

- The launcher keeps a copy of each script, hook file and named program for Revert only up to
  8 MB a file and 128 MB in all.
- A larger file that the sandbox changed is listed as "No copy kept".
  Revert leaves it as the sandbox changed it and names it. Look at such a file before it runs.
- A watched folder with more than 50,000 files is one row, "too many files to compare".
  Revert takes out every file in it that was not there at switch-on.
- Files in `mcp-installs` are compared by name, size and time. They are not read and no copy is
  kept, so Revert moves a changed install out whole and says which server to install again.
- The copy taken at switch-on names the folders it covers. When it does not cover the program
  folders, the list says "Not fully checked" for them, and the next switch-on covers them.
