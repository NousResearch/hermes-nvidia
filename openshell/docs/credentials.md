# API keys and providers

This page explains how a profile's keys reach the sandbox, which providers work there, and what
keeps the switch off.

## How a key reaches the sandbox

The profile's credential files stay hidden from the sandbox, whether or not they exist yet.
That covers `.env` and the other stores Hermes keeps in a profile folder.

Keys reach the sandbox as OpenShell provider placeholders.
OpenShell's proxy puts the real key into a request only when all three hold:

1. Hermes's interpreter sends the request.
2. The request goes to the key's own address.
3. The key sits in the place it travels in there: a bearer token, or a header such as `x-api-key`
   or `x-goog-api-key`.

How the files are hidden on each system is in
[How it works](how-it-works.md#how-credential-files-are-hidden).

## Which keys the sandbox can use

A key gets a placeholder when the profile has an address for it:

- the model, the fallback models, an auxiliary model with a provider of its own, and the saved
  endpoints, as they were at switch-on;
- every key of a provider Hermes knows, at that provider's own address.
  Another model of that provider then works when you choose it inside.

A key of a web search service whose address Hermes itself states (Tavily, Keenable, Perplexity,
Brave Search) is a tool's key. It gets its placeholder once the tool's category is allowed in a
chat (see [Approval cards](cards.md#tool-categories)). Until then its row on the Sandbox page
says "Used in the sandbox once Web search is allowed in a chat."

Every other key stays on the host.

## Providers that work in the sandbox

| Provider | In the sandbox |
|---|---|
| A provider with an API key stored in the profile's `.env` | Works |
| A model server on this computer, with or without a key | Works |
| Nous Portal, OpenAI Codex, xAI, MiniMax, Anthropic (Hermes's own sign-in) | Works. See [Provider sign-ins](sign-ins.md). |
| A provider that is a program with its own sign-in | Not available |
| Qwen OAuth, which keeps its sign-in outside the profile | Not available |
| Anthropic through Claude Code's sign-in | Not available |
| Azure with Entra ID, Vertex and Bedrock, which sign in through a cloud SDK on this computer | Not available |

Use a provider with an API key or one of the sign-ins above, or run the profile without the
sandbox.

### A model server on this computer

Hermes inside the sandbox reaches a model server on this computer at `host.openshell.internal`
and the server's port.

- With a key, the key's placeholder opens that address.
- Without a key, the launcher opens that one port for Hermes. It opens the address the model had
  at switch-on, and no other site.
- A server that takes no key checks no caller. What the agent runs inside the sandbox can call
  everything that server offers on its port.

The Sandbox page's "Network" section shows the model's address with "Allowed".

## Read the Providers section

Before the switch, the Sandbox page's "Providers" section lists the profile's providers, one row
each, with what each will do in the sandbox:

- a key that stays on this computer, and where it is used;
- a sign-in that stays signed in on this computer, and where it is used;
- a sign-in that is needed first;
- a provider that is not available in the sandbox, and why.

| Mark on a row | Meaning |
|---|---|
| "Model" | The profile's model uses this provider |
| "Fallback" | The profile's fallback model uses this provider |
| "Sign in first" | The provider needs a sign-in before it works in the sandbox |
| "Sign-in expired" | The sign-in could not be renewed. See [Provider sign-ins](sign-ins.md#an-expired-sign-in). |
| "Not available" | The provider cannot work in a sandbox. The row says why. |
| "Key withheld" | The model's endpoint was changed inside the sandbox |
| "In config.yaml" | A key is written in `config.yaml` |
| "No key" | The key's variable is not set in the profile's `.env` |

- While the sandbox is on, the section shows the launcher's rows, and signing in or out on the
  desktop's Keys page is refused.
- While a file cannot be read, the rows stay as they were last read.
- `hermes -p <profile> sandbox check` and `sandbox status` list the same providers and whether
  each works in the sandbox.

## What keeps the switch off

While one of these holds, the switch is greyed, reads "Can't turn on" and shows the reason.
`hermes -p <profile> sandbox check` then gives `"ready": false` with the reason in
`"switch_refused"`, and exit status 2.

| Reason | What to do |
|---|---|
| A key is written in `config.yaml`, which the sandbox reads | [Move it to `.env`](#move-a-key-out-of-configyaml) |
| The main model's provider cannot work in a sandbox | Use another provider for the model, or run the profile without the sandbox |
| The main model's provider needs a sign-in first | Sign in with the sandbox off |
| `config.yaml`, an env file or a sign-in file of the profile cannot be read | Close the program that has it open, or fix a `config.yaml` that is not valid YAML. The page follows by itself. |

A file that cannot be read is never taken for an empty one.
The page then says, for example, "Can't read this profile's config.yaml. Another program may
have it open."

These do not keep the switch off:

- **A main model whose key is not in `.env`.** Its row says "No key found" and "The model won't
  answer in the sandbox without it." The confirm before the switch-on and `sandbox on` say the
  same in one line.
- **A fallback or auxiliary model on a provider that is not available.** Its row says that it is
  not available.

## Move a key out of config.yaml

The sandbox reads `config.yaml`, so a key written there is a key the sandbox holds.
The switch names the key and stays off.

The whole file is read.

- A value counts when its name can only be a credential's (`api_key`, `token`, `password`, `secret`,
  or a name that ends in one of them), and under a key-like name (`key`, `signing_key`) when it
  looks like a credential: 16 or more characters with a long run of mixed letters and digits, and
  not a file path.
- A value also counts by its shape, whatever its name: a URL with a password or a token in it, a
  webhook URL, a command with a `Bearer` value or with `--api-key`.

- On the Sandbox page, the bar above the tabs offers **Move to .env**.
- In a terminal, `hermes -p <profile> sandbox on --move-keys` moves the key and turns the sandbox
  on.

The move puts the key in `.env` and leaves `${NAME}` in its place in `config.yaml`.
It moves the keys of the profile's models and of its MCP servers.

A key anywhere else is moved by hand, for example `tts.openai.api_key`, a messaging platform's
token or a dashboard password. The switch's message names the key and a variable for it:

1. Put the value in the profile's `.env` under that name.
2. Write `${NAME}` in its place in `config.yaml`.

A copy of `config.yaml` in the profile folder counts too, for example `config.yaml.bak` or
`config.yaml~`: the sandbox reads it like `config.yaml`. The switch names the file. Delete it or
move it out of the profile folder.

A copy that can't be read as a config file keeps the switch off too, for example an editor's swap
file or a file larger than 256 KB.

- After the move the key is in `.env` and in no other file. No copy of either file is kept.
- A move that was stopped between the two files leaves the key in both. The switch stays refused,
  and the next move finishes it.

## Save or change a key while the sandbox is on

Save keys on the Sandbox page or on the desktop's Keys page.
Those writes go through the launcher and update its copies.
When you save a key on the Sandbox page, the page says in one line what happened:

| What you did | When the sandbox uses it |
|---|---|
| Replaced a key while no reply was running | With the next request |
| Added a key, removed a key, or saved one during a reply | After the sandbox restarts |
| Saved a key that no model in the profile names | Never: it is not handed in |

> [!WARNING]
> Switch the sandbox off before you edit `.env` by hand.
> An edit made while the sandbox is on is not picked up, and the launcher undoes it.

What the launcher does with an env file that differs from its copy:

- It puts the file back as it was at switch-on. It does so before every sandbox start, before the
  keys are listed and at switch-off.
- It keeps the other version in `openshell/<profile>/quarantine`.

The keys that the Sandbox page and the desktop's Keys page list and reveal are the ones in the
launcher's copy.

## A model endpoint changed in the sandbox

The sandbox can write its profile folder, `config.yaml` included.
So the launcher does not read keys or their endpoints from there while the sandbox is on.

A key is handed out for an endpoint only when one of these holds:

- that pair was configured at switch-on;
- the endpoint is the key's own provider's registered address;
- you allowed it.

If a model's endpoint or key name is changed from inside the sandbox, the key is withheld.
The Sandbox page shows "Model endpoint changed in the sandbox. Key withheld." with **Allow** and
**Dismiss**.

## Where the launcher keeps its copies

When the sandbox is switched on, the launcher copies these into `openshell/<profile>/pins` in the
Hermes data folder, and uses the copies until the sandbox is switched off:

| Copied | From |
|---|---|
| The env files | `.env`, `.op.env` |
| The sign-in files | `auth.json`, `.anthropic_oauth.json` |
| The secret sources | The `secrets:` block of `config.yaml` |
| The models' endpoints | `config.yaml` |

Limits that concern keys are listed in [Known issues](known-issues.md#keys-and-providers).
