# Approval cards

This page explains the cards the sandbox raises in a chat, what each answer does, and how long the
agent waits for it.

## When a card appears

When the sandbox refuses a folder or a website during a chat, the plugin raises one card in that
chat.

| Card | Raised when | What it covers |
|---|---|---|
| **Website access** | A program in the sandbox was refused a site | One host, on http and https, for any program in the sandbox |
| **Folder access** | A tool was refused a path | The nearest existing folder, with the access asked for: **Read only** or **Read and write** |
| A tool's card, for example "Web extract" | A tool of that category is used for the first time | Every service the category's tools use for this profile. The card names each host. |

## Answer a card

| Answer | What it does |
|---|---|
| **Allow** | Grants it until the sandbox is switched off. It is not saved. |
| **Always allow** | After you confirm, saves it to the sandbox's stored policy. Hermes doesn't ask again for that folder or site in any chat. |
| **Deny** | Refuses it. You can add a reason, which the agent reads. |

## Tool categories

At switch-on the sandbox opens what the profile's model needs and nothing a tool needs.
The first time a tool of a category is used, one card asks for the whole category.

The categories are Web search, Web extract, Browser, Image generation, Video generation, Speech,
Connected apps and Remote terminal.

An Allow covers every service the category's tools use for this profile:

- the services Hermes's web tools use without a key (https, any program in the sandbox);
- the Nous tool gateway's host for the category, where the profile is signed in to Nous Portal;
- a web search service's own host, where the profile holds its key.

The approval is for the category.
It keeps working when the profile's settings send the tool to another of these services.

> [!NOTE]
> A service that fetches pages for a tool lets the agent read any public page.
> The cards for Web search, Web extract and Browser say so, and so does the grant's row on the
> Sandbox page.

Limits of a category approval:

- A host of the tool gateway that no category's tools ask for stays closed.
- No card opens another category's hosts.

## How long the agent waits

The agent waits for your answer.

| What happened | What is held | Longest wait |
|---|---|---|
| A tool call was refused and its result shows the refusal | That tool call | Two minutes |
| A program failed without printing a refusal (`curl -s`) | That tool call, once OpenShell's own record confirms that a site it named was refused | Two minutes |
| A command did not fail although a program in it was refused (`curl -s` piped into `head`, or `curl` followed by `echo`) | That tool call, when OpenShell's record shows a site it named refused during the command | Two minutes |
| A refusal shows in no tool result (the record comes later, or the command names no site) | The reply. The card comes from OpenShell's record a moment later, and the launcher pauses the reply. | 90 seconds |

Details:

- A host name alone never raises a card. OpenShell's own record must show the site refused.
- A command that did not fail is judged by OpenShell's record. What it printed does not decide.
- The launcher follows OpenShell's records as they happen. A command that names a site waits a
  fraction of a second for a record after it returns, and two seconds at most when its output
  shows a refusal.
- A command that names no site is never made to wait.
- If nobody answers in time, the agent says what it needs and stops.
  An answer given later continues the reply.

## How an answer takes effect

The answer applies to the reply in progress.

| You allowed | What the plugin does | Usual time |
|---|---|---|
| A website | Stops the turn at the refused tool call, loads the rule into the running sandbox, and the chat continues by itself | A few seconds |
| A folder | Stops the turn, restarts the sandbox ("Restarting sandbox…"), and the chat continues by itself | 10 to 20 seconds |
| A tool category that uses a sign-in or a key | Restarts the sandbox, as for a folder | 10 to 20 seconds |
| A tool category that only uses services without a key | Loads into the running sandbox, as for a website | A few seconds |

Why the differences:

- The pinned OpenShell builds close open connections when they reload a policy.
  So the launcher first stops the turn at the refused tool call, then loads the website rule.
- Folder rules are fixed when a sandbox starts, so a folder needs a restart.
- A credential reaches a new address only in a sandbox that starts with it.
  So a tool category that binds a sign-in or a key to a host restarts the sandbox.
  Removing such a grant restarts it the same way.

What you see meanwhile:

- While the launcher holds the turn, the desktop shows the reply as continuing.
  A message you send meanwhile is kept until the continuation has run.
  This needs a Hermes core whose `session.interrupt` takes `resume`.
  On an older core the reply shows "Response stopped" until it continues.
- The chat continues whichever page of the window is open, and whether or not the window has
  focus. The launcher resumes the chat on that window's connection.
- With no window connected for two minutes, the reply cannot go on.
  The chat then says "This reply stopped when the sandbox restarted. Send your message again."
  when it is next opened. The approval stands, so sending the request again raises no second card.
  The note for the agent goes with that message.

## See and remove what you allowed

The Sandbox page lists what you allowed from cards under **Allowed from chat**, each with
**Remove**.

- What you saved with **Always allow**, a tool category included, applies whenever the sandbox is
  on. It stays listed while the sandbox is off and can be removed there. Nothing restarts then.
- Removing a website: the sandbox can no longer reach it, and the agent is asked again next time.
- Removing a folder: the sandbox restarts without the folder when the current turn ends.

The **Activity** tab shows every answer you gave. See [Activity log](activity-log.md).

Open problems with cards are listed in [Known issues](known-issues.md#cards-and-replies).
