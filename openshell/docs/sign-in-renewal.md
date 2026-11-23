# Sign-in renewal

This page explains how the launcher keeps a provider sign-in current while the sandbox is on, and
what happens when a sign-in can no longer be renewed.

The basics of sign-ins are in [Provider sign-ins](sign-ins.md).

## When a sign-in is renewed

The launcher renews each sign-in in its host-only copy, with Hermes's own code:

- ahead of the token's expiry;
- at a moment no reply is streaming.

It then hands the current token to OpenShell.

## A reply that is streaming when a renewal is due

OpenShell closes the sandbox's open connections whenever a credential's value is replaced.
The launcher therefore renews between replies.

When replies stream from the moment a renewal is due until shortly before the token expires, the
value is replaced anyway:

- The reply that is streaming is cut, and Hermes asks the model again by itself.
- The chat stays connected and shows no error. The text that had arrived can stay in the reply,
  followed by the new answer.
- Replacing one sign-in's value cuts whatever streams, whichever sign-in it is.
  Hermes asks the model again three times at most for one reply.
- So when one value has to go in under a streaming reply, the launcher renews every other sign-in
  that is due first and hands their values over together.
  The reply starts again twice at most, however many sign-ins are due.

This is what OpenShell does on Linux.
In the one run on Windows, a value replaced under a streaming reply did not cut it.

## How often the launcher asks a provider

How often the launcher asks a provider to renew a sign-in does not depend on what the token says.

| Rule | Value |
|---|---|
| Shortest time between two renewals of one sign-in | 25 seconds |
| Wait after an answer that is unusable | Twice as long after each such answer, up to ten minutes |
| Renewals of one sign-in within an hour | 150. After that the sign-in is left alone until the sandbox is turned off and on. |

- An unusable answer is a token that is already expired, lasts a few seconds, or is the one it was
  to replace. The cause is a fault at the provider, or this computer's clock far ahead of the
  provider's.
- Meanwhile the Sandbox page says that the sign-in could not be renewed in time.
  The first token that lasts ends it.
- For a sign-in that is left alone, the page shows "Sign-in expired". The sign-in itself is kept
  and goes back to the profile at switch-off.
- A token that OpenShell does not take is offered again with the same restraint, and renewing it
  is not tried a second time.

## A sign-in that the provider no longer renews

When the provider refuses to renew a sign-in, the launcher does not ask again.

- The Sandbox page shows "Sign-in expired" for that provider, with what to do.
- A notice with the same sentence comes up once in the window, whichever page is open.
- The agent gets a note with the chat's next message.
- The token the sandbox last got is left in place until the sandbox starts again.

To fix it:

1. Turn the sandbox off.
2. Sign in again.
3. Turn the sandbox on.

A sign-in that is shared with the default profile is one sign-in: it is signed out for that
profile too.

### What the sandbox does until then

A sandbox that restarts after the sign-in ended starts without it.
A folder or a tool approval, or its removal, restarts the sandbox.

- The models on the profile's other sign-ins and keys keep answering.
- Hermes in the sandbox reads as not signed in to that provider.

The same holds for a sign-in whose token ran out before it could be renewed.
Once it is renewed, the page asks for a restart, which hands it in again.

### What a chat shows

What a message shows once the provider no longer accepts the token is Hermes's own:

| Run | What the chat showed |
|---|---|
| Linux | The reply failed with Hermes's text for a rejected sign-in, which names a sign-in command. That command needs the sandbox off. |
| Windows | "Provider temporarily unavailable", and Hermes retried for several minutes |
