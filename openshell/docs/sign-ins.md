# Provider sign-ins

This page explains how a profile that is signed in to a provider works in the sandbox, and what
happens to the sign-in while the sandbox is on.

## Which sign-ins work

A profile that is signed in to one of these providers runs in the sandbox under the same
provider:

| Provider | Status |
|---|---|
| Nous Portal | Tested on Windows and Linux |
| OpenAI Codex | Tested on Linux |
| xAI | Not yet run against the provider |
| MiniMax | Not yet run against the provider |
| Anthropic (Hermes's own sign-in) | Not yet run against the provider |

Providers whose sign-in cannot be used are listed in
[API keys and providers](credentials.md#providers-that-work-in-the-sandbox).

## What the sandbox gets

The sandbox never gets the tokens.

| | Where it is while the sandbox is on |
|---|---|
| The real sign-in files (`auth.json`, `.anthropic_oauth.json`) | In the launcher's host-only copy. That copy is the live sign-in until the switch-off. |
| The current token | With OpenShell, which puts it into requests to the provider's addresses |
| What the sandbox finds under the file's name | A stand-in: the same rows, with a placeholder where each token was and no refresh grant |

- A start-up step writes the stand-in before Hermes starts in the sandbox.
- The stand-in is an ordinary file the sandbox can read and write. For a signed-in profile that
  one name is therefore not hidden. Every other credential file stays hidden.
- A profile that is not signed in to a provider the sandbox can use gets no stand-in.
  Its sign-in files are hidden like the other credential files.

## Where a sign-in is used

At switch-on a sign-in is used at the addresses the profile's model uses and at no others.

- A Nous Portal sign-in is used at its inference address only.
  It is not used at the Portal or at any host of the Nous tool gateway, although Hermes's tools
  use the gateway with the same token.
- A tool's host is added once its category is allowed in a chat.
  See [Approval cards](cards.md#tool-categories).

## How a sign-in is renewed

The launcher renews each sign-in in its copy with Hermes's own code, ahead of the token's expiry
and at a moment no reply is streaming. It then hands the current token to OpenShell.

The rules and their limits are in [Sign-in renewal](sign-in-renewal.md).

## What happens at switch-off

1. The stand-in is thrown away. What the sandbox wrote into it is lost.
2. The copy, with the newest refresh grant, goes back under the file's name.
   The profile is still signed in.

If the launcher was stopped in between, its next start, the next switch-on or
`hermes -p <profile> sandbox off` does the same.

## Sign in with the sandbox off

> [!WARNING]
> Sign in with the sandbox off.
> A sign-in made for the profile from a terminal while its sandbox is on is not used.

- The file such a sign-in wrote is kept in `openshell/<profile>/quarantine`.
- Signing in or out on the desktop's Keys page is refused while the sandbox is on.

## A sign-in shared with the default profile

| Case | What happens |
|---|---|
| The profile uses the default profile's Nous Portal or Codex sign-in | It keeps using it. The sign-in is renewed in the default profile's store. |
| A named profile signed in to Nous Portal on a computer whose default profile is signed in | The profile holds the same sign-in as the default profile. Hermes keeps it current through a store all profiles share, `shared/nous_auth.json` in the Hermes data folder. |

In the second case, while the sandbox is on:

- the launcher and Hermes on this computer renew the sign-in in turns through that store;
- each takes the pair the other renewed, and neither signs the other out;
- Hermes may then fold the profile's own copy into the default profile's sign-in.
  The profile uses that one from then on, also after the switch-off.

For its renewals the launcher writes two files outside its own folder.
It does so with Hermes's own code and under Hermes's own locks:

- the shared store, at every Nous Portal renewal;
- the default profile's `auth.json`, for a sign-in that lives there.

## An expired sign-in

A sign-in that the provider no longer renews shows on the Sandbox page as "Sign-in expired".
One note goes into the chat.

To fix it:

1. Turn the sandbox off.
2. Sign in again.
3. Turn the sandbox on.

What else happens around an expired sign-in is in
[Sign-in renewal](sign-in-renewal.md#a-sign-in-that-the-provider-no-longer-renews).
