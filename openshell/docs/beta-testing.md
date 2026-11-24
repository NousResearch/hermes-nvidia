# Beta testing

This page is for people who test the plugin before its Hermes support is released: what you need,
what to try, and how to report what you find.

## Get set up

1. Check that your system is supported and finish its setup:
   [Set up Windows](setup-windows.md) or [Set up Linux](setup-linux.md).
2. Get a Hermes build with sandbox support:
   [Install](install.md#get-a-hermes-build-with-sandbox-support).
3. Create a profile and install the plugin: [Install](install.md#choose-a-profile).
4. Check the computer and install OpenShell: [Install](install.md#check-the-computer).

## What to try

| Try this | Where it is described |
|---|---|
| Turn the sandbox on and off from the Sandbox page | [Use the sandbox](using.md#turn-the-sandbox-on) |
| Ask the agent to read a file outside the profile folder, and answer the card | [Approval cards](cards.md) |
| Ask the agent to fetch a web page, with a web tool and with `curl`, and answer the cards | [Approval cards](cards.md#tool-categories) |
| Answer **Allow**, **Always allow** and **Deny**, then remove a grant under **Allowed from chat** | [Approval cards](cards.md#see-and-remove-what-you-allowed) |
| Add a folder and a destination on the Sandbox page | [Use the sandbox](using.md#add-a-folder) |
| Run a chat with your model's provider: an API key, or a signed-in provider | [API keys and providers](credentials.md) |
| Let the agent change a setting in the profile, then turn the sandbox off and answer the review | [Review changes at switch-off](switching-off.md) |
| Look at the **Activity** tab and export it | [Activity log](activity-log.md) |
| Sign out of Windows or Linux and back in: the sandbox starts again | [Use the sandbox](using.md#turn-the-sandbox-on) |

## Report a problem

1. Check [Known issues](known-issues.md).
2. Collect the logs before you switch the sandbox off:
   [Collect the logs](troubleshooting.md#collect-the-logs).
3. Report through the channel you got this beta from, or open an issue in this repository.
   What to include is listed in [Report a problem](troubleshooting.md#report-a-problem).

## When you are done

Follow [Uninstall](install.md#uninstall).
