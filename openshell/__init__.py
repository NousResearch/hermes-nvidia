"""OpenShell sandbox for a Hermes profile.

On the host, ``hermes sandbox`` runs the launcher: it starts the profile's backend inside a sandbox
and fronts it with an authenticating proxy that answers this plugin's own routes and keeps credential
writes on the host. Inside a Windows sandbox, the busybox terminal backend replaces Git Bash, whose
MSYS runtime cannot start in an AppContainer. Inside any sandbox the launcher started, a
``transform_tool_result`` hook waits for the user's answer to the card a refusal raised, so the card
resolves in the same turn (``sandbox_hook.py``). Inside a Windows sandbox the loopback names are kept away from
OpenShell's proxy (``loopback_env.py``).
"""


def register(ctx):
    from . import busybox_env, launcher_cli, loopback_env, relay_receipts, sandbox_hook

    loopback_env.apply()
    ctx.register_terminal_environment_provider(busybox_env.BusyboxProvider())
    launcher_cli.register(ctx)
    sandbox_hook.register(ctx)
    relay_receipts.register(ctx)
