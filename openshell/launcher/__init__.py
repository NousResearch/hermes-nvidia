"""Host launcher for a sandboxed profile backend.

``supervisor`` runs the profile's ``hermes serve`` through a ``driver`` (an OpenShell sandbox on a
private gateway) and ``proxy`` fronts it on a fixed loopback port. ``layout`` decides what the
sandbox may touch; ``host_routes`` answers the plugin's own routes and credential writes on the host.
"""
