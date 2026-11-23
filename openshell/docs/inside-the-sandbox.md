# Programs inside the sandbox

This page explains what differs for programs that run inside the sandbox: the shell, web tools,
`execute_code`, curl and git.

## Windows: the shell is busybox

Git Bash can't start inside MXC, so the terminal and file tools run on busybox-w32 there.
The launcher sets that terminal backend through Hermes's managed scope, which outranks the
profile's `config.yaml`.

## Windows: services on this computer

Programs that follow the proxy variables (curl, Python, Node) connect to `127.0.0.1`, `localhost`
and `::1` directly. The plugin lists those three names in `NO_PROXY`.
The reason is in [Security](security.md#services-on-this-computer-windows).

## Linux: web tools and `execute_code`

Inside a Linux sandbox two things differ from the host:

- OpenShell's policy DNS answers every name with an address from 198.18.0.0/15.
- OpenShell's proxy presents OpenShell's certificate authority, which the sandbox's CA variables
  (`SSL_CERT_FILE` and the like) point to.

On every start the launcher writes both into the managed scope it gives the sandboxed Hermes.
It keeps the entries of the profile's `config.yaml` and of the host's managed scope.

| Setting | What the launcher adds | Effect |
|---|---|---|
| `security.fake_ip_ranges` | The address block | Hermes's SSRF check lets the fetch through to the proxy, which still refuses private destinations |
| `terminal.env_passthrough` | The CA variables | Python run by `execute_code` trusts the sites you allowed |

## Windows: curl and git

Inside a Windows sandbox, Windows cannot reach the revocation servers (OCSP and CRL) of
certificate authorities. A program that leaves certificate checks to Windows (Schannel) can then
fail on a site you allowed.

| Program | What the launcher does |
|---|---|
| Windows' own `curl.exe` | Writes a config file with the one option `ssl-revoke-best-effort` into its state folder on every start, and points `CURL_HOME` at it. The sandbox can read the file but not change it. |
| git | Switches git to its OpenSSL backend (`http.sslBackend=openssl`), which verifies against the sandbox's CA bundle |

- curl still validates the certificate chain and the host name, and still refuses a certificate
  known to be revoked. It only continues when the revocation server cannot be reached.
- A `CURL_HOME` or `http.sslBackend` that the sandbox's environment already carries is left as it
  is.
