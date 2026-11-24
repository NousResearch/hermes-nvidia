# Set up Linux

This page lists what a Linux computer needs before the sandbox can run, and the checks to run.

The sandbox runs in Docker, through OpenShell's Docker driver.
It needs x86_64 or aarch64 with glibc, Linux 6.2 or newer (Landlock ABI 3) and seccomp user
notification.

## Install curl and git

The commands on these pages use `curl` and `git`.
Install them if the system does not have them. On Ubuntu or Debian:

```bash
sudo apt update && sudo apt install -y curl git
```

## Check the kernel

```bash
uname -r
cat /sys/kernel/security/lsm
```

- `uname -r` must be 6.2 or newer.
- The second command must list `landlock`.

The plugin's own check, `hermes sandbox check`, confirms the Landlock ABI and the seccomp support.
See [Check the computer](install.md#check-the-computer).

## Install Docker

The sandbox needs Docker Engine, usable without `sudo`.

1. Install Docker if you don't have it, for example:

   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   ```

2. Add your user to the `docker` group, then sign out and back in:

   ```bash
   sudo usermod -aG docker "$USER"
   ```

3. Check that Docker runs without `sudo`:

   ```bash
   docker run --rm hello-world
   ```

## Check the systemd user session

The sandbox and its gateway run as `systemd --user` services.

```bash
systemctl --user status --no-pager | head -3
```

- To keep the sandbox running after you sign out, also run `sudo loginctl enable-linger "$USER"`.
- In WSL2, systemd must be on. `/etc/wsl.conf` needs a `[boot]` section with `systemd=true`.
  Then run `wsl --shutdown` from Windows and reopen the distribution.

Go on with [Install](install.md#get-a-hermes-build-with-sandbox-support).

## Remove the images

When you uninstall the plugin, remove the sandbox's base image and OpenShell's images if you don't
need them.

1. List them:

   ```bash
   docker image ls hermes-sandbox-base
   docker image ls --digests --filter 'reference=ghcr.io/nvidia/openshell/*'
   ```

2. Remove the ones listed with `docker image rm`.
