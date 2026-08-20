# Server Setup

This chapter is for the CA operator.

Pick one install path:

- [Debian package](#debian-package), the fastest way on Debian or Ubuntu.
- [NixOS module](#nixos-module), if you run NixOS.
- [From source](#from-source), everything else.

The CA server needs its own machine or VM.
Whoever owns the CA key can issue certificates for anybody.
Treat that machine like a domain controller.

## Debian package

Packages are published on every
[GitHub Release](https://github.com/gvz/ssh-certificate-authority/releases).
`amd64` only. Other architectures build [from source](#from-source).

```bash
sudo dpkg -i ssh-ca-server_<version>_amd64.deb
sudo apt-get install -f
```

The nix-built package creates this on first install:

| What | Path |
|---|---|
| SSH host key | `/etc/ssh_ca_server/ssh_ca_host_ed25519_key` |
| CA signing key | `/etc/ssh_ca_server/ca_key` |
| Host inventory | `/etc/ssh_ca_server/hosts/` |
| Config | `/etc/ssh_ca_server/config.toml` |
| User list | `/etc/ssh_ca_server/user.toml` |
| Default user template | `/etc/ssh_ca_server/user_default.toml` |
| systemd service | `ssh-ca-server.service`, enabled and started |

Binary: `/usr/bin/ssh_ca_server`.

> The package built with `cargo deb` differs.
> Binary `ssh-ca-server`, config directory `/etc/ssh-ca-server/`.
> It ships `config.toml.example` and creates no keys.
> Copy the example to `config.toml` and generate the keys yourself.

Continue with [Configure users](#configure-users).

## NixOS module

The flake exports `nixosModules.<system>`.

```nix
{
  imports = [ inputs.ssh-ca-server.nixosModules.${system} ];

  services.ssh-ca-server = {
    enable = true;
    configFile = "/etc/ssh_ca_server/config.toml";
    dataDir = "/var/lib/ssh-ca-server";
  };
}
```

The module creates a systemd service that runs
`ssh_ca_server -c <configFile>`.
You still create the keys and the config file yourself.
See [Generate the keys](#generate-the-keys).

> The module sets `Restart = "no"` and `RUST_LOG=debug`.
> Override both for production. See [Maintenance](maintenance.md#restarts).

## From source

### Build dependencies

Debian or Ubuntu:

```bash
sudo apt install build-essential pkg-config libpam-dev libssl-dev
```

Fedora or RHEL:

```bash
sudo dnf install gcc pkg-config pam-devel openssl-devel
```

Rust, if you have none:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

With nix, all of it comes from the dev shell:

```bash
nix develop     # or: direnv allow
```

### Build

```bash
git clone https://github.com/gvz/ssh-certificate-authority.git
cd ssh-certificate-authority
cargo build --release
sudo cp target/release/ssh_ca_server /usr/local/bin/ssh_ca_server
```

### Generate the keys

Two different keys are needed. Do not mix them up.

| Key | Job |
|---|---|
| SSH host key | Identifies the CA server to clients |
| CA signing key | Signs all user and host certificates |

```bash
sudo mkdir -p /etc/ssh_ca/hosts

# host key of the CA server
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host"

# CA signing key
sudo ssh-keygen -t ed25519 -f /etc/ssh_ca/ca_key -N "" -C "ssh_ca"
sudo chmod 600 /etc/ssh_ca/ca_key
```

> The CA key has no passphrase.
> The server must read it unattended at startup.
> Protect it with file permissions and with access control on the machine.

### Write the config

`/etc/ssh_ca/config.toml`:

```toml
[ssh]
bind = "0.0.0.0"
port = 2222
private_key = "/etc/ssh/ssh_ca_host_ed25519_key"
# certificate = "/etc/ssh/ssh_ca_host_ed25519_key-cert.pub"  # see below

[ca]
ca_key                = "/etc/ssh_ca/ca_key"
user_list_file        = "/etc/ssh_ca/user.toml"
default_user_template = "/etc/ssh_ca/user_default.toml"
host_inventory        = "/etc/ssh_ca/hosts/"

[identity_handlers]
user_authenticators = ["pam"]
```

Every field is described in the
[Configuration Reference](configuration-reference.md).

### PAM

The server uses the PAM service `login`.
It works out of the box on most distributions.
Check that `/etc/pam.d/login` exists.

`root` is always rejected, whatever PAM says.

### Run in the foreground

```bash
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml
```

The process starts the CA child itself.

### Run as a systemd service

`/etc/systemd/system/ssh-ca-server.service`:

```ini
[Unit]
Description=SSH Certificate Authority
After=network.target

[Service]
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ssh_ca_server -c /etc/ssh_ca/config.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-ca-server.service
journalctl -u ssh-ca-server.service -f
```

### Split the two processes

You can run the SSH server and the CA separately, for example under different
users.
Both then need the same IPC token, and the CA also needs the socket path.

```bash
# create the shared token
umask 077
head -c 32 /dev/urandom | base64 > /run/ssh_ca/ca.token

# SSH server: reads the token, does not start a CA
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml \
    --socket-path /run/ssh_ca/ca.sock \
    --token-file /run/ssh_ca/ca.token \
    --disable-ca &

# CA: reads the token, then deletes the token file
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml \
    --certificate-authority \
    --socket-path /run/ssh_ca/ca.sock \
    --token-file /run/ssh_ca/ca.token
```

Start the SSH server first.
The CA deletes the token file as soon as it has read it.

In CA mode both `--socket-path` and `--token-file` are mandatory.
The process exits if one is missing.

## Configure users

Users listed in `user.toml` get their own template.
All other users get `default_user_template`.

`/etc/ssh_ca_server/user.toml`:

```toml
[users]
alice = "./alice.toml"
bob   = "./bob.toml"
```

Relative paths resolve against the directory of `user.toml`.

Per-user template, `/etc/ssh_ca_server/alice.toml`:

```toml
validity_in_days = 1
principals = ["alice", "alice-sudo"]
extensions = ["permit-pty", "permit-agent-forwarding"]
```

Default template, `/etc/ssh_ca_server/user_default.toml`:

```toml
validity_in_days = 7
principals = ["{{ user_name }}"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
    "permit-x11-forwarding",
    "permit-user-rc",
]
```

`{{ user_name }}` is the authenticated username.
It is the only variable available.

Changes take effect on the next signing request.
No restart needed.

## Enroll a host

See [Enroll a host](maintenance.md#enroll-a-host) in the maintenance chapter.

## Sign the CA server's own host key

Optional, but it removes the last trust-on-first-use step for your users.

```bash
sudo ssh-keygen -s /etc/ssh_ca_server/ca_key \
    -h -I "ssh_ca_server" -n "ssh_ca_server" -V +3650d \
    /etc/ssh_ca_server/ssh_ca_host_ed25519_key.pub
```

Then set in `config.toml`:

```toml
certificate = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub"
```

Restart the service:

```bash
sudo systemctl restart ssh-ca-server.service
journalctl -u ssh-ca-server.service -f
```

The principal in `-n` must match the name your users connect to.

## Distribute the CA public key

Users and hosts need `ca_key.pub`.

```bash
cat /etc/ssh_ca_server/ca_key.pub
```

Publish it where people can check it, and tell them the fingerprint over a
second channel:

```bash
ssh-keygen -lf /etc/ssh_ca_server/ca_key.pub
```

Clients install it as described in
[User Certificates](user-certificates.md#step-1-trust-the-ca) and
[Host Certificates](host-certificates.md#step-6-accept-user-certificates).

## First test

```bash
# from a client, with an account on the CA
ssh-ca-sign-user-key -s ca-server.example.com -v
ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub
```

Watch the server side at the same time:

```bash
journalctl -u ssh-ca-server.service -f
```
