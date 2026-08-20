# CA Server Setup

Two install options: Debian package (recommended for Debian/Ubuntu) or build from source.

## Option A: Debian package

Packages published on every [GitHub Release](https://github.com/gvz/ssh-certificate-authority/releases). `amd64` only — other architectures use [Option B](#option-b-build-from-source).

```bash
sudo dpkg -i ssh-ca-server_<version>_amd64.deb
sudo apt-get install -f
```

On first install, the package creates:

| What | Path |
|---|---|
| SSH host key | `/etc/ssh_ca_server/ssh_ca_host_ed25519_key` |
| CA signing key | `/etc/ssh_ca_server/ca_key` |
| Host inventory | `/etc/ssh_ca_server/hosts/` |
| Config | `/etc/ssh_ca_server/config.toml` |
| User list | `/etc/ssh_ca_server/user.toml` |
| User cert template | `/etc/ssh_ca_server/user_default.toml` |
| systemd service | `ssh-ca-server.service` (enabled + started) |

Binary: `/usr/bin/ssh_ca_server`.

> The package built with `cargo deb` uses different names: binary `ssh-ca-server`, config directory `/etc/ssh-ca-server/`. It ships `config.toml.example` and creates no keys.

### Configure users

Edit `/etc/ssh_ca_server/user.toml`. Users not listed get the default template.

```toml
[users]
alice = "./alice.toml"
bob   = "./bob.toml"
```

Paths relative to `/etc/ssh_ca_server/`.

Per-user override (`/etc/ssh_ca_server/alice.toml`):
```toml
validity_in_days = 1
principals = ["alice", "alice-sudo"]
extensions = ["permit-pty", "permit-agent-forwarding"]
```

Default template (`/etc/ssh_ca_server/user_default.toml`):
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

### Enroll a host

Get the host's public key from the host machine:
```bash
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Create `/etc/ssh_ca_server/hosts/<hostname>.toml` on the CA:
```toml
public_key       = "ssh-ed25519 AAAA<...>"
validity_in_days = 365
hostnames        = ["webserver", "webserver.example.com"]
extensions       = []
```

> Filename (without `.toml`) must match the hostname the host uses when authenticating.

### (Optional) Sign the CA server's own host key

```bash
sudo ssh-keygen -s /etc/ssh_ca_server/ca_key \
    -h -I "ssh_ca_server" -n "ssh_ca_server" -V +3650d \
    /etc/ssh_ca_server/ssh_ca_host_ed25519_key.pub
```

Uncomment in `/etc/ssh_ca_server/config.toml`:
```toml
certificate = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub"
```

Apply changes:
```bash
sudo systemctl restart ssh-ca-server.service
journalctl -u ssh-ca-server.service -f
```

### Distribute the CA public key

Users and hosts need `ca_key.pub` to trust issued certificates. Share it out-of-band:
```bash
cat /etc/ssh_ca_server/ca_key.pub
```

See [User Setup](setup-user.md) and [Host Setup](setup-host.md) for how clients install it.

---

## Option B: Build from source

### Prerequisites

**Debian/Ubuntu:**
```bash
sudo apt install build-essential pkg-config libpam-dev libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc pkg-config pam-devel openssl-devel
```

Rust via [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

**Or with Nix (recommended):**
```bash
nix develop   # or: direnv allow
```

### Build

```bash
git clone https://github.com/gvz/ssh-certificate-authority.git
cd ssh-certificate-authority
cargo build --release
sudo cp target/release/ssh_ca_server /usr/local/bin/ssh_ca_server
```

### Generate keys

```bash
sudo mkdir -p /etc/ssh_ca/hosts
# SSH host key
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host"
# CA signing key
sudo ssh-keygen -t ed25519 -f /etc/ssh_ca/ca_key -N "" -C "ssh_ca"
sudo chmod 600 /etc/ssh_ca/ca_key
```

> **Security:** `ca_key` readable only by server user. Keep off shared/world-readable filesystems.

### Configuration

`/etc/ssh_ca/config.toml`:
```toml
[ssh]
bind = "0.0.0.0"
port = 2222
private_key = "/etc/ssh/ssh_ca_host_ed25519_key"
# certificate = "/etc/ssh/ssh_ca_host_ed25519_key-cert.pub"  # uncomment if signed

[ca]
ca_key                = "/etc/ssh_ca/ca_key"
user_list_file        = "/etc/ssh_ca/user.toml"
default_user_template = "/etc/ssh_ca/user_default.toml"
host_inventory        = "/etc/ssh_ca/hosts/"

[identity_handlers]
user_authenticators = ["pam"]
```

Create `/etc/ssh_ca/user.toml`:
```toml
[users]
alice = "./alice.toml"
```

Create `/etc/ssh_ca/user_default.toml`:
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

Per-user overrides and host inventory entries use the same format as Option A (paths under `/etc/ssh_ca/`).

### (Optional) Sign the CA server's own host key

```bash
sudo ssh-keygen -s /etc/ssh_ca/ca_key \
    -h -I "ssh_ca_server" -n "ssh_ca_server" -V +3650d \
    /etc/ssh/ssh_ca_host_ed25519_key.pub
```

Uncomment in `/etc/ssh_ca/config.toml`:
```toml
certificate = "/etc/ssh/ssh_ca_host_ed25519_key-cert.pub"
```

### PAM

Uses the `login` service. Works out of the box on most distros — verify `/etc/pam.d/login` exists. `root` always rejected.

### Run

**Foreground (testing):**
```bash
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml
```

**Separate CA and SSH server processes:**
```bash
# CA process
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml \
    --certificate-authority --socket-path /run/ssh_ca/ca.sock

# SSH server process
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml \
    --socket-path /run/ssh_ca/ca.sock --disable-ca
```

### systemd service

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

### Distribute the CA public key

```bash
cat /etc/ssh_ca/ca_key.pub
```

See [User Setup](setup-user.md) and [Host Setup](setup-host.md) for how clients install it.
