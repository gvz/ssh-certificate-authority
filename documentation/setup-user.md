# User Setup

**Prerequisites:**
- CA running. See [CA Server Setup](setup-ca.md).
- SSH key pair. Generate if needed: `ssh-keygen -t ed25519`.
- Account on CA server (CA operator must have added you to user list).
- `bash`, `ssh`, `ssh-keygen`, `getopt` available (standard Linux).

## 1. Trust the CA

Add to `~/.ssh/known_hosts` (per user) or `/etc/ssh/ssh_known_hosts` (system-wide):
```
@cert-authority * <contents of ca_key.pub>
```

Fetch the CA public key from the CA server (confirm path with CA operator):
```bash
# Package install
scp ca-server.example.com:/etc/ssh_ca_server/ca_key.pub ~/ca_key.pub
# From source
scp ca-server.example.com:/etc/ssh_ca/ca_key.pub ~/ca_key.pub
```

Then add it:
```bash
# Per user
echo "@cert-authority * $(cat ~/ca_key.pub)" >> ~/.ssh/known_hosts
# System-wide
echo "@cert-authority * $(cat ~/ca_key.pub)" | sudo tee -a /etc/ssh/ssh_known_hosts
```

## Install client script

**Option A — Debian package** (any arch):
```bash
sudo dpkg -i ssh-ca-client_<version>_all.deb
sudo apt-get install -f
```
Installs `ssh-ca-sign-user-key` to `/usr/bin/`.

**Option B — manual:**
```bash
sudo cp clients/ssh-ca-sign-user-key.sh /usr/local/bin/ssh-ca-sign-user-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-user-key
```

## 2. Request a user certificate

```bash
ssh-ca-sign-user-key -s ca-server.example.com
```

Signs `~/.ssh/id_ed25519.pub` → `~/.ssh/id_ed25519-cert.pub`. Prompts for password.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--user <NAME>` | `-u` | `$USER` | Username for auth |
| `--key <PATH>` | `-k` | `~/.ssh/id_ed25519.pub` | Public key to sign |
| `--output <PATH>` | `-o` | `<key>-cert.pub` | Output cert path |
| `--known-hosts <PATH>` | | system default | Custom known_hosts for CA |
| `--no-host-check` | | off | Skip CA host key verification |
| `--retry <N>` | | `0` | Retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Verbose output |

### Examples

```bash
ssh-ca-sign-user-key -s ca-server.example.com
ssh-ca-sign-user-key -s ca-server.example.com -u alice -k ~/.ssh/id_ed25519.pub
ssh-ca-sign-user-key -s ca-server.example.com -p 2222 -o ~/.ssh/id_ed25519-cert.pub -v
ssh-ca-sign-user-key -s ca-server.example.com --retry 3 --retry-delay 10
```

### Manual alternative

```bash
ssh -T -p 2222 alice@ca-server.example.com \
    < ~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
```

## 3. Configure SSH client

Add to `~/.ssh/config`:
```
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile    ~/.ssh/id_ed25519
```

Certificate has limited validity. Re-run script before it expires to renew.
