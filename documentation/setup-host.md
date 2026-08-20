# Host Setup

**Prerequisites:**
- CA running. See [CA Server Setup](setup-ca.md).
- Host public key registered in CA inventory by CA operator.
- `bash`, `ssh`, `ssh-keygen`, `getopt` available (standard Linux).

## Install client script

**Option A — Debian package** (any arch):
```bash
sudo dpkg -i ssh-ca-client_<version>_all.deb
sudo apt-get install -f
```
Installs `ssh-ca-sign-host-key` to `/usr/sbin/`.
The package built with `cargo deb` installs it to `/usr/bin/` instead.

**Option B — manual:**
```bash
sudo cp clients/ssh-ca-sign-host-key.sh /usr/local/bin/ssh-ca-sign-host-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-host-key
```

## Trust the CA server's host key

Before first connection, add the CA server to known_hosts:
```bash
ssh-keyscan -p 2222 ca-server.example.com >> ~/.ssh/known_hosts
```

Verify the fingerprint out-of-band with your CA operator. Alternatively pass `--no-host-check` on first run only (insecure).

## Request a host certificate

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com
```

Signs `/etc/ssh/ssh_host_ed25519_key` → `/etc/ssh/ssh_host_ed25519_key-cert.pub`.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--identity <PATH>` | `-i` | `/etc/ssh/ssh_host_ed25519_key` | Host private key |
| `--hostname <NAME>` | `-n` | `$(hostname)` | Hostname to authenticate as |
| `--output <PATH>` | `-o` | `<identity>-cert.pub` | Output cert path |
| `--known-hosts <PATH>` | | system default | Custom known_hosts for CA |
| `--no-host-check` | | off | Skip CA host key verification |
| `--reload` | | off | Reload sshd after signing |
| `--retry <N>` | | `0` | Retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Verbose output |

### Examples

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com
sudo ssh-ca-sign-host-key -s ca-server.example.com -i /etc/ssh/ssh_host_ed25519_key --reload
sudo ssh-ca-sign-host-key -s ca-server.example.com -p 2222 -n webserver --retry 3
sudo ssh-ca-sign-host-key -s ca-server.example.com --known-hosts /etc/ssh_ca/ca_known_hosts
```

### Manual alternative

```bash
ssh -i /etc/ssh/ssh_host_ed25519_key -p 2222 webserver@ca-server.example.com sign_host_key \
    > /etc/ssh/ssh_host_ed25519_key-cert.pub
```

## Configure sshd

Add to `/etc/ssh/sshd_config`:
```
HostKey         /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

```bash
sudo systemctl reload sshd
```

## Automate renewal

`/etc/systemd/system/ssh-host-cert-renew.service`:
```ini
[Unit]
Description=Renew SSH host certificate from CA

[Service]
Type=oneshot
ExecStart=/usr/sbin/ssh-ca-sign-host-key -s ca-server.example.com --reload
```

> Manual install: adjust path to `/usr/local/bin/ssh-ca-sign-host-key`.

`/etc/systemd/system/ssh-host-cert-renew.timer`:
```ini
[Unit]
Description=Renew SSH host certificate daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-host-cert-renew.timer
```
