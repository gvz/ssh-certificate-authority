# Host Certificates

This chapter is for an admin who enrolls a server.
The server gets a host certificate, so users stop seeing host key warnings.

## Before you start

- The CA is running.
- The CA operator has added this host to the inventory.
  See [Enroll a host](maintenance.md#enroll-a-host).
- You have root on the host.

The enrollment is a two-sided job.
You send your host public key to the operator.
The operator creates the inventory entry.
Without that entry, the login to the CA fails.

## Step 1: send your host public key

```bash
cat /etc/ssh/ssh_host_ed25519_key.pub
hostname
```

Send both to the CA operator.
They create `<hostname>.toml` in the inventory.

The file name must match the name the host uses to log in.
That is `$(hostname)` by default, or the value of `--hostname`.

## Step 2: install the client script

Debian package:

```bash
sudo dpkg -i ssh-ca-client_<version>_all.deb
sudo apt-get install -f
```

The nix-built package installs `ssh-ca-sign-host-key` to `/usr/sbin/`.
The package built with `cargo deb` installs it to `/usr/bin/`.

Manual:

```bash
sudo cp clients/ssh-ca-sign-host-key.sh /usr/local/bin/ssh-ca-sign-host-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-host-key
```

## Step 3: trust the CA server host key

Add the CA server to `known_hosts` before the first run:

```bash
ssh-keyscan -p 2222 ca-server.example.com >> ~/.ssh/known_hosts
```

Verify the fingerprint with the operator.
`--no-host-check` skips this check.
Use it on the first run only, and only if you accept the risk.

## Step 4: request the certificate

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com
```

This signs `/etc/ssh/ssh_host_ed25519_key` and writes
`/etc/ssh/ssh_host_ed25519_key-cert.pub`.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--identity <PATH>` | `-i` | `/etc/ssh/ssh_host_ed25519_key` | Host private key |
| `--hostname <NAME>` | `-n` | `$(hostname)` | Name to authenticate as |
| `--output <PATH>` | `-o` | `<identity>-cert.pub` | Output certificate path |
| `--known-hosts <PATH>` | | system default | Custom `known_hosts` for the CA |
| `--no-host-check` | | off | Skip CA host key check |
| `--reload` | | off | Reload `sshd` after signing |
| `--retry <N>` | | `0` | Retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Verbose output |
| `--help` | `-h` | | Show help |

### Examples

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com
sudo ssh-ca-sign-host-key -s ca-server.example.com -i /etc/ssh/ssh_host_ed25519_key --reload
sudo ssh-ca-sign-host-key -s ca-server.example.com -p 2222 -n webserver --retry 3
sudo ssh-ca-sign-host-key -s ca-server.example.com --known-hosts /etc/ssh_ca/ca_known_hosts
```

### Without the script

```bash
ssh -i /etc/ssh/ssh_host_ed25519_key -p 2222 webserver@ca-server.example.com sign_host_key \
    > /etc/ssh/ssh_host_ed25519_key-cert.pub
```

The username in that command is the host name.
The CA ignores it for authentication, but uses `sign_host_key` as the command.

## Step 5: tell sshd to present the certificate

Add to `/etc/ssh/sshd_config`:

```text
HostKey         /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

```bash
sudo sshd -t          # check the config first
sudo systemctl reload sshd
```

`--reload` does the reload for you.

## Step 6: accept user certificates

A host certificate stops the warnings for your users.
To let users log in with their certificates, the host must also trust the CA.

Copy the CA public key to the host, then add to `/etc/ssh/sshd_config`:

```text
TrustedUserCAKeys /etc/ssh/ca_key.pub
```

```bash
sudo systemctl reload sshd
```

Now any user with a valid certificate can log in as a username listed in the
certificate principals.
No `authorized_keys` entry is needed.

> Test this in a second session before you close the first one.
> A broken `sshd_config` can lock you out.

## Step 7: automate renewal

Host certificates expire too. The example inventory uses 365 days.
Renew daily, so an expiry never surprises you.

`/etc/systemd/system/ssh-host-cert-renew.service`:

```ini
[Unit]
Description=Renew SSH host certificate from CA
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ssh-ca-sign-host-key -s ca-server.example.com --reload --retry 3
```

Adjust the path for a manual install: `/usr/local/bin/ssh-ca-sign-host-key`.

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

`RandomizedDelaySec` spreads the load, so a large fleet does not hit the CA at
the same second.

## Check the result

```bash
ssh-keygen -Lf /etc/ssh/ssh_host_ed25519_key-cert.pub
```

From a client that trusts the CA:

```bash
ssh -v webserver.example.com 2>&1 | grep -i 'certificate\|host key'
```

You should see the host certificate being accepted, and no prompt.
