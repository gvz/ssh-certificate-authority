# Troubleshooting

Run the client with `-v` and watch the server log at the same time:

```bash
journalctl -u ssh-ca-server.service -f
```

## Getting a certificate fails

### Permission denied (password), as a user

The CA machine rejected the password.
The account must exist on the CA machine, and PAM must accept it.

```bash
# on the CA machine
getent passwd alice
sudo passwd alice
ls /etc/pam.d/login
```

`root` is always rejected. Use a normal account.

A username with characters outside `a-z A-Z 0-9 . _ @ -` is rejected before
PAM sees it.

### Permission denied (publickey), as a host

The host public key is not in the inventory, or does not match.

```bash
# on the host
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# on the CA
grep -r public_key /etc/ssh_ca_server/hosts/
```

Check that the host name matches the file name:

```bash
hostname                                   # on the host
ls /etc/ssh_ca_server/hosts/               # on the CA
```

`webserver` needs `webserver.toml`.
Pass `--hostname` if the host name differs from the inventory file name.

### Key Mismatch for host

The login worked, the signing did not.
The key in `<hostname>.toml` is a different key from the one presented.

This happens when the host key was rotated and the inventory was not updated.
Copy the current public key into the entry.

### Empty output, no certificate

The CA process failed. Look for these in the log:

| Log line | Cause |
|---|---|
| `failed to open user template` | Wrong path in `user.toml`. |
| `user template ... exceeds maximum allowed size` | Template larger than 64 KiB. |
| `Failed to read config file` | Bad TOML, or a missing file. |
| `signing failed` | The CA key is unreadable or not a supported key type. |

## The server does not start

### Config file not found

```text
Config file /etc/ssh_ca/config.toml not found
```

The `-c` path is wrong, or the service user cannot read the file.

### Panic: in CA mode the socket path is mandatory

You started with `--certificate-authority` and no `--socket-path`.
CA mode also requires `--token-file`.
See [Split the two processes](server-setup.md#split-the-two-processes).

### The port is busy

Another process listens on the port.

```bash
sudo ss -tlnp | grep 2222
```

Do not use port 22 on a machine where `sshd` already runs.

### Paths in the config do not exist

The server checks the paths on startup.
Every path in `[ca]` must exist, and `private_key` in `[ssh]` must be
readable.

## Login with the certificate fails

### The client does not send the certificate

```bash
ssh -v host.example.com 2>&1 | grep -i cert
```

Add both files to `~/.ssh/config`:

```text
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile    ~/.ssh/id_ed25519
```

The certificate file must sit next to its private key.

### name is not a listed principal

```text
Refusing certificate ID "user-bob-1787172344": name is not a listed principal
```

You logged in as a username that is not in the certificate.

```bash
ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub    # look at Principals
```

Either log in as a listed name, or ask the operator to add the principal to
your template.

A common cause is a template that uses `{{user}}` instead of
`{{ user_name }}`.
An unknown variable renders empty, and the certificate gets an empty
principal.

### The certificate is not accepted at all

The host does not trust the CA.
On the host:

```bash
grep TrustedUserCAKeys /etc/ssh/sshd_config
sudo sshd -t
```

The file must contain the CA public key, not the CA private key.

### Certificate invalid: expired

Request a new one.
If it expires much sooner than expected, check `validity_in_days` in your
template.

### Certificate invalid: not yet valid

Clock skew.
The certificate starts at the moment of signing, with no tolerance.

```bash
timedatectl status     # on the client and on the CA
```

Turn on NTP on both.

## Host key warnings continue

The client trusts the CA, but the connection still prompts.

Check the `@cert-authority` line:

```bash
grep cert-authority ~/.ssh/known_hosts /etc/ssh/ssh_known_hosts
```

- The pattern must match the host name you type. `*` matches everything.
- The line holds the CA public key, one line, no line break.
- An old plain host key entry for the same host wins over the certificate.
  Remove it:

  ```bash
  ssh-keygen -R webserver.example.com
  ```

On the host, check that `sshd` actually presents the certificate:

```bash
grep HostCertificate /etc/ssh/sshd_config
ssh-keygen -Lf /etc/ssh/ssh_host_ed25519_key-cert.pub
```

The certificate must list the name the users type, in `Principals`.

## Still stuck

Collect this before you ask for help:

```bash
ssh_ca_server --version
journalctl -u ssh-ca-server.service -n 100 --no-pager
ssh-ca-sign-user-key -s ca-server.example.com -v 2>&1 | tail -30
ssh-keygen -Lf <the certificate, if you got one>
```

Never paste a private key or a password into an issue.
