# User Certificates

This chapter is for a person who wants a certificate for their own SSH key.

## Before you start

- The CA is running. Ask your CA operator for the address and port.
- You have an account on the CA server. PAM authenticates against it.
- You have a key pair. Create one with `ssh-keygen -t ed25519` if needed.
- `bash`, `ssh`, `ssh-keygen` and `getopt` are installed.

`root` cannot get a user certificate. The CA rejects it.

## Step 1: trust the CA

Your client must trust the CA, so host certificates are accepted.

Get the CA public key from your operator.
Verify the fingerprint out of band, for example by phone or in person.

```bash
# package install
scp ca-server.example.com:/etc/ssh_ca_server/ca_key.pub ~/ca_key.pub
# source install
scp ca-server.example.com:/etc/ssh_ca/ca_key.pub ~/ca_key.pub
ssh-keygen -lf ~/ca_key.pub    # compare this fingerprint with your operator
```

Add it as a certificate authority:

```bash
# for you only
echo "@cert-authority * $(cat ~/ca_key.pub)" >> ~/.ssh/known_hosts
# for everybody on the machine
echo "@cert-authority * $(cat ~/ca_key.pub)" | sudo tee -a /etc/ssh/ssh_known_hosts
```

Replace `*` with a pattern like `*.example.com` if the CA signs only some of
your hosts.

## Step 2: install the client script

Debian package:

```bash
sudo dpkg -i ssh-ca-client_<version>_all.deb
sudo apt-get install -f
```

This installs `ssh-ca-sign-user-key` to `/usr/bin/`.

Manual:

```bash
sudo cp clients/ssh-ca-sign-user-key.sh /usr/local/bin/ssh-ca-sign-user-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-user-key
```

## Step 3: request a certificate

```bash
ssh-ca-sign-user-key -s ca-server.example.com
```

You are asked for your password.
The script signs `~/.ssh/id_ed25519.pub` and writes
`~/.ssh/id_ed25519-cert.pub`.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--user <NAME>` | `-u` | `$USER` | Username for authentication |
| `--key <PATH>` | `-k` | `~/.ssh/id_ed25519.pub` | Public key to sign |
| `--output <PATH>` | `-o` | `<key>-cert.pub` | Output certificate path |
| `--known-hosts <PATH>` | | system default | Custom `known_hosts` for the CA |
| `--no-host-check` | | off | Skip CA host key check |
| `--retry <N>` | | `0` | Retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Verbose output |
| `--help` | `-h` | | Show help |

### Examples

```bash
ssh-ca-sign-user-key -s ca-server.example.com
ssh-ca-sign-user-key -s ca-server.example.com -u alice -k ~/.ssh/id_ed25519.pub
ssh-ca-sign-user-key -s ca-server.example.com -p 2222 -o ~/.ssh/id_ed25519-cert.pub -v
ssh-ca-sign-user-key -s ca-server.example.com --retry 3 --retry-delay 10
```

### Without the script

The script is a wrapper. This does the same:

```bash
ssh -T -p 2222 alice@ca-server.example.com \
    < ~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
```

The public key goes in on stdin. The certificate comes out on stdout.

## Step 4: use the certificate

Add this to `~/.ssh/config`:

```text
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile    ~/.ssh/id_ed25519
```

Check what you got:

```bash
ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub
```

Look at `Valid`, `Principals` and `Extensions`.
You can only log in as a username that is listed in `Principals`.

## Step 5: renew

Certificates are short-lived. The default is 7 days.
Run the same command again to renew:

```bash
ssh-ca-sign-user-key -s ca-server.example.com
```

Renew automatically with a systemd user timer:

```ini
# ~/.config/systemd/user/ssh-cert.service
[Unit]
Description=Renew SSH user certificate

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-ca-sign-user-key -s ca-server.example.com --retry 3
```

```ini
# ~/.config/systemd/user/ssh-cert.timer
[Unit]
Description=Renew SSH user certificate daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable --now ssh-cert.timer
```

This only works if the login needs no password prompt, which is rarely the
case with PAM password authentication.
Most people renew by hand.

## Common problems

See [Troubleshooting](troubleshooting.md).
