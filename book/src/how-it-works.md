# How This Service Works

## Two processes

One binary runs in two modes.

| Mode | Started with | Job |
|---|---|---|
| SSH server | default | Accepts client connections, authenticates them |
| CA | `--certificate-authority` | Holds the CA private key, signs certificates |

The SSH server starts the CA as a child process.
Only the CA process reads the CA private key.
The SSH server never sees it.

```text
   client ---- SSH ----> [ SSH server ] ---- unix socket ----> [ CA ]
                              |                                  |
                     PAM / host inventory                    ca_key
```

Run the SSH server alone with `--disable-ca` if you start the CA yourself.

## The unix socket

The two processes talk over a unix socket in a private temporary directory.
The socket is protected in several ways.

- File permissions on the socket.
- Peer UID check on every connection.
- A random 32 byte token, shared through a `0600` file that the CA deletes
  after reading it.
- A monotonic counter in every message, against replay.
- Length-prefixed messages.

You normally do not need to touch this.
See `--socket-path` and `--token-file` in the
[Configuration Reference](configuration-reference.md).

## User certificate flow

1. The user connects to the CA server with username and password.
2. The SSH server checks the username against `[a-zA-Z0-9._@-]`, 1 to 64
   characters. `root` is always rejected.
3. PAM authenticates the password.
4. The user sends the public key as channel data.
5. The SSH server asks the CA to sign it.
6. The CA looks up the user in `user_list_file`.
   If the user is not listed, it uses `default_user_template`.
7. The CA renders the template, then signs.
8. The certificate comes back on the same channel.

## Host certificate flow

1. The host connects with its host private key.
2. The SSH server searches the host inventory for that public key.
   No match means no login.
3. The host runs the command `sign_host_key`.
4. The SSH server asks the CA to sign.
5. The CA reads `<hostname>.toml` from the inventory and compares the public
   key again.
6. The certificate comes back on the same channel.

The public key is checked twice, once at login and once at signing.

## What ends up in the certificate

| Field | User certificate | Host certificate |
|---|---|---|
| Type | user | host |
| Principals | `principals` from the template | `hostnames` from the inventory entry |
| Valid from | now | now |
| Valid to | now + `validity_in_days` | now + `validity_in_days` |
| Serial | random 64 bit | random 64 bit |
| Key ID | `user-<name>-<unix time>` | `host-<name>-<unix time>` |
| Extensions | `extensions` from the template | `extensions` from the inventory entry |

There is no clock skew tolerance.
The certificate starts to be valid at the moment of signing.
Keep the clocks in sync with NTP.

Critical options are not supported.
A `[critical_options]` table in a template file is ignored.
