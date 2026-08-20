# Configuration Reference

## Command line flags

| Flag | Short | Description |
|---|---|---|
| `--config-file <PATH>` | `-c` | Path to the TOML config file. Required. |
| `--certificate-authority` | `-a` | Run as CA process instead of SSH server. |
| `--socket-path <PATH>` | `-s` | Unix socket for CA traffic. Generated if omitted in SSH server mode. Required in CA mode. |
| `--disable-ca` | | Do not start a CA child process. |
| `--token-file <PATH>` | | File with the IPC token. Required in CA mode, where the file is read and then deleted. In SSH server mode the token is read from the file, or generated when the flag is missing. |
| `--help` | `-h` | Show help. |
| `--version` | `-V` | Show version. |

## Environment

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace`. |

Logs go to stderr, so systemd collects them in the journal.

## config.toml

Relative paths inside the file resolve against the directory of the file
itself.

### `[ssh]`

| Key | Type | Required | Description |
|---|---|---|---|
| `bind` | string | yes | Listen address, for example `0.0.0.0`. |
| `port` | integer | yes | Listen port. The clients default to `2222`. |
| `private_key` | string | yes | Host key of the CA server. Not the CA signing key. |
| `certificate` | string | no | Host certificate of the CA server. |

### `[ca]`

| Key | Type | Required | Description |
|---|---|---|---|
| `ca_key` | path | yes | Private key that signs certificates. |
| `user_list_file` | path | yes | Maps users to their template. |
| `default_user_template` | path | yes | Template for users not in the list. |
| `host_inventory` | path | yes | Directory with one TOML file per host. |

### `[identity_handlers]`

| Key | Type | Required | Description |
|---|---|---|---|
| `user_authenticators` | list of strings | yes | Enabled authenticators. Only `"pam"` exists today. |

### Example

```toml
[ssh]
bind = "0.0.0.0"
port = 2222
private_key = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key"
certificate = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub"

[ca]
ca_key                = "/etc/ssh_ca_server/ca_key"
user_list_file        = "/etc/ssh_ca_server/user.toml"
default_user_template = "/etc/ssh_ca_server/user_default.toml"
host_inventory        = "/etc/ssh_ca_server/hosts/"

[identity_handlers]
user_authenticators = ["pam"]
```

## User list file

```toml
[users]
alice = "./alice.toml"
bob   = "/etc/ssh_ca_server/bob.toml"
```

Relative paths resolve against the directory of the user list file.
A user that is not listed gets `default_user_template`.

## User certificate template

```toml
validity_in_days = 7
principals = ["{{ user_name }}"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
]
```

| Key | Type | Required | Description |
|---|---|---|---|
| `validity_in_days` | integer | yes | Lifetime in days. Maximum 65535. |
| `principals` | list of strings | yes | Usernames the certificate may log in as. |
| `extensions` | list of strings | yes | SSH extensions, all with an empty value. |

The file is a Jinja2 template, rendered with MiniJinja before it is parsed as
TOML.
`user_name` is the only variable.

Limits and behaviour:

- Template files larger than 64 KiB are rejected.
- Unknown keys are ignored. A `[critical_options]` table has no effect.
- A misspelled variable renders as an empty string, which produces an empty
  principal. Check your templates.

Common extensions:

| Extension | Effect |
|---|---|
| `permit-pty` | Interactive shell. Needed for normal logins. |
| `permit-agent-forwarding` | `ssh -A` |
| `permit-port-forwarding` | `ssh -L`, `ssh -R` |
| `permit-x11-forwarding` | `ssh -X` |
| `permit-user-rc` | Runs `~/.ssh/rc` on login |

Leave out what people do not need.

## Host inventory entry

One file per host, named `<hostname>.toml`, inside `host_inventory`.

```toml
public_key       = "ssh-ed25519 AAAA... root@webserver"
validity_in_days = 365
hostnames        = ["webserver", "webserver.example.com"]
extensions       = []
```

| Key | Type | Required | Description |
|---|---|---|---|
| `public_key` | string | yes | The host public key in OpenSSH format. |
| `validity_in_days` | integer | yes | Lifetime in days. Maximum 65535. |
| `hostnames` | list of strings | yes | Names the certificate is valid for. |
| `extensions` | list of strings | yes | Usually empty for hosts. |

Rules:

- The file name without `.toml` must match the name the host authenticates as.
- The public key is matched at login and compared again at signing.
- Host names with `/` or `..` are rejected.
- Files outside the inventory directory are skipped, including through
  symlinks.

Host certificate templates are not rendered.
Jinja2 syntax in an inventory file is not expanded.

## Fixed limits

These are compiled in and not configurable.

| Limit | Value |
|---|---|
| Username characters | `a-z A-Z 0-9 . _ @ -` |
| Username length | 1 to 64 |
| Blocked username | `root` |
| Template file size | 64 KiB |
| Connection inactivity timeout | 5 s |
| Delay after failed authentication | 3 s |
| Certificate start time | time of signing, no skew tolerance |
