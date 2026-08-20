# SSH Certificate Authority

This project provides a self-hosted SSH Certificate Authority (CA), similar in spirit to Let's Encrypt but for SSH certificates. Machines and users connect to this server over SSH to obtain short-lived, automatically renewable SSH certificates — replacing long-lived static keys.

## User Guide

The full guide lives in `book/`. It covers use cases, requesting user and host
certificates, server setup, and maintenance.

Read it online: <https://gvz.github.io/ssh-certificate-authority/>

Build it locally:

```bash
nix develop --command mdbook serve book --open
```

## Features

- **SSH Certificate Authority:** A built-in CA that signs SSH public keys into user or host certificates.
- **Pluggable Authentication:** Supports different authentication methods for users requesting certificates (currently PAM). `root` is explicitly blocked.
- **Host Certificate Signing:** Hosts authenticate with their public key (verified against a pre-registered inventory) and receive a signed host certificate.
- **Unix Socket IPC:** The SSH server and CA server communicate over a Unix socket, authenticated with a shared token (see `--token-file`).
- **Configurable:** Configured via TOML files for SSH server settings, CA settings, and per-user certificate templates.
- **Dynamic User Templates:** User certificate templates are rendered with [MiniJinja](https://docs.rs/minijinja) (Jinja2-compatible), allowing flexible principal and extension management per user.

## Project Structure

```
src/
├── main.rs                               # Entry point
├── lib.rs                                # CLI argument parsing and server orchestration
├── config/
│   └── mod.rs                            # Top-level config struct and file reader
├── certificat_authority/
│   ├── mod.rs                            # CertificateAuthority struct; sign_certificate / sign_host_certificate
│   ├── ca_client.rs                      # Unix socket client — sends requests to the CA server
│   ├── ca_server.rs                      # Unix socket server — receives and dispatches signing requests
│   ├── config.rs                         # CA configuration struct
│   ├── user_defaults_reader.rs           # Reads and renders per-user certificate templates
│   ├── host_config_reader.rs             # Reads host inventory TOML files; matches keys to hosts
│   └── certificat_template_reader.rs     # Low-level Jinja-templated TOML config reader
├── ssh_server/
│   ├── mod.rs                            # SSH server, connection handler, auth dispatch
│   ├── config.rs                         # SSH server configuration struct
│   ├── user_key_signer.rs                # Handles user certificate signing requests (password auth flow)
│   ├── host_key_signer.rs                # Handles host certificate signing requests (public key auth flow)
│   └── signing_common.rs                 # Shared signing helpers used by both signers
└── identiy_handlers/
    ├── mod.rs                            # UserAuthenticator trait and authenticator setup
    └── pam_auth.rs                       # PAM-based authenticator

book/                                     # User guide (mdBook)
clients/                                  # Bash client scripts for certificate signing
config/                                   # Example configuration files
docker/                                   # Docker-based end-to-end test setup
nix/                                      # Nix packages, checks, NixOS module, Debian packaging
scripts/                                  # Helper scripts
test_data/                                # Test keys and fixtures
tests/                                    # Integration and end-to-end tests
fuzz/                                     # cargo-fuzz (libFuzzer) fuzzing harness
```

## Client Scripts

The `clients/` directory contains two Bash scripts for requesting certificates from the CA.

**Sign a user certificate** (run on the user's workstation):

```bash
ssh-ca-sign-user-key -s ca-server.example.com
```

**Sign a host certificate** (run on the managed host, as root):

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com --reload
```

Both scripts support `--help` for the full option list. See [User Certificates](book/src/user-certificates.md) and [Host Certificates](book/src/host-certificates.md) for installation instructions and all options.

---

## CLI flags

| Flag                      | Short | Description                                                                 |
|---------------------------|-------|-----------------------------------------------------------------------------|
| `--config-file <PATH>`    | `-c`  | Path to the TOML configuration file (**required**)                          |
| `--certificate-authority` | `-a`  | Run as a standalone CA server                                               |
| `--socket-path <PATH>`    | `-s`  | Unix socket path for CA communication (auto-generated if omitted)           |
| `--disable-ca`            |       | Start the SSH server without spawning a CA child process                    |
| `--token-file <PATH>`     |       | File holding the IPC authentication token. In SSH server mode the token is generated and written here (auto-generated path if omitted). In CA mode the token is read and the file is deleted at once. |

## How It Works

### User Certificate Flow

1. A user connects to the SSH Certificate Authority server with their **username and password**.
2. The server authenticates the user against the configured identity handlers (e.g. PAM). `root` is always rejected.
3. On success, the user sends their **SSH public key** as channel data (stdin).
4. The SSH server forwards a `SignCertificate` request to the CA server over the Unix socket.
5. The CA looks up the user's certificate template (falling back to the default template), renders it, and signs the public key.
6. The signed certificate is returned to the user over the same SSH channel.

### Host Certificate Flow

1. A host connects to the SSH Certificate Authority server using **public key authentication**, presenting its host public key.
2. The server checks the CA's host inventory for a matching public key entry. If no match is found, the connection is rejected.
3. The host sends the `sign_host_key` command over the exec channel.
4. The SSH server forwards a `SignHostCertificate` request to the CA server.
5. The CA verifies the public key against the host's inventory entry and signs it.
6. The signed host certificate is returned to the host over the same SSH channel.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.