# SSH ACME Server

Self-hosted SSH Certificate Authority. Issues short-lived signed SSH certificates for users and hosts — like Let's Encrypt, but for SSH.

Communication happens over SSH. CA listens on a dedicated port. Users authenticate via PAM; hosts via their existing SSH host key.

Pre-built Debian packages published on every [GitHub Release](https://github.com/your-org/ssh_acme_server/releases). Building from source also supported on any Linux system.

## Roles

| Role | Who | Guide |
|---|---|---|
| **CA operator** | Runs and maintains the CA server | [CA Server Setup](setup-ca.md) |
| **Host admin** | Enrolls a server to receive a signed host certificate | [Host Setup](setup-host.md) |
| **User** | Obtains a signed certificate for their own SSH key | [User Setup](setup-user.md) |

## Setup order

1. CA operator: [CA Server Setup](setup-ca.md) — run CA, add hosts to inventory.
2. Host admins: [Host Setup](setup-host.md) — request signed host certificate, configure sshd.
3. Users: [User Setup](setup-user.md) — trust CA, request signed user certificate.
