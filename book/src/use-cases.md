# Why SSH Certificates

Plain SSH keys have two problems.
Certificates fix both.

## Problem 1: authorized_keys does not scale

With plain keys, every user key must be copied to every server.

- 50 users and 200 servers means 10000 key entries.
- Removing a person means editing 200 files.
- A forgotten entry stays valid forever.

With certificates, each server trusts one CA public key.
The CA decides who gets in.
No per-user files on the servers.

## Problem 2: known_hosts trust on first use

With plain host keys, the first connection asks:

```text
The authenticity of host 'server1 (10.0.0.5)' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no)?
```

Almost everybody types `yes` without checking.
That is an open door for a machine-in-the-middle attack.

With host certificates, the client trusts the CA once.
Every signed host is then verified automatically.
No prompt, no blind trust.

## Use cases

### Onboarding and offboarding

A new person gets a login on the CA server, and nothing else.
They request a certificate and can reach every server their principals allow.

When they leave, remove them from the CA.
Their current certificate expires within days.
No server has to be touched.

### Servers that come and go

Autoscaled or reinstalled servers get new host keys every time.
Users see host key warnings, or worse, learn to ignore them.

With host certificates, the new server enrolls, gets a certificate, and
clients accept it right away.

### Contractors and time-boxed access

Set `validity_in_days = 1` for a contractor template.
The access ends by itself.
There is no cleanup task to forget.

### Least privilege per person

Certificates carry principals and extensions.

- A database admin gets the principal `dbadmin`.
- A junior gets `permit-pty` only, no port forwarding.

The rules live in one template file on the CA, not on 200 servers.

### Shared accounts with an audit trail

Several people may log in as `deploy`.
Each certificate carries a key ID like `user-alice-1787172344`.
`sshd` logs that key ID, so you can see who used the shared account.

### Air-gapped or self-hosted requirements

Some environments cannot use a hosted CA product.
This service is a single binary plus TOML files.
All traffic is SSH.

## When you do not need this

- One admin, three servers. The effort is not worth it.
- You already run a mature secrets platform with SSH CA support.
- You need instant revocation. This service has no KRL support.

## How certificates work in SSH

An SSH certificate is a public key, plus metadata, signed by a CA key.

| Field | Meaning |
|---|---|
| Type | User certificate or host certificate |
| Principals | Usernames (user cert) or hostnames (host cert) |
| Validity | Start and end time |
| Serial | Random number for logging |
| Key ID | Free text, logged by `sshd` |
| Extensions | Allowed features, for example `permit-pty` |

A server accepts a user certificate if it trusts the CA and the requested
username is a listed principal.
A client accepts a host certificate if it trusts the CA and the hostname is a
listed principal.
