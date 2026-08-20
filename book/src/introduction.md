# Introduction

This is a self-hosted SSH Certificate Authority (CA).
It works like Let's Encrypt, but for SSH certificates instead of TLS.

Users and hosts connect to the CA over SSH.
They send a public key.
They get back a short-lived SSH certificate.

## Who this guide is for

| You are | Read |
|---|---|
| Deciding if you need this | [Why SSH Certificates](use-cases.md) |
| A user who wants a certificate | [User Certificates](user-certificates.md) |
| An admin enrolling a server | [Host Certificates](host-certificates.md) |
| The CA operator | [Server Setup](server-setup.md), [Maintenance](maintenance.md) |

## What the service does

- Signs user public keys after a password login (PAM).
- Signs host public keys after a public key login against an inventory.
- Renders certificate parameters from per-user TOML templates.
- Blocks `root` from getting a user certificate.

## What the service does not do

- No certificate revocation lists (KRL). Use short validity instead.
- No web interface or REST API. Everything runs over SSH.
- No user database. User authentication is delegated to PAM.
- No critical options in certificates. Only extensions and principals.

## Status

The project is young.
Read the [Maintenance](maintenance.md) chapter before you run it for a large fleet.

Parts of the code and documentation were written with AI assistance.
