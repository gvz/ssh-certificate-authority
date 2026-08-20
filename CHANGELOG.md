# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Debian packaging metadata for `cargo-deb` (server and client packages)
- CI workflow that builds Debian packages for Debian 12/13 and Ubuntu 26.04

### Changed
- Shared signing helpers extracted from the user and host key signers
- Shared `read_toml_file` helper for all TOML reads
- Pinned the `russh` dependency to an audited commit across all build paths
- Adapted to the russh 0.63 channel-open handle API

### Fixed
- CA skips an unreadable host config instead of aborting the search
- CA detects `u64` counter overflow instead of wrapping

### Security
- Usernames are validated against an allowlist to prevent TOML injection
- Removed a timing oracle on the first authentication rejection
- The `test_auth` feature now fails at compile time instead of panicking at runtime

## [0.2.2] - 2026-03-04

### Changed
- CI no longer publishes pages on tags

## [0.2.1] - 2026-03-03

### Added
- Fuzz targets for the CA, including `sign_host_certificate`
- Fuzzing in CI, with published fuzz coverage
- CA docker image published to the GitHub Container Registry

### Changed
- Replaced the AFL++ fuzzing setup with cargo-fuzz (libFuzzer)
- Split `flake.nix` into separate modules under `nix/`
- Hostname validation and exec command parsing moved into testable functions
- Updated MiniJinja from 2.10.2 to 2.16.0
- Rust toolchain switched to nightly via fenix

### Security
- Hardened MiniJinja usage against out-of-memory from adversarial templates

## [0.2.0] - 2026-02-28

### Added
- SSH Certificate Authority server with PAM authentication
- Pluggable authentication system (currently supports PAM)
- Host certificate signing with inventory-based public key verification
- Unix socket IPC for secure communication between SSH server and CA
- Configurable certificate templates using MiniJinja (Jinja2-compatible)
- Dynamic per-user certificate templates with fallback to defaults
- Client scripts for requesting user and host certificates
- Debian packages for easy installation (server and client)
- NixOS module for declarative server configuration
- Comprehensive end-to-end tests using NixOS VMs
- Docker-based testing infrastructure
- Fuzzing harness using AFL++ (replaced by cargo-fuzz in 0.2.1)
- Root user blocking for enhanced security
- Systemd service integration

### Security
- Password-based authentication for user certificates via PAM
- Public key authentication for host certificates
- Inventory-based host verification to prevent unauthorized certificates
- Explicit root user blocking in authentication flow
- Short-lived certificates (7-day default validity)
- Token authentication and a monotonic counter against replay on the CA socket
- Socket permissions and peer UID verification on the CA socket
- Hostname sanitizing to prevent config path breakouts
- CA private key buffer zeroized after loading
