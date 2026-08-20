# Maintenance

Day-to-day work of the CA operator.

## Who can get a certificate

Read this before you plan your access control.

The user list is **not** an allowlist.
A user that is missing from `user.toml` still gets a certificate, made from
`default_user_template`.

Access is decided by two things only:

1. PAM accepts the password on the CA machine.
2. The username is not `root`.

To deny a person, remove their login on the CA machine, or block them in PAM.
Editing `user.toml` only changes which template they get.

Ways to restrict PAM:

- Delete or lock the account: `sudo usermod -L alice`, `sudo userdel alice`.
- Use `pam_access` in `/etc/pam.d/login` with an `access.conf` allow rule.
- Give the CA machine its own account namespace, for example a dedicated LDAP
  group.

Test after every change:

```bash
ssh-ca-sign-user-key -s ca-server.example.com -u alice -v
```

## User tasks

### Add a user with a custom template

```bash
sudo tee /etc/ssh_ca_server/alice.toml <<'EOF'
validity_in_days = 1
principals = ["alice", "deploy"]
extensions = ["permit-pty"]
EOF
```

Add the entry to `/etc/ssh_ca_server/user.toml`:

```toml
[users]
alice = "./alice.toml"
```

No restart. The next request reads the new files.

### Change what a user may do

Edit their template.
The change applies to the next certificate, not to the ones already issued.
Old certificates keep working until they expire.

Keep `validity_in_days` low if you want changes to take effect quickly.

### Remove a user

1. Lock or delete the account on the CA machine.
2. Remove their entry from `user.toml` and delete their template file.
3. Wait for the certificate to expire, or shut them out on the target hosts.

There is no revocation list.
The expiry is your only automatic protection, so keep it short.

## Host tasks

### Enroll a host

Get the public key and the host name from the host admin:

```bash
# on the host
cat /etc/ssh/ssh_host_ed25519_key.pub
hostname
```

Create the inventory entry on the CA:

```bash
sudo tee /etc/ssh_ca_server/hosts/webserver.toml <<'EOF'
public_key       = "ssh-ed25519 AAAA... root@webserver"
validity_in_days = 365
hostnames        = ["webserver", "webserver.example.com"]
extensions       = []
EOF
```

The file name must match the name the host logs in with.
Tell the admin to continue with [Host Certificates](host-certificates.md).

### Remove a host

```bash
sudo rm /etc/ssh_ca_server/hosts/webserver.toml
```

The host can no longer log in to the CA and gets no new certificate.
Its current certificate stays valid until it expires.
Shorten `validity_in_days` in your entries if that window is too long.

### Rotate a host key

1. The admin creates a new host key on the host.
2. Replace `public_key` in the inventory entry.
3. The admin runs the signing script again with `--reload`.

Do not delete the old key from `sshd_config` before the new certificate works.

## Certificate lifetimes

| Kind | Suggested |
|---|---|
| Employee user certificate | 1 to 7 days |
| Contractor user certificate | 1 day |
| Host certificate | 90 to 365 days, renewed daily |

Short user lifetimes are the substitute for revocation.
Host lifetimes can be longer, because a host with a daily timer renews long
before the expiry.

## Rotate the CA key

Plan this. A wrong order locks everybody out.

Do it when the key may be exposed, when staff with access leave, or every few
years by schedule.

1. Create the new key next to the old one.

   ```bash
   sudo ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ca_key.new -N "" -C "ssh_ca_2"
   sudo chmod 600 /etc/ssh_ca_server/ca_key.new
   ```

2. Distribute the new public key to every client and every host, **next to**
   the old one. Both are trusted at the same time.

   ```text
   # ~/.ssh/known_hosts or /etc/ssh/ssh_known_hosts
   @cert-authority * ssh-ed25519 AAAA...old...
   @cert-authority * ssh-ed25519 AAAA...new...
   ```

   ```text
   # /etc/ssh/sshd_config on the hosts, both keys in one file
   TrustedUserCAKeys /etc/ssh/ca_keys.pub
   ```

3. Check that the rollout is complete. Every host and every client must have
   the new key. A missed host is locked out in the next step.

4. Switch the CA over.

   ```bash
   sudo mv /etc/ssh_ca_server/ca_key.new /etc/ssh_ca_server/ca_key
   sudo mv /etc/ssh_ca_server/ca_key.new.pub /etc/ssh_ca_server/ca_key.pub
   sudo systemctl restart ssh-ca-server.service
   ```

5. Let everybody request new certificates. Hosts get theirs from the daily
   timer, or run the script by hand.

6. When the longest old certificate has expired, remove the old public key
   from the clients and hosts.

Keep a break-glass account with a plain `authorized_keys` entry on a few
hosts.
It saves you when a rotation goes wrong.

## Backup

Back up, encrypted and off the machine:

| What | Why |
|---|---|
| `ca_key` | Without it, every client and host must be re-trusted. |
| `config.toml` | Small, but annoying to rebuild. |
| `user.toml` and templates | Your access rules. |
| `hosts/` | Your host inventory. |

Do not back up the CA key to a place with wide access.
A backup copy of the CA key is as powerful as the original.

Restore test, once a year:

```bash
sudo systemctl stop ssh-ca-server.service
# restore files, then
sudo systemctl start ssh-ca-server.service
ssh-ca-sign-user-key -s ca-server.example.com -v
```

## Monitoring

Watch the log:

```bash
journalctl -u ssh-ca-server.service -f
```

Useful lines:

| Log line | Meaning |
|---|---|
| `signing <key> for <name>` | A certificate was issued. |
| `user <name> is forbidden from logging in` | `root` tried. |
| `Key Mismatch for host <name>` | Inventory key differs from the presented key. |
| `failed to open user template` | A path in `user.toml` is wrong. |
| `spawning CA` / `Starting CA server` | Normal startup. |

Things worth an alert:

- The service is not running.
- No certificate issued in 24 hours, if you expect daily host renewals.
- Repeated authentication failures from one address.
- Free disk on `/etc` and the journal.

The service has no metrics endpoint.
Count log lines if you need numbers.

### Check what is deployed

```bash
# a user certificate
ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub
# a host certificate
ssh-keygen -Lf /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Find certificates that expire soon, from a host list:

```bash
for h in web1 web2 db1; do
  echo -n "$h: "
  ssh "$h" 'ssh-keygen -Lf /etc/ssh/ssh_host_ed25519_key-cert.pub | grep Valid'
done
```

## Restarts

A restart drops open connections.
Signing requests are short, so restart when you like.
Nobody loses an issued certificate.

Config changes and restarts:

| Change | Restart needed |
|---|---|
| User template, `user.toml` | No |
| Host inventory entry | No |
| `config.toml` | Yes |
| CA key file | Yes |

The NixOS module sets `Restart = "no"`.
Set `Restart = "on-failure"` if you want the service to come back after a
crash.

## Clock

Certificates start being valid at the second they are signed.
There is no tolerance for clock skew.

Run NTP on the CA, on the hosts and on the clients.
A client whose clock runs behind sees a certificate that is not valid yet.

## Upgrades

1. Read the [changelog](https://github.com/gvz/ssh-certificate-authority/blob/main/CHANGELOG.md).
2. Back up `/etc/ssh_ca_server/`.
3. Install the new package, or build and replace the binary.
4. Restart and watch the log.
5. Request one user certificate and one host certificate as a test.

The certificate format does not change between versions.
Certificates issued before an upgrade stay valid.

## Security checklist

- The CA machine does nothing else.
- Only operators have shell access to it.
- `ca_key` is mode `600` and owned by the service user.
- Backups of `ca_key` are encrypted.
- The CA server port is reachable only from where requests should come.
- `validity_in_days` is as short as your users tolerate.
- Certificate issuance is logged and the logs are shipped off the machine.
- A break-glass access path exists and is tested.
