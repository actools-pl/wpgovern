# Installation Manual

## Status

This manual is for technical installers and sysadmins installing WPGovern v1.0.0 on a fresh server. It describes requirements, environment configuration, installer execution, expected phases, and post-install verification.

## 1. Installation model

WPGovern v1.0.0 installs a single-tenant, single-user, single-node governed WordPress system.

The installer is phase-based and idempotent at phase boundaries. If a phase is complete, a later installer run skips it. If a phase is incomplete, the installer resumes from the appropriate point.

The installer entry command is:

```bash
sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env
```

A firewall safety override exists, but should be used only when the installer operator understands the SSH risk:

```bash
sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env --force-firewall
```

## 2. Server requirements

WPGovern v1.0.0 expects:

- Ubuntu 24.04 LTS,
- root or sudo access,
- Docker-capable host,
- public network access for package installation and TLS issuance,
- Hetzner CX22-class server or equivalent,
- sufficient disk space for WordPress data, MariaDB data, logs, and encrypted backups.

The installer checks `/etc/os-release` and rejects unsupported operating systems.

## 3. DNS requirements

Before stack installation, configure DNS:

```text
A record: your-domain.example -> server public IPv4 address
```

The WPGovern domain is supplied through `WPGOVERN_DOMAIN` in the env file.

TLS issuance depends on the domain resolving to the server and inbound HTTP/HTTPS being reachable.

## 4. Environment file

Create an env file from the template:

```bash
cp wpgovern.env.example wpgovern.env
chmod 600 wpgovern.env
$EDITOR wpgovern.env
```

The env file contains secrets and must not be committed to source control.

The installer requires `--env-file`.

Core variables include:

```text
WPGOVERN_OPERATOR_EMAIL
WPGOVERN_DOMAIN
WPGOVERN_WP_ADMIN_USER
WPGOVERN_WP_ADMIN_PASSWORD
WPGOVERN_WP_ADMIN_EMAIL
```

Other values may be generated and persisted by the installer, including database passwords, backup password, and WordPress auth keys/salts.

Backup variables include:

```text
WPGOVERN_DB_BACKUP_PASSWORD
WPGOVERN_AGE_PRIVATE_KEY_PATH
WPGOVERN_AGE_PUBLIC_KEY_PATH
WPGOVERN_BACKUP_DIR
WPGOVERN_RCLONE_REMOTE
```

`WPGOVERN_RCLONE_REMOTE` is optional.

## 5. Important env-file discipline

The env file is not a general script interface for arbitrary behaviour.

Do not add unreviewed shell logic.

Do not put real secrets into `wpgovern.env.example`.

Do not store the age private key content directly in the env file. The env file stores key paths, not key material.

Do not rely on env-file settings for `--force-firewall`; the firewall force option is CLI-only.

## 6. Installer phases

The installer writes and reads phase completion state.

The v1.0.0 phase names are:

| Phase | Purpose |
|---|---|
| `host` | Packages, kernel tuning, swap, firewall, Docker, logrotate. |
| `stack` | Docker Compose stack, image pinning, Caddyfile, MariaDB config. |
| `db` | Database readiness, credentials, backup user, encrypted state. |
| `wp` | WordPress preparation, provisioning, and secure configuration. |
| `ceremony` | Python control-plane installation and byte-one governance ceremony. |
| `audit` | Installation of `wpgovern-install-audit`. |
| `backup` | age keypair, restore shim, systemd backup timers, runbook. |

Each phase should complete before the next begins.

## 7. State file

The installer state file normally lives under the install directory:

```text
${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json
```

The canonical v1 install directory is:

```text
/opt/wpgovern-install
```

The installer records facts such as phase completion, env-file path, OS facts, backup facts, and DR key acknowledgement.

Do not manually edit the state file unless following a documented repair procedure.

## 8. Running the installer

From the repository root on the target server:

```bash
sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env
```

Expected behaviour:

- unsupported OS is rejected,
- jq is installed as a preflight if missing,
- an installer lock prevents concurrent installer runs,
- completed phases are skipped on re-run,
- failed phases record failure facts where possible.

If SSH uses a non-standard port, set `WPGOVERN_SSH_PORT` in the env file before firewall configuration.

## 9. Confirming installation succeeded

After install, run:

```bash
wpgovern-install-audit --complete
```

Expected condition:

```text
No unexpected FAIL findings.
```

Also run the governance check if available in the installed control plane:

```bash
wpgovern governance-check
```

Expected condition:

```text
exit code 0
```

Then check restore tooling:

```bash
wpgovern-restore --help
wpgovern-restore list
```

## 10. Common install failures

### Unsupported OS

The installer requires Ubuntu 24.04 LTS.

### DNS not ready

TLS issuance and stack access may fail if the domain does not resolve to the server.

### SSH firewall risk

If firewall checks fail, verify the SSH port before using `--force-firewall`.

### Docker or stack health failure

Check:

```bash
docker compose ps
docker compose logs
```

### Missing required env values

Re-open the env file and confirm required WordPress and domain variables are set.

### Backup key or timer failure

Run:

```bash
wpgovern-install-audit --complete
```

and inspect `WPG-BKUP-*` and `WPG-DR-*` findings.

## 11. Re-run and resumability

The installer is designed to be re-run with the same env file.

Use the same command:

```bash
sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env
```

Completed phases should be skipped. The installer should not regenerate persisted secrets on a normal re-run.

If state and filesystem disagree, do not guess. Preserve logs and state, then review the failing phase.

## 12. Post-install operator handover

After installation, provide the operator with:

```text
[ ] Server access procedure.
[ ] Domain and DNS details.
[ ] Env file path.
[ ] Install directory.
[ ] Backup directory.
[ ] age private key path and off-server custody procedure.
[ ] Latest wpgovern-install-audit --complete output.
[ ] This manual.
[ ] OPERATOR_MANUAL.md.
[ ] BACKUP_AND_DR_MANUAL.md.
[ ] SECURITY_TRUST_MODEL.md.
```

Do not hand over the system without explaining off-server key custody.

## 13. Closure / Summary

A WPGovern installation is complete only when the installer phases have completed, governance check succeeds, audit has no unexpected FAIL findings, backup tooling is installed, and the operator understands the age private key custody responsibility. Installation is the beginning of governance, not the end of operation.