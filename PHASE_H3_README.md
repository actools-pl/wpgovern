# Phase H.3 — Database Module

**Status:** Complete  
**Bats tests:** 189 (was 164; +25 new)  
**Python tests:** 776 (unchanged)  
**New bash files:** 3 (`modules/db/wait.sh`, `modules/db/credentials.sh`, `modules/db/users.sh`)  
**New test files:** 5 (`test_h3_wait.bats`, `test_h3_credentials.bats`, `test_h3_users.bats`, `test_h3_entry_script_db_phase.bats`, `test_h3_ci_credentials.bats`)  
**Modified:** `wpgovern-install.sh`, `core/bootstrap.sh`, `modules/host/packages.sh`, `wpgovern.env.example`, `test_h1_host_module_structure.bats`, `test_h1_bootstrap.bats`

---

## Three concerns closed

### Concern 1 — Wait-for-ready discipline

After `docker compose up -d`, MariaDB starts but takes time to initialize binary logs and accept connections. H.3's `wait_for_ready` provides:

**Three failure paths with distinct state reasons:**

| Path | Condition | State reason |
|------|-----------|-------------|
| 1 | Container state ≠ "running" | `wait_for_ready: container not running` |
| 2 | No connection within 180s | `wait_for_ready: timeout after 180s` |
| 3 | `USE wordpress` fails | `wait_for_ready: wordpress database missing` |

Every mariadb invocation uses `>/dev/null 2>&1`. The CI guard `test_h3_ci_credentials.bats` verifies this structurally (exec count ≤ redirection count).

### Concern 2 — Credentials management

Three functions in `modules/db/credentials.sh`:

**`ensure_backup_password`:** generates `WPGOVERN_DB_BACKUP_PASSWORD` via `openssl rand -base64 32 | tr -d '/=+' | head -c 32` if blank. Persists to env file using `_wpgovern_credentials_persist` from H.2's credentials.sh.

**`generate_age_key`:** generates an age key pair at `${WPGOVERN_INSTALL_DIR}/.wpgovern-age.key`. Enforces 600 perms on every run (not just first run — silently restores if operator or restore script leaves it readable).

**`encrypt_state`:** encrypts all three DB passwords (root, wp, backup) to `${WPGOVERN_INSTALL_DIR}/.wpgovern-credentials.age`. The plaintext payload is built in a local variable and piped directly to `age` stdin — **never logged**. `2>/dev/null` on the age invocation suppresses any password-containing output.

### Concern 3 — Backup user with least privilege

Two functions in `modules/db/users.sh`:

**`verify_application_user`:** confirms `wpuser@%` exists in `mysql.user`. This user was created by the MariaDB image's first-run environment variable setup. If it doesn't exist, it indicates first-run failed — `mark_phase_failed`.

**`create_backup_user`:** idempotency-checked, then single atomic SQL invocation: `CREATE USER + GRANT + FLUSH PRIVILEGES`. Privileges exactly per strategic plan: `REPLICATION CLIENT, SELECT, LOCK TABLES, PROCESS`. Nothing else. Every mariadb invocation uses `>/dev/null 2>&1` — the CREATE statement contains the password literal.

---

## Age dependency rationale

`age` (https://age-encryption.org) was chosen for two reasons:

**H.3 use:** encrypt DB credentials at rest. Replaces plaintext env-file-only storage with a second copy that survives env file loss or rotation.

**H.6 use (forward):** backup encryption. The same age key pair and recipient pattern used here will be used in H.6 to encrypt `mariadb-dump` output before rclone transfer. Adding age in H.3 rather than H.6 means H.6 inherits an already-established pattern.

`age` is added to `modules/host/packages.sh` (H.3-4) so it's available before the db phase runs.

---

## Credential storage trust model

| Storage | Format | Perms | Governance-signed? |
|---------|--------|-------|-------------------|
| `wpgovern.env` | Plaintext | 600, enforced | No — it's the secret source of truth, not configuration |
| `.wpgovern-credentials.age` | age-encrypted | 600, enforced | No — contains SECRETS, not CONFIGURATION |
| `wpgovern-installer-state.json` | Plaintext (facts only) | owner rw | No — state facts don't contain credential values |

**The distinction: governance signs CONFIGURATION; credentials are SECRETS.**

H.5's baseline ceremony will sign `docker-compose.yml`, `Caddyfile`, and `my.cnf`. It will NOT sign `.wpgovern-credentials.age`. That file contains secrets that change per deployment. The governance model protects configuration integrity, not secret storage.

---

## Operator recovery procedure

If `wpgovern.env` is lost, credentials can be recovered from the encrypted state:

```bash
# On the server, with the age key in place:
age -d -i ${WPGOVERN_INSTALL_DIR}/.wpgovern-age.key \
         ${WPGOVERN_INSTALL_DIR}/.wpgovern-credentials.age
```

This outputs the three passwords in env-file format. Pipe to a new `wpgovern.env` and the installer can be re-run.

If the age key is also lost: the backup user password is needed for H.7 backups. The MariaDB root password can be reset via single-user mode. Document the key at a second location (e.g., encrypted password manager) during first install.

---

## Why the backup user has exactly these privileges

`REPLICATION CLIENT, SELECT, LOCK TABLES, PROCESS` are the four privileges that `mariadb-dump --single-transaction --master-data=2` requires and nothing else:

| Privilege | Purpose |
|-----------|---------|
| `REPLICATION CLIENT` | `SHOW MASTER STATUS` for binlog coordinates |
| `SELECT` | Read table data |
| `LOCK TABLES` | Consistent snapshot (with `--single-transaction`) |
| `PROCESS` | `SHOW PROCESSLIST` for kill-on-timeout |

Notably absent: `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `GRANT`, `SUPER`. If the backup user is compromised, it cannot modify data.

---

## Why application user is verified, not created

The `wpuser@%` application user is created by the MariaDB Docker image's first-run logic using the `MYSQL_USER` / `MYSQL_PASSWORD` environment variables in `docker-compose.yml`. This is the authoritative creation event — it also sets the database ownership. H.3's `verify_application_user` confirms it happened correctly rather than duplicating the creation. If verification fails, the correct response is to investigate the compose first-run logs, not retry creation.

---

## New state facts

| Fact | Value |
|------|-------|
| `db.wait_for_ready.completed_at` | ISO timestamp |
| `db.wait_for_ready.elapsed_seconds` | Seconds waited |
| `db.credentials.age_key_path` | Absolute path to age key |
| `db.credentials.age_key_generated_at` | ISO timestamp (first run only) |
| `db.credentials.encrypted_path` | Absolute path to encrypted credentials |
| `db.credentials.encrypted_at` | ISO timestamp |
| `db.users.app_user_verified_at` | ISO timestamp |
| `db.users.backup_created_at` | ISO timestamp |
| `db.users.backup_user_exists` | `"true"` |

---

## What H.3 does NOT do

- No WordPress installation (H.4)
- No backup execution (H.7)
- No automatic credential rotation
- No multi-database support
- No rclone remote backup integration (H.7)

---

## What H.4 begins next

- WordPress file population via the `wordpress` container or CLI
- `wp-config.php` generation (governance-tracked, H.5 will sign it)
- WordPress database initialization (`wp core install` or equivalent)
- Admin credential generation and encryption (same age-key pattern)
- Three-step pattern: prepare → provision → secure

---

## Test count

| Suite | H.2.1 | H.3 |
|-------|-------|-----|
| Bats | 164 | 189 |
| Python | 776 | 776 |
