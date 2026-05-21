# Phase H.2 — Docker Compose Stack Module

**Status:** Complete  
**Bats tests:** 144 (was 104; 40 new)  
**Python tests:** 776 (unchanged from v52.1)  
**New bash files:** 5 (under `modules/stack/`)  
**Modified files:** `wpgovern-install.sh`, `core/bootstrap.sh`, `wpgovern.env.example`

---

## Purpose

H.2 brings up the four-container stack on top of H.1's host foundation. After H.2 completes:
- `docker compose ps` shows all containers healthy
- `curl http://localhost/health` returns `ok`
- Three governance-critical files generated: `docker-compose.yml`, `Caddyfile`, `my.cnf`

**Determinism is the central property of H.2.** The three governance-critical files must be byte-identical when generated twice with the same inputs. This is the precondition for H.5's file-hash governance: the baseline ceremony signature-binds these files, and non-determinism would break every re-install check.

---

## Four-container architecture

```
                    ┌─────────────────────────────┐
Internet ──HTTPS──► │  caddy (port 80/443)         │
                    │  TLS + reverse proxy + headers│
                    └──────────────┬──────────────-┘
                                   │ php_fastcgi :9000
                    ┌──────────────▼──────────────-┐
                    │  php (WordPress FPM)          │
                    │  wordpress:6.5-php8.2-fpm     │
                    └──────────────┬──────────────-┘
                                   │ TCP :3306
                    ┌──────────────▼──────────────-┐
                    │  mariadb                      │
                    │  mariadb:10.11, binlog ON      │
                    └─────────────────────────────-┘
```

All services: `restart: unless-stopped`, healthcheck, explicit host bind-mounts.

---

## Files created

| File | Purpose |
|------|---------|
| `modules/stack/images.sh` | Pull + pin image digests to state. Three failure paths. |
| `modules/stack/credentials.sh` | Generate DB passwords if blank; persist to env file; chmod 600. |
| `modules/stack/compose.sh` | Generate `docker-compose.yml`. Deterministic. Idempotent. |
| `modules/stack/caddyfile.sh` | Generate `Caddyfile`. Deterministic. HTTPS + security headers. |
| `modules/stack/mycnf.sh` | Generate `my.cnf`. Deterministic. Binary logging + TLS. |

---

## Determinism contract

Every generator follows this pattern:

```bash
tmp_file="$(mktemp "${output_file}.tmp.XXXXXX")"
_write_function "$tmp_file" <inputs...>
new_hash="$(sha256sum "$tmp_file" | cut -d' ' -f1)"

# Idempotency: if file is byte-identical, no-op (mtime unchanged)
if [[ existing_hash == new_hash ]]; then
    rm -f "$tmp_file"
    return 0
fi

# Atomic publish
mv "$tmp_file" "$output_file"
```

**Same inputs → same byte output, always.** Random values (DB passwords) are generated exactly once and persisted to the env file. Re-running with persisted values produces byte-identical files.

---

## New state facts

| Fact | Set by | Value |
|------|--------|-------|
| `stack.images.caddy_digest` | `images.sh` | `sha256:<64 hex>` |
| `stack.images.mariadb_digest` | `images.sh` | `sha256:<64 hex>` |
| `stack.images.php_digest` | `images.sh` | `sha256:<64 hex>` |
| `stack.images.pinned_at` | `images.sh` | ISO timestamp |
| `stack.credentials.generated_at` | `credentials.sh` | ISO timestamp |
| `stack.compose.config_sha256` | `compose.sh` | SHA-256 of generated file |
| `stack.compose.config_path` | `compose.sh` | Absolute path |
| `stack.caddyfile.config_sha256` | `caddyfile.sh` | SHA-256 of generated file |
| `stack.caddyfile.config_path` | `caddyfile.sh` | Absolute path |
| `stack.mycnf.config_sha256` | `mycnf.sh` | SHA-256 of generated file |
| `stack.mycnf.config_path` | `mycnf.sh` | Absolute path |

---

## Operator notes

**Credentials:** Leave `WPGOVERN_DB_ROOT_PASSWORD` and `WPGOVERN_DB_WP_PASSWORD` blank in `wpgovern.env`. The installer generates strong 32-char passwords and writes them back to the file. The env file is automatically `chmod 600` after credential write.

**Domain:** Set `WPGOVERN_DOMAIN` before running H.2. Must resolve to the server's public IP for Let's Encrypt to issue a cert.

**Re-running:** Re-running the installer with the same state is byte-identical idempotent. Generated files are unchanged if inputs haven't changed.

**First run timing:** Image pulls + MariaDB binary-log initialization make the first run take 2-3 minutes. The installer waits 120s for all containers to reach healthy state.

---

## Design choices documented

**Binary logging in my.cnf:** Non-negotiable — H.6 PITR depends on it.

**`require_secure_transport = ON` in my.cnf:** Forces TLS on MariaDB connections. Note: the WordPress image's first connection may require cert provisioning or a TLS-via-Unix-socket workaround. Verify during first production install; adjust in a future H.3 hardening pass if MariaDB→WordPress TLS setup requires additional cert distribution.

**No anonymous volumes:** All volumes are explicit host bind-mounts. Anonymous `volumes: name:/path` patterns don't survive `docker compose down -v` and don't appear in file-hash governance.

**Image digest pinning:** Protects against Docker Hub silently changing the digest for a tag between runs. Persisted digests in state means re-running uses the exact same image versions the baseline was created for.

---

## What H.2 does NOT do

- No WordPress files installed (H.4)
- No database initialization beyond what the MariaDB image does on first run (H.3)
- No WPGovern Python control plane invocation (H.5)
- No backups, DR, or observability beyond logrotate (H.6/H.7)
- No `docker compose down` or teardown
- No signed/governed state file (deferred per H.1.1 scope note)

---

## What H.3 begins next

- Wait-for-MariaDB-ready discipline (the `healthcheck.sh --connect --innodb_initialized` condition)
- Explicit database + user creation (not relying on MariaDB image's `MYSQL_DATABASE` env)
- Backup user creation with read-only grants (H.6 preparation)
- TLS cert distribution if `require_secure_transport` requires explicit cert paths

---

## Test count

| Suite | v53.2 | H.2 |
|-------|-------|-----|
| Bats | 104 | 144 |
| Python | 776 | 776 |
