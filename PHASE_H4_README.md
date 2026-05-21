# Phase H.4 — WordPress Provisioning Module

**Status:** Complete  
**Bats tests:** 223 (was 198; +25 new)  
**Python tests:** 776 (unchanged)  
**New bash files:** 3 (`modules/wp/prepare.sh`, `modules/wp/provision.sh`, `modules/wp/secure.sh`)  
**Modified:** `modules/stack/compose.sh`, `modules/stack/images.sh`, `wpgovern-install.sh`, `core/bootstrap.sh`, `wpgovern.env.example`

---

## Purpose

H.4 installs WordPress and writes the hardened `wp-config.php` that H.5 will sign as the fourth file-hash-governed artifact. Three steps:

**Prepare → Provision → Secure**

After H.4 completes:
- `${WPGOVERN_INSTALL_DIR}/wordpress/` exists with 33:33 ownership and 755 perms
- WordPress core installed at `https://${WPGOVERN_DOMAIN}/`
- `wp-config.php` exists with 640 perms, www-data:www-data ownership
- All 8 AUTH_KEYs generated and persisted to env file
- `wp.secure.config_hash` recorded in state for H.5 signing

---

## The defining property: wp-config.php determinism

**Given stable inputs** (WPGOVERN_DOMAIN, all 8 AUTH_KEYs, WPGOVERN_DB_WP_PASSWORD), the `generate_config` function MUST produce byte-identical output on every invocation. This is the property H.5's file-hash governance depends on.

Determinism is achieved by:
1. **Atomic write via `mktemp` + `mv`** — same pattern as H.2's compose/Caddyfile/my.cnf generators
2. **Ordered indexed array for AUTH_KEYs** — never associative array (bash hash ordering is implementation-defined across systems)
3. **One-time AUTH_KEY generation** — `ensure_auth_keys` generates only blank keys; once persisted, the same values are used on every run
4. **Heredoc with explicit escape convention** — `${WPGOVERN_*}` = bash expansion; `\$_SERVER`, `\$table_prefix` = literal PHP

Verified: 10/10 repeated invocations produce identical sha256. The negative test (changed domain → different sha256) confirms the generator responds to input changes.

---

## Heredoc escape convention (required reading for modifications)

`secure.sh` uses an UNQUOTED heredoc delimiter (`CONFIG`) so bash variable expansion IS active. Every `$` in the PHP template must be classified:

| Pattern | Classification | Count |
|---------|---------------|-------|
| `${WPGOVERN_DB_WP_PASSWORD}` | bash expansion (DB password) | 1 |
| `${WPGOVERN_WP_AUTH_KEY}` through `${WPGOVERN_WP_NONCE_SALT}` | bash expansion (8 AUTH_KEYs) | 8 |
| `${WPGOVERN_DOMAIN}` | bash expansion (domain) | 2 |
| `\$_SERVER` | literal PHP dollar sign | 2 |
| `\$table_prefix` | literal PHP dollar sign | 1 |

**Total: 11 bash expansions, 3 escaped PHP literals.** If you modify the wp-config.php template, count every `$` and update this table.

---

## UID/GID coordination with PHP-FPM container

`_WPGOVERN_WP_UID=33` / `_WPGOVERN_WP_GID=33` matches `www-data` in:
- `wordpress:6.5-php8.2-fpm` (the `php` service)
- `wordpress:6.5-apache` (the `wordpress` service)
- `wordpress:cli` (the `cli` service)

If the upstream base image changes, audit these constants in `prepare.sh` and `secure.sh`. The misalignment symptom is permission errors on WordPress file writes (uploads, plugin installs, auto-updates).

---

## cli profile-gated service

The `cli` service (wordpress:cli image) is added to `docker-compose.yml` with `profiles: ["cli"]`. This means:
- `docker compose up -d` does NOT start the cli service
- `docker compose ps` does NOT show the cli service (H.3.1-10's `expected_services=4` remains correct)
- `docker compose --profile cli run --rm cli wp <command>` invokes wp-cli on demand

To run wp-cli commands after install:
```bash
docker compose --profile cli run --rm cli wp --info
docker compose --profile cli run --rm cli wp plugin list
docker compose --profile cli run --rm cli wp core check-update
```

---

## AUTH_KEY persistence model

AUTH_KEYs are:
1. **Generated** once by `ensure_auth_keys` using `openssl rand -hex 32` (64 hex chars, 256-bit entropy)
2. **Persisted** to the env file via `_wpgovern_credentials_persist` (same helper as DB credentials)
3. **Stable** on re-run — `ensure_auth_keys` is idempotent (skips keys already set)
4. **NOT age-encrypted** in H.4 — they're env-file-only in this round

The governance model for AUTH_KEYs: H.5 will sign `wp-config.php` which contains the AUTH_KEY values. The signed baseline hash IS the governance proof. Age-encrypting AUTH_KEYs separately would require a second encryption ceremony and is deferred.

---

## wp-config.php trust model

| Property | Value |
|----------|-------|
| Permissions | 640 (owner read/write, group read, world none) |
| Ownership | 33:33 (www-data:www-data) |
| Governance status | File-hash-governed from H.5 onward |
| Contains | DB password + 8 AUTH_KEYs + hardening config |
| World-readable? | No — `640` prevents world read |

---

## Hardening defaults in wp-config.php

| Constant | Value | Rationale |
|----------|-------|-----------|
| `DISALLOW_FILE_EDIT` | `true` | Prevents PHP file editing via admin UI |
| `DISALLOW_FILE_MODS` | `false` | Plugin/theme update still allowed (can be tightened) |
| `WP_DEBUG` | `false` | No debug output in production |
| `WP_AUTO_UPDATE_CORE` | `'minor'` | Auto-patch minor security releases |
| `FORCE_SSL_ADMIN` | `true` | Admin UI only over HTTPS |
| `COOKIE_SECURE` | `true` | Cookies only sent over HTTPS |
| `COOKIE_HTTPONLY` | `true` | Cookies inaccessible to JavaScript |

---

## New state facts

| Fact | Value |
|------|-------|
| `wp.prepare.completed_at` | ISO timestamp |
| `wp.prepare.uid_gid` | `"33:33"` |
| `wp.provision.installed_at` | ISO timestamp (first run) |
| `wp.provision.skipped_at` | ISO timestamp (re-run) |
| `wp.secure.config_hash` | sha256 of wp-config.php |
| `wp.secure.config_path` | Absolute path to wp-config.php |
| `wp.secure.generated_at` | ISO timestamp |

---

## What H.4 does NOT do

- No plugin or theme installation (H.5 baseline is empty WordPress)
- No SMTP / email configuration (`--skip-email` on wp-cli core install)
- No multisite
- No AUTH_KEY rotation (generated once, future hardening)
- No WPGovern Python control plane bootstrap (H.5)
- No baseline ceremony (H.5)
- No automatic update execution (H.5 controls upgrade lifecycle)

---

## Methodology: Lesson 2 fourth refinement applied

The pre-flight checklist included the first concrete application of the Lesson 2 fourth refinement (registered after H.3.1.1): **test code that invokes production functions in isolated subshells must source every file those functions transitively depend on.**

The exemplar from the pre-flight: `test_h3_users.bats` line 172 — the H.3-3 sentinel test sourced `modules/db/users.sh` in a `bash -c` subshell without sourcing `core/credentials.sh`. Functions failed silently with rc=127 (BW01), the sentinel grep trivially passed. Fixed by adding `source core/credentials.sh` before sourcing `modules/db/users.sh`.

After fix: zero BW01 warnings across the full bats suite.

---

## What H.5 begins next

- Python control plane bootstrap (WPGovern v52.1)
- Byte-one ceremony: trust keys, baseline all four config-file hashes, cryptographic approval, activation
- `governance-check` command: validates all four file hashes against signed baseline
- Governance state: separate from installer state (Python JSON, not bash JSON)

---

## Test count

| Suite | H.3.1.1 | H.4 |
|-------|---------|-----|
| Bats | 198 | 223 |
| Python | 776 | 776 |
| Bash files | 18 | 21 |
| File-hash-governed artifacts | 3 | 4 |
