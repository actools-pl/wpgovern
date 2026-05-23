#!/usr/bin/env bash
# =============================================================================
# modules/backup/restore_test.sh — Backup integrity verification
# Decrypts most-recent full backup → loads into test schema → verifies → drops.
# Lesson 2 sixth refinement: age private key is a credential.
# =============================================================================

set -euo pipefail

wpgovern::backup::run_restore_test() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac

    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    local db_backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:-}"
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local test_schema="wpgovern_test_${ts}"

    if [[ ! -f "$privkey_path" ]]; then
        wpgovern::bootstrap::log "ERROR: age private key not found at ${privkey_path}"
        wpgovern::state::set_fact "backup.last_restore_test_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        wpgovern::state::set_fact "backup.last_restore_test_result" "FAIL: private key missing"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    if [[ -z "$db_backup_pw" ]]; then
        wpgovern::bootstrap::log "ERROR: WPGOVERN_DB_BACKUP_PASSWORD not set"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Find most recent full backup
    local latest_backup
    latest_backup="$(ls -1t "${backup_dir}/full-"*.sql.age 2>/dev/null | head -1)"
    if [[ -z "$latest_backup" ]]; then
        wpgovern::bootstrap::log "ERROR: no full backup found in ${backup_dir}"
        wpgovern::state::set_fact "backup.last_restore_test_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        wpgovern::state::set_fact "backup.last_restore_test_result" "FAIL: no backup found"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    wpgovern::bootstrap::log "Running restore-test from ${latest_backup} → schema ${test_schema}"

    # Cleanup trap: always drop test schema even on failure
    _restore_test_cleanup() {
        docker compose exec -T mariadb mariadb \
            --user=wpbackup --password="${db_backup_pw}" \
            -e "DROP SCHEMA IF EXISTS \`${test_schema}\`;" 2>/dev/null || true
    }
    # EXIT trap as backstop; also call explicitly before each early return (H.7.1-10)
    trap _restore_test_cleanup EXIT

    # Create test schema
    docker compose exec -T mariadb mariadb \
        --user=wpbackup --password="${db_backup_pw}" \
        -e "CREATE SCHEMA \`${test_schema}\` CHARACTER SET utf8mb4;" 2>/dev/null || {
        wpgovern::bootstrap::log "ERROR: could not create test schema ${test_schema}"
        wpgovern::state::set_fact "backup.last_restore_test_result" "FAIL: schema creation failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    }

    # Decrypt and load into test schema (stream — no plaintext on disk)
    if ! age -d -i "$privkey_path" "$latest_backup" 2>/dev/null \
        | docker compose exec -T mariadb mariadb \
              --user=wpbackup --password="${db_backup_pw}" \
              "$test_schema" 2>/dev/null; then
        wpgovern::bootstrap::log "ERROR: restore-test decrypt+load failed"
        wpgovern::state::set_fact "backup.last_restore_test_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        wpgovern::state::set_fact "backup.last_restore_test_result" "FAIL: decrypt+load failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Verify expected tables
    local table_check
    table_check="$(docker compose exec -T mariadb mariadb \
        --user=wpbackup --password="${db_backup_pw}" \
        --batch --skip-column-names \
        -e "SELECT COUNT(*) FROM information_schema.tables \
            WHERE table_schema='${test_schema}' \
            AND table_name IN ('wp_options','wp_users','wp_posts');" \
        2>/dev/null || echo 0)"
    table_check="${table_check//[[:space:]]/}"

    local options_rows=0
    options_rows="$(docker compose exec -T mariadb mariadb \
        --user=wpbackup --password="${db_backup_pw}" \
        --batch --skip-column-names \
        -e "SELECT COUNT(*) FROM \`${test_schema}\`.wp_options LIMIT 1;" \
        2>/dev/null || echo 0)"
    options_rows="${options_rows//[[:space:]]/}"

    local test_result
    if [[ "${table_check:-0}" -ge 3 && "${options_rows:-0}" -gt 0 ]]; then
        test_result="PASS"
        wpgovern::bootstrap::log "Restore-test PASSED: ${table_check} tables verified, wp_options has ${options_rows} rows"
    else
        test_result="FAIL: tables=${table_check:-0} wp_options_rows=${options_rows:-0}"
        wpgovern::bootstrap::log "Restore-test FAILED: ${test_result}"
    fi

    wpgovern::state::set_fact "backup.last_restore_test_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.last_restore_test_result" "$test_result"

    # Explicit cleanup at success/completion paths (H.7.1-10)
    _restore_test_cleanup
    trap - EXIT

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    [[ "$test_result" == "PASS" ]] || return 1
    return 0
}
