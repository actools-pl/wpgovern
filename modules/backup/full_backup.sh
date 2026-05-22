#!/usr/bin/env bash
# =============================================================================
# modules/backup/full_backup.sh — Streaming-encrypted full backup
#
# Decision 1: stream encryption — plaintext SQL never touches disk.
# Pipeline: mariadb-dump | age -r <pubkey> -o <file.sql.age>
# Governance tarball: tar | age -r <pubkey> -o <governance.tar.gz.age>
# CRITICAL: age private key is NOT in the governance tarball.
# =============================================================================

set -euo pipefail

# Default governed dirs — override by setting _BACKUP_GOVERNED_DIRS before sourcing
_BACKUP_GOVERNED_DIRS=(
    "/opt/wpgovern-install"
    "/etc/wpgovern"
    "/var/lib/wpgovern"
)

wpgovern::backup::run_full() {
    # Lesson 2 sixth refinement: WPGOVERN_DB_BACKUP_PASSWORD is a credential
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac

    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    local pubkey_path="${WPGOVERN_AGE_PUBLIC_KEY_PATH:-/etc/wpgovern/age.pub}"
    local db_backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:-}"
    local log_dir="${WPGOVERN_LOG_DIR:-/var/log/wpgovern}"

    # Validate prerequisites
    if [[ -z "$db_backup_pw" ]]; then
        wpgovern::bootstrap::log "ERROR: WPGOVERN_DB_BACKUP_PASSWORD not set"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    if [[ ! -f "$pubkey_path" ]]; then
        wpgovern::bootstrap::log "ERROR: age public key not found at ${pubkey_path}"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    local pubkey; pubkey="$(cat "$pubkey_path")"

    mkdir -p "$backup_dir" "$log_dir"
    local sql_backup="${backup_dir}/full-${ts}.sql.age"
    local gov_backup="${backup_dir}/governance-${ts}.tar.gz.age"
    local backup_log="${log_dir}/backup-${ts}.log"

    # --- SQL backup: stream directly through age (no plaintext on disk) ---
    wpgovern::bootstrap::log "Starting full SQL backup → ${sql_backup}"
    if ! docker compose exec -T mariadb mariadb-dump \
            --single-transaction --master-data=2 --routines --triggers \
            --user=backup_user \
            --password="${db_backup_pw}" \
            wordpress \
            2>>"$backup_log" \
        | age -r "$pubkey" -o "$sql_backup"; then
        wpgovern::bootstrap::log "ERROR: SQL backup failed — see ${backup_log}"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Verify .age file is non-empty (belt+suspenders after stream)
    if [[ ! -s "$sql_backup" ]]; then
        wpgovern::bootstrap::log "ERROR: SQL backup produced empty .age file — backup corrupt"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # --- Governance tarball: governed dirs EXCLUDING the age private key ---
    wpgovern::bootstrap::log "Starting governance state backup → ${gov_backup}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    # tar exits 1 on "file changed" warnings (acceptable); only fail on exit 2+
    # Use || true on tar to prevent pipefail from catching non-fatal tar warnings
    if ! { tar -czf - \
                --exclude="${privkey_path}" \
                "${_BACKUP_GOVERNED_DIRS[@]}" \
                2>>"$backup_log" || true; } \
        | age -r "$pubkey" -o "$gov_backup"; then
        wpgovern::bootstrap::log "ERROR: Governance tarball backup failed — see ${backup_log}"
        rm -f "$gov_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    if [[ ! -s "$gov_backup" ]]; then
        wpgovern::bootstrap::log "ERROR: Governance backup produced empty .age file"
        rm -f "$gov_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    local sql_size; sql_size="$(stat -c '%s' "$sql_backup" 2>/dev/null || echo 0)"
    wpgovern::state::set_fact "backup.last_full_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.last_full_ts" "$ts"
    wpgovern::state::set_fact "backup.last_full_size_bytes" "$sql_size"
    wpgovern::bootstrap::log "Full backup complete: ${sql_backup} (${sql_size} bytes encrypted)"

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}
