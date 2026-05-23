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
            --user=wpbackup \
            --password="${db_backup_pw}" \
            wordpress \
            2>>"$backup_log" \
        | age -r "$pubkey" -o "$sql_backup"; then
        wpgovern::bootstrap::log "ERROR: SQL backup failed — see ${backup_log}"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Size check (basic guard)
    if [[ ! -s "$sql_backup" ]]; then
        wpgovern::bootstrap::log "ERROR: SQL backup produced empty .age file — backup corrupt"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # H.7.1-11: logical-completion verification — file size is insufficient.
    # An empty/headers-only database produces a non-empty .age file with zero CREATE TABLE.
    # Verify TWO structural sentinels; use streaming form to stay memory-bounded.
    local privkey_path_for_verify="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    # Sentinel 1: wp_options table present (WPGovern deployments ALWAYS have wp_options from H.4)
    if ! age -d -i "${privkey_path_for_verify}" "${sql_backup}" 2>/dev/null \
            | grep -qE "CREATE TABLE.*\`?wp_options\`?"; then
        wpgovern::bootstrap::log "ERROR: SQL backup ${sql_backup} missing CREATE TABLE wp_options — logically empty or wrong database"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    # Sentinel 2: clean dump termination (truncated dumps lack this trailer)
    if ! age -d -i "${privkey_path_for_verify}" "${sql_backup}" 2>/dev/null \
            | tail -5 | grep -q "Dump completed on"; then
        wpgovern::bootstrap::log "ERROR: SQL backup ${sql_backup} missing 'Dump completed on' trailer — dump may be truncated"
        rm -f "$sql_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # --- Governance tarball: governed dirs EXCLUDING the age private key ---
    wpgovern::bootstrap::log "Starting governance state backup → ${gov_backup}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"

    # H.7.1-3: use PIPESTATUS to distinguish tar exit codes.
    # tar exit 1 = "file changed" warning (non-fatal; acceptable for live systems).
    # tar exit 2 = fatal error (empty/corrupt stream; not acceptable; treat as failure).
    # The prior `|| true` masked BOTH exit codes, allowing empty governance backups.
    { tar -czf - \
            --exclude="${privkey_path}" \
            "${_BACKUP_GOVERNED_DIRS[@]}" \
            2>>"$backup_log" \
        | age -r "$pubkey" -o "$gov_backup"; }
    local tar_exit="${PIPESTATUS[0]}" age_exit="${PIPESTATUS[1]}"

    if [[ "$tar_exit" -ge 2 || "$age_exit" -ne 0 ]]; then
        wpgovern::bootstrap::log "ERROR: Governance tarball backup failed (tar_exit=${tar_exit} age_exit=${age_exit}) — see ${backup_log}"
        rm -f "$gov_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    if [[ "$tar_exit" -eq 1 ]]; then
        wpgovern::bootstrap::log "WARN: tar reported file-changed warnings (exit 1) — governance backup may be slightly inconsistent but is non-empty"
    fi

    if [[ ! -s "$gov_backup" ]]; then
        wpgovern::bootstrap::log "ERROR: Governance backup produced empty .age file"
        rm -f "$gov_backup"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    local sql_size; sql_size="$(stat -c '%s' "$sql_backup" 2>/dev/null || echo 0)"

    # H.7.1-5: extract binlog position from --master-data=2 comment for PITR-aware restore.
    # mariadb-dump --master-data=2 embeds the position near the start of the dump.
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    local master_status
    master_status="$(age -d -i "${privkey_path}" "${sql_backup}" 2>/dev/null \
        | head -c 4096 \
        | grep -oE "CHANGE MASTER TO MASTER_LOG_FILE='[^']+', MASTER_LOG_POS=[0-9]+" \
        | head -1 || true)"
    if [[ -n "$master_status" ]]; then
        local binlog_file; binlog_file="$(echo "$master_status" | sed -nE "s/.*MASTER_LOG_FILE='([^']+)'.*/\1/p")"
        local binlog_pos;  binlog_pos="$(echo "$master_status"  | sed -nE "s/.*MASTER_LOG_POS=([0-9]+).*/\1/p")"
        [[ -n "$binlog_file" ]] && wpgovern::state::set_fact "backup.${ts}.binlog_file" "$binlog_file"
        [[ -n "$binlog_pos"  ]] && wpgovern::state::set_fact "backup.${ts}.binlog_pos"  "$binlog_pos"
    fi

    wpgovern::state::set_fact "backup.last_full_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.last_full_ts" "$ts"
    wpgovern::state::set_fact "backup.last_full_size_bytes" "$sql_size"
    wpgovern::bootstrap::log "Full backup complete: ${sql_backup} (${sql_size} bytes encrypted)"

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}
