#!/usr/bin/env bash
# =============================================================================
# modules/backup/binlog_rotate.sh — Hourly binlog rotation + encryption
#
# CRITICAL ordering: encrypt → verify .age non-empty → THEN delete plaintext.
# If encryption fails, plaintext binlog is PRESERVED. Never delete before verify.
# =============================================================================

set -euo pipefail

wpgovern::backup::rotate_binlogs() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac

    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}/binlogs"
    local pubkey_path="${WPGOVERN_AGE_PUBLIC_KEY_PATH:-/etc/wpgovern/age.pub}"
    local binlog_dir="${WPGOVERN_BINLOG_DIR:-/var/lib/mysql/binlogs}"
    local db_backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:-}"

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
    mkdir -p "$backup_dir"

    # Flush binary logs — closes current binlog, opens fresh one
    docker compose exec -T mariadb mariadb \
        --user=backup_user --password="${db_backup_pw}" \
        -e "FLUSH BINARY LOGS;" 2>/dev/null || {
        wpgovern::bootstrap::log "WARN: FLUSH BINARY LOGS failed; continuing with existing files"
    }

    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local encrypted_count=0 failed_count=0

    # Find closed binlog files (all except the currently-active one)
    while IFS= read -r binlog_file; do
        [[ -f "$binlog_file" ]] || continue
        local seq; seq="$(basename "$binlog_file")"
        local age_dest="${backup_dir}/binlog-${seq}-${ts}.age"

        # Skip if already encrypted (idempotent)
        if ls "${backup_dir}/binlog-${seq}-"*.age >/dev/null 2>&1; then
            continue
        fi

        # Encrypt → verify non-empty → delete plaintext (CRITICAL ORDER)
        if age -r "$pubkey" -o "$age_dest" < "$binlog_file" 2>/dev/null; then
            if [[ -s "$age_dest" ]]; then
                rm -f "$binlog_file"
                encrypted_count=$((encrypted_count + 1))
            else
                rm -f "$age_dest"
                wpgovern::bootstrap::log "WARN: encrypted binlog ${age_dest} is empty — preserving plaintext ${binlog_file}"
                failed_count=$((failed_count + 1))
            fi
        else
            rm -f "$age_dest" 2>/dev/null || true
            wpgovern::bootstrap::log "WARN: encryption failed for ${binlog_file} — plaintext preserved"
            failed_count=$((failed_count + 1))
        fi
    done < <(find "$binlog_dir" -name "binlog.*" -not -name "binlog.index" \
                 -newer "${binlog_dir}/binlog.index" 2>/dev/null | sort || true)

    wpgovern::state::set_fact "backup.last_binlog_rotated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.binlog_encrypted_count" "$encrypted_count"
    wpgovern::bootstrap::log "Binlog rotation: ${encrypted_count} encrypted, ${failed_count} failed"

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    [[ "$failed_count" -eq 0 ]] || return 1
    return 0
}
