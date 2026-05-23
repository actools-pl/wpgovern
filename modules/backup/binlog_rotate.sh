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

    # H.7.2-3: default binlog dir aligned with Docker MariaDB volume layout.
    # The H.3 stack mounts ${install_dir}/mariadb/data:/var/lib/mysql and configures
    # log-bin = /var/lib/mysql/binlog (singular). So host-side binlogs live at
    # ${install_dir}/mariadb/data/binlog.* — NOT at /var/lib/mysql/binlogs (native host).
    local install_dir="${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}/binlogs"
    local pubkey_path="${WPGOVERN_AGE_PUBLIC_KEY_PATH:-/etc/wpgovern/age.pub}"
    local binlog_dir="${WPGOVERN_BINLOG_DIR:-${install_dir}/mariadb/data}"
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

    # H.7.1-4: determine active binlog BEFORE flush via SHOW MASTER STATUS.
    # Prior code used -newer binlog.index which was inverted: after FLUSH BINARY LOGS,
    # binlog.index gets a fresh mtime but closed binlogs retain their original timestamps,
    # so -newer selected zero files. Fix: explicit active-binlog query.
    local active_before
    active_before="$(docker compose exec -T mariadb mariadb \
        --user=wpbackup --password="${db_backup_pw}" \
        -Nse "SHOW MASTER STATUS" 2>/dev/null | awk '{print $1}' || true)"

    if [[ -z "$active_before" ]]; then
        wpgovern::bootstrap::log "ERROR: could not determine active binlog from SHOW MASTER STATUS"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # FLUSH BINARY LOGS — closes current binlog, creates a new active one
    if ! docker compose exec -T mariadb mariadb \
            --user=wpbackup --password="${db_backup_pw}" \
            -e "FLUSH BINARY LOGS;" 2>/dev/null; then
        wpgovern::bootstrap::log "ERROR: FLUSH BINARY LOGS failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Get the new active binlog (opened by FLUSH)
    local new_active
    new_active="$(docker compose exec -T mariadb mariadb \
        --user=wpbackup --password="${db_backup_pw}" \
        -Nse "SHOW MASTER STATUS" 2>/dev/null | awk '{print $1}' || true)"

    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local encrypted_count=0 failed_count=0

    # Iterate ALL binlogs; skip the new active one (still being written)
    while IFS= read -r binlog_file; do
        [[ -f "$binlog_file" ]] || continue
        local seq; seq="$(basename "$binlog_file")"
        [[ "$seq" == "binlog.index" ]] && continue
        [[ -n "$new_active" && "$seq" == "$new_active" ]] && continue
        local age_dest="${backup_dir}/binlog-${seq}-${ts}.age"
        # Skip if already encrypted (idempotent)
        if ls "${backup_dir}/binlog-${seq}-"*.age >/dev/null 2>&1; then
            continue
        fi
        # Encrypt → verify non-empty → delete plaintext (CRITICAL ORDER preserved)
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
    done < <(find "$binlog_dir" -name "binlog.*" 2>/dev/null | sort || true)

    # H.7.1-4 truthfulness: warn if zero encrypted but prior runs found N>0
    local prior_count
    prior_count="$(wpgovern::state::get_fact "backup.binlog_encrypted_count" 2>/dev/null || echo "0")"
    prior_count="${prior_count//[[:space:]]/}"
    if [[ "${encrypted_count}" -eq 0 && "${prior_count:-0}" -gt 0 ]]; then
        wpgovern::bootstrap::log "WARN: zero binlogs encrypted but prior count was ${prior_count} — investigate binlog configuration"
    fi


    wpgovern::state::set_fact "backup.last_binlog_rotated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.binlog_encrypted_count" "$encrypted_count"
    wpgovern::bootstrap::log "Binlog rotation: ${encrypted_count} encrypted, ${failed_count} failed"

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    [[ "$failed_count" -eq 0 ]] || return 1
    return 0
}
