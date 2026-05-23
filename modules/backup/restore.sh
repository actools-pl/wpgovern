#!/usr/bin/env bash
# =============================================================================
# modules/backup/restore.sh — Governance-aware restore phases
# Decision 2: single script, internal phases, Decision 1 order.
# CRITICAL ORDER: governance state BEFORE database.
# =============================================================================

set -euo pipefail

_restore_phase_validate() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac
    local backup_ts="$1"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"

    local sql_file="${backup_dir}/full-${backup_ts}.sql.age"
    local gov_file="${backup_dir}/governance-${backup_ts}.tar.gz.age"

    if [[ ! -f "$sql_file" ]]; then
        echo "ERROR: SQL backup not found: ${sql_file}" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi
    if [[ ! -s "$sql_file" ]]; then
        echo "ERROR: SQL backup is empty: ${sql_file}" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi
    if [[ ! -f "$gov_file" ]]; then
        echo "ERROR: Governance backup not found: ${gov_file}" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi
    if [[ ! -f "$privkey_path" ]]; then
        echo "ERROR: age private key not found at ${privkey_path}" >&2
        echo "       Restore the private key from your off-server backup first." >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi
    if [[ "$(stat -c '%a' "$privkey_path" 2>/dev/null)" != "600" ]]; then
        echo "ERROR: age private key has wrong mode (must be 0600)" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi
    # Verify mariadb container is running
    if ! docker compose ps mariadb 2>/dev/null | grep -q "running\|healthy"; then
        echo "ERROR: mariadb container is not running" >&2
        echo "       Run: docker compose up -d mariadb" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi

    # H.7.1-6: decryptability check — prove private key can decrypt the backup files.
    # Corrupt file or wrong key surfaces here (exit 10) not at phase 12/13.
    # Reads only 256 bytes of the decrypted stream; cost is minimal.
    local sql_backup="${backup_dir}/full-${backup_ts}.sql.age"
    local gov_backup="${backup_dir}/governance-${backup_ts}.tar.gz.age"
    if ! age -d -i "$privkey_path" "$sql_backup" 2>/dev/null | head -c 256 > /dev/null; then
        echo "ERROR: SQL backup ${sql_backup} cannot be decrypted with ${privkey_path}" >&2
        echo "       Verify: age -d -i ${privkey_path} ${sql_backup} | head -c 256" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 10
    fi
    if ! age -d -i "$privkey_path" "$gov_backup" 2>/dev/null | head -c 256 > /dev/null; then
        echo "ERROR: Governance backup ${gov_backup} cannot be decrypted with ${privkey_path}" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 10
    fi

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}

_restore_phase_install_check() {
    local state_file="${WPGOVERN_STATE_FILE:-${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}/.wpgovern-installer-state.json}"
    if [[ ! -f "$state_file" ]]; then
        echo "ERROR: installer state not found at ${state_file}" >&2
        echo "       Run wpgovern-install.sh on this box first, then re-run restore." >&2
        return 1
    fi
    local required_phases=("host" "stack" "db" "wp" "ceremony" "audit")
    for phase in "${required_phases[@]}"; do
        if ! jq -e --arg p "$phase" '.phases_complete | contains([$p])' \
                "$state_file" >/dev/null 2>&1; then
            echo "ERROR: install phase '${phase}' not complete on this box" >&2
            echo "       Run wpgovern-install.sh fully first." >&2
            return 1
        fi
    done
    return 0
}

_restore_phase_governance_state() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac
    local backup_ts="$1"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    local gov_file="${backup_dir}/governance-${backup_ts}.tar.gz.age"
    local state_file="${WPGOVERN_STATE_FILE:-${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}/.wpgovern-installer-state.json}"

    echo "Restoring governance state from ${gov_file}" >&2

    # Preserve current phases_complete (this box's install history)
    local current_phases
    current_phases="$(jq -c '.phases_complete // []' "$state_file" 2>/dev/null || echo '[]')"

    # Decrypt and extract governance tarball (no plaintext on disk)
    if ! age -d -i "$privkey_path" "$gov_file" 2>/dev/null | tar -xzf - -C / 2>/dev/null; then
        echo "ERROR: governance state restore failed" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi

    # Restore current box's phases_complete into the newly-extracted state
    local tmp_state; tmp_state="$(mktemp)"
    if jq --argjson phases "$current_phases" \
            '.phases_complete = $phases' \
            "$state_file" > "$tmp_state" 2>/dev/null; then
        mv "$tmp_state" "$state_file"
    else
        rm -f "$tmp_state"
    fi

    echo "Governance state restored" >&2
    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}

_restore_phase_database() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac
    local backup_ts="$1"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    local db_backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:-}"
    local sql_file="${backup_dir}/full-${backup_ts}.sql.age"

    if [[ -z "$db_backup_pw" ]]; then
        echo "ERROR: WPGOVERN_DB_BACKUP_PASSWORD not set" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi

    echo "Restoring database from ${sql_file}" >&2

    # Decrypt and load into mariadb (stream — no plaintext on disk)
    if ! age -d -i "$privkey_path" "$sql_file" 2>/dev/null \
        | docker compose exec -T mariadb mariadb \
              --user=wpbackup --password="${db_backup_pw}" \
              wordpress 2>/dev/null; then
        echo "ERROR: database restore failed" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi

    # H.7.1-5: PITR target-range — apply only binlogs AFTER the full backup's position.
    # Prior code applied ALL binlogs, including those already included in the full backup
    # (causing data corruption) and those beyond the intended restore point (unbounded).
    # Fix: read the binlog_file recorded during full_backup.sh and apply only later files.
    local binlog_dir="${backup_dir}/binlogs"
    if [[ -d "$binlog_dir" ]]; then
        local binlog_count=0
        local base_binlog
        base_binlog="$(wpgovern::state::get_fact "backup.${backup_ts}.binlog_file" 2>/dev/null || echo "")"
        base_binlog="${base_binlog//[[:space:]]/}"
        while IFS= read -r binlog_age; do
            [[ -f "$binlog_age" ]] || continue
            local age_basename; age_basename="$(basename "$binlog_age")"
            # Extract binlog sequence from filename e.g. binlog-binlog.000003-20260101T120000Z.age
            local binlog_seq; binlog_seq="$(echo "$age_basename" | sed -nE 's/binlog-([^-]+)-.*/\1/p')"
            # If we have a base binlog recorded, skip files lex-sorted at or before it
            if [[ -n "$base_binlog" ]] && [[ "$binlog_seq" < "$base_binlog" || "$binlog_seq" == "$base_binlog" ]]; then
                continue
            fi
            if age -d -i "$privkey_path" "$binlog_age" 2>/dev/null \
                | docker compose exec -T mariadb mariadb \
                      --user=wpbackup --password="${db_backup_pw}" \
                      2>/dev/null; then
                binlog_count=$((binlog_count + 1))
            else
                echo "WARN: binlog apply failed for ${binlog_age}" >&2
                break
            fi
        done < <(ls -1 "${binlog_dir}/"*.age 2>/dev/null | sort)
        [[ -n "$base_binlog" ]] && \
            echo "PITR: applied ${binlog_count} binlog file(s) after position ${base_binlog}" >&2 || \
            echo "PITR: applied ${binlog_count} binlog file(s) (no base binlog recorded)" >&2
    fi

    echo "Database restore complete" >&2
    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}

_restore_phase_verify() {
    echo "Running post-restore verification" >&2
    local exit_code=0

    if ! wpgovern governance-check >/dev/null 2>&1; then
        echo "WARN: governance-check returned non-zero after restore" >&2
        exit_code=1
    else
        echo "governance-check: PASS" >&2
    fi

    if ! wpgovern-install-audit --complete >/dev/null 2>&1; then
        local audit_rc=$?
        if [[ "$audit_rc" -eq 2 ]]; then
            echo "WARN: install-audit returned internal error (exit 2) after restore" >&2
            exit_code=1
        else
            echo "install-audit: findings present (exit ${audit_rc}) — review output separately" >&2
        fi
    else
        echo "install-audit: PASS" >&2
    fi

    return "$exit_code"
}

wpgovern::backup::run_restore() {
    local backup_ts="$1"
    _restore_phase_validate   "$backup_ts" || return 10
    _restore_phase_install_check           || return 11
    _restore_phase_governance_state "$backup_ts" || return 12
    _restore_phase_database   "$backup_ts" || return 13
    _restore_phase_verify                  || return 14
    return 0
}

wpgovern::backup::ack_key_backup() {
    local location_hint="${1:-}"
    wpgovern::state::set_fact "dr.key_backed_up_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [[ -n "$location_hint" ]] && \
        wpgovern::state::set_fact "dr.key_backup_location_hint" "$location_hint"
    wpgovern::bootstrap::log "age private key backup acknowledged as completed"
    echo "WPG-DR-01: key backup acknowledged. Run wpgovern-install-audit to verify."
    return 0
}

wpgovern::backup::list_backups() {
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    if [[ ! -d "$backup_dir" ]]; then
        echo "No backup directory at ${backup_dir}"
        return 0
    fi
    echo "Available full backups in ${backup_dir}:"
    ls -lh "${backup_dir}/full-"*.sql.age 2>/dev/null | \
        awk '{print $NF, $5}' | sort -r || echo "  (none)"
}
