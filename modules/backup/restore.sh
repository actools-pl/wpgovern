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
    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}

_restore_phase_install_check() {
    local state_file="${WPGOVERN_STATE_FILE:-/var/lib/wpgovern/.state.json}"
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
    local state_file="${WPGOVERN_STATE_FILE:-/var/lib/wpgovern/.state.json}"

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
              --user=backup_user --password="${db_backup_pw}" \
              wordpress 2>/dev/null; then
        echo "ERROR: database restore failed" >&2
        [[ -n "${_restore_xtrace:-}" ]] && set -x; return 1
    fi

    # Apply available binlogs in sequence (point-in-time recovery)
    local binlog_dir="${backup_dir}/binlogs"
    if [[ -d "$binlog_dir" ]]; then
        local binlog_count=0
        while IFS= read -r binlog_age; do
            [[ -f "$binlog_age" ]] || continue
            if age -d -i "$privkey_path" "$binlog_age" 2>/dev/null \
                | docker compose exec -T mariadb mariadb \
                      --user=backup_user --password="${db_backup_pw}" \
                      2>/dev/null; then
                binlog_count=$((binlog_count + 1))
            else
                echo "WARN: binlog apply failed for ${binlog_age}" >&2
                break
            fi
        done < <(ls -1t "${binlog_dir}/"*.age 2>/dev/null | sort)
        echo "Applied ${binlog_count} binlog file(s)" >&2
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
