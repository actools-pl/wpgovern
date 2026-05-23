#!/usr/bin/env bash
# =============================================================================
# core/state.sh — WPGovern Installer State Machine
#
# H.1.1-1: All write operations use mktemp for unique temp paths and
# explicit checked writes (if ! jq ... > tmp; then rm -f tmp; return 1; fi).
# This makes writes safe regardless of the caller's errexit context — the
# function reports failure correctly even when invoked from if/while/&&/|| .
# =============================================================================

set -euo pipefail

wpgovern::state::init() {
    local state_file="${WPGOVERN_STATE_FILE}"
    local state_dir
    state_dir="$(dirname "$state_file")"

    if [[ ! -d "$state_dir" ]]; then
        mkdir -p "$state_dir"
    fi

    if [[ -f "$state_file" ]]; then
        # Validate existing file is parseable JSON
        if ! jq empty "$state_file" 2>/dev/null; then
            wpgovern::bootstrap::log "WARNING: state file is corrupt — reinitializing (JSON parse failed)"
            _wpgovern_state_write_initial "$state_file" || return 1
        else
            # Update last_run_at on load
            local tmp
            tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
            if ! jq --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                    '.last_run_at = $ts' \
                    "$state_file" > "$tmp"; then
                rm -f "$tmp"
                return 1
            fi
            mv "$tmp" "$state_file"
        fi
    else
        _wpgovern_state_write_initial "$state_file" || return 1
    fi
}

_wpgovern_state_write_initial() {
    local state_file="$1"
    local tmp
    tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat > "$tmp" <<JSON
{
  "started_at": "${ts}",
  "last_run_at": "${ts}",
  "phases_complete": [],
  "phases_failed": [],
  "host_facts": {}
}
JSON
    mv "$tmp" "$state_file"
}

wpgovern::state::phase_complete() {
    local phase="$1"
    local state_file="${WPGOVERN_STATE_FILE}"
    if [[ ! -f "$state_file" ]]; then
        return 1
    fi
    jq -e --arg p "$phase" \
       '.phases_complete | map(. == $p) | any' \
       "$state_file" > /dev/null 2>&1
}


# H.7.1-12: lock file for concurrent state mutation safety.
# FD 8 chosen; installer main process uses FD 9 (wpgovern-install.sh:132).
_WPGOVERN_STATE_LOCK="${WPGOVERN_STATE_LOCK:-/var/lock/wpgovern-state.lock}"

wpgovern::state::mark_phase_complete() {
    local phase="$1"
    local state_file="${WPGOVERN_STATE_FILE}"
    local lock_file="${_WPGOVERN_STATE_LOCK}"
    # H.7.1-12: flock ensures read-modify-write atomicity (no lost updates under concurrent writers)
    mkdir -p "$(dirname "$lock_file")" 2>/dev/null || true
    touch "$lock_file" 2>/dev/null || true
    (
        flock -x 8 || exit 1
        local tmp; tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
        # H.1.1-1: explicit checked write
        if ! jq --arg p "$phase" \
                --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                '.phases_complete |= (. + [$p] | unique) | .last_run_at = $ts' \
                "$state_file" > "$tmp"; then
            rm -f "$tmp"; exit 1
        fi
        mv "$tmp" "$state_file"
    ) 8>>"$lock_file"
}

wpgovern::state::mark_phase_failed() {
    local phase="$1"
    local reason="${2:-unknown}"
    local state_file="${WPGOVERN_STATE_FILE}"
    local lock_file="${_WPGOVERN_STATE_LOCK}"
    # H.7.1-12: flock for concurrent safety
    mkdir -p "$(dirname "$lock_file")" 2>/dev/null || true
    touch "$lock_file" 2>/dev/null || true
    (
        flock -x 8 || exit 1
        local tmp; tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
        if ! jq --arg p "$phase" \
                --arg r "$reason" \
                --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                '.phases_failed += [{"phase": $p, "reason": $r, "failed_at": $ts}] | .last_run_at = $ts' \
                "$state_file" > "$tmp"; then
            rm -f "$tmp"; exit 1
        fi
        mv "$tmp" "$state_file"
    ) 8>>"$lock_file"
}

wpgovern::state::set_fact() {
    local key="$1"
    local value="$2"
    local state_file="${WPGOVERN_STATE_FILE}"
    local lock_file="${_WPGOVERN_STATE_LOCK}"
    # H.7.1-12: flock for concurrent safety (midnight boundary race between full+binlog timers)
    mkdir -p "$(dirname "$lock_file")" 2>/dev/null || true
    touch "$lock_file" 2>/dev/null || true
    (
        flock -x 8 || exit 1
        local tmp; tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
        if ! jq --arg k "$key" \
                --arg v "$value" \
                '.host_facts[$k] = $v' \
                "$state_file" > "$tmp"; then
            rm -f "$tmp"; exit 1
        fi
        mv "$tmp" "$state_file"
    ) 8>>"$lock_file"
}

wpgovern::state::get_fact() {
    local key="$1"
    local state_file="${WPGOVERN_STATE_FILE}"
    if [[ ! -f "$state_file" ]]; then
        echo ""
        return 0
    fi
    jq -r --arg k "$key" '.host_facts[$k] // empty' "$state_file" 2>/dev/null || echo ""
}

# H.7.1-7: shared helper for state-file path resolution.
# Called by modules/audit/entry.sh and modules/backup/restore_entry.sh.
# Precedence: WPGOVERN_STATE_FILE env var → installer default at WPGOVERN_INSTALL_DIR.
# The /var/lib/wpgovern fallback was wrong — the installer writes state to
# ${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json (default /opt/wpgovern-install/).
wpgovern::state::resolve_default_state_file() {
    if [[ -n "${WPGOVERN_STATE_FILE:-}" ]]; then
        echo "$WPGOVERN_STATE_FILE"
        return 0
    fi
    local install_dir="${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}"
    local state_file="${install_dir}/.wpgovern-installer-state.json"
    if [[ -f "$state_file" ]]; then
        echo "$state_file"
        return 0
    fi
    return 1
}
