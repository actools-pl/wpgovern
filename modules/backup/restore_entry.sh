#!/usr/bin/env bash
# =============================================================================
# modules/backup/restore_entry.sh — wpgovern-restore entry script
# Invoked by /usr/local/bin/wpgovern-restore shim.
# =============================================================================

set -euo pipefail

_WPGOVERN_BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WPGOVERN_INSTALLER_DIR="$_WPGOVERN_BACKUP_DIR"
export WPGOVERN_INSTALLER_DIR

source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"

# Env-file discovery (same precedence as audit entry.sh — H.6.2-3 pattern)
_state="$(wpgovern::state::resolve_default_state_file 2>/dev/null)" || _state=""
_env_path="$(jq -r '.host_facts["bootstrap.env_file_path"] // ""' "$_state" 2>/dev/null || true)"
if [[ -n "$_env_path" && -f "$_env_path" ]]; then
    wpgovern::bootstrap::load_env_readonly "$_env_path" 2>/dev/null || true
elif [[ -f "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" ]]; then
    wpgovern::bootstrap::load_env_readonly "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" 2>/dev/null || true
fi

source "${WPGOVERN_INSTALLER_DIR}/modules/backup/restore.sh"
source "${WPGOVERN_INSTALLER_DIR}/modules/backup/restore_test.sh"

_restore_help() {
    cat << HELP
wpgovern-restore — WPGovern governance-aware restore command

Usage:
  wpgovern-restore <backup_ts>              Full restore from backup timestamp
  wpgovern-restore ack-key-backup           Acknowledge off-server key backup
    [--location-hint "<string>"]
  wpgovern-restore restore-test             Verify most recent backup is restorable
  wpgovern-restore list                     List available backups
  wpgovern-restore --version
  wpgovern-restore --help

Exit codes per phase (full restore):
  0   = restore complete, all checks passed
  10  = validate failed (backup files missing or corrupt)
  11  = install check failed (wpgovern-install.sh not complete on this box)
  12  = governance state restore failed
  13  = database restore failed
  14  = post-restore verification failed
HELP
}

case "${1:-}" in
    --version)
        echo "wpgovern-restore 1.0 (WPGovern H.7)"
        exit 0
        ;;
    --help|-h)
        _restore_help
        exit 0
        ;;
    ack-key-backup)
        shift
        location_hint=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --location-hint) location_hint="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        wpgovern::backup::ack_key_backup "$location_hint"
        exit 0
        ;;
    restore-test)
        wpgovern::backup::run_restore_test
        exit $?
        ;;
    list)
        wpgovern::backup::list_backups
        exit 0
        ;;
    "")
        _restore_help
        exit 2
        ;;
    *)
        # H.7.1-9: validate timestamp format; unknown subcommand exits 2.
        # Backup timestamps are: YYYYMMDDTHHMMSSZ (e.g., 20260524T030000Z)
        if [[ ! "$1" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
            echo "ERROR: unknown subcommand or invalid timestamp format: '$1'" >&2
            echo "Expected: YYYYMMDDTHHMMSSZ (e.g., 20260524T030000Z)" >&2
            _restore_help >&2
            exit 2
        fi
        # Full restore from timestamp
        backup_ts="$1"
        echo "Starting governance-aware restore from backup: ${backup_ts}" >&2
        echo "CRITICAL: this will overwrite the current database and governance state." >&2
        wpgovern::backup::run_restore "$backup_ts"
        rc=$?
        if [[ "$rc" -eq 0 ]]; then
            echo "RESTORE COMPLETE — system operational at ${backup_ts}" >&2
        else
            echo "RESTORE FAILED with exit code ${rc}" >&2
            echo "See the runbook for recovery guidance per exit code." >&2
        fi
        exit $rc
        ;;
esac
