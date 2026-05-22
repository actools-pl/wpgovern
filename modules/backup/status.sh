#!/usr/bin/env bash
# =============================================================================
# modules/backup/status.sh — Backup status command
# =============================================================================

set -euo pipefail

wpgovern::backup::status() {
    local mode="${1:-human}"
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"

    local last_full_at;  last_full_at="$(wpgovern::state::get_fact "backup.last_full_at" 2>/dev/null || echo "")"
    local last_full_size; last_full_size="$(wpgovern::state::get_fact "backup.last_full_size_bytes" 2>/dev/null || echo "")"
    local last_binlog_at; last_binlog_at="$(wpgovern::state::get_fact "backup.last_binlog_rotated_at" 2>/dev/null || echo "")"
    local binlog_count;  binlog_count="$(wpgovern::state::get_fact "backup.binlog_encrypted_count" 2>/dev/null || echo "")"
    local last_test_at;  last_test_at="$(wpgovern::state::get_fact "backup.last_restore_test_at" 2>/dev/null || echo "")"
    local last_test_result; last_test_result="$(wpgovern::state::get_fact "backup.last_restore_test_result" 2>/dev/null || echo "")"

    local backup_count=0 backup_total_size=0
    if [[ -d "$backup_dir" ]]; then
        backup_count="$(find "$backup_dir" -name "*.age" 2>/dev/null | wc -l)"
        backup_total_size="$(du -sb "$backup_dir" 2>/dev/null | awk '{print $1}' || echo 0)"
    fi

    if [[ "$mode" == "--json" ]]; then
        jq -n \
            --arg last_full_at "${last_full_at:-}" \
            --arg last_full_size "${last_full_size:-0}" \
            --arg last_binlog_at "${last_binlog_at:-}" \
            --arg binlog_count "${binlog_count:-0}" \
            --arg last_test_at "${last_test_at:-}" \
            --arg last_test_result "${last_test_result:-}" \
            --argjson backup_count "$backup_count" \
            --argjson backup_total_size "$backup_total_size" \
            '{last_full_at:$last_full_at, last_full_size_bytes:($last_full_size|tonumber),
              last_binlog_rotated_at:$last_binlog_at, binlog_encrypted_count:($binlog_count|tonumber),
              last_restore_test_at:$last_test_at, last_restore_test_result:$last_test_result,
              backup_file_count:$backup_count, backup_total_bytes:$backup_total_size}'
        return 0
    fi

    printf '\n%s\n\n' "WPGovern Backup Status"
    printf '%-30s %s\n' "Last full backup:" "${last_full_at:-never}"
    printf '%-30s %s\n' "Last full backup size:" "${last_full_size:-unknown} bytes (encrypted)"
    printf '%-30s %s\n' "Last binlog rotation:" "${last_binlog_at:-never}"
    printf '%-30s %s\n' "Total backup files:" "$backup_count"
    printf '%-30s %s\n' "Backup dir total size:" "${backup_total_size} bytes"
    printf '%-30s %s\n' "Last restore-test:" "${last_test_at:-never}"
    printf '%-30s %s\n' "Last restore-test result:" "${last_test_result:-not run}"
    echo
}
