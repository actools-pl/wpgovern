#!/usr/bin/env bash
# =============================================================================
# modules/audit/infrastructure.sh — Layer 2: Infrastructure health
# =============================================================================

set -euo pipefail

readonly _AUDIT_EXPECTED_SERVICES=("caddy" "mariadb" "php" "wordpress")
readonly _AUDIT_TLS_WARN_DAYS=30
readonly _AUDIT_TLS_FAIL_DAYS=7
readonly _AUDIT_BACKUP_WARN_HOURS=48
readonly _AUDIT_DISK_WARN_PCT=80
readonly _AUDIT_DISK_FAIL_PCT=90
readonly _AUDIT_MEM_WARN_PCT=80
readonly _AUDIT_MEM_FAIL_PCT=90

_audit_probe_containers_healthy() {
    local ps_output
    if ! ps_output="$(docker compose ps --format json 2>/dev/null)"; then
        _audit_finding "WPG-STACK-001" "HIGH" "FAIL" "2" \
            "docker compose ps failed — stack may not be running" \
            "Run: docker compose up -d"
        return 0
    fi
    local all_healthy=1
    local svc
    for svc in "${_AUDIT_EXPECTED_SERVICES[@]}"; do
        local svc_status
        svc_status="$(echo "$ps_output" | jq -r \
            --arg svc "$svc" \
            '.[] | select(.Name | contains($svc)) | .Health // .Status // "unknown"' \
            2>/dev/null | head -1)"
        if [[ "$svc_status" != "healthy" && "$svc_status" != "running" ]]; then
            _audit_finding "WPG-STACK-001" "HIGH" "FAIL" "2" \
                "Container '${svc}' not healthy (status: ${svc_status:-unknown})" \
                "Run: docker compose up -d && docker compose ps"
            all_healthy=0
        fi
    done
    if [[ "$all_healthy" -eq 1 ]]; then
        _audit_finding "WPG-STACK-001" "HIGH" "PASS" "2" \
            "All expected containers (caddy, mariadb, php, wordpress) are healthy" ""
    fi
}

_audit_probe_disk_pressure() {
    local partitions=("/opt/wpgovern-install" "/var/log")
    [[ -d "/srv" ]] && partitions+=("/srv")
    local p
    for p in "${partitions[@]}"; do
        [[ -d "$p" ]] || continue
        local pct
        pct="$(df --output=pcent "$p" 2>/dev/null | tail -1 | tr -d '% ')"
        [[ -z "${pct:-}" ]] && continue
        if [[ "$pct" -ge "$_AUDIT_DISK_FAIL_PCT" ]]; then
            _audit_finding "WPG-STACK-002" "CRITICAL" "FAIL" "2" \
                "Disk pressure CRITICAL: ${p} at ${pct}% (≥${_AUDIT_DISK_FAIL_PCT}%)" \
                "Free disk space immediately: du -sh ${p}/* | sort -rh | head -20"
        elif [[ "$pct" -ge "$_AUDIT_DISK_WARN_PCT" ]]; then
            _audit_finding "WPG-STACK-002" "HIGH" "WARN" "2" \
                "Disk pressure HIGH: ${p} at ${pct}% (≥${_AUDIT_DISK_WARN_PCT}%)" \
                "Review disk usage: du -sh ${p}/* | sort -rh | head -20"
        else
            _audit_finding "WPG-STACK-002" "LOW" "PASS" "2" \
                "Disk ${p}: ${pct}% used" ""
        fi
    done
}

_audit_probe_memory_pressure() {
    local mem_pct
    mem_pct="$(free | awk '/^Mem:/ {printf "%d", int(100*$3/$2)}')"
    if [[ "${mem_pct:-0}" -ge "$_AUDIT_MEM_FAIL_PCT" ]]; then
        _audit_finding "WPG-STACK-003" "CRITICAL" "FAIL" "2" \
            "Memory pressure CRITICAL: ${mem_pct}% used (≥${_AUDIT_MEM_FAIL_PCT}%)" \
            "Check memory consumers: docker stats --no-stream"
    elif [[ "${mem_pct:-0}" -ge "$_AUDIT_MEM_WARN_PCT" ]]; then
        _audit_finding "WPG-STACK-003" "HIGH" "WARN" "2" \
            "Memory pressure HIGH: ${mem_pct}% used (≥${_AUDIT_MEM_WARN_PCT}%)" \
            "Monitor: docker stats --no-stream"
    else
        _audit_finding "WPG-STACK-003" "LOW" "PASS" "2" \
            "Memory: ${mem_pct}% used" ""
    fi
}

_audit_probe_tls_cert_expiry() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local expiry_str days_remaining

    if ! expiry_str="$(echo "" | timeout 10 \
        openssl s_client -connect "${domain}:443" -servername "$domain" \
        2>/dev/null | openssl x509 -noout -enddate 2>/dev/null)"; then
        _audit_finding "WPG-SEC-001" "HIGH" "WARN" "2" \
            "Could not retrieve TLS certificate for ${domain}" \
            "Check Caddy certificate status: docker compose logs caddy | grep -i cert"
        return 0
    fi
    local expiry_epoch; expiry_epoch="$(date -d "$(echo "$expiry_str" | cut -d= -f2)" +%s 2>/dev/null || echo 0)"
    local now_epoch; now_epoch="$(date +%s)"
    days_remaining="$(( (expiry_epoch - now_epoch) / 86400 ))"

    if [[ "$days_remaining" -le "$_AUDIT_TLS_FAIL_DAYS" ]]; then
        _audit_finding "WPG-SEC-001" "CRITICAL" "FAIL" "2" \
            "TLS certificate expires in ${days_remaining} day(s) — CRITICAL" \
            "Renew certificate immediately: docker compose restart caddy"
    elif [[ "$days_remaining" -le "$_AUDIT_TLS_WARN_DAYS" ]]; then
        _audit_finding "WPG-SEC-001" "HIGH" "WARN" "2" \
            "TLS certificate expires in ${days_remaining} day(s)" \
            "Verify Caddy auto-renewal is working: docker compose logs caddy | grep renew"
    else
        _audit_finding "WPG-SEC-001" "LOW" "PASS" "2" \
            "TLS certificate valid for ${days_remaining} more day(s)" ""
    fi
}

_audit_probe_backup_currency() {
    # H.7: activated from H.6 placeholder. Enforces SLO using state-fact
    # backup.last_full_at; falls back to filesystem scan.
    local backup_dir="${WPGOVERN_BACKUP_DIR:-/srv/wpgovern/backups}"
    if [[ ! -d "$backup_dir" ]]; then
        _audit_finding "WPG-BKUP-001" "HIGH" "FAIL" "2" \
            "Backup directory ${backup_dir} not present — backup module not configured" \
            "Deploy H.7 backup module or set WPGOVERN_BACKUP_DIR in wpgovern.env"
        return 0
    fi
    local last_full_at; last_full_at="$(wpgovern::state::get_fact "backup.last_full_at" 2>/dev/null || echo "")"
    local backup_age_hours=999
    if [[ -n "$last_full_at" ]]; then
        local last_epoch; last_epoch="$(date -d "$last_full_at" +%s 2>/dev/null || echo 0)"
        local now_epoch; now_epoch="$(date +%s)"
        backup_age_hours="$(( (now_epoch - last_epoch) / 3600 ))"
    else
        local recent; recent="$(find "$backup_dir" -name "full-*.sql.age" -mmin "-$((48*60))" 2>/dev/null | head -1)"
        [[ -n "$recent" ]] && backup_age_hours=0
    fi
    if [[ "$backup_age_hours" -le 24 ]]; then
        _audit_finding "WPG-BKUP-001" "HIGH" "PASS" "2" \
            "Full backup current: last backup ${backup_age_hours}h ago" ""
    elif [[ "$backup_age_hours" -le 48 ]]; then
        _audit_finding "WPG-BKUP-001" "HIGH" "WARN" "2" \
            "Full backup aging: last backup ${backup_age_hours}h ago (24-48h)" \
            "Trigger manual backup: systemctl start wpgovern-backup-full.service"
    else
        _audit_finding "WPG-BKUP-001" "HIGH" "FAIL" "2" \
            "Full backup overdue: last backup ${backup_age_hours}h ago (>48h)" \
            "Check backup timer: systemctl status wpgovern-backup-full.timer"
    fi
}

_audit_probe_backup_integrity() {
    # WPG-BKUP-002: activated from H.6 catalog forward-reference.
    local last_test_at; last_test_at="$(wpgovern::state::get_fact "backup.last_restore_test_at" 2>/dev/null || echo "")"
    local last_test_result; last_test_result="$(wpgovern::state::get_fact "backup.last_restore_test_result" 2>/dev/null || echo "")"
    if [[ -z "$last_test_at" ]]; then
        _audit_finding "WPG-BKUP-002" "HIGH" "FAIL" "2" \
            "Backup restore-test has never been run" \
            "Run: wpgovern-restore restore-test"
        return 0
    fi
    local test_age_days=0
    local test_epoch; test_epoch="$(date -d "$last_test_at" +%s 2>/dev/null || echo 0)"
    local now_epoch; now_epoch="$(date +%s)"
    test_age_days="$(( (now_epoch - test_epoch) / 86400 ))"
    if [[ "$last_test_result" != "PASS" ]]; then
        _audit_finding "WPG-BKUP-002" "HIGH" "WARN" "2" \
            "Last restore-test FAILED at ${last_test_at}: ${last_test_result}" \
            "Investigate and re-run: wpgovern-restore restore-test"
    elif [[ "$test_age_days" -le 7 ]]; then
        _audit_finding "WPG-BKUP-002" "HIGH" "PASS" "2" \
            "Restore-test passed ${test_age_days}d ago (within 7d)" ""
    elif [[ "$test_age_days" -le 30 ]]; then
        _audit_finding "WPG-BKUP-002" "MEDIUM" "WARN" "2" \
            "Restore-test last passed ${test_age_days}d ago (7-30d)" \
            "Run: wpgovern-restore restore-test"
    else
        _audit_finding "WPG-BKUP-002" "HIGH" "FAIL" "2" \
            "Restore-test overdue: last passed ${test_age_days}d ago (>30d)" \
            "Run immediately: wpgovern-restore restore-test"
    fi
}


_audit_probe_mariadb_reachable() {
    # H.6.1-1: xtrace guard at function entry.
    # This function reads WPGOVERN_DB_WP_PASSWORD and substitutes it into a
    # docker exec invocation. Without this guard, bash -x produces ~5 cleartext
    # leak occurrences of the password (variable assignment + subprocess arg expansion).
    # Pattern identical to H.4.1-2's load_env protection.
    # NOTE: _wpgovern_disable_xtrace_for_credentials is NOT used here because that
    # helper protects within its calling scope only — it does not propagate down
    # the call stack. Each credential-touching function needs its own guard.
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac

    local db_wp_pw="${WPGOVERN_DB_WP_PASSWORD:-}"
    if [[ -z "$db_wp_pw" ]]; then
        _audit_finding "WPG-STACK-004" "MEDIUM" "WARN" "2" \
            "WPGOVERN_DB_WP_PASSWORD not set — cannot probe MariaDB connectivity" ""
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 0
    fi
    local result
    if result="$(timeout 10 docker compose exec -T php \
        php -r "
\$c = new mysqli('mariadb', 'wpuser', '${db_wp_pw}', 'wordpress');
if (\$c->connect_error) { echo 'FAIL'; exit(1); }
echo 'OK';
" 2>/dev/null)"; then
        _audit_finding "WPG-STACK-004" "HIGH" "PASS" "2" \
            "MariaDB reachable from PHP container" ""
    else
        _audit_finding "WPG-STACK-004" "HIGH" "FAIL" "2" \
            "MariaDB NOT reachable from PHP container (${result:-connection failed})" \
            "Check MariaDB health: docker compose logs mariadb"
    fi
    [[ -n "${_restore_xtrace:-}" ]] && set -x
}
