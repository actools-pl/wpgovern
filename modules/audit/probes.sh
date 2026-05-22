#!/usr/bin/env bash
# =============================================================================
# modules/audit/probes.sh — Layer 1: WordPress truth via wp-cli
# All probes are read-only. Each has a 15-second timeout.
# =============================================================================

set -euo pipefail

readonly _AUDIT_WP_TIMEOUT=15  # seconds
readonly _AUDIT_KNOWN_SECURITY_PLUGINS=(
    "wordfence"
    "sucuri-scanner"
    "all-in-one-wp-security"
    "miniorange-malware-protection-and-security-scanner"
    "malcare-security"
)

# Run a wp-cli command inside the cli container with timeout.
# Usage: _audit_wp_cli [args...] — prints stdout; returns exit code
_audit_wp_cli() {
    timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color --skip-themes --skip-plugins \
        "$@" 2>/dev/null || return $?
}

_audit_probe_wp_core_version() {
    local version
    if ! version="$(timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color core version 2>/dev/null)"; then
        _audit_finding "WPG-WP-001" "MEDIUM" "WARN" "1" \
            "Could not retrieve WordPress core version (wp-cli timeout or error)" \
            "Check container health: docker compose ps"
        return 0
    fi
    version="$(echo "$version" | tr -d '[:space:]')"
    _audit_finding "WPG-WP-001" "LOW" "PASS" "1" \
        "WordPress core version: ${version}" ""
}

_audit_probe_wp_plugin_updates() {
    local count
    if ! count="$(timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color plugin list --update=available --format=count \
        2>/dev/null)"; then
        _audit_finding "WPG-WP-002" "LOW" "WARN" "1" \
            "Could not check for plugin updates (wp-cli timeout or error)" ""
        return 0
    fi
    count="$(echo "$count" | tr -d '[:space:]')"
    if [[ "${count:-0}" -gt 0 ]]; then
        _audit_finding "WPG-WP-002" "MEDIUM" "WARN" "1" \
            "${count} WordPress plugin(s) have available updates" \
            "wp plugin update --all  (run via: docker compose --profile cli run --rm cli wp plugin update --all)"
    else
        _audit_finding "WPG-WP-002" "LOW" "PASS" "1" \
            "All WordPress plugins are up to date" ""
    fi
}

_audit_probe_wp_cron_status() {
    local cron_output
    if ! cron_output="$(timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color cron event list --format=json 2>/dev/null)"; then
        _audit_finding "WPG-WP-003" "LOW" "WARN" "1" \
            "Could not check WordPress cron status (wp-cli timeout or error)" ""
        return 0
    fi
    # Check for events overdue by >1 hour
    local now_epoch; now_epoch="$(date +%s)"
    local overdue_count
    overdue_count="$(echo "$cron_output" | jq --arg now "$now_epoch" \
        '[.[] | select(.timestamp < ($now|tonumber) - 3600)] | length' 2>/dev/null || echo 0)"
    if [[ "${overdue_count:-0}" -gt 0 ]]; then
        _audit_finding "WPG-WP-003" "MEDIUM" "WARN" "1" \
            "${overdue_count} WordPress cron event(s) overdue by >1 hour" \
            "Check WP Cron: docker compose --profile cli run --rm cli wp cron event list"
    else
        _audit_finding "WPG-WP-003" "LOW" "PASS" "1" \
            "WordPress cron events are current" ""
    fi
}

_audit_probe_wp_config_drift() {
    local db_siteurl
    if ! db_siteurl="$(timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color option get siteurl 2>/dev/null)"; then
        _audit_finding "WPG-WP-004" "LOW" "WARN" "1" \
            "Could not retrieve siteurl from database" ""
        return 0
    fi
    db_siteurl="$(echo "$db_siteurl" | tr -d '[:space:]')"
    local expected_url="https://${WPGOVERN_DOMAIN:-unknown}"
    if [[ "$db_siteurl" != "$expected_url" ]]; then
        _audit_finding "WPG-WP-004" "HIGH" "WARN" "1" \
            "WordPress siteurl (${db_siteurl}) does not match expected (${expected_url})" \
            "Update wp-config.php WP_HOME or run: docker compose --profile cli run --rm cli wp option update siteurl '${expected_url}'"
    else
        _audit_finding "WPG-WP-004" "LOW" "PASS" "1" \
            "WordPress siteurl matches configured domain (${db_siteurl})" ""
    fi
}

_audit_probe_wp_security_plugin() {
    # WPG-WP-007: visible architectural delegation signal.
    # WordPress content-layer security is operator-delegated. This finding communicates
    # the delegation choice. With a recognized plugin installed → PASS.
    local active_plugins
    if ! active_plugins="$(timeout "${_AUDIT_WP_TIMEOUT}" \
        docker compose --profile cli run --rm --quiet cli wp \
        --quiet --no-color plugin list --status=active --field=name 2>/dev/null)"; then
        _audit_finding "WPG-WP-007" "LOW" "WARN" "1" \
            "Could not verify WordPress security plugin status" ""
        return 0
    fi
    local p
    for p in "${_AUDIT_KNOWN_SECURITY_PLUGINS[@]}"; do
        if echo "$active_plugins" | grep -qF "$p"; then
            _audit_finding "WPG-WP-007" "LOW" "PASS" "1" \
                "WordPress security plugin active: ${p}" ""
            return 0
        fi
    done
    _audit_finding "WPG-WP-007" "LOW" "WARN" "1" \
        "No WordPress security plugin detected (architectural delegation signal)" \
        "Install Wordfence, Sucuri Security, or MalCare from wp-admin → Plugins → Add New"
}
