#!/usr/bin/env bash
# =============================================================================
# modules/audit/orchestrator.sh — Audit runner
#
# Doctrine: boringly predictable, brutally honest, immediately useful.
# - Predictable: same checks, same order, every run.
# - Honest: no short-circuit on failure; full picture always produced.
# - Useful: every finding has a fix-ID and a fix command.
#
# Internal findings buffer format (pipe-delimited):
#   ${fix_id}|${priority}|${status}|${layer}|${message}|${fix_command}
# Pipe character '|' is FORBIDDEN in any field value.
# =============================================================================

set -euo pipefail

# Global findings buffer — populated by _audit_emit, consumed by formatters
_WPGOVERN_AUDIT_FINDINGS=""
# H.6.2-5: internal error flag — set to 1 when any probe returns non-zero.
# run_full returns exit code 2 when this is set (per documented semantics).
_WPGOVERN_AUDIT_INTERNAL_ERROR=0

# Emit a finding line to the buffer
_audit_emit() {
    local line="$1"
    if [[ -n "$_WPGOVERN_AUDIT_FINDINGS" ]]; then
        _WPGOVERN_AUDIT_FINDINGS="${_WPGOVERN_AUDIT_FINDINGS}"$'\n'"${line}"
    else
        _WPGOVERN_AUDIT_FINDINGS="${line}"
    fi
}

# Convenience wrapper: emit with explicit fields
_audit_finding() {
    local fix_id="$1"
    local priority="$2"
    local status="$3"
    local layer="$4"
    local message="$5"
    local fix_cmd="${6:-}"
    _audit_emit "${fix_id}|${priority}|${status}|${layer}|${message}|${fix_cmd}"
}

# Run a probe function; on unhandled failure record an error finding, continue.
# Implements the full-picture-over-fast-fail doctrine.
_audit_run_probe() {
    local probe_fn="$1"
    local fix_id_on_error="${2:-WPG-STACK-000}"
    if ! "$probe_fn"; then
        _WPGOVERN_AUDIT_INTERNAL_ERROR=1   # H.6.2-5: track crash for exit code 2
        _audit_finding "$fix_id_on_error" "MEDIUM" "WARN" "0" \
            "Probe ${probe_fn} failed unexpectedly" \
            "Check wpgovern-install-audit output for details; re-run with bash -x for debugging"
    fi
}

wpgovern::audit::layer1() {
    _audit_run_probe _audit_probe_wp_core_version     "WPG-WP-000"
    _audit_run_probe _audit_probe_wp_plugin_updates   "WPG-WP-000"
    _audit_run_probe _audit_probe_wp_cron_status      "WPG-WP-000"
    _audit_run_probe _audit_probe_wp_config_drift     "WPG-WP-000"
    _audit_run_probe _audit_probe_wp_security_plugin  "WPG-WP-000"
}

wpgovern::audit::layer1_5() {
    _audit_run_probe _audit_probe_redis_writeback        "WPG-STACK-000"
    _audit_run_probe _audit_probe_login_session          "WPG-WP-000"
    _audit_run_probe _audit_probe_http_cache_headers     "WPG-SEC-000"
    _audit_run_probe _audit_probe_trusted_host_rejection "WPG-SEC-000"
}

wpgovern::audit::layer2() {
    _audit_run_probe _audit_probe_containers_healthy  "WPG-STACK-000"
    _audit_run_probe _audit_probe_disk_pressure       "WPG-STACK-000"
    _audit_run_probe _audit_probe_memory_pressure     "WPG-STACK-000"
    _audit_run_probe _audit_probe_tls_cert_expiry     "WPG-SEC-000"
    _audit_run_probe _audit_probe_backup_currency     "WPG-BKUP-000"
    _audit_run_probe _audit_probe_backup_integrity    "WPG-BKUP-000"  # H.7 activated
    _audit_run_probe _audit_probe_mariadb_reachable   "WPG-STACK-000"
}

wpgovern::audit::layer3() {
    _audit_run_probe _audit_probe_https_enforced         "WPG-SEC-000"
    _audit_run_probe _audit_probe_security_headers       "WPG-SEC-000"
    _audit_run_probe _audit_probe_ports_open             "WPG-SEC-000"
    _audit_run_probe _audit_probe_server_header_hidden   "WPG-SEC-000"
    _audit_run_probe _audit_probe_docker_images_pinned   "WPG-SEC-000"
    _audit_run_probe _audit_probe_dr_key_backup          "WPG-DR-000"  # H.7 new
}

wpgovern::audit::layer1_security_subset() {
    # Security-relevant Layer 1 probes only (used by --security mode)
    _audit_run_probe _audit_probe_wp_security_plugin "WPG-WP-000"
    _audit_run_probe _audit_probe_wp_config_drift    "WPG-WP-000"
}

wpgovern::audit::run_full() {
    _wpgovern_disable_xtrace_for_credentials  # audit reads env that may contain credentials
    local mode="${1:-complete}"
    _WPGOVERN_AUDIT_FINDINGS=""
    _WPGOVERN_AUDIT_INTERNAL_ERROR=0  # H.6.2-5: reset per run

    case "$mode" in
        complete|ci|json)
            wpgovern::audit::layer1
            wpgovern::audit::layer1_5
            wpgovern::audit::layer2
            wpgovern::audit::layer3
            ;;
        security)
            wpgovern::audit::layer3
            wpgovern::audit::layer1_security_subset
            ;;
        *)
            echo "ERROR: unknown audit mode: ${mode}" >&2
            return 2
            ;;
    esac

    case "$mode" in
        json) wpgovern::audit::format_json ;;
        ci)   wpgovern::audit::format_ci ;;
        *)    wpgovern::audit::format_human ;;
    esac

    # H.6.2-5: exit code per documented contract (precedence: 2 > 1 > 0)
    # 2 = internal error (any probe crashed — worse signal than findings)
    # 1 = at least one FAIL finding
    # 0 = no FAIL findings (warnings allowed)
    if [[ "${_WPGOVERN_AUDIT_INTERNAL_ERROR:-0}" -eq 1 ]]; then
        return 2
    fi
    if echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "|FAIL|"; then
        return 1
    fi
    return 0
}
