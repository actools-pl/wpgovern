#!/usr/bin/env bash
# =============================================================================
# modules/audit/formatters.sh — Audit output formatters
# Internal line format: fix_id|priority|status|layer|message|fix_command
# Three output modes: human (color), ci (sorted, no color), json.
# =============================================================================

set -euo pipefail

# ANSI colors (suppressed if NO_COLOR set or output is not a TTY)
_audit_color_reset=""
_audit_color_critical=""
_audit_color_high=""
_audit_color_medium=""
_audit_color_low=""
_audit_color_pass=""
_audit_color_warn=""
_audit_color_fail=""

_audit_colors_init() {
    if [[ -z "${NO_COLOR:-}" ]] && [[ -t 1 ]]; then
        _audit_color_reset="\033[0m"
        _audit_color_critical="\033[1;31m"    # bold red
        _audit_color_high="\033[0;31m"        # red
        _audit_color_medium="\033[0;33m"      # yellow
        _audit_color_low="\033[0;36m"         # cyan
        _audit_color_pass="\033[0;32m"        # green
        _audit_color_warn="\033[0;33m"        # yellow
        _audit_color_fail="\033[0;31m"        # red
    fi
}

_audit_priority_color() {
    local priority="$1"
    case "$priority" in
        CRITICAL) printf '%s' "$_audit_color_critical" ;;
        HIGH)     printf '%s' "$_audit_color_high" ;;
        MEDIUM)   printf '%s' "$_audit_color_medium" ;;
        LOW)      printf '%s' "$_audit_color_low" ;;
    esac
}

_audit_status_color() {
    local status="$1"
    case "$status" in
        PASS) printf '%s' "$_audit_color_pass" ;;
        WARN) printf '%s' "$_audit_color_warn" ;;
        FAIL) printf '%s' "$_audit_color_fail" ;;
    esac
}

wpgovern::audit::format_human() {
    _audit_colors_init
    local pass_count=0 warn_count=0 fail_count=0

    printf '\n%s\n' "WPGovern Install Audit"
    printf '%s\n\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf '%-20s  %-8s  %-6s  %s\n' "FIX-ID" "PRIORITY" "STATUS" "MESSAGE"
    printf '%s\n' "$(printf '%0.s-' {1..80})"

    while IFS='|' read -r fix_id priority status layer message fix_cmd; do
        [[ -z "$fix_id" ]] && continue
        local pc; pc="$(_audit_priority_color "$priority")"
        local sc; sc="$(_audit_status_color "$status")"
        printf "${pc}%-20s${_audit_color_reset}  %-8s  ${sc}%-6s${_audit_color_reset}  %s\n" \
            "$fix_id" "$priority" "$status" "$message"
        [[ -n "$fix_cmd" ]] && printf '%s\n' "          ↳ Fix: ${fix_cmd}"
        case "$status" in
            PASS) pass_count=$((pass_count+1)) ;;
            WARN) warn_count=$((warn_count+1)) ;;
            FAIL) fail_count=$((fail_count+1)) ;;
        esac
    done <<< "$_WPGOVERN_AUDIT_FINDINGS"

    printf '\n%s\n' "$(printf '%0.s-' {1..80})"
    printf 'Summary: %s PASS  %s WARN  %s FAIL\n\n' \
        "$pass_count" "$warn_count" "$fail_count"
}

wpgovern::audit::format_ci() {
    # No colors, sorted by fix-ID for diff stability
    printf '%-20s  %-8s  %-6s  %s\n' "FIX-ID" "PRIORITY" "STATUS" "MESSAGE"
    echo "$_WPGOVERN_AUDIT_FINDINGS" | sort | while IFS='|' read -r fix_id priority status layer message fix_cmd; do
        [[ -z "$fix_id" ]] && continue
        printf '%-20s  %-8s  %-6s  %s\n' "$fix_id" "$priority" "$status" "$message"
        [[ -n "$fix_cmd" ]] && printf '                               Fix: %s\n' "$fix_cmd"
    done || true
}

wpgovern::audit::format_json() {
    # H.6.2-2+8: jq-based construction handles ALL escaping (newlines, backslashes,
    # control chars, pipes-in-values). No manual awk JSON emission.
    # H.6.2-5: reads _WPGOVERN_AUDIT_INTERNAL_ERROR for exit_code: 2 in output.
    local ts domain pass_count=0 warn_count=0 fail_count=0
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    domain="${WPGOVERN_DOMAIN:-unknown}"

    while IFS='|' read -r fix_id priority status layer message fix_cmd; do
        [[ -z "$fix_id" ]] && continue
        case "$status" in
            PASS) pass_count=$((pass_count+1)) ;;
            WARN) warn_count=$((warn_count+1)) ;;
            FAIL) fail_count=$((fail_count+1)) ;;
        esac
    done <<< "$_WPGOVERN_AUDIT_FINDINGS"

    local exit_code=0
    if [[ "${_WPGOVERN_AUDIT_INTERNAL_ERROR:-0}" -eq 1 ]]; then
        exit_code=2
    elif [[ "$fail_count" -gt 0 ]]; then
        exit_code=1
    fi

    # Build findings array using jq — jq handles ALL field escaping correctly
    local findings_json="[]"
    while IFS='|' read -r fix_id priority status layer message fix_cmd; do
        [[ -z "$fix_id" ]] && continue
        # fix_cmd may contain pipes — IFS='|' read with 6 vars puts remainder in last var
        local fix_val
        if [[ -z "$fix_cmd" ]]; then
            fix_val="null"
        else
            fix_val="$(jq -n --arg v "$fix_cmd" '$v')"
        fi
        findings_json="$(jq -n \
            --argjson acc "$findings_json" \
            --arg fix_id "$fix_id" \
            --arg priority "$priority" \
            --arg status "$status" \
            --argjson layer "${layer:-0}" \
            --arg message "$message" \
            --argjson fix "$fix_val" \
            '$acc + [{fix_id:$fix_id, priority:$priority, status:$status,
                      layer:$layer, message:$message, fix:$fix}]')"
    done <<< "$_WPGOVERN_AUDIT_FINDINGS"

    jq -n \
        --arg version "1.0" \
        --arg ts "$ts" \
        --arg domain "$domain" \
        --argjson exit_code "$exit_code" \
        --argjson pass "$pass_count" \
        --argjson warn "$warn_count" \
        --argjson fail "$fail_count" \
        --argjson findings "$findings_json" \
        '{wpgovern_install_audit_version: $version,
          timestamp: $ts,
          domain: $domain,
          exit_code: $exit_code,
          summary: {pass: $pass, warn: $warn, fail: $fail},
          findings: $findings}'
}
