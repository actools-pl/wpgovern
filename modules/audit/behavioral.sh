#!/usr/bin/env bash
# =============================================================================
# modules/audit/behavioral.sh — Layer 1.5: Behavioral verification
# Probes WORKING behavior, not just running status.
# HTTP probes: 10-second timeout. Redis probes: 5-second timeout.
# =============================================================================

set -euo pipefail

readonly _AUDIT_HTTP_TIMEOUT=10   # seconds
readonly _AUDIT_REDIS_TIMEOUT=5   # seconds
readonly _AUDIT_SENTINEL_KEY="wpgovern_audit_sentinel"

_audit_probe_redis_writeback() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"

    # Check if Redis is running first; if not, emit INFO (skip, not warn)
    if ! docker compose ps redis --format json 2>/dev/null | grep -q '"Health"'; then
        _audit_finding "WPG-STACK-005" "LOW" "PASS" "1.5" \
            "Redis not configured — behavioral writeback check skipped" ""
        return 0
    fi

    local sentinel_val; sentinel_val="$(date +%s)"
    # Write sentinel key with 30-second TTL
    if ! timeout "${_AUDIT_REDIS_TIMEOUT}" docker exec \
            "$(docker compose ps -q wordpress 2>/dev/null)" \
            redis-cli SET "$_AUDIT_SENTINEL_KEY" "$sentinel_val" EX 30 \
            >/dev/null 2>&1; then
        _audit_finding "WPG-STACK-005" "MEDIUM" "WARN" "1.5" \
            "Redis writeback probe: could not write sentinel key" \
            "Check Redis connectivity from WordPress container"
        return 0
    fi
    # Read back
    local readback
    readback="$(timeout "${_AUDIT_REDIS_TIMEOUT}" docker exec \
        "$(docker compose ps -q wordpress 2>/dev/null)" \
        redis-cli GET "$_AUDIT_SENTINEL_KEY" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$readback" != "$sentinel_val" ]]; then
        _audit_finding "WPG-STACK-005" "HIGH" "FAIL" "1.5" \
            "Redis writeback probe: value mismatch (wrote '${sentinel_val}', read '${readback}')" \
            "Investigate Redis persistence configuration"
        return 0
    fi
    # Verify TTL was set
    local ttl
    ttl="$(timeout "${_AUDIT_REDIS_TIMEOUT}" docker exec \
        "$(docker compose ps -q wordpress 2>/dev/null)" \
        redis-cli TTL "$_AUDIT_SENTINEL_KEY" 2>/dev/null | tr -d '[:space:]')"
    if [[ "${ttl:-0}" -le 0 ]]; then
        _audit_finding "WPG-STACK-005" "MEDIUM" "WARN" "1.5" \
            "Redis writeback probe: key written but TTL not set (got TTL=${ttl})" \
            "Check Redis maxmemory-policy configuration"
        return 0
    fi
    _audit_finding "WPG-STACK-005" "LOW" "PASS" "1.5" \
        "Redis writeback probe: read/write/TTL all verified" ""
}

_audit_probe_login_session() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local login_url="https://${domain}/wp-login.php"

    local response_file; response_file="$(mktemp)"
    local cookie_jar; cookie_jar="$(mktemp)"

    # POST with deliberate invalid credentials — we're testing the login flow responds,
    # not that credentials work. A session cookie must be set regardless of auth result.
    if ! timeout "${_AUDIT_HTTP_TIMEOUT}" curl --silent --max-time "${_AUDIT_HTTP_TIMEOUT}" \
            --cookie-jar "$cookie_jar" \
            -X POST "$login_url" \
            -d "log=audit_probe&pwd=invalid_probe_password&wp-submit=Log+In" \
            -o /dev/null -w "%{http_code}" \
            --output "$response_file" \
            2>/dev/null; then
        rm -f "$response_file" "$cookie_jar"
        _audit_finding "WPG-WP-008" "MEDIUM" "WARN" "1.5" \
            "Login flow probe: could not reach ${login_url} (timeout or connection error)" \
            "Check that Caddy is running and domain resolves: curl -I https://${domain}/"
        return 0
    fi
    rm -f "$response_file"
    # A functional login flow sets a cookie (even on failed auth)
    if [[ -s "$cookie_jar" ]]; then
        _audit_finding "WPG-WP-008" "LOW" "PASS" "1.5" \
            "Login flow probe: WordPress responds to login POST and sets session cookie" ""
    else
        _audit_finding "WPG-WP-008" "MEDIUM" "WARN" "1.5" \
            "Login flow probe: no cookie returned from login endpoint" \
            "Check WordPress sessions configuration"
    fi
    rm -f "$cookie_jar"
}

_audit_probe_http_cache_headers() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local login_url="https://${domain}/wp-login.php"

    local headers
    if ! headers="$(timeout "${_AUDIT_HTTP_TIMEOUT}" curl --silent --max-time "${_AUDIT_HTTP_TIMEOUT}" \
            -I "$login_url" 2>/dev/null)"; then
        _audit_finding "WPG-SEC-010" "LOW" "WARN" "1.5" \
            "Cache-header probe: could not reach ${login_url}" ""
        return 0
    fi
    if echo "$headers" | grep -qi "^Cache-Control:.*no-cache"; then
        _audit_finding "WPG-SEC-010" "LOW" "PASS" "1.5" \
            "wp-login.php has Cache-Control: no-cache header" ""
    else
        local cc_val
        cc_val="$(echo "$headers" | grep -i "^Cache-Control:" | head -1 | tr -d '\r\n' || true)"
        _audit_finding "WPG-SEC-010" "HIGH" "FAIL" "1.5" \
            "wp-login.php missing Cache-Control: no-cache (got: '${cc_val:-not present}')" \
            "Add Caddy rewrite rule: header /wp-login.php Cache-Control no-cache"
    fi
}

_audit_probe_trusted_host_rejection() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local status_code

    if ! status_code="$(timeout "${_AUDIT_HTTP_TIMEOUT}" curl --silent --max-time "${_AUDIT_HTTP_TIMEOUT}" \
            -o /dev/null -w "%{http_code}" \
            -H 'Host: evil.example.com' \
            "https://${domain}/" \
            2>/dev/null)"; then
        _audit_finding "WPG-SEC-011" "LOW" "WARN" "1.5" \
            "Trusted-host spoof probe: could not reach ${domain}" ""
        return 0
    fi
    if [[ "$status_code" == "400" || "$status_code" == "421" || \
          "$status_code" == "403" || "$status_code" == "444" ]]; then
        _audit_finding "WPG-SEC-011" "HIGH" "PASS" "1.5" \
            "Trusted-host spoof rejected with HTTP ${status_code}" ""
    elif [[ "$status_code" == "200" ]]; then
        _audit_finding "WPG-SEC-011" "HIGH" "FAIL" "1.5" \
            "Trusted-host spoof NOT rejected (HTTP 200 returned)" \
            "Add Caddy SNI validation or WordPress trusted-host check to wp-config.php"
    else
        _audit_finding "WPG-SEC-011" "MEDIUM" "WARN" "1.5" \
            "Trusted-host spoof returned unexpected HTTP ${status_code}" ""
    fi
}
