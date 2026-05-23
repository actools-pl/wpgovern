#!/usr/bin/env bash
# =============================================================================
# modules/audit/security.sh — Layer 3: Security posture
# =============================================================================

set -euo pipefail

_audit_probe_https_enforced() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local status_code location_header

    if ! status_code="$(timeout 10 curl --silent --max-time 10 \
            -o /dev/null -w "%{http_code}\n%{redirect_url}" \
            "http://${domain}/" 2>/dev/null)"; then
        _audit_finding "WPG-SEC-002" "HIGH" "WARN" "3" \
            "Could not probe HTTP redirect for ${domain}" ""
        return 0
    fi
    local code; code="$(echo "$status_code" | head -1)"
    local loc;  loc="$(echo "$status_code" | tail -1)"
    if [[ "$code" == "301" || "$code" == "308" ]] && \
       [[ "$loc" == https://* ]]; then
        _audit_finding "WPG-SEC-002" "HIGH" "PASS" "3" \
            "HTTPS enforced: HTTP redirects to HTTPS (HTTP ${code})" ""
    elif [[ "$code" == "200" ]]; then
        _audit_finding "WPG-SEC-002" "HIGH" "FAIL" "3" \
            "HTTPS NOT enforced: HTTP returns 200 (no redirect)" \
            "Add HTTP→HTTPS redirect in Caddyfile"
    else
        _audit_finding "WPG-SEC-002" "MEDIUM" "WARN" "3" \
            "Unexpected HTTP response code ${code} for ${domain}" ""
    fi
}

_audit_probe_security_headers() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local headers
    if ! headers="$(timeout 10 curl --silent --max-time 10 -I \
            "https://${domain}/" 2>/dev/null)"; then
        _audit_finding "WPG-SEC-003" "MEDIUM" "WARN" "3" \
            "Could not retrieve security headers for ${domain}" ""
        return 0
    fi
    # HSTS — FAIL if absent (HTTPS enforced means HSTS expected)
    if echo "$headers" | grep -qi "^Strict-Transport-Security:"; then
        _audit_finding "WPG-SEC-003" "HIGH" "PASS" "3" \
            "Strict-Transport-Security header present" ""
    else
        _audit_finding "WPG-SEC-003" "HIGH" "FAIL" "3" \
            "Strict-Transport-Security (HSTS) header missing" \
            "Add to Caddyfile: header Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
    fi
    # X-Content-Type-Options — WARN if absent
    if echo "$headers" | grep -qi "^X-Content-Type-Options:"; then
        _audit_finding "WPG-SEC-004" "MEDIUM" "PASS" "3" \
            "X-Content-Type-Options header present" ""
    else
        _audit_finding "WPG-SEC-004" "MEDIUM" "WARN" "3" \
            "X-Content-Type-Options header missing" \
            "Add to Caddyfile: header X-Content-Type-Options nosniff"
    fi
    # X-Frame-Options — WARN if absent
    if echo "$headers" | grep -qi "^X-Frame-Options:"; then
        _audit_finding "WPG-SEC-006" "MEDIUM" "PASS" "3" \
            "X-Frame-Options header present" ""
    else
        _audit_finding "WPG-SEC-006" "MEDIUM" "WARN" "3" \
            "X-Frame-Options header missing" \
            "Add to Caddyfile: header X-Frame-Options SAMEORIGIN"
    fi
    # CSP — INFO only (operator-configurable)
    if echo "$headers" | grep -qi "^Content-Security-Policy:"; then
        _audit_finding "WPG-SEC-007" "LOW" "PASS" "3" \
            "Content-Security-Policy header present" ""
    else
        _audit_finding "WPG-SEC-007" "LOW" "WARN" "3" \
            "Content-Security-Policy header not configured (operator-configurable)" \
            "Consider adding a CSP header in Caddyfile; see OWASP CSP cheat sheet"
    fi
}

_audit_probe_ports_open() {
    local allowed_ports=("22" "80" "443")
    local listening_ports
    listening_ports="$(ss -tnl 2>/dev/null | awk '$1=="LISTEN" {print $4}' | \
        grep -oE '[0-9]+$' | sort -un)"
    local unexpected=()
    local port
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        local allowed=0
        local ap
        for ap in "${allowed_ports[@]}"; do
            [[ "$port" == "$ap" ]] && allowed=1 && break
        done
        [[ "$allowed" -eq 0 ]] && unexpected+=("$port")
    done <<< "$listening_ports"

    if [[ ${#unexpected[@]} -gt 0 ]]; then
        _audit_finding "WPG-SEC-008" "HIGH" "FAIL" "3" \
            "Unexpected ports listening on public interfaces: ${unexpected[*]}" \
            "Review open ports: ss -tnlp  (close or firewall unexpected ports)"
    else
        _audit_finding "WPG-SEC-008" "HIGH" "PASS" "3" \
            "Only expected ports open: 22, 80, 443" ""
    fi
}

_audit_probe_server_header_hidden() {
    local domain="${WPGOVERN_DOMAIN:-localhost}"
    local headers server_val

    if ! headers="$(timeout 10 curl --silent --max-time 10 -I \
            "https://${domain}/" 2>/dev/null)"; then
        _audit_finding "WPG-SEC-005" "LOW" "WARN" "3" \
            "Could not probe server header for ${domain}" ""
        return 0
    fi
    server_val="$(echo "$headers" | grep -i "^Server:" | head -1 | tr -d '\r\n' | \
        sed 's/^[Ss]erver: *//' || true)"

    if [[ -z "$server_val" ]]; then
        _audit_finding "WPG-SEC-005" "MEDIUM" "PASS" "3" \
            "Server header not present (best practice)" ""
    elif echo "$server_val" | grep -qE '/[0-9]'; then
        _audit_finding "WPG-SEC-005" "MEDIUM" "FAIL" "3" \
            "Server header leaks version information: '${server_val}'" \
            "Add to Caddyfile: header -Server  (or suppress via Caddy admin.server_name config)"
    else
        _audit_finding "WPG-SEC-005" "LOW" "WARN" "3" \
            "Server header present but version-stripped: '${server_val}'" \
            "Consider removing entirely: header -Server"
    fi
}

_audit_probe_docker_images_pinned() {
    local compose_output
    if ! compose_output="$(docker compose config 2>/dev/null)"; then
        _audit_finding "WPG-SEC-009" "MEDIUM" "WARN" "3" \
            "Could not inspect docker compose config" ""
        return 0
    fi
    local unpinned_images=()
    while IFS= read -r line; do
        [[ "$line" =~ "image:" ]] || continue
        local img; img="$(echo "$line" | awk '{print $2}')"
        [[ -z "$img" ]] && continue
        if ! echo "$img" | grep -q "@sha256:"; then
            unpinned_images+=("$img")
        fi
    done <<< "$compose_output"

    if [[ ${#unpinned_images[@]} -gt 0 ]]; then
        _audit_finding "WPG-SEC-009" "HIGH" "FAIL" "3" \
            "Docker images not digest-pinned: ${unpinned_images[*]}" \
            "Re-run H.2 image pinning: wpgovern-install.sh to update image digests"
    else
        _audit_finding "WPG-SEC-009" "HIGH" "PASS" "3" \
            "All Docker images are digest-pinned (@sha256:)" ""
    fi
}

_audit_probe_dr_key_backup() {
    # WPG-DR-01 (H.7 Decision 3): operator-attestation probe for age key backup.
    # PASS = operator has acknowledged backing up the key off-server.
    # WARN = operator has not yet acknowledged.
    # NOTE: PASS is operator-attested via "wpgovern-restore ack-key-backup".
    # WPGovern CANNOT verify the key is actually safe off-server — it cannot reach
    # off-server storage. The attestation is the operator's responsibility.
    local ack_ts; ack_ts="$(wpgovern::state::get_fact "dr.key_backed_up_at" 2>/dev/null || echo "")"
    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"

    if [[ -z "$ack_ts" ]]; then
        _audit_finding "WPG-DR-01" "HIGH" "WARN" "3" \
            "age private key backup NOT acknowledged (unacknowledged = disaster recovery risk)" \
            "Back up ${privkey_path} off-server, then run: wpgovern-restore ack-key-backup"
    else
        _audit_finding "WPG-DR-01" "LOW" "PASS" "3" \
            "age private key backup acknowledged at ${ack_ts} (operator-attested)" ""
    fi
}
