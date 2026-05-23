#!/usr/bin/env bash
# =============================================================================
# modules/host/firewall.sh — UFW firewall configuration
#
# H.1.1-3: Uses ${WPGOVERN_SSH_PORT:-22}. Listener check uses exact-port ss.
# H.1.1-7: UFW idempotency verifies required rules before skipping.
# H.1.2-2: _wpgovern_ufw_rule_present uses awk exact-field matching.
#           Prevents 2222/tcp from satisfying a required 22/tcp rule.
# =============================================================================

set -euo pipefail

# H.1.2-2: exact-field UFW rule checker — same defect class as H.1.1-3.
# awk field matching: port_spec must exactly equal the port field.
_wpgovern_ufw_rule_present() {
    local ufw_output="$1"
    local port_spec="$2"   # e.g., "22/tcp" or "443/tcp"

    echo "$ufw_output" | awk -v port="$port_spec" '
        NF == 0    { next }
        /^Status:/ { next }
        /^To/      { next }
        /^---/     { next }
        {
            # ufw status:         $1=port  $2=action  $3=from
            # ufw status numbered: $1="["  $2="N]"    $3=port  $4=action  $5=from
            port_field = ""; allow_field = ""
            if ($1 == port)      { port_field = $1; allow_field = $2 }
            else if ($3 == port) { port_field = $3; allow_field = $4 }
            if (port_field == port && allow_field == "ALLOW") { found = 1 }
        }
        END { exit !found }
    '
}

wpgovern::host::firewall::configure() {
    local ssh_port="${WPGOVERN_SSH_PORT:-22}"

    # H.1.1-7 + H.1.2-2: UFW active → verify required rules before claiming idempotency
    if ufw status 2>/dev/null | grep -q "^Status: active"; then
        local ufw_output
        ufw_output="$(ufw status 2>/dev/null)"
        local ufw_verbose
        ufw_verbose="$(ufw status verbose 2>/dev/null)"

        local missing=()
        # H.1.2-2: all three rule checks use exact-field helper
        if ! _wpgovern_ufw_rule_present "$ufw_output" "${ssh_port}/tcp"; then
            missing+=("SSH port ${ssh_port}/tcp")
        fi
        if ! _wpgovern_ufw_rule_present "$ufw_output" "80/tcp"; then
            missing+=("80/tcp")
        fi
        if ! _wpgovern_ufw_rule_present "$ufw_output" "443/tcp"; then
            missing+=("443/tcp")
        fi
        if ! echo "$ufw_verbose" | grep -qi "default:.*deny.*(incoming)\|deny (incoming)"; then
            missing+=("default deny incoming")
        fi

        if [[ "${#missing[@]}" -eq 0 ]]; then
            wpgovern::bootstrap::log "UFW already active with required rules — skipping"
            wpgovern::state::set_fact "host.firewall_configured" "true"
            wpgovern::state::set_fact "host.firewall.ssh_port" "$ssh_port"
            return 0
        else
            wpgovern::bootstrap::log "UFW active but missing required rules: ${missing[*]}"
            wpgovern::bootstrap::log "Proceeding with reconfiguration"
        fi
    fi

    wpgovern::bootstrap::log "Configuring UFW firewall (SSH port: ${ssh_port})..."

    if [[ "${WPGOVERN_FORCE_FIREWALL:-false}" != "true" ]]; then
        _wpgovern_firewall_check_ssh_safety "$ssh_port"
    else
        wpgovern::bootstrap::log "  --force-firewall set; skipping SSH safety check"
    fi

    ufw --force reset > /dev/null
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    ufw allow "${ssh_port}/tcp" > /dev/null
    ufw allow 80/tcp > /dev/null
    ufw allow 443/tcp > /dev/null
    ufw --force enable > /dev/null

    systemctl enable fail2ban > /dev/null 2>&1 || true
    systemctl start fail2ban > /dev/null 2>&1 || true

    wpgovern::state::set_fact "host.firewall_configured_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.firewall_configured" "true"
    wpgovern::state::set_fact "host.firewall.ssh_port" "$ssh_port"
    wpgovern::bootstrap::log "UFW configured (port ${ssh_port}/80/443 allowed, default deny)"
}

_wpgovern_firewall_check_ssh_safety() {
    local ssh_port="$1"
    if ! ss -H -ltn "sport = :${ssh_port}" 2>/dev/null | grep -q .; then
        wpgovern::bootstrap::log \
            "WARNING: SSH does not appear to be listening on port ${ssh_port}"
        wpgovern::bootstrap::log \
            "  Use --force-firewall to proceed anyway, or set WPGOVERN_SSH_PORT"
        return 1
    fi
    wpgovern::bootstrap::log "  SSH connectivity check passed (port ${ssh_port} is listening)"
}
