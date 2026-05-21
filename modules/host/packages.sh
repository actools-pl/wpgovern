#!/usr/bin/env bash
# =============================================================================
# modules/host/packages.sh — System package installation
# =============================================================================

set -euo pipefail

wpgovern::host::packages::install() {
    wpgovern::bootstrap::log "Installing host packages..."

    # Idempotency: check if all packages already installed
    local required=(
        curl
        gnupg
        ca-certificates
        lsb-release
        jq               # state.sh JSON manipulation
        ufw              # firewall
        fail2ban         # SSH brute-force protection
        logrotate        # log rotation
        apt-transport-https
    )

    local missing=()
    for pkg in "${required[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        wpgovern::bootstrap::log "All host packages already installed — skipping"
        wpgovern::state::set_fact "host.packages_installed" "true"
        return 0
    fi

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${required[@]}"

    wpgovern::state::set_fact "host.packages_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.packages_installed" "true"
    wpgovern::bootstrap::log "Host packages installed"
}
