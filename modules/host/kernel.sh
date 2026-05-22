#!/usr/bin/env bash
# =============================================================================
# modules/host/kernel.sh — Kernel parameter tuning
#
# sysctl settings tuned for the Caddy + MariaDB + WordPress workload on CX22.
# Parameters:
#   vm.swappiness=10          Prefer RAM, use swap only under pressure
#   vm.overcommit_memory=1    Allow Redis (used in H.2) to fork safely
#   fs.file-max=131072        High file descriptor limit for web workload
#   net.ipv4.ip_local_port_range  Widen ephemeral port range
#   net.core.somaxconn=1024   Larger listen backlog for Caddy
#   net.ipv4.tcp_tw_reuse=1   Reuse TIME_WAIT sockets (outbound connections)
# =============================================================================

set -euo pipefail

wpgovern::host::kernel::tune() {
    local sysctl_conf="/etc/sysctl.d/99-wpgovern.conf"

    # Idempotency: if config file already exists with our marker, skip
    if [[ -f "$sysctl_conf" ]] && grep -q "wpgovern" "$sysctl_conf" 2>/dev/null; then
        wpgovern::bootstrap::log "Kernel parameters already configured — skipping"
        wpgovern::state::set_fact "host.kernel_tuned" "true"
        return 0
    fi

    wpgovern::bootstrap::log "Applying kernel parameters..."

    cat > "$sysctl_conf" <<'SYSCTL'
# wpgovern: kernel tuning for Caddy + MariaDB + WordPress workload (CX22)
vm.swappiness = 10
vm.overcommit_memory = 1
fs.file-max = 131072
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 1024
net.ipv4.tcp_tw_reuse = 1
SYSCTL

    sysctl -p "$sysctl_conf" > /dev/null

    wpgovern::state::set_fact "host.kernel_tuned_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.kernel_tuned" "true"
    wpgovern::bootstrap::log "Kernel parameters applied"
}
