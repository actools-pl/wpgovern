#!/usr/bin/env bash
# =============================================================================
# modules/host/swap.sh — Swap file creation
#
# Creates a 2GB swap file at /swapfile on CX22 (4GB RAM).
# Skips if /swapfile already exists (idempotent).
# =============================================================================

set -euo pipefail

wpgovern::host::swap::create() {
    local swapfile="/swapfile"
    local swap_size_mb="${WPGOVERN_SWAP_SIZE_MB:-2048}"

    # Idempotency: skip if swap already configured
    if swapon --show 2>/dev/null | grep -q "^${swapfile}"; then
        wpgovern::bootstrap::log "Swap already active at ${swapfile} — skipping"
        wpgovern::state::set_fact "host.swap_configured" "true"
        return 0
    fi

    if [[ -f "$swapfile" ]]; then
        wpgovern::bootstrap::log "Swap file exists but not active — enabling"
        chmod 600 "$swapfile"
        swapon "$swapfile"
        _wpgovern_swap_persist "$swapfile"
        wpgovern::state::set_fact "host.swap_configured" "true"
        wpgovern::state::set_fact "host.swap_size_mb" "$swap_size_mb"
        return 0
    fi

    wpgovern::bootstrap::log "Creating ${swap_size_mb}MB swap file at ${swapfile}..."

    fallocate -l "${swap_size_mb}M" "$swapfile"
    chmod 600 "$swapfile"
    mkswap "$swapfile" > /dev/null
    swapon "$swapfile"
    _wpgovern_swap_persist "$swapfile"

    wpgovern::state::set_fact "host.swap_created_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.swap_size_mb" "$swap_size_mb"
    wpgovern::state::set_fact "host.swap_configured" "true"
    wpgovern::bootstrap::log "Swap configured (${swap_size_mb}MB)"
}

_wpgovern_swap_persist() {
    local swapfile="$1"
    # Add to fstab if not already present (survive reboots)
    if ! grep -q "^${swapfile}" /etc/fstab 2>/dev/null; then
        echo "${swapfile} none swap sw 0 0" >> /etc/fstab
    fi
}
