#!/usr/bin/env bash
# =============================================================================
# modules/host/docker.sh — Docker CE + Compose plugin installation
#
# H.1.1-4: Verifies Docker GPG key fingerprint before installing.
#          Fails closed on mismatch — refuses to add a repo with unverified key.
# =============================================================================

set -euo pipefail

# Docker apt repo signing key fingerprint, published at:
# https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository
readonly _DOCKER_GPG_EXPECTED_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

wpgovern::host::docker::install() {
    if command -v docker &>/dev/null && docker compose version &>/dev/null; then
        local docker_version
        docker_version="$(docker --version 2>/dev/null | head -1)"
        wpgovern::bootstrap::log "Docker already installed (${docker_version}) — skipping"
        wpgovern::state::set_fact "host.docker_installed" "true"
        return 0
    fi

    wpgovern::bootstrap::log "Installing Docker CE from official repository..."

    # H.1.1-4: Download GPG key to temp, verify fingerprint, then install
    install -m 0755 -d /etc/apt/keyrings
    local tmp_key
    tmp_key="$(mktemp /tmp/wpgovern-docker-gpg.XXXXXX)"
    # shellcheck disable=SC2064
    trap "rm -f '${tmp_key}'" RETURN

    if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$tmp_key"; then
        wpgovern::bootstrap::log "ERROR: failed to download Docker GPG key"
        wpgovern::state::mark_phase_failed "host" "docker gpg download failed"
        return 1
    fi

    # H.1.2-3: guard fingerprint extraction explicitly.
    # Three failure paths, each records state honestly before returning 1.
    # Without this guard, gpg non-zero exit under pipefail aborts the function
    # before reaching mark_phase_failed — state machine never learns host failed.
    local actual_fpr
    if ! actual_fpr="$(gpg --show-keys --with-colons "$tmp_key" 2>/dev/null \
                       | awk -F: '/^fpr:/ {print $10; exit}')"; then
        wpgovern::bootstrap::log "ERROR: Docker GPG key is not parseable"
        wpgovern::state::mark_phase_failed "host" "docker gpg key parse failed"
        return 1
    fi

    if [[ -z "$actual_fpr" ]]; then
        wpgovern::bootstrap::log "ERROR: Docker GPG key has no fingerprint"
        wpgovern::state::mark_phase_failed "host" "docker gpg fingerprint missing"
        return 1
    fi

    if [[ "$actual_fpr" != "$_DOCKER_GPG_EXPECTED_FPR" ]]; then
        wpgovern::bootstrap::log "ERROR: Docker GPG fingerprint mismatch"
        wpgovern::bootstrap::log "  expected: ${_DOCKER_GPG_EXPECTED_FPR}"
        wpgovern::bootstrap::log "  actual:   ${actual_fpr}"
        wpgovern::state::mark_phase_failed "host" "docker gpg fingerprint mismatch"
        return 1
    fi

    install -m 0644 "$tmp_key" /etc/apt/keyrings/docker.asc

    # Add Docker apt repository
    local codename
    # shellcheck disable=SC1091
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu ${codename} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    if ! docker compose version &>/dev/null; then
        wpgovern::bootstrap::log "ERROR: docker compose version check failed after install"
        wpgovern::state::mark_phase_failed "host" "docker compose plugin not functional"
        return 1
    fi

    systemctl enable docker > /dev/null
    systemctl start docker

    local docker_version compose_version
    docker_version="$(docker --version 2>/dev/null | head -1)"
    compose_version="$(docker compose version 2>/dev/null | head -1)"

    wpgovern::state::set_fact "host.docker_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.docker_version" "$docker_version"
    wpgovern::state::set_fact "host.compose_version" "$compose_version"
    wpgovern::state::set_fact "host.docker.gpg_fingerprint" "$actual_fpr"
    wpgovern::state::set_fact "host.docker_installed" "true"
    wpgovern::bootstrap::log "Docker installed: ${docker_version}"
    wpgovern::bootstrap::log "Compose plugin: ${compose_version}"
}
