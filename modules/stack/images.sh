#!/usr/bin/env bash
# =============================================================================
# modules/stack/images.sh — Docker image digest pinning
#
# Pulls each base image once, captures SHA-256 digest, persists to state.
# Idempotent: re-running with persisted digests uses those digests rather
# than re-pulling. Protects against Docker Hub silently changing the digest
# for a tag between runs.
#
# Three failure paths, each records state honestly (H.1.1-1 + H.1.2-3 lesson):
#   1. docker pull fails → mark_phase_failed "image pull failed: ..."
#   2. docker inspect fails → mark_phase_failed "image inspect failed: ..."
#   3. digest format unexpected → mark_phase_failed "digest format unexpected: ..."
# =============================================================================

set -euo pipefail

wpgovern::stack::images::pin() {
    # Image list: name:tag pairs to pull and pin
    local images=("caddy:2" "mariadb:10.11" "wordpress:6.5-php8.2-fpm")
    # State fact key suffixes corresponding to each image
    local fact_names=("caddy" "mariadb" "php")

    local i
    for i in "${!images[@]}"; do
        local image="${images[$i]}"
        local fact_name="${fact_names[$i]}"
        local fact_key="stack.images.${fact_name}_digest"

        # Idempotency: persisted digest wins — no re-pull on subsequent runs
        local existing_digest
        existing_digest="$(wpgovern::state::get_fact "$fact_key")"
        if [[ -n "$existing_digest" ]]; then
            wpgovern::bootstrap::log "Using persisted digest for ${image}: ${existing_digest}"
            continue
        fi

        # Failure path 1: docker pull fails
        wpgovern::bootstrap::log "Pulling ${image} to capture digest..."
        if ! docker pull "$image" >/dev/null 2>&1; then
            wpgovern::bootstrap::log "ERROR: docker pull failed for ${image}"
            wpgovern::state::mark_phase_failed "stack" "image pull failed: ${image}"
            return 1
        fi

        # Failure path 2: docker inspect / digest extraction command fails
        local raw_digest
        if ! raw_digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null)"; then
            wpgovern::bootstrap::log "ERROR: docker inspect failed for ${image}"
            wpgovern::state::mark_phase_failed "stack" "image inspect failed: ${image}"
            return 1
        fi

        # Failure path 3: digest doesn't match sha256:<64-hex> format
        local extracted
        extracted="$(echo "$raw_digest" | grep -oE 'sha256:[a-f0-9]{64}')"
        if [[ -z "$extracted" ]]; then
            wpgovern::bootstrap::log "ERROR: unexpected digest format for ${image}: ${raw_digest}"
            wpgovern::state::mark_phase_failed "stack" "digest format unexpected: ${image} (got: ${raw_digest})"
            return 1
        fi

        wpgovern::state::set_fact "$fact_key" "$extracted"
        wpgovern::bootstrap::log "Pinned ${image} @ ${extracted}"
    done

    wpgovern::state::set_fact "stack.images.pinned_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Image digest pinning complete"
    return 0
}
