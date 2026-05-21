#!/usr/bin/env bash
# =============================================================================
# modules/stack/images.sh — Docker image digest pinning
#
# H.2.1-5: digest extraction is now errexit-safe (|| true on grep).
# H.2.1-8: persisted digests are validated before reuse.
# =============================================================================

set -euo pipefail

# H.2.1-5 + H.2.1-8: shared digest validator — single source of truth.
_wpgovern_is_valid_digest() {
    local digest="$1"
    [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
}

wpgovern::stack::images::pin() {
    # Image list: name:tag pairs to pull and pin
    local images=("caddy:2" "mariadb:10.11" "wordpress:6.5-php8.2-fpm" "wordpress:6.5-apache")
    # State fact key suffixes corresponding to each image
    local fact_names=("caddy" "mariadb" "php" "wordpress")

    local i
    for i in "${!images[@]}"; do
        local image="${images[$i]}"
        local fact_name="${fact_names[$i]}"
        local fact_key="stack.images.${fact_name}_digest"

        # H.2.1-8: validate persisted digest format before trusting it
        local existing_digest
        existing_digest="$(wpgovern::state::get_fact "$fact_key")"
        if [[ -n "$existing_digest" ]]; then
            if ! _wpgovern_is_valid_digest "$existing_digest"; then
                wpgovern::bootstrap::log "ERROR: persisted digest for ${image} is malformed: ${existing_digest}"
                wpgovern::state::mark_phase_failed "stack" \
                    "persisted digest invalid: ${image} (got: ${existing_digest})"
                return 1
            fi
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

        # Failure path 2: docker inspect command fails
        local raw_digest
        if ! raw_digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null)"; then
            wpgovern::bootstrap::log "ERROR: docker inspect failed for ${image}"
            wpgovern::state::mark_phase_failed "stack" "image inspect failed: ${image}"
            return 1
        fi

        # H.2.1-5: errexit-safe extraction — || true prevents pipefail from
        # aborting before the emptiness check (same defect class as v53.2 GPG fix)
        local extracted
        extracted="$(printf '%s\n' "$raw_digest" | grep -oE 'sha256:[a-f0-9]{64}' || true)"

        # Failure path 3: digest format doesn't match sha256:<64-hex>
        if [[ -z "$extracted" ]]; then
            wpgovern::bootstrap::log "ERROR: unexpected digest format for ${image}: ${raw_digest}"
            wpgovern::state::mark_phase_failed "stack" \
                "digest format unexpected: ${image} (got: ${raw_digest})"
            return 1
        fi

        wpgovern::state::set_fact "$fact_key" "$extracted"
        wpgovern::bootstrap::log "Pinned ${image} @ ${extracted}"
    done

    wpgovern::state::set_fact "stack.images.pinned_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Image digest pinning complete"
    return 0
}
