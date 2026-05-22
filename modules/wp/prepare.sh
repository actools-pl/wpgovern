#!/usr/bin/env bash
# =============================================================================
# modules/wp/prepare.sh — WordPress directory structure + ownership
#
# NOTE: _WPGOVERN_WP_UID=33 / _WPGOVERN_WP_GID=33 matches www-data in the
# official wordpress:php8.2-fpm and wordpress:apache images. If the upstream
# base image changes, audit these constants.
# =============================================================================

set -euo pipefail

readonly _WPGOVERN_WP_UID=33
readonly _WPGOVERN_WP_GID=33

wpgovern::wp::prepare() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2 discipline

    local wp_dir="${WPGOVERN_INSTALL_DIR}/wordpress"

    # Idempotency: correct ownership → skip
    if [[ -d "$wp_dir" ]]; then
        local current_owner
        current_owner="$(stat -c '%u:%g' "$wp_dir")"
        if [[ "$current_owner" == "${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID}" ]]; then
            wpgovern::bootstrap::log "WordPress directory already prepared — skipping"
            wpgovern::state::set_fact "wp.prepare.completed_at" \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            return 0
        fi
        wpgovern::bootstrap::log "WordPress directory exists with wrong ownership (${current_owner}) — re-chowning"
    fi

    if ! mkdir -p "$wp_dir"; then
        wpgovern::state::mark_phase_failed "wp" "prepare: mkdir failed"
        return 1
    fi

    if ! chown -R "${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID}" "$wp_dir"; then
        wpgovern::state::mark_phase_failed "wp" "prepare: chown failed"
        return 1
    fi

    chmod 755 "$wp_dir"

    wpgovern::state::set_fact "wp.prepare.completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "wp.prepare.uid_gid" "${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID}"
    wpgovern::bootstrap::log "WordPress directory prepared at ${wp_dir} (${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID})"
    return 0
}
