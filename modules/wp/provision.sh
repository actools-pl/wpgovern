#!/usr/bin/env bash
# =============================================================================
# modules/wp/provision.sh — wp-cli core install orchestration
#
# Invokes wp-cli via the profile-gated cli service in docker compose.
# Idempotent: skips if WordPress already installed.
#
# Credentials discipline: >/dev/null 2>&1 on every wp-cli invocation.
# Admin password is on the command line; xtrace would leak it.
# =============================================================================

set -euo pipefail

wpgovern::wp::provision() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2: admin password on command line

    # Idempotency: if WordPress is already installed, skip
    if docker compose --profile cli run --rm cli wp core is-installed \
        >/dev/null 2>&1; then
        wpgovern::bootstrap::log "WordPress already installed — skipping provision"
        wpgovern::state::set_fact "wp.provision.skipped_at" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    fi

    # Validate required env vars
    local v
    for v in WPGOVERN_WP_ADMIN_USER WPGOVERN_WP_ADMIN_PASSWORD \
              WPGOVERN_WP_ADMIN_EMAIL WPGOVERN_DOMAIN; do
        if [[ -z "${!v:-}" ]]; then
            wpgovern::bootstrap::log "ERROR: ${v} is required for WordPress provisioning"
            wpgovern::state::mark_phase_failed "wp" "provision: ${v} not set"
            return 1
        fi
    done

    local site_title="${WPGOVERN_WP_SITE_TITLE:-WPGovern Site}"

    # >/dev/null 2>&1 MANDATORY — admin password is on command line
    # --skip-email: prevents wp-cli from attempting SMTP (not configured at this stage)
    if ! docker compose --profile cli run --rm cli wp core install \
        --url="https://${WPGOVERN_DOMAIN}" \
        --title="${site_title}" \
        --admin_user="${WPGOVERN_WP_ADMIN_USER}" \
        --admin_password="${WPGOVERN_WP_ADMIN_PASSWORD}" \
        --admin_email="${WPGOVERN_WP_ADMIN_EMAIL}" \
        --skip-email \
        >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "wp" "provision: wp-cli core install failed"
        return 1
    fi

    wpgovern::state::set_fact "wp.provision.installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "WordPress core installed for ${WPGOVERN_DOMAIN}"
    return 0
}
