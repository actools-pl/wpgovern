#!/usr/bin/env bash
# =============================================================================
# modules/stack/credentials.sh — Database credential generation + persistence
#
# H.3.1-1: _wpgovern_credentials_persist moved to core/credentials.sh so it
#          is available across all phase boundaries (cross-phase resumability).
# H.3.1-2: xtrace protection applied at top of credential-sensitive function.
# =============================================================================

set -euo pipefail

wpgovern::stack::credentials::ensure() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2
    # Read env file path — set by bootstrap::load_env (H.2 addition)
    local env_file="${WPGOVERN_ENV_FILE_PATH:-}"

    if [[ -z "$env_file" ]] || [[ ! -f "$env_file" ]]; then
        wpgovern::bootstrap::log "ERROR: env file not found for credential persistence"
        wpgovern::state::mark_phase_failed "stack" "credentials: env file not found"
        return 1
    fi

    # Generate root password if blank
    if [[ -z "${WPGOVERN_DB_ROOT_PASSWORD:-}" ]]; then
        local new_root
        new_root="$(openssl rand -hex 32)"
        export WPGOVERN_DB_ROOT_PASSWORD="$new_root"
        _wpgovern_credentials_persist "$env_file" "WPGOVERN_DB_ROOT_PASSWORD" "$new_root"
        wpgovern::bootstrap::log "Generated WPGOVERN_DB_ROOT_PASSWORD and persisted to env file"
    fi

    # Generate WordPress DB password if blank
    if [[ -z "${WPGOVERN_DB_WP_PASSWORD:-}" ]]; then
        local new_wp
        new_wp="$(openssl rand -hex 32)"
        export WPGOVERN_DB_WP_PASSWORD="$new_wp"
        _wpgovern_credentials_persist "$env_file" "WPGOVERN_DB_WP_PASSWORD" "$new_wp"
        wpgovern::bootstrap::log "Generated WPGOVERN_DB_WP_PASSWORD and persisted to env file"
    fi

    # Enforce 600 perms on env file — it now contains credentials
    chmod 600 "$env_file"

    wpgovern::state::set_fact "stack.credentials.generated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    return 0
}
# Note: _wpgovern_credentials_persist is defined in core/credentials.sh (H.3.1-1)
