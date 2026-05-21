#!/usr/bin/env bash
# =============================================================================
# modules/stack/credentials.sh — Database credential generation + persistence
#
# Generates WPGOVERN_DB_ROOT_PASSWORD and WPGOVERN_DB_WP_PASSWORD if blank.
# Persists generated values back to the env file so subsequent runs read them
# instead of regenerating — determinism property for credentials.
#
# Enforces chmod 600 on env file after credential write.
# =============================================================================

set -euo pipefail

wpgovern::stack::credentials::ensure() {
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
        new_root="$(openssl rand -base64 32 | tr -d '/=+' | head -c 32)"
        export WPGOVERN_DB_ROOT_PASSWORD="$new_root"
        _wpgovern_credentials_persist "$env_file" "WPGOVERN_DB_ROOT_PASSWORD" "$new_root"
        wpgovern::bootstrap::log "Generated WPGOVERN_DB_ROOT_PASSWORD and persisted to env file"
    fi

    # Generate WordPress DB password if blank
    if [[ -z "${WPGOVERN_DB_WP_PASSWORD:-}" ]]; then
        local new_wp
        new_wp="$(openssl rand -base64 32 | tr -d '/=+' | head -c 32)"
        export WPGOVERN_DB_WP_PASSWORD="$new_wp"
        _wpgovern_credentials_persist "$env_file" "WPGOVERN_DB_WP_PASSWORD" "$new_wp"
        wpgovern::bootstrap::log "Generated WPGOVERN_DB_WP_PASSWORD and persisted to env file"
    fi

    # Enforce 600 perms on env file — it now contains credentials
    chmod 600 "$env_file"

    wpgovern::state::set_fact "stack.credentials.generated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    return 0
}

_wpgovern_credentials_persist() {
    local env_file="$1"
    local key="$2"
    local value="$3"

    # If key exists in file (commented or not), replace it; otherwise append
    if grep -qE "^#?\s*${key}=" "$env_file"; then
        sed -i "s|^#\?\s*${key}=.*|${key}=\"${value}\"|" "$env_file"
    else
        printf '\n%s="%s"\n' "$key" "$value" >> "$env_file"
    fi
}
