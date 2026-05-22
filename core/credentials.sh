#!/usr/bin/env bash
# =============================================================================
# core/credentials.sh — Shared credential helpers
#
# Sourced unconditionally early in wpgovern-install.sh so all phases can use
# these helpers regardless of which prior phases have run.
#
# H.3.1-1: _wpgovern_credentials_persist extracted from modules/stack/credentials.sh
#          so it's available across ALL phase boundaries (cross-phase resumability).
#
# H.3.1-2: _wpgovern_disable_xtrace_for_credentials applied at top of every
#          credential-sensitive function to prevent bash -x / xtrace leaks.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# H.3.1-2: xtrace protection helper
#   Applied at the top of every function that handles plaintext credentials.
#   Fail-soft: warn + disable (don't fail-closed; operator may need bash -x).
#   Deliberately does NOT restore xtrace — re-enabling mid-installer would
#   re-expose later credential-sensitive function calls.
# ---------------------------------------------------------------------------
_wpgovern_disable_xtrace_for_credentials() {
    case "$-" in
        *x*)
            wpgovern::bootstrap::log \
                "WARNING: xtrace/debug mode was active; disabling for credential-sensitive operations"
            set +x
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# H.3.1-1: shared credential persistence helper
#   Persist or update an env-file entry in-place.
#   Used by both modules/stack/credentials.sh (H.2) and
#   modules/db/credentials.sh (H.3) across all phase boundaries.
# ---------------------------------------------------------------------------
_wpgovern_credentials_persist() {
    local env_file="$1"
    local key="$2"
    local value="$3"

    if [[ -z "$env_file" ]] || [[ ! -f "$env_file" ]]; then
        wpgovern::bootstrap::log \
            "ERROR: _wpgovern_credentials_persist: env file not found: '${env_file}'"
        return 1
    fi

    # If key exists in file (commented or not), uncomment and update in-place
    if grep -qE "^#?\s*${key}=" "$env_file"; then
        sed -i "s|^#\?\s*${key}=.*|${key}=\"${value}\"|" "$env_file"
    else
        printf '%s="%s"\n' "$key" "$value" >> "$env_file"
    fi
}
