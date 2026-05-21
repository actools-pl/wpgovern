#!/usr/bin/env bash
# =============================================================================
# modules/db/credentials.sh — Backup credential generation + age-encrypted state
#
# Three functions:
#   ensure_backup_password — generate WPGOVERN_DB_BACKUP_PASSWORD if blank
#   generate_age_key       — generate/enforce age key with 600 perms
#   encrypt_state          — encrypt all three DB passwords via age
#
# Credentials discipline: $payload is NEVER logged. The variable is only
# ever piped to `age` stdin and then discarded.
# =============================================================================

set -euo pipefail

wpgovern::db::credentials::ensure_backup_password() {
    if [[ -n "${WPGOVERN_DB_BACKUP_PASSWORD:-}" ]]; then
        wpgovern::bootstrap::log "WPGOVERN_DB_BACKUP_PASSWORD already set — skipping generation"
        return 0
    fi

    local env_file
    # Prefer exported env var (same run); fall back to state fact (cross-phase)
    env_file="${WPGOVERN_ENV_FILE_PATH:-$(wpgovern::state::get_fact "bootstrap.env_file_path")}"

    if [[ -z "$env_file" || ! -f "$env_file" ]]; then
        wpgovern::bootstrap::log "ERROR: env file not available for credential persistence"
        wpgovern::state::mark_phase_failed "db" "credentials: env file missing for backup password"
        return 1
    fi

    local new_pw
    new_pw="$(openssl rand -base64 32 | tr -d '/=+' | head -c 32)"
    export WPGOVERN_DB_BACKUP_PASSWORD="$new_pw"

    # Reuse the persistence helper from modules/stack/credentials.sh
    # (already sourced in entry script before db phase)
    _wpgovern_credentials_persist "$env_file" "WPGOVERN_DB_BACKUP_PASSWORD" "$new_pw"
    chmod 600 "$env_file"

    wpgovern::bootstrap::log "Generated WPGOVERN_DB_BACKUP_PASSWORD and persisted to env file"
    return 0
}

wpgovern::db::credentials::generate_age_key() {
    local key_path="${WPGOVERN_INSTALL_DIR}/.wpgovern-age.key"

    if [[ -f "$key_path" ]]; then
        # Enforce 600 perms on every run — restores if operator or restore left it readable
        chmod 600 "$key_path"
        wpgovern::bootstrap::log "age key already exists — enforced 600 perms"
        wpgovern::state::set_fact "db.credentials.age_key_path" "$key_path"
        return 0
    fi

    if ! age-keygen -o "$key_path" 2>/dev/null; then
        wpgovern::bootstrap::log "ERROR: age-keygen failed"
        wpgovern::state::mark_phase_failed "db" "credentials: age-keygen failed"
        return 1
    fi
    chmod 600 "$key_path"

    wpgovern::state::set_fact "db.credentials.age_key_path" "$key_path"
    wpgovern::state::set_fact "db.credentials.age_key_generated_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "age key generated at ${key_path}"
    return 0
}

wpgovern::db::credentials::encrypt_state() {
    local encrypted_path="${WPGOVERN_INSTALL_DIR}/.wpgovern-credentials.age"
    local key_path
    key_path="$(wpgovern::state::get_fact "db.credentials.age_key_path")"

    if [[ -z "$key_path" || ! -f "$key_path" ]]; then
        wpgovern::bootstrap::log "ERROR: age key not found — run generate_age_key first"
        wpgovern::state::mark_phase_failed "db" "credentials: age key missing for encryption"
        return 1
    fi

    # Extract public-key recipient from key file header
    # age-keygen writes "# public key: age1..." as a comment on the first line
    # errexit-safe: grep || true because first run file may exist without comment
    local recipient
    recipient="$(grep -oE 'age1[a-z0-9]+' "$key_path" | head -1 || true)"
    if [[ -z "$recipient" ]]; then
        wpgovern::bootstrap::log "ERROR: could not extract age public key recipient from ${key_path}"
        wpgovern::state::mark_phase_failed "db" "credentials: recipient extraction failed"
        return 1
    fi

    # Build plaintext payload — NEVER LOG THIS VARIABLE
    # Only piped to age stdin; never echoed, never stored unencrypted beyond this scope
    local payload
    payload="$(printf 'WPGOVERN_DB_ROOT_PASSWORD=%s\nWPGOVERN_DB_WP_PASSWORD=%s\nWPGOVERN_DB_BACKUP_PASSWORD=%s\n' \
        "${WPGOVERN_DB_ROOT_PASSWORD}" \
        "${WPGOVERN_DB_WP_PASSWORD}" \
        "${WPGOVERN_DB_BACKUP_PASSWORD}")"

    local tmp_file
    tmp_file="$(mktemp "${encrypted_path}.tmp.XXXXXX")"

    # H.2.1-4 lesson: explicit cleanup on failure
    if ! printf '%s\n' "$payload" | age -r "$recipient" -o "$tmp_file" 2>/dev/null; then
        rm -f "$tmp_file"
        wpgovern::bootstrap::log "ERROR: age encryption failed"
        wpgovern::state::mark_phase_failed "db" "credentials: age encryption failed"
        return 1
    fi

    chmod 600 "$tmp_file"
    mv "$tmp_file" "$encrypted_path"
    chmod 600 "$encrypted_path"

    wpgovern::state::set_fact "db.credentials.encrypted_path" "$encrypted_path"
    wpgovern::state::set_fact "db.credentials.encrypted_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Log ONLY the path — never the content
    wpgovern::bootstrap::log "Credentials encrypted to ${encrypted_path}"
    return 0
}
