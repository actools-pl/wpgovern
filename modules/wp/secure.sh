#!/usr/bin/env bash
# =============================================================================
# modules/wp/secure.sh — wp-config.php generator
#
# Two functions:
#   ensure_auth_keys  — generate 8 AUTH_KEYs/SALTs if blank, persist to env
#   generate_config   — write deterministic wp-config.php
#
# HEREDOC ESCAPE CONVENTION (required reading):
#   ${WPGOVERN_*}    = bash variable expansion (intentional, produces config values)
#   \$_SERVER        = literal PHP dollar sign (must NOT be expanded by bash)
#   \$table_prefix   = literal PHP dollar sign (must NOT be expanded by bash)
#   The heredoc delimiter CONFIG is UNQUOTED — bash expansion IS active.
#   Every literal $ in PHP source must be \$ in this file.
#   Pre-merge audit: count every $ in the template; classify each.
#
# DETERMINISM CONTRACT:
#   Given stable inputs (WPGOVERN_DOMAIN, all 8 AUTH_KEYs, WPGOVERN_DB_WP_PASSWORD),
#   generate_config MUST produce byte-identical output on every invocation.
#   This is the property H.5's file-hash governance depends on.
#
# ORDERED ITERATION:
#   AUTH_KEYs are declared in an INDEXED array, never an associative array.
#   Bash associative array ordering is implementation-defined — using it would
#   make wp-config.php non-deterministic across systems.
# =============================================================================

set -euo pipefail

# Guard against re-declaration if prepare.sh already sourced these (same session)
[[ -v _WPGOVERN_WP_UID ]] || readonly _WPGOVERN_WP_UID=33
[[ -v _WPGOVERN_WP_GID ]] || readonly _WPGOVERN_WP_GID=33

# Ordered list of AUTH_KEY/SALT names — MUST remain in this exact order
# to preserve deterministic iteration and stable wp-config.php output.
readonly _WPGOVERN_WP_KEY_NAMES=(
    WPGOVERN_WP_AUTH_KEY
    WPGOVERN_WP_SECURE_AUTH_KEY
    WPGOVERN_WP_LOGGED_IN_KEY
    WPGOVERN_WP_NONCE_KEY
    WPGOVERN_WP_AUTH_SALT
    WPGOVERN_WP_SECURE_AUTH_SALT
    WPGOVERN_WP_LOGGED_IN_SALT
    WPGOVERN_WP_NONCE_SALT
)

wpgovern::wp::secure::ensure_auth_keys() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2

    local env_file
    # Prefer exported env var (same run); fall back to state fact (cross-phase)
    env_file="${WPGOVERN_ENV_FILE_PATH:-$(wpgovern::state::get_fact "bootstrap.env_file_path")}"

    if [[ -z "$env_file" || ! -f "$env_file" ]]; then
        wpgovern::bootstrap::log "ERROR: env file not available for AUTH_KEY persistence"
        wpgovern::state::mark_phase_failed "wp" "secure: env file missing for auth keys"
        return 1
    fi

    # Iterate over INDEXED array — deterministic ordering on every system
    local k
    for k in "${_WPGOVERN_WP_KEY_NAMES[@]}"; do
        if [[ -z "${!k:-}" ]]; then
            local new_val
            new_val="$(openssl rand -hex 32)"   # H.3.1-9: pipeline-free, 64 hex chars
            export "${k}=${new_val}"
            _wpgovern_credentials_persist "$env_file" "$k" "$new_val"
            wpgovern::bootstrap::log "Generated ${k} and persisted to env"
        fi
    done

    chmod 600 "$env_file"
    return 0
}

wpgovern::wp::secure::generate_config() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2: AUTH_KEYs + DB password in file

    local target="${WPGOVERN_INSTALL_DIR}/wp-config.php"
    local tmp_file
    tmp_file="$(mktemp "${target}.tmp.XXXXXX")"

    # Write to tmp file; on failure clean up and return
    if ! _wpgovern_wp_write_config "$tmp_file"; then
        rm -f "$tmp_file"
        wpgovern::state::mark_phase_failed "wp" "secure: wp-config.php write failed"
        return 1
    fi

    if ! chmod 640 "$tmp_file"; then
        rm -f "$tmp_file"
        wpgovern::state::mark_phase_failed "wp" "secure: chmod 640 on wp-config.php temp failed"
        return 1
    fi

    if ! chown "${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID}" "$tmp_file"; then
        rm -f "$tmp_file"
        wpgovern::state::mark_phase_failed "wp" \
            "secure: chown ${_WPGOVERN_WP_UID}:${_WPGOVERN_WP_GID} on wp-config.php temp failed"
        return 1
    fi

    # Guard: target must not be a directory (mv would silently move INTO it)
    if [[ -d "$target" ]]; then
        rm -f "$tmp_file"
        wpgovern::state::mark_phase_failed "wp" \
            "secure: wp-config.php target path is a directory: $target"
        return 1
    fi

    if ! mv "$tmp_file" "$target"; then
        rm -f "$tmp_file"
        wpgovern::state::mark_phase_failed "wp" "secure: mv to ${target} failed"
        return 1
    fi

    # Record hash for downstream governance (H.5 will sign this)
    local config_hash
    config_hash="$(sha256sum "$target" | awk '{print $1}')"
    wpgovern::state::set_fact "wp.secure.config_hash" "$config_hash"
    wpgovern::state::set_fact "wp.secure.config_path" "$target"
    wpgovern::state::set_fact "wp.secure.generated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Log only hash prefix — never the config content
    wpgovern::bootstrap::log "wp-config.php generated at ${target} (sha256: ${config_hash:0:16}...)"
    return 0
}

# Write wp-config.php content to the target file.
# Separated into its own function so generate_config can clean up $tmp_file on failure.
#
# HEREDOC ESCAPE AUDIT — every $ classified:
#   ${WPGOVERN_DB_WP_PASSWORD}   ← bash expansion (DB password value)
#   ${WPGOVERN_WP_AUTH_KEY}      ← bash expansion (AUTH_KEY value)
#   ... (all 8 AUTH_KEYs)        ← bash expansion
#   ${WPGOVERN_DOMAIN}           ← bash expansion (domain value)
#   \$_SERVER                    ← literal PHP $ (escaped)
#   \$table_prefix               ← literal PHP $ (escaped)
#   __DIR__                      ← PHP constant, no $ involved
#   Total bash $ expansions: 11 (1 DB pw + 8 AUTH_KEYs + 2 domain refs)
#   Total escaped \$ for PHP: 3 (\$_SERVER ×2, \$table_prefix ×1)
_wpgovern_wp_write_config() {
    local out="$1"

    cat > "$out" << CONFIG
<?php
/**
 * wp-config.php — generated by WPGovern installer H.4.
 * DO NOT EDIT — file-hash governed by WPGovern from H.5 onward.
 * Re-run wpgovern-install.sh to regenerate.
 */

// Database
define( 'DB_NAME',     'wordpress' );
define( 'DB_USER',     'wpuser' );
define( 'DB_PASSWORD', '${WPGOVERN_DB_WP_PASSWORD}' );
define( 'DB_HOST',     'mariadb' );
define( 'DB_CHARSET',  'utf8mb4' );
define( 'DB_COLLATE',  '' );

// Authentication keys and salts (generated once, persisted to env file)
define( 'AUTH_KEY',         '${WPGOVERN_WP_AUTH_KEY}' );
define( 'SECURE_AUTH_KEY',  '${WPGOVERN_WP_SECURE_AUTH_KEY}' );
define( 'LOGGED_IN_KEY',    '${WPGOVERN_WP_LOGGED_IN_KEY}' );
define( 'NONCE_KEY',        '${WPGOVERN_WP_NONCE_KEY}' );
define( 'AUTH_SALT',        '${WPGOVERN_WP_AUTH_SALT}' );
define( 'SECURE_AUTH_SALT', '${WPGOVERN_WP_SECURE_AUTH_SALT}' );
define( 'LOGGED_IN_SALT',   '${WPGOVERN_WP_LOGGED_IN_SALT}' );
define( 'NONCE_SALT',       '${WPGOVERN_WP_NONCE_SALT}' );

// Hardening
define( 'DISALLOW_FILE_EDIT',  true );
define( 'DISALLOW_FILE_MODS',  false );
define( 'WP_DEBUG',            false );
define( 'WP_DEBUG_LOG',        false );
define( 'WP_DEBUG_DISPLAY',    false );
define( 'WP_AUTO_UPDATE_CORE', 'minor' );
define( 'FORCE_SSL_ADMIN',     true );

// Secure cookies (HTTPS only)
define( 'COOKIE_SECURE',    true );
define( 'COOKIE_HTTPONLY',  true );

// Trusted host validation
\$_SERVER['HTTP_HOST']   = isset( \$_SERVER['HTTP_HOST'] )   ? \$_SERVER['HTTP_HOST']   : '${WPGOVERN_DOMAIN}';
\$_SERVER['SERVER_NAME'] = isset( \$_SERVER['SERVER_NAME'] ) ? \$_SERVER['SERVER_NAME'] : '${WPGOVERN_DOMAIN}';

// Table prefix
\$table_prefix = 'wp_';

// WordPress paths
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
CONFIG
}
