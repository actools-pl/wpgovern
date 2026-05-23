#!/usr/bin/env bash
# =============================================================================
# core/bootstrap.sh — WPGovern Installer Bootstrap
#
# H.1.1-10: load_env now uses a whitelist parser instead of `source`.
# Rejects unknown keys, shell metacharacters in values, and malformed lines.
# =============================================================================

set -euo pipefail

# Whitelist of permitted env var names (H.1.1-10)
_WPGOVERN_ENV_ALLOWED=(
    WPGOVERN_INSTALL_DIR
    WPGOVERN_LOG_DIR
    WPGOVERN_STATE_FILE
    WPGOVERN_OPERATOR_EMAIL
    WPGOVERN_SWAP_SIZE_MB
    WPGOVERN_SSH_PORT
    # H.1.2-1: WPGOVERN_FORCE_FIREWALL is CLI-only — not permitted in env file
    WPGOVERN_DOMAIN              # H.2: domain for HTTPS + Caddyfile
    WPGOVERN_LE_EMAIL            # H.2: Let's Encrypt registration email
    WPGOVERN_DB_ROOT_PASSWORD    # H.2: MariaDB root password (generated if blank)
    WPGOVERN_DB_WP_PASSWORD      # H.2: WordPress DB user password (generated if blank)
    WPGOVERN_DB_BACKUP_PASSWORD  # H.3: backup DB user password (generated if blank)
    # H.4: WordPress provisioning
    WPGOVERN_WP_ADMIN_USER       # H.4: WordPress admin username (required)
    WPGOVERN_WP_ADMIN_PASSWORD   # H.4: WordPress admin password (required)
    WPGOVERN_WP_ADMIN_EMAIL      # H.4: WordPress admin email (required)
    WPGOVERN_WP_SITE_TITLE       # H.4: WordPress site title (default: WPGovern Site)
    # H.4: Authentication keys and salts (generated if blank, persisted)
    WPGOVERN_WP_AUTH_KEY
    WPGOVERN_WP_SECURE_AUTH_KEY
    WPGOVERN_WP_LOGGED_IN_KEY
    WPGOVERN_WP_NONCE_KEY
    WPGOVERN_WP_AUTH_SALT
    WPGOVERN_WP_SECURE_AUTH_SALT
    WPGOVERN_WP_LOGGED_IN_SALT
    WPGOVERN_WP_NONCE_SALT
    # H.5: byte-one ceremony identity
    WPGOVERN_ACTOR_ID            # governance actor identity (default: installer)
    WPGOVERN_CEREMONY_REASON     # governance reason for bootstrap (default: byte-one bootstrap)
)

wpgovern::bootstrap::load_env() {
    # H.4.1-2: protect against credential leakage under xtrace/debug mode.
    # load_env parses env-file lines which include passwords and AUTH_KEYs.
    # Under bash -x, those assignments print to stderr before core/credentials.sh
    # is sourced — so _wpgovern_disable_xtrace_for_credentials is unavailable.
    # This inline guard protects all callers regardless of source order.
    case "$-" in
        *x*)
            echo "WARNING: xtrace/debug mode was active; disabling for credential-sensitive env parsing" >&2
            set +x
            ;;
    esac
    local env_file="$1"

    if [[ ! -f "$env_file" ]]; then
        echo "ERROR: environment file not found: $env_file" >&2
        echo "Copy wpgovern.env.example to wpgovern.env and edit it." >&2
        return 1
    fi

    # Parse line by line — refuse shell metacharacters and unknown keys
    local line key value line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))

        # Strip leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        # Skip blank lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Must match KEY=VALUE pattern
        if [[ ! "$line" =~ ^[A-Z_][A-Z0-9_]*=.*$ ]]; then
            echo "ERROR: ${env_file}:${line_num}: invalid line format (expected KEY=VALUE)" >&2
            return 1
        fi

        key="${line%%=*}"
        value="${line#*=}"

        # Strip optional surrounding quotes from value
        if [[ "$value" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi

        # Refuse values containing shell metacharacters or whitespace (injection prevention)
        # H.4 + H.5.1-3: allow whitespace for human-readable values
        # Exception covers site title (H.4) and ceremony reason (H.5) — both are
        # human-readable strings that legitimately contain spaces.
        local space_check_value="$value"
        if [[ "$key" == "WPGOVERN_WP_SITE_TITLE" || "$key" == "WPGOVERN_CEREMONY_REASON" ]]; then
            space_check_value="${value// /}"  # remove spaces before metacharacter check
        fi
        if [[ "$space_check_value" =~ [\`\$\;\|\&\<\>[:space:]] ]]; then
            echo "ERROR: ${env_file}:${line_num}: value for $key contains shell metacharacters" >&2
            return 1
        fi

        # Check key is in allowlist
        local found=0
        for allowed_key in "${_WPGOVERN_ENV_ALLOWED[@]}"; do
            if [[ "$key" == "$allowed_key" ]]; then
                found=1
                break
            fi
        done
        if [[ "$found" -ne 1 ]]; then
            echo "ERROR: ${env_file}:${line_num}: unknown key '$key'" >&2
            echo "  Allowed keys: ${_WPGOVERN_ENV_ALLOWED[*]}" >&2
            return 1
        fi

        # Export the validated key/value
        export "$key=$value"
    done < "$env_file"

    # Apply defaults for unset optional variables
    # H.5.1-4: default must match Python control plane's hardcoded install_dir.
    # byte_one() validates WPGOVERN_INSTALL_DIR == /opt/wpgovern-install at entry.
    export WPGOVERN_INSTALL_DIR="${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}"
    export WPGOVERN_LOG_DIR="${WPGOVERN_LOG_DIR:-/var/log/wpgovern-installer}"
    export WPGOVERN_STATE_FILE="${WPGOVERN_STATE_FILE:-${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json}"
    export WPGOVERN_OPERATOR_EMAIL="${WPGOVERN_OPERATOR_EMAIL:-}"

    # Ensure log dir and install dir exist
    mkdir -p "$WPGOVERN_LOG_DIR"
    mkdir -p "$WPGOVERN_INSTALL_DIR"

    # H.2: record absolute env file path so credentials.sh can persist generated passwords
    export WPGOVERN_ENV_FILE_PATH
    WPGOVERN_ENV_FILE_PATH="$(cd "$(dirname "$env_file")" && pwd)/$(basename "$env_file")"
    # H.3: also persist to state fact so db/credentials.sh can find it after phase boundary
    # Note: state is not yet initialized at load_env time; the fact is recorded in entry script
    # The path is exported as WPGOVERN_ENV_FILE_PATH for direct use by credentials.sh
}


# ---------------------------------------------------------------------------
# H.6.2-3: Read-only env loader for diagnostic commands (wpgovern-install-audit).
# Parses env vars from file and exports them WITHOUT creating directories or
# running strict regex validation. The installer already validated at install
# time; the audit just needs the values for probes to use.
# Does NOT call mkdir_p on WPGOVERN_LOG_DIR / WPGOVERN_INSTALL_DIR.
# Does NOT run the allowlist/metacharacter validation in load_env.
# Has xtrace guard (Lesson 2 sixth refinement: every credential-reading
# function protects itself at entry; does not rely on caller's guard).
# ---------------------------------------------------------------------------
wpgovern::bootstrap::load_env_readonly() {
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac
    local env_file="$1"
    if [[ ! -f "$env_file" ]]; then
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
            local _key="${BASH_REMATCH[1]}"
            local _val="${BASH_REMATCH[2]}"
            # Strip surrounding quotes if present
            _val="${_val#\"}"
            _val="${_val%\"}"
            export "${_key}=${_val}"
        fi
    done < "$env_file"
    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}

wpgovern::bootstrap::validate_env() {
    local errors=()

    if [[ -z "${WPGOVERN_INSTALL_DIR:-}" ]]; then
        errors+=("WPGOVERN_INSTALL_DIR is required")
    fi
    if [[ -z "${WPGOVERN_OPERATOR_EMAIL:-}" ]]; then
        errors+=("WPGOVERN_OPERATOR_EMAIL is required")
    fi
    # H.2-6: WPGOVERN_DOMAIN required for stack phase (Caddyfile + compose generation)
    # Not required for host-only runs but validated here eagerly to fail fast.
    # Operators can set it before H.2 runs; if missing, generation will fail with a clear error.
    # Validation is advisory here — enforce strictly inside the stack module generators.

    # Email format: RFC 5322 minimal
    if [[ -n "${WPGOVERN_OPERATOR_EMAIL:-}" ]]; then
        if ! echo "$WPGOVERN_OPERATOR_EMAIL" | \
             grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
            errors+=("WPGOVERN_OPERATOR_EMAIL '${WPGOVERN_OPERATOR_EMAIL}' is not a valid email address")
        fi
    fi

    # Install dir must be writable or creatable
    if [[ -n "${WPGOVERN_INSTALL_DIR:-}" ]]; then
        if [[ -e "$WPGOVERN_INSTALL_DIR" ]] && [[ ! -w "$WPGOVERN_INSTALL_DIR" ]]; then
            errors+=("WPGOVERN_INSTALL_DIR '${WPGOVERN_INSTALL_DIR}' exists but is not writable")
        elif [[ ! -e "$WPGOVERN_INSTALL_DIR" ]]; then
            if ! mkdir -p "$WPGOVERN_INSTALL_DIR" 2>/dev/null; then
                errors+=("WPGOVERN_INSTALL_DIR '${WPGOVERN_INSTALL_DIR}' cannot be created (check permissions)")
            fi
        fi
    fi

    # H.2.2.1-6: WPGOVERN_DOMAIN validation — required; must be a valid hostname
    # Rejects whitespace, braces, semicolons, and Caddyfile-special characters
    if [[ -z "${WPGOVERN_DOMAIN:-}" ]]; then
        errors+=("WPGOVERN_DOMAIN is required (stack phase cannot run without it)")
    elif [[ ! "${WPGOVERN_DOMAIN}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]; then
        errors+=("WPGOVERN_DOMAIN is not a valid hostname: '${WPGOVERN_DOMAIN}' (must be a valid FQDN, no special characters)")
    fi

    # H.2.1-7: DB password validation — rejects YAML-special and shell-unsafe chars
    # Empty is fine — credentials.sh generates safe passwords on first run
    _wpgovern_validate_db_password() {
        local var_name="$1"
        local value="$2"
        [[ -z "$value" ]] && return 0  # blank = will be generated
        if [[ ! "$value" =~ ^[A-Za-z0-9._@%-]{24,128}$ ]]; then
            errors+=("${var_name} contains unsafe characters or is outside 24-128 char range. Allowed: A-Za-z0-9._@%- Only set this manually if you need a specific password; otherwise leave blank for auto-generation.")
        fi
    }
    _wpgovern_validate_db_password "WPGOVERN_DB_ROOT_PASSWORD" "${WPGOVERN_DB_ROOT_PASSWORD:-}"
    _wpgovern_validate_db_password "WPGOVERN_DB_WP_PASSWORD"   "${WPGOVERN_DB_WP_PASSWORD:-}"
    _wpgovern_validate_db_password "WPGOVERN_DB_BACKUP_PASSWORD" "${WPGOVERN_DB_BACKUP_PASSWORD:-}"

    # H.4-7: WordPress admin credential validators
    _wpgovern_validate_wp_username() {
        local val="${WPGOVERN_WP_ADMIN_USER:-}"
        [[ -z "$val" ]] && return 0  # blank = not yet set, checked by phase
        if [[ ! "$val" =~ ^[a-z][a-z0-9_-]{2,30}$ ]]; then
            errors+=("WPGOVERN_WP_ADMIN_USER must match ^[a-z][a-z0-9_-]{2,30}$ (got: '${val}')")
        fi
    }
    _wpgovern_validate_wp_username

    _wpgovern_validate_db_password "WPGOVERN_WP_ADMIN_PASSWORD" "${WPGOVERN_WP_ADMIN_PASSWORD:-}"

    _wpgovern_validate_email() {
        local val="${WPGOVERN_WP_ADMIN_EMAIL:-}"
        if [[ -n "${WPGOVERN_WP_ADMIN_USER:-}" && -z "$val" ]]; then
            errors+=("WPGOVERN_WP_ADMIN_EMAIL is required when WPGOVERN_WP_ADMIN_USER is set")
            return
        fi
        [[ -z "$val" ]] && return 0
        if [[ ! "$val" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then
            errors+=("WPGOVERN_WP_ADMIN_EMAIL is not a valid email address: '${val}'")
        fi
    }
    _wpgovern_validate_email

    _wpgovern_validate_site_title() {
        local val="${WPGOVERN_WP_SITE_TITLE:-}"
        [[ -z "$val" ]] && return 0  # blank = will use default
        if [[ "${#val}" -gt 100 ]] || [[ ! "$val" =~ ^[[:print:]]+$ ]]; then
            errors+=("WPGOVERN_WP_SITE_TITLE must be ≤100 printable ASCII chars (got: '${val}')")
        fi
    }
    _wpgovern_validate_site_title

    # AUTH_KEYs: same safe charset as DB passwords (hex output of openssl rand -hex 32 always passes)
    for _wp_key in WPGOVERN_WP_AUTH_KEY WPGOVERN_WP_SECURE_AUTH_KEY \
                   WPGOVERN_WP_LOGGED_IN_KEY WPGOVERN_WP_NONCE_KEY \
                   WPGOVERN_WP_AUTH_SALT WPGOVERN_WP_SECURE_AUTH_SALT \
                   WPGOVERN_WP_LOGGED_IN_SALT WPGOVERN_WP_NONCE_SALT; do
        _wpgovern_validate_db_password "$_wp_key" "${!_wp_key:-}"
    done

    # H.5-4: WPGOVERN_ACTOR_ID — optional; must match ^[a-zA-Z][a-zA-Z0-9_.@-]{0,63}$
    if [[ -n "${WPGOVERN_ACTOR_ID:-}" ]]; then
        if [[ ! "${WPGOVERN_ACTOR_ID}" =~ ^[a-zA-Z][a-zA-Z0-9_.@-]{0,63}$ ]]; then
            errors+=("WPGOVERN_ACTOR_ID must match ^[a-zA-Z][a-zA-Z0-9_.@-]{0,63}$ (got: '${WPGOVERN_ACTOR_ID}')")
        fi
    fi

    # H.5-4: WPGOVERN_CEREMONY_REASON — optional; ≤200 printable chars (spaces allowed)
    if [[ -n "${WPGOVERN_CEREMONY_REASON:-}" ]]; then
        if [[ "${#WPGOVERN_CEREMONY_REASON}" -gt 200 ]]; then
            errors+=("WPGOVERN_CEREMONY_REASON must be ≤200 chars (got: ${#WPGOVERN_CEREMONY_REASON})")
        fi
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        echo "ERROR: Environment validation failed:" >&2
        for err in "${errors[@]}"; do
            echo "  - $err" >&2
        done
        return 1
    fi
}

wpgovern::bootstrap::log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local msg="[${ts}] $*"
    echo "$msg"
    if [[ -n "${WPGOVERN_LOG_DIR:-}" ]] && [[ -d "$WPGOVERN_LOG_DIR" ]]; then
        echo "$msg" >> "${WPGOVERN_LOG_DIR}/wpgovern-installer.log"
    fi
}

wpgovern::bootstrap::log_invocation() {
    wpgovern::bootstrap::log "wpgovern-install.sh invoked"
    wpgovern::bootstrap::log "  WPGOVERN_INSTALL_DIR=${WPGOVERN_INSTALL_DIR}"
    wpgovern::bootstrap::log "  WPGOVERN_LOG_DIR=${WPGOVERN_LOG_DIR}"
    wpgovern::bootstrap::log "  WPGOVERN_STATE_FILE=${WPGOVERN_STATE_FILE}"
}
