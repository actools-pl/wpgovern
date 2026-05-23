#!/usr/bin/env bats
# =============================================================================
# test_h4_secure.bats — wp-config.php generator tests
# Determinism tests are the defining tests of H.4.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
WP_DIR="${BATS_TEST_DIRNAME}/../modules/wp"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_ENV_FILE_PATH="${TEST_TMPDIR}/wpgovern.env"
    export WPGOVERN_DOMAIN="test.example.com"
    export WPGOVERN_DB_WP_PASSWORD="testdbwp12345678901234567890123"

    cat > "$WPGOVERN_ENV_FILE_PATH" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
ENV

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    wpgovern::state::set_fact "bootstrap.env_file_path" "$WPGOVERN_ENV_FILE_PATH"
    source "${WP_DIR}/secure.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_set_all_auth_keys() {
    export WPGOVERN_WP_AUTH_KEY="aaaa$(printf '%0.sa' {1..60})"
    export WPGOVERN_WP_SECURE_AUTH_KEY="bbbb$(printf '%0.sb' {1..60})"
    export WPGOVERN_WP_LOGGED_IN_KEY="cccc$(printf '%0.sc' {1..60})"
    export WPGOVERN_WP_NONCE_KEY="dddd$(printf '%0.sd' {1..60})"
    export WPGOVERN_WP_AUTH_SALT="eeee$(printf '%0.se' {1..60})"
    export WPGOVERN_WP_SECURE_AUTH_SALT="ffff$(printf '%0.sf' {1..60})"
    export WPGOVERN_WP_LOGGED_IN_SALT="0000$(printf '%0.s0' {1..60})"
    export WPGOVERN_WP_NONCE_SALT="1111$(printf '%0.s1' {1..60})"
}

@test "H.4-3: ensure_auth_keys generates all 8 when blank" {
    for k in WPGOVERN_WP_AUTH_KEY WPGOVERN_WP_SECURE_AUTH_KEY \
              WPGOVERN_WP_LOGGED_IN_KEY WPGOVERN_WP_NONCE_KEY \
              WPGOVERN_WP_AUTH_SALT WPGOVERN_WP_SECURE_AUTH_SALT \
              WPGOVERN_WP_LOGGED_IN_SALT WPGOVERN_WP_NONCE_SALT; do
        unset "$k"
    done
    # Call directly (not via run) — export propagates to current shell
    wpgovern::wp::secure::ensure_auth_keys
    [[ $? -eq 0 ]] || { echo "ensure_auth_keys failed"; return 1; }

    # Verify all 8 persisted to env file (persistent check, not env var check)
    for k in WPGOVERN_WP_AUTH_KEY WPGOVERN_WP_SECURE_AUTH_KEY \
              WPGOVERN_WP_LOGGED_IN_KEY WPGOVERN_WP_NONCE_KEY \
              WPGOVERN_WP_AUTH_SALT WPGOVERN_WP_SECURE_AUTH_SALT \
              WPGOVERN_WP_LOGGED_IN_SALT WPGOVERN_WP_NONCE_SALT; do
        local val
        val="$(grep "^${k}=" "$WPGOVERN_ENV_FILE_PATH" | cut -d= -f2 | tr -d '"')"
        [[ -n "$val" ]] || { echo "$k not in env file"; return 1; }
        [[ "${#val}" -ge 64 ]] || { echo "$k too short in env file: ${#val}"; return 1; }
    done
}

@test "H.4-3: ensure_auth_keys only generates MISSING keys (partial state)" {
    local fixed_key="existing_fixed_auth_key_$(printf '%0.sx' {1..46})"
    export WPGOVERN_WP_AUTH_KEY="$fixed_key"
    # Pre-seed in env file too
    echo "WPGOVERN_WP_AUTH_KEY=\"${fixed_key}\"" >> "$WPGOVERN_ENV_FILE_PATH"

    for k in WPGOVERN_WP_SECURE_AUTH_KEY WPGOVERN_WP_LOGGED_IN_KEY \
              WPGOVERN_WP_NONCE_KEY WPGOVERN_WP_AUTH_SALT \
              WPGOVERN_WP_SECURE_AUTH_SALT WPGOVERN_WP_LOGGED_IN_SALT \
              WPGOVERN_WP_NONCE_SALT; do
        unset "$k"
    done

    wpgovern::wp::secure::ensure_auth_keys

    # AUTH_KEY must be unchanged in env file
    local persisted
    persisted="$(grep "^WPGOVERN_WP_AUTH_KEY=" "$WPGOVERN_ENV_FILE_PATH" | cut -d= -f2 | tr -d '"')"
    [[ "$persisted" == "$fixed_key" ]] || {
        echo "AUTH_KEY was regenerated (should be preserved)"; return 1
    }
    # NONCE_SALT must now be in env file
    local nonce; nonce="$(grep "^WPGOVERN_WP_NONCE_SALT=" "$WPGOVERN_ENV_FILE_PATH" | cut -d= -f2 | tr -d '"')"
    [[ -n "$nonce" ]] || { echo "NONCE_SALT not generated in env file"; return 1; }
}

@test "H.4-3: generate_config creates file with 640 perms" {
    _set_all_auth_keys
    wpgovern::wp::secure::generate_config
    local perms; perms="$(stat -c '%a' "${TEST_TMPDIR}/install/wp-config.php")"
    [[ "$perms" == "640" ]] || { echo "Expected 640, got $perms"; return 1; }
}

@test "H.4-3: DETERMINISM positive — same inputs → byte-identical sha256" {
    _set_all_auth_keys
    wpgovern::wp::secure::generate_config
    local hash1; hash1="$(sha256sum "${TEST_TMPDIR}/install/wp-config.php" | awk '{print $1}')"
    rm "${TEST_TMPDIR}/install/wp-config.php"
    wpgovern::wp::secure::generate_config
    local hash2; hash2="$(sha256sum "${TEST_TMPDIR}/install/wp-config.php" | awk '{print $1}')"
    [[ "$hash1" == "$hash2" ]] || {
        echo "DETERMINISM VIOLATED: hash1=$hash1  hash2=$hash2"; return 1
    }
}

@test "H.4-3: DETERMINISM negative — different domain → different sha256" {
    _set_all_auth_keys
    export WPGOVERN_DOMAIN="test.example.com"
    wpgovern::wp::secure::generate_config
    local hash1; hash1="$(sha256sum "${TEST_TMPDIR}/install/wp-config.php" | awk '{print $1}')"
    rm "${TEST_TMPDIR}/install/wp-config.php"
    export WPGOVERN_DOMAIN="different.example.org"
    wpgovern::wp::secure::generate_config
    local hash2; hash2="$(sha256sum "${TEST_TMPDIR}/install/wp-config.php" | awk '{print $1}')"
    [[ "$hash1" != "$hash2" ]] || {
        echo "DETERMINISM UNRESPONSIVE: same hash for different domains"; return 1
    }
}

@test "H.4-3: generate_config contains required hardening constants" {
    _set_all_auth_keys
    wpgovern::wp::secure::generate_config
    local cfg="${TEST_TMPDIR}/install/wp-config.php"
    grep -q "DISALLOW_FILE_EDIT" "$cfg" || { echo "Missing DISALLOW_FILE_EDIT"; return 1; }
    grep -q "WP_DEBUG"           "$cfg" || { echo "Missing WP_DEBUG"; return 1; }
    grep -q "FORCE_SSL_ADMIN"    "$cfg" || { echo "Missing FORCE_SSL_ADMIN"; return 1; }
    grep -q "COOKIE_SECURE"      "$cfg" || { echo "Missing COOKIE_SECURE"; return 1; }
}

@test "H.4-3: wp.secure.config_hash recorded in state matches file" {
    _set_all_auth_keys
    wpgovern::wp::secure::generate_config
    local recorded_hash; recorded_hash="$(wpgovern::state::get_fact "wp.secure.config_hash")"
    local actual_hash; actual_hash="$(sha256sum "${TEST_TMPDIR}/install/wp-config.php" | awk '{print $1}')"
    [[ "$recorded_hash" == "$actual_hash" ]] || {
        echo "Hash mismatch: state=$recorded_hash  file=$actual_hash"; return 1
    }
}

@test "H.4-3: AUTH_KEY and DB password do NOT appear in log output" {
    _set_all_auth_keys
    export WPGOVERN_DB_WP_PASSWORD="SENTINEL_DBWP_SECURE_h4"
    export WPGOVERN_WP_AUTH_KEY="SENTINEL_AUTHKEY_SECURE_h4_aaaa$(printf '%0.sa' {1..34})"

    run wpgovern::wp::secure::generate_config
    for sentinel in "SENTINEL_DBWP_SECURE_h4" "SENTINEL_AUTHKEY_SECURE_h4_aaaa"; do
        if echo "$output" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK: $sentinel in output"; return 1
        fi
    done
    if grep -qF "SENTINEL_DBWP_SECURE_h4" \
        "${TEST_TMPDIR}/logs/wpgovern-installer.log" 2>/dev/null; then
        echo "CREDENTIAL LEAK: DB password in log"; return 1
    fi
}

@test "H.4.1-3: chown failure removes temp file and records mark_phase_failed" {
    _set_all_auth_keys

    # Write a script that replaces chown with a failing stub, then calls generate_config
    local script="${TEST_TMPDIR}/test_chown_fail.sh"
    cat > "$script" << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
export WPGOVERN_ENV_FILE_PATH="${WPGOVERN_ENV_FILE_PATH}"
export WPGOVERN_DOMAIN="test.example.com"
export WPGOVERN_DB_WP_PASSWORD="${WPGOVERN_DB_WP_PASSWORD}"
export WPGOVERN_WP_AUTH_KEY="${WPGOVERN_WP_AUTH_KEY}"
export WPGOVERN_WP_SECURE_AUTH_KEY="${WPGOVERN_WP_SECURE_AUTH_KEY}"
export WPGOVERN_WP_LOGGED_IN_KEY="${WPGOVERN_WP_LOGGED_IN_KEY}"
export WPGOVERN_WP_NONCE_KEY="${WPGOVERN_WP_NONCE_KEY}"
export WPGOVERN_WP_AUTH_SALT="${WPGOVERN_WP_AUTH_SALT}"
export WPGOVERN_WP_SECURE_AUTH_SALT="${WPGOVERN_WP_SECURE_AUTH_SALT}"
export WPGOVERN_WP_LOGGED_IN_SALT="${WPGOVERN_WP_LOGGED_IN_SALT}"
export WPGOVERN_WP_NONCE_SALT="${WPGOVERN_WP_NONCE_SALT}"
source "${CORE_DIR}/bootstrap.sh"
source "${CORE_DIR}/state.sh"
source "${CORE_DIR}/credentials.sh"
wpgovern::state::init
wpgovern::state::set_fact "bootstrap.env_file_path" "${WPGOVERN_ENV_FILE_PATH}"
# Override chown to always fail
chown() { return 1; }
export -f chown
source "${WP_DIR}/secure.sh"
wpgovern::wp::secure::generate_config
SCRIPT
    chmod +x "$script"

    run bash "$script"
    [[ "$status" -ne 0 ]] || { echo "Expected failure, got 0"; return 1; }

    # No temp files should remain
    local tmp_count
    tmp_count="$(find "${TEST_TMPDIR}/install" -maxdepth 1 -name '*.tmp.*' 2>/dev/null | wc -l)"
    [[ "$tmp_count" -eq 0 ]] || {
        echo "Temp files leaked after chown failure: $tmp_count"
        find "${TEST_TMPDIR}/install" -maxdepth 1 -name '*.tmp.*'
        return 1
    }

    # mark_phase_failed must be recorded
    local reason
    reason="$(jq -r '.phases_failed[0].reason' "${TEST_TMPDIR}/install/.state.json" 2>/dev/null)"
    [[ "$reason" =~ "chown" ]] || [[ "$reason" =~ "secure:" ]] || {
        echo "Expected chown failure reason, got: $reason"
        return 1
    }
}
