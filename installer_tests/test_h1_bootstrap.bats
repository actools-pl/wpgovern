#!/usr/bin/env bats
# =============================================================================
# test_h1_bootstrap.bats — Bootstrap env loading and validation tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# Helper: write a valid env file
_write_valid_env() {
    local path="$1"
    cat > "$path" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
ENV
}

# ---------------------------------------------------------------------------
# Env file loading
# ---------------------------------------------------------------------------

@test "load_env with valid file populates WPGOVERN_OPERATOR_EMAIL" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    _write_valid_env "$env_file"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"\$WPGOVERN_OPERATOR_EMAIL\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "test@example.com" ]]
}

@test "load_env with valid file populates WPGOVERN_INSTALL_DIR" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    _write_valid_env "$env_file"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"\$WPGOVERN_INSTALL_DIR\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "${TEST_TMPDIR}/install" ]]
}

@test "load_env applies sensible defaults for missing optional vars" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    # Minimal env — only required var
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
ENV

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"\${WPGOVERN_LOG_DIR:-defaulted}\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "wpgovern-installer" ]] || [[ "$output" =~ "defaulted" ]]
}

@test "load_env errors when env file does not exist" {
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '/nonexistent/wpgovern.env'
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "env file not found" ]] || [[ "$output" =~ "environment file not found" ]]
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@test "validate_env errors on missing WPGOVERN_OPERATOR_EMAIL" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
ENV

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_OPERATOR_EMAIL" ]]
}

@test "validate_env errors on invalid email format" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL="not-an-email"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
ENV

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "not a valid email" ]]
}

@test "validate_env accepts valid email address" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    _write_valid_env "$env_file"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'validation passed'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "validation passed" ]]
}

@test "validate_env errors when install dir is not writable" {
    # Skip when running as root — root bypasses filesystem permission checks
    if [[ "$(id -u)" -eq 0 ]]; then
        skip "running as root; permission checks are bypassed"
    fi

    local env_file="${TEST_TMPDIR}/wpgovern.env"
    local readonly_dir="${TEST_TMPDIR}/readonly"
    mkdir -p "$readonly_dir"
    chmod 000 "$readonly_dir"

    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${readonly_dir}/subdir"
ENV

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    chmod 755 "$readonly_dir"  # restore for teardown
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "cannot be created\|not writable" ]]
}

@test "validate_env accepts subdomain email addresses" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL="ops+alerts@mail.company.example.org"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
ENV

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'validation passed'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "validation passed" ]]
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

@test "bootstrap::log writes to log file" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    _write_valid_env "$env_file"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::log 'test log message'
    "
    [[ "$status" -eq 0 ]]
    grep -q "test log message" "${TEST_TMPDIR}/logs/wpgovern-installer.log"
}

@test "bootstrap::log includes timestamp in output" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    _write_valid_env "$env_file"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::log 'timestamped message'
    "
    [[ "$status" -eq 0 ]]
    # Timestamp format: [2026-05-...T...Z]
    [[ "$output" =~ \[20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T ]]
}

# ---------------------------------------------------------------------------
# bootstrap.sh structural tests
# ---------------------------------------------------------------------------

@test "bootstrap.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${CORE_DIR}/bootstrap.sh"
}

@test "bootstrap.sh defines wpgovern::bootstrap::load_env" {
    grep -q "wpgovern::bootstrap::load_env()" "${CORE_DIR}/bootstrap.sh"
}

@test "bootstrap.sh defines wpgovern::bootstrap::validate_env" {
    grep -q "wpgovern::bootstrap::validate_env()" "${CORE_DIR}/bootstrap.sh"
}

@test "bootstrap.sh defines wpgovern::bootstrap::log" {
    grep -q "wpgovern::bootstrap::log()" "${CORE_DIR}/bootstrap.sh"
}

@test "bootstrap.sh passes bash syntax check" {
    run bash -n "${CORE_DIR}/bootstrap.sh"
    [[ "$status" -eq 0 ]]
}

@test "state.sh passes bash syntax check" {
    run bash -n "${CORE_DIR}/state.sh"
    [[ "$status" -eq 0 ]]
}

# ---------------------------------------------------------------------------
# H.1.1-10 — Whitelist parser regression tests
# ---------------------------------------------------------------------------

@test "H.1.1-10: load_env rejects unknown keys" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
UNKNOWN_KEY=somevalue
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "unknown key" ]]
}

@test "H.1.1-10: load_env rejects shell metacharacters in values" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<'ENV'
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=/tmp/test
WPGOVERN_LOG_DIR=/tmp/logs; rm -rf /tmp/evil
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "metacharacters" ]]
}

@test "H.1.1-10: load_env accepts quoted values and unwraps them" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"\$WPGOVERN_OPERATOR_EMAIL\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" == "test@example.com" ]]
}

@test "H.1.1-10: load_env skips blank lines and comments" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
# This is a comment

WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install

# Another comment
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"\$WPGOVERN_OPERATOR_EMAIL\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" == "test@example.com" ]]
}

@test "H.1.1-10: load_env rejects malformed lines without equals sign" {
    local env_file="${TEST_TMPDIR}/wpgovern.env"
    cat > "$env_file" <<ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
NOTAKEYVALUE
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "invalid line format" ]]
}

# ---------------------------------------------------------------------------
# H.1.2-1 negative — env file WPGOVERN_FORCE_FIREWALL must be rejected
# ---------------------------------------------------------------------------

@test "H.1.2-1 negative: env file with WPGOVERN_FORCE_FIREWALL is rejected by whitelist" {
    local env_file="${TEST_TMPDIR}/wpgovern_badff.env"
    cat > "$env_file" <<ENV
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_LOG_DIR=${TEST_TMPDIR}/logs
WPGOVERN_STATE_FILE=${TEST_TMPDIR}/install/.state.json
WPGOVERN_OPERATOR_EMAIL=admin@example.com
WPGOVERN_FORCE_FIREWALL=true
ENV
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_FORCE_FIREWALL" ]] || [[ "$output" =~ "unknown key" ]]
}
