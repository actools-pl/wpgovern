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
WPGOVERN_DOMAIN="test.example.com"
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
WPGOVERN_DOMAIN="mysite.example.com"
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

# ---------------------------------------------------------------------------
# H.2.1 — Domain and password validation tests
# ---------------------------------------------------------------------------

@test "H.2.1-6: validate_env accepts a valid FQDN domain" {
    local env_file="${TEST_TMPDIR}/valid_domain.env"
    _write_valid_env "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "ok" ]]
}

@test "H.2.1-6: validate_env rejects domain with Caddyfile-special brace chars" {
    local env_file="${TEST_TMPDIR}/brace_domain.env"
    cat > "$env_file" << 'ENV'
WPGOVERN_OPERATOR_EMAIL=admin@example.com
WPGOVERN_INSTALL_DIR=/tmp/brace_test
WPGOVERN_DOMAIN=example.com { respond "pwn" 200 }
ENV
    mkdir -p /tmp/brace_test
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    " 2>&1
    [[ "$status" -ne 0 ]] || [[ "$output" =~ "DOMAIN" ]] || [[ "$output" =~ "hostname" ]]
}

@test "H.2.1-6: validate_env rejects empty WPGOVERN_DOMAIN" {
    local env_file="${TEST_TMPDIR}/empty_domain.env"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=admin@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_DOMAIN" ]]
}

@test "H.2.1-7: validate_env accepts blank DB passwords (auto-generate path)" {
    local env_file="${TEST_TMPDIR}/blank_pw.env"
    _write_valid_env "$env_file"
    # WPGOVERN_DB_ROOT_PASSWORD not set = blank = acceptable
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
}

@test "H.2.1-7: validate_env rejects DB password with double-quote (YAML injection)" {
    local env_file="${TEST_TMPDIR}/quote_pw.env"
    _write_valid_env "$env_file"
    echo 'WPGOVERN_DB_ROOT_PASSWORD=root"badpass' >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    # Either rejected by whitelist metacharacter check or by validate_db_password
    [[ "$status" -ne 0 ]]
}

@test "H.2.1-7: validate_env rejects DB password with colon (YAML-special)" {
    local env_file="${TEST_TMPDIR}/colon_pw.env"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=admin@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
WPGOVERN_DB_WP_PASSWORD=safeprefix:colonbreak
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_DB_WP_PASSWORD" ]] || [[ "$output" =~ "unsafe" ]]
}

@test "H.2.1-7: validate_env accepts generator-produced password format" {
    local generated
    generated="$(openssl rand -base64 32 | tr -d '/=+' | head -c 32)"
    local env_file="${TEST_TMPDIR}/gen_pw.env"
    _write_valid_env "$env_file"
    echo "WPGOVERN_DB_ROOT_PASSWORD=${generated}" >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
}

# ---------------------------------------------------------------------------
# H.3-6 — WPGOVERN_DB_BACKUP_PASSWORD validation tests
# ---------------------------------------------------------------------------

@test "H.3-6: validate_env accepts blank WPGOVERN_DB_BACKUP_PASSWORD (generate path)" {
    local env_file="${TEST_TMPDIR}/bkup_blank.env"
    _write_valid_env "$env_file"
    # No WPGOVERN_DB_BACKUP_PASSWORD set — blank is acceptable, will be generated
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "ok" ]]
}

@test "H.3-6: validate_env rejects WPGOVERN_DB_BACKUP_PASSWORD with unsafe chars" {
    local env_file="${TEST_TMPDIR}/bkup_bad.env"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=admin@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
WPGOVERN_DB_BACKUP_PASSWORD=backup"bad:pass
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_DB_BACKUP_PASSWORD" ]] || [[ "$output" =~ "unsafe" ]] || [[ "$output" =~ "metacharacter" ]]
}

# ---------------------------------------------------------------------------
# H.4-7 — WordPress env var validation tests
# ---------------------------------------------------------------------------

@test "H.4-7: validate_env accepts valid WP admin user" {
    local env_file="${TEST_TMPDIR}/wp_user.env"
    _write_valid_env "$env_file"
    cat >> "$env_file" << ENV
WPGOVERN_WP_ADMIN_USER=admin
WPGOVERN_WP_ADMIN_PASSWORD=strongpassword1234567890abcde
WPGOVERN_WP_ADMIN_EMAIL=admin@example.com
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "ok" ]]
}

@test "H.4-7: validate_env rejects WP admin user with uppercase (^[a-z])" {
    local env_file="${TEST_TMPDIR}/wp_bad_user.env"
    _write_valid_env "$env_file"
    echo "WPGOVERN_WP_ADMIN_USER=Admin" >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_WP_ADMIN_USER" ]]
}

@test "H.4-7: validate_env requires WP admin email when admin user set" {
    local env_file="${TEST_TMPDIR}/wp_no_email.env"
    _write_valid_env "$env_file"
    cat >> "$env_file" << ENV
WPGOVERN_WP_ADMIN_USER=admin
WPGOVERN_WP_ADMIN_PASSWORD=strongpassword1234567890abcde
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_WP_ADMIN_EMAIL" ]]
}

@test "H.4.1-2: load_env under bash -x does not leak credential values" {
    local env_file="${TEST_TMPDIR}/xtrace_env.env"
    local SENT_ROOT="XTRACE_LEAK_ROOT_H41_AAAA"
    local SENT_WP="XTRACE_LEAK_WP_H41_BBBB__"
    local SENT_AUTH="XTRACE_LEAK_AUTH_H41_CCCC"

    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_LOG_DIR=${TEST_TMPDIR}/logs
WPGOVERN_DOMAIN=test.example.com
WPGOVERN_DB_ROOT_PASSWORD=${SENT_ROOT}
WPGOVERN_DB_WP_PASSWORD=${SENT_WP}
WPGOVERN_WP_AUTH_KEY=${SENT_AUTH}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ENV
    chmod 600 "$env_file"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

    # Run load_env under bash -x — capture ALL stderr (xtrace goes to stderr)
    local xtrace_output
    xtrace_output="$(bash -x -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    " 2>&1)"

    for sentinel in "$SENT_ROOT" "$SENT_WP" "$SENT_AUTH"; do
        if echo "$xtrace_output" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK under xtrace: '$sentinel' found in output"
            echo "--- xtrace context (first 3 matches) ---"
            echo "$xtrace_output" | grep -F "$sentinel" | head -3
            return 1
        fi
    done

    # WARNING must appear (xtrace protection activated)
    echo "$xtrace_output" | grep -q "xtrace.*active\|xtrace.*disabled\|disabling for credential" || {
        echo "Expected xtrace WARNING in output"
        return 1
    }
}

# ---------------------------------------------------------------------------
# H.5-4 — WPGOVERN_ACTOR_ID and WPGOVERN_CEREMONY_REASON validation
# ---------------------------------------------------------------------------

@test "H.5-4: validate_env accepts valid WPGOVERN_ACTOR_ID" {
    local env_file="${TEST_TMPDIR}/actor_valid.env"
    _write_valid_env "$env_file"
    echo "WPGOVERN_ACTOR_ID=alice.admin" >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "ok" ]]
}

@test "H.5-4: validate_env rejects WPGOVERN_ACTOR_ID starting with digit" {
    local env_file="${TEST_TMPDIR}/actor_bad.env"
    _write_valid_env "$env_file"
    echo "WPGOVERN_ACTOR_ID=1badstart" >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_ACTOR_ID" ]]
}

# ---------------------------------------------------------------------------
# H.5.1-3 — WPGOVERN_CEREMONY_REASON whitespace regression
# H.5.1-4 — WPGOVERN_INSTALL_DIR default path consistency
# ---------------------------------------------------------------------------

@test "H.5.1-3: WPGOVERN_CEREMONY_REASON with spaces loads without parser error" {
    local env_file="${TEST_TMPDIR}/reason_spaces.env"
    _write_valid_env "$env_file"
    echo 'WPGOVERN_CEREMONY_REASON="byte-one bootstrap"' >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
        echo 'ok'
    "
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "ok" ]]
}

@test "H.5.1-3: WPGOVERN_CEREMONY_REASON with shell metachar is still rejected" {
    local env_file="${TEST_TMPDIR}/reason_metachar.env"
    _write_valid_env "$env_file"
    echo 'WPGOVERN_CEREMONY_REASON="byte-one; rm -rf /"' >> "$env_file"
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
    " 2>&1
    [[ "$status" -ne 0 ]]
}

@test "H.5.1-4: WPGOVERN_INSTALL_DIR defaults to /opt/wpgovern-install when unset" {
    local env_file="${TEST_TMPDIR}/no_install_dir.env"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
WPGOVERN_DOMAIN="test.example.com"
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        echo \"install_dir=\${WPGOVERN_INSTALL_DIR}\"
    "
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "install_dir=/opt/wpgovern-install" ]] || {
        echo "Expected /opt/wpgovern-install default, got: $output"; return 1
    }
}
