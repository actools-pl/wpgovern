#!/usr/bin/env bats
# =============================================================================
# test_h2_caddyfile_generator.bats — Caddyfile generator tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
STACK_DIR="${BATS_TEST_DIRNAME}/../modules/stack"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export WPGOVERN_OPERATOR_EMAIL="ops@example.com"
    export WPGOVERN_LE_EMAIL="le@example.com"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init

    source "${STACK_DIR}/caddyfile.sh"
    wpgovern::stack::caddyfile::generate
    CADDY_FILE="${TEST_TMPDIR}/install/Caddyfile"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "caddyfile: domain substituted into output (not literal placeholder)" {
    grep -q "test.example.com" "$CADDY_FILE"
    ! grep -q 'WPGOVERN_DOMAIN\|<DOMAIN>' "$CADDY_FILE"
}

@test "caddyfile: LE email present" {
    grep -q "le@example.com" "$CADDY_FILE"
}

@test "caddyfile: all required security headers present" {
    grep -q "Strict-Transport-Security" "$CADDY_FILE"
    grep -q "X-Content-Type-Options" "$CADDY_FILE"
    grep -q "X-Frame-Options" "$CADDY_FILE"
    grep -q "Referrer-Policy" "$CADDY_FILE"
    grep -q "Permissions-Policy" "$CADDY_FILE"
}

@test "caddyfile: encode gzip and zstd present" {
    grep -q "encode" "$CADDY_FILE"
    grep -q "gzip" "$CADDY_FILE"
    grep -q "zstd" "$CADDY_FILE"
}

@test "caddyfile: php_fastcgi reverse-proxies to php:9000" {
    grep -q "php_fastcgi.*php:9000\|php_fastcgi php:9000" "$CADDY_FILE"
}

@test "caddyfile: :80 health endpoint returns ok" {
    grep -q "/health" "$CADDY_FILE"
    grep -q '"ok"' "$CADDY_FILE" || grep -q "ok" "$CADDY_FILE"
}

@test "caddyfile: governance header comment present" {
    grep -q "wpgovern H.2" "$CADDY_FILE"
    grep -q "Do not edit by hand" "$CADDY_FILE"
}

@test "caddyfile: missing LE email fails with clear error" {
    local tmp_install
    tmp_install="$(mktemp -d)"
    local tmp_state
    tmp_state="${tmp_install}/.state.json"
    mkdir -p "${tmp_install}/install" "${tmp_install}/logs"

    # Fresh state without LE email
    local saved_le="$WPGOVERN_LE_EMAIL"
    local saved_op="$WPGOVERN_OPERATOR_EMAIL"
    local saved_dir="$WPGOVERN_INSTALL_DIR"
    local saved_state="$WPGOVERN_STATE_FILE"

    export WPGOVERN_LE_EMAIL=""
    export WPGOVERN_OPERATOR_EMAIL=""
    export WPGOVERN_INSTALL_DIR="${tmp_install}/install"
    export WPGOVERN_STATE_FILE="$tmp_state"

    source "${CORE_DIR}/state.sh"
    wpgovern::state::init

    run wpgovern::stack::caddyfile::generate
    [[ "$status" -ne 0 ]] || { echo "Expected non-zero, got 0. Output: $output"; return 1; }

    # Restore
    export WPGOVERN_LE_EMAIL="$saved_le"
    export WPGOVERN_OPERATOR_EMAIL="$saved_op"
    export WPGOVERN_INSTALL_DIR="$saved_dir"
    export WPGOVERN_STATE_FILE="$saved_state"
    rm -rf "$tmp_install"
}
