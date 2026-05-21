#!/usr/bin/env bats
# =============================================================================
# test_h2_compose_generator.bats — Docker Compose generator tests
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
    export WPGOVERN_DB_ROOT_PASSWORD="testroot32chars1234567890123456"
    export WPGOVERN_DB_WP_PASSWORD="testwp32chars12345678901234567"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    wpgovern::state::set_fact "stack.images.caddy_digest"   "sha256:$(printf '%0.sa' {1..64})"
    wpgovern::state::set_fact "stack.images.mariadb_digest" "sha256:$(printf '%0.sb' {1..64})"
    wpgovern::state::set_fact "stack.images.php_digest"     "sha256:$(printf '%0.sc' {1..64})"

    source "${STACK_DIR}/compose.sh"
    wpgovern::stack::compose::generate
    COMPOSE_FILE="${TEST_TMPDIR}/install/docker-compose.yml"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "compose: no :latest tags in generated output" {
    ! grep -q ':latest' "$COMPOSE_FILE" || { echo "Found :latest tag in compose file"; return 1; }
}

@test "compose: all images have digest pinning (sha256: format)" {
    local image_lines
    image_lines="$(grep '^\s*image:' "$COMPOSE_FILE")"
    echo "$image_lines" | while IFS= read -r line; do
        echo "$line" | grep -qE 'sha256:[a-f0-9]{64}' || {
            echo "Image line missing digest: $line"
            return 1
        }
    done
}

@test "compose: all volumes are explicit bind-mounts (no anonymous volumes)" {
    local vol_lines
    vol_lines="$(grep -E '^\s+-\s+/' "$COMPOSE_FILE")"
    # Every volume line must start with a path (not an anonymous name)
    [[ -n "$vol_lines" ]] || { echo "No volume lines found — expected bind-mounts"; return 1; }
    grep -E '^\s+-\s+[a-zA-Z_]+:' "$COMPOSE_FILE" && {
        echo "Found named/anonymous volume — all volumes must be bind-mounts"
        return 1
    } || true
}

@test "compose: all three service names present (caddy, mariadb, php)" {
    grep -q '^\s*caddy:'   "$COMPOSE_FILE"
    grep -q '^\s*mariadb:' "$COMPOSE_FILE"
    grep -q '^\s*php:'     "$COMPOSE_FILE"
}

@test "compose: each service has restart: policy" {
    local service_count restart_count
    service_count=$(grep -c '^\s*[a-z]*:$' "$COMPOSE_FILE" || true)
    restart_count=$(grep -c '^\s*restart:' "$COMPOSE_FILE" || true)
    [[ "$restart_count" -ge 3 ]] || { echo "Expected restart on 3+ services, got $restart_count"; return 1; }
}

@test "compose: each service has healthcheck:" {
    local hc_count
    hc_count=$(grep -c '^\s*healthcheck:' "$COMPOSE_FILE" || true)
    [[ "$hc_count" -ge 3 ]] || { echo "Expected healthcheck on 3+ services, got $hc_count"; return 1; }
}

@test "compose: missing digest in state fails generation with clear error" {
    # Remove a digest from state and verify generation fails
    local tmp_state
    tmp_state="$(mktemp -d)"
    export WPGOVERN_STATE_FILE="${tmp_state}/.state.json"
    export WPGOVERN_INSTALL_DIR="${tmp_state}/install"
    mkdir -p "${tmp_state}/install"

    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    # Intentionally do NOT set any digests

    run wpgovern::stack::compose::generate
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "digest" ]] || [[ "$output" =~ "not in state" ]]
    rm -rf "$tmp_state"
}

@test "compose: generated file has governance header comment" {
    grep -q "wpgovern H.2" "$COMPOSE_FILE"
    grep -q "Do not edit by hand" "$COMPOSE_FILE"
}
