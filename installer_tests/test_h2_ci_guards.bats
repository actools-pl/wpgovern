#!/usr/bin/env bats
# =============================================================================
# test_h2_ci_guards.bats — H.2 structural CI guards
#
# Enforces governance properties on generated output:
# - No :latest tags
# - All four services declared
# - Restart + healthcheck on each service
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
    export WPGOVERN_OPERATOR_EMAIL="test@example.com"
    export WPGOVERN_LE_EMAIL="test@example.com"
    export WPGOVERN_DB_ROOT_PASSWORD="testroot32chars1234567890123456"
    export WPGOVERN_DB_WP_PASSWORD="testwp32chars12345678901234567"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    wpgovern::state::set_fact "stack.images.caddy_digest"   "sha256:$(printf '%0.sa' {1..64})"
    wpgovern::state::set_fact "stack.images.mariadb_digest" "sha256:$(printf '%0.sb' {1..64})"
    wpgovern::state::set_fact "stack.images.php_digest"     "sha256:$(printf '%0.sc' {1..64})"
    wpgovern::state::set_fact "stack.images.wordpress_digest" "sha256:$(printf '%0.sd' {1..64})"

    source "${STACK_DIR}/compose.sh"
    source "${STACK_DIR}/caddyfile.sh"
    source "${STACK_DIR}/mycnf.sh"

    wpgovern::stack::compose::generate
    wpgovern::stack::caddyfile::generate
    wpgovern::stack::mycnf::generate

    COMPOSE_FILE="${TEST_TMPDIR}/install/docker-compose.yml"
    CADDY_FILE="${TEST_TMPDIR}/install/Caddyfile"
    MYCNF_FILE="${TEST_TMPDIR}/install/my.cnf"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "CI guard: docker-compose.yml has no :latest tags" {
    ! grep -q ':latest' "$COMPOSE_FILE" || {
        echo "VIOLATION: :latest tag found in docker-compose.yml"
        grep ':latest' "$COMPOSE_FILE"
        return 1
    }
}

@test "CI guard: all four services declared in compose file" {
    grep -q '^\s*caddy:'     "$COMPOSE_FILE" || { echo "caddy service missing"; return 1; }
    grep -q '^\s*mariadb:'   "$COMPOSE_FILE" || { echo "mariadb service missing"; return 1; }
    grep -q '^\s*php:'       "$COMPOSE_FILE" || { echo "php service missing"; return 1; }
    grep -q '^\s*wordpress:' "$COMPOSE_FILE" || { echo "wordpress service missing"; return 1; }
}

@test "CI guard: all services have restart policy" {
    local count
    count="$(grep -c '^\s*restart:' "$COMPOSE_FILE" || echo 0)"
    [[ "$count" -ge 4 ]] || { echo "Expected 3+ restart policies, got $count"; return 1; }
}

@test "CI guard: all services have healthcheck" {
    local count
    count="$(grep -c '^\s*healthcheck:' "$COMPOSE_FILE" || echo 0)"
    [[ "$count" -ge 4 ]] || { echo "Expected 3+ healthchecks, got $count"; return 1; }
}

@test "CI guard: governance files all have non-empty content" {
    [[ -s "$COMPOSE_FILE" ]] || { echo "docker-compose.yml is empty"; return 1; }
    [[ -s "$CADDY_FILE" ]]   || { echo "Caddyfile is empty"; return 1; }
    [[ -s "$MYCNF_FILE" ]]   || { echo "my.cnf is empty"; return 1; }
}

@test "CI guard: state facts recorded for all three governance files" {
    local compose_hash caddy_hash mycnf_hash
    compose_hash="$(wpgovern::state::get_fact "stack.compose.config_sha256")"
    caddy_hash="$(wpgovern::state::get_fact "stack.caddyfile.config_sha256")"
    mycnf_hash="$(wpgovern::state::get_fact "stack.mycnf.config_sha256")"

    [[ -n "$compose_hash" ]] || { echo "stack.compose.config_sha256 not set"; return 1; }
    [[ -n "$caddy_hash" ]]   || { echo "stack.caddyfile.config_sha256 not set"; return 1; }
    [[ -n "$mycnf_hash" ]]   || { echo "stack.mycnf.config_sha256 not set"; return 1; }
}
