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
    wpgovern::state::set_fact "stack.images.wordpress_digest" "sha256:$(printf '%0.sd' {1..64})"
    wpgovern::state::set_fact "stack.images.cli_digest"       "sha256:$(printf '%0.se' {1..64})"

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

@test "compose: all four service names present (caddy, mariadb, php, wordpress)" {
    grep -q '^\s*caddy:'     "$COMPOSE_FILE"
    grep -q '^\s*mariadb:'   "$COMPOSE_FILE"
    grep -q '^\s*php:'       "$COMPOSE_FILE"
    grep -q '^\s*wordpress:' "$COMPOSE_FILE"
}

@test "compose: each service has restart: policy" {
    local service_count restart_count
    service_count=$(grep -c '^\s*[a-z]*:$' "$COMPOSE_FILE" || true)
    restart_count=$(grep -c '^\s*restart:' "$COMPOSE_FILE" || true)
    [[ "$restart_count" -ge 4 ]] || { echo "Expected restart on 4+ services, got $restart_count"; return 1; }
}

@test "compose: each service has healthcheck:" {
    local hc_count
    hc_count=$(grep -c '^\s*healthcheck:' "$COMPOSE_FILE" || true)
    [[ "$hc_count" -ge 4 ]] || { echo "Expected healthcheck on 4+ services, got $hc_count"; return 1; }
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

# ---------------------------------------------------------------------------
# H.2.1 new tests
# ---------------------------------------------------------------------------

@test "H.2.1-3: Caddy service mounts WordPress docroot read-only" {
    grep -q 'wordpress:/var/www/html:ro' "$COMPOSE_FILE" || {
        echo "Caddy is missing read-only WordPress docroot mount"
        return 1
    }
}

@test "H.2.1-4: no temp files remain after idempotent no-op" {
    # First generation already in setup; second generation should be no-op
    source "${STACK_DIR}/compose.sh"
    wpgovern::stack::compose::generate  # should be idempotent no-op

    local tmp_count
    tmp_count=$(find "$WPGOVERN_INSTALL_DIR" -maxdepth 1 -name '*.tmp.*' 2>/dev/null | wc -l)
    [[ "$tmp_count" -eq 0 ]] || {
        echo "Temp files lingering after idempotent no-op: $tmp_count"
        find "$WPGOVERN_INSTALL_DIR" -maxdepth 1 -name '*.tmp.*'
        return 1
    }
}

@test "H.2.1-9: regeneration warns when file was hand-edited" {
    source "${STACK_DIR}/compose.sh"

    # Hand-edit the generated file
    echo "# hand-edited" >> "$COMPOSE_FILE"

    # Regenerate — should warn
    run wpgovern::stack::compose::generate
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "WARNING" ]] || [[ "$output" =~ "modified outside" ]] || {
        echo "Expected modification warning. Got: $output"; return 1
    }
}

@test "H.2.1-7: DB password with YAML-special chars rejected at bootstrap" {
    local env_file="${TEST_TMPDIR}/badpw.env"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
WPGOVERN_DB_ROOT_PASSWORD=root"bad:pass
ENV
    run bash -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env '${env_file}'
        wpgovern::bootstrap::validate_env
    "
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "WPGOVERN_DB_ROOT_PASSWORD" ]] || [[ "$output" =~ "unsafe" ]] || {
        echo "Expected password rejection. Got: $output"; return 1
    }
}
