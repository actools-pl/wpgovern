#!/usr/bin/env bats
# =============================================================================
# test_h2_determinism.bats — Generator determinism tests
#
# THE critical H.2 tests. Byte-identical output on regeneration for all three
# governance-critical files. Same inputs → same sha256 hash every time.
# Non-determinism here breaks H.5 file-hash governance.
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

    # Pre-populate pinned digests in state (simulate images.pin having run)
    wpgovern::state::set_fact "stack.images.caddy_digest"   "sha256:aaaa$(printf '%0.sa' {1..60})"
    wpgovern::state::set_fact "stack.images.mariadb_digest" "sha256:bbbb$(printf '%0.sb' {1..60})"
    wpgovern::state::set_fact "stack.images.php_digest"     "sha256:cccc$(printf '%0.sc' {1..60})"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "H.2 determinism: docker-compose.yml byte-identical on two generations" {
    source "${STACK_DIR}/compose.sh"

    wpgovern::stack::compose::generate
    local hash1
    hash1="$(sha256sum "${WPGOVERN_INSTALL_DIR}/docker-compose.yml" | cut -d' ' -f1)"
    [[ -n "$hash1" ]]

    # Remove and regenerate
    rm "${WPGOVERN_INSTALL_DIR}/docker-compose.yml"
    wpgovern::stack::compose::generate
    local hash2
    hash2="$(sha256sum "${WPGOVERN_INSTALL_DIR}/docker-compose.yml" | cut -d' ' -f1)"

    [[ "$hash1" == "$hash2" ]] || {
        echo "HASH MISMATCH: first=$hash1  second=$hash2"
        echo "Generator is non-deterministic — H.5 file-hash governance will fail"
        return 1
    }
}

@test "H.2 determinism: Caddyfile byte-identical on two generations" {
    source "${STACK_DIR}/caddyfile.sh"

    wpgovern::stack::caddyfile::generate
    local hash1
    hash1="$(sha256sum "${WPGOVERN_INSTALL_DIR}/Caddyfile" | cut -d' ' -f1)"
    [[ -n "$hash1" ]]

    rm "${WPGOVERN_INSTALL_DIR}/Caddyfile"
    wpgovern::stack::caddyfile::generate
    local hash2
    hash2="$(sha256sum "${WPGOVERN_INSTALL_DIR}/Caddyfile" | cut -d' ' -f1)"

    [[ "$hash1" == "$hash2" ]] || {
        echo "HASH MISMATCH: first=$hash1  second=$hash2"
        return 1
    }
}

@test "H.2 determinism: my.cnf byte-identical on two generations" {
    source "${STACK_DIR}/mycnf.sh"

    wpgovern::stack::mycnf::generate
    local hash1
    hash1="$(sha256sum "${WPGOVERN_INSTALL_DIR}/my.cnf" | cut -d' ' -f1)"
    [[ -n "$hash1" ]]

    rm "${WPGOVERN_INSTALL_DIR}/my.cnf"
    wpgovern::stack::mycnf::generate
    local hash2
    hash2="$(sha256sum "${WPGOVERN_INSTALL_DIR}/my.cnf" | cut -d' ' -f1)"

    [[ "$hash1" == "$hash2" ]] || {
        echo "HASH MISMATCH: first=$hash1  second=$hash2"
        return 1
    }
}

@test "H.2 determinism: all three files together produce identical aggregate hash" {
    source "${STACK_DIR}/compose.sh"
    source "${STACK_DIR}/caddyfile.sh"
    source "${STACK_DIR}/mycnf.sh"

    wpgovern::stack::compose::generate
    wpgovern::stack::caddyfile::generate
    wpgovern::stack::mycnf::generate

    local hash1
    hash1="$(cat "${WPGOVERN_INSTALL_DIR}/docker-compose.yml" \
                  "${WPGOVERN_INSTALL_DIR}/Caddyfile" \
                  "${WPGOVERN_INSTALL_DIR}/my.cnf" \
             | sha256sum | cut -d' ' -f1)"

    # Regenerate all three
    rm "${WPGOVERN_INSTALL_DIR}/docker-compose.yml" \
       "${WPGOVERN_INSTALL_DIR}/Caddyfile" \
       "${WPGOVERN_INSTALL_DIR}/my.cnf"

    wpgovern::stack::compose::generate
    wpgovern::stack::caddyfile::generate
    wpgovern::stack::mycnf::generate

    local hash2
    hash2="$(cat "${WPGOVERN_INSTALL_DIR}/docker-compose.yml" \
                  "${WPGOVERN_INSTALL_DIR}/Caddyfile" \
                  "${WPGOVERN_INSTALL_DIR}/my.cnf" \
             | sha256sum | cut -d' ' -f1)"

    [[ "$hash1" == "$hash2" ]] || {
        echo "AGGREGATE HASH MISMATCH: first=$hash1  second=$hash2"
        return 1
    }
}

@test "H.2 idempotency: regenerate with same inputs is no-op (file mtime unchanged)" {
    source "${STACK_DIR}/compose.sh"

    wpgovern::stack::compose::generate
    local mtime1
    mtime1="$(stat -c '%Y' "${WPGOVERN_INSTALL_DIR}/docker-compose.yml")"

    # Small sleep to ensure mtime would differ if file were touched
    sleep 1

    wpgovern::stack::compose::generate
    local mtime2
    mtime2="$(stat -c '%Y' "${WPGOVERN_INSTALL_DIR}/docker-compose.yml")"

    [[ "$mtime1" == "$mtime2" ]] || {
        echo "MTIME CHANGED: file was rewritten on identical inputs (idempotency broken)"
        return 1
    }
}
