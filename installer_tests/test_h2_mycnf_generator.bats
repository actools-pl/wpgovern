#!/usr/bin/env bats
# =============================================================================
# test_h2_mycnf_generator.bats — my.cnf generator tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
STACK_DIR="${BATS_TEST_DIRNAME}/../modules/stack"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init

    source "${STACK_DIR}/mycnf.sh"
    wpgovern::stack::mycnf::generate
    MYCNF_FILE="${TEST_TMPDIR}/install/my.cnf"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "mycnf: binary logging enabled (log-bin present)" {
    grep -q "^log-bin" "$MYCNF_FILE" || grep -q "^log_bin" "$MYCNF_FILE"
}

@test "mycnf: binlog_format = ROW" {
    grep -qiE "binlog_format\s*=\s*ROW" "$MYCNF_FILE"
}

@test "mycnf: require_secure_transport = ON" {
    grep -qiE "require_secure_transport\s*=\s*ON" "$MYCNF_FILE"
}

@test "mycnf: innodb_buffer_pool_size = 2G (CX22 tuning)" {
    grep -qiE "innodb_buffer_pool_size\s*=\s*2G" "$MYCNF_FILE"
}

@test "mycnf: character-set-server = utf8mb4" {
    grep -qiE "character-set-server\s*=\s*utf8mb4" "$MYCNF_FILE"
}

@test "mycnf: max_connections present" {
    grep -qiE "max_connections\s*=" "$MYCNF_FILE"
}

@test "mycnf: governance header comment present" {
    grep -q "wpgovern H.2" "$MYCNF_FILE"
    grep -q "Do not edit by hand" "$MYCNF_FILE"
}
