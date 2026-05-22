#!/usr/bin/env bats
# test_h7_keygen.bats — keypair generation idempotency, modes, state facts

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "${TEST_TMPDIR}/keys"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/keys/age.key"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/keys/age.pub"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${BACKUP_DIR}/keygen.sh"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_require_age_keygen() {
    command -v age-keygen >/dev/null 2>&1 || skip "age-keygen not available"
}

@test "H.7-1: generate_keypair creates private key at mode 0600" {
    _require_age_keygen
    wpgovern::backup::generate_keypair
    [[ -f "$WPGOVERN_AGE_PRIVATE_KEY_PATH" ]] || { echo "Private key not created"; return 1; }
    local mode; mode="$(stat -c '%a' "$WPGOVERN_AGE_PRIVATE_KEY_PATH")"
    [[ "$mode" == "600" ]] || { echo "Expected 0600, got $mode"; return 1; }
}

@test "H.7-1: generate_keypair creates public key at mode 0644" {
    _require_age_keygen
    wpgovern::backup::generate_keypair
    [[ -f "$WPGOVERN_AGE_PUBLIC_KEY_PATH" ]] || { echo "Public key not created"; return 1; }
    local mode; mode="$(stat -c '%a' "$WPGOVERN_AGE_PUBLIC_KEY_PATH")"
    [[ "$mode" == "644" ]] || { echo "Expected 0644, got $mode"; return 1; }
}

@test "H.7-1: generate_keypair is idempotent — second invocation skips, state fact unchanged" {
    _require_age_keygen
    wpgovern::backup::generate_keypair
    local first_ts; first_ts="$(wpgovern::state::get_fact "backup.age_keypair_generated_at")"
    [[ -n "$first_ts" ]] || { echo "First invocation state fact missing"; return 1; }

    sleep 1
    wpgovern::backup::generate_keypair  # second invocation — must skip
    local second_ts; second_ts="$(wpgovern::state::get_fact "backup.age_keypair_generated_at")"

    # Timestamps must match (or second invocation sets skipped_at, not generated_at again)
    local skipped_ts; skipped_ts="$(wpgovern::state::get_fact "backup.age_keypair_skipped_at" 2>/dev/null || echo "")"
    [[ -n "$skipped_ts" || "$first_ts" == "$second_ts" ]] || {
        echo "Idempotency failed: generated_at changed from $first_ts to $second_ts"
        return 1
    }
}

@test "H.7-1: generate_keypair records state fact backup.age_keypair_generated_at" {
    _require_age_keygen
    wpgovern::backup::generate_keypair
    local ts; ts="$(wpgovern::state::get_fact "backup.age_keypair_generated_at")"
    [[ -n "$ts" ]] || { echo "state fact not recorded"; return 1; }
}

@test "H.7-1: xtrace guard prevents key content leakage under bash -x" {
    _require_age_keygen
    local SENT="XTRACE_SENTINEL_KEYGEN_H7"
    # Generate a key first so it's "existing" for the idempotent path
    wpgovern::backup::generate_keypair
    # Now invoke under xtrace and verify the key content isn't in trace output
    local xtrace_out
    xtrace_out="$(bash -x -c "
        export WPGOVERN_AGE_PRIVATE_KEY_PATH='${WPGOVERN_AGE_PRIVATE_KEY_PATH}'
        export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
        export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
        export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
        export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        source '${BACKUP_DIR}/keygen.sh'
        wpgovern::backup::generate_keypair
    " 2>&1)"
    # The private key content (age1... format) must not appear
    if echo "$xtrace_out" | grep -q "^AGE-SECRET-KEY"; then
        echo "CREDENTIAL LEAK: age private key appeared in xtrace output"
        return 1
    fi
}
