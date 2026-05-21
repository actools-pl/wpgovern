#!/usr/bin/env bats
# =============================================================================
# test_h2_images_pinning.bats — Image digest pinning tests
#
# Tests the three failure paths (pull, inspect, format) and idempotency.
# Uses mock docker binary on PATH — same pattern as H.1.2 curl-mock test.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
STACK_DIR="${BATS_TEST_DIRNAME}/../modules/stack"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init

    source "${STACK_DIR}/images.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_docker_mock() {
    local pull_exit="${1:-0}"
    local inspect_exit="${2:-0}"
    local inspect_output="${3:-"caddy:2@sha256:$(printf '%0.sa' {1..64})"}"

    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
case "\$1" in
    pull)    exit ${pull_exit} ;;
    inspect) [[ ${inspect_exit} -ne 0 ]] && exit ${inspect_exit}; echo "${inspect_output}" ;;
    compose) echo "Docker Compose version v2.0.0"; exit 0 ;;
    *)       exit 0 ;;
esac
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "images: successful pin populates state with sha256 digests" {
    _make_docker_mock 0 0 "caddy:2@sha256:$(printf '%0.sa' {1..64})"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::stack::images::pin
    [[ "$status" -eq 0 ]]

    local caddy_digest
    caddy_digest="$(wpgovern::state::get_fact "stack.images.caddy_digest")"
    [[ "$caddy_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
        echo "Expected sha256 digest, got: $caddy_digest"
        return 1
    }
}

@test "images: idempotency — second run uses persisted digests, no docker pull" {
    # Pre-populate digests in state
    wpgovern::state::set_fact "stack.images.caddy_digest"   "sha256:$(printf '%0.sa' {1..64})"
    wpgovern::state::set_fact "stack.images.mariadb_digest" "sha256:$(printf '%0.sb' {1..64})"
    wpgovern::state::set_fact "stack.images.php_digest"     "sha256:$(printf '%0.sc' {1..64})"

    # Mock docker that would fail if called
    cat > "${MOCK_BIN}/docker" <<'MOCK'
#!/usr/bin/env bash
# If pull is called, that means idempotency check failed
if [[ "$1" == "pull" ]]; then
    echo "IDEMPOTENCY BROKEN: docker pull was called" >&2
    exit 1
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::stack::images::pin
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
}

@test "images: failure path 1 — docker pull fails records mark_phase_failed" {
    _make_docker_mock 1 0 ""  # pull fails
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::stack::images::pin
    [[ "$status" -ne 0 ]]

    local failed_count reason
    failed_count="$(jq -r '.phases_failed | length' "$WPGOVERN_STATE_FILE")"
    [[ "$failed_count" -ge 1 ]]
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "image pull failed" ]] || { echo "Expected pull-failed reason, got: $reason"; return 1; }
}

@test "images: failure path 2 — docker inspect fails records mark_phase_failed" {
    _make_docker_mock 0 1 ""  # pull succeeds, inspect fails
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::stack::images::pin
    [[ "$status" -ne 0 ]]

    local failed_count reason
    failed_count="$(jq -r '.phases_failed | length' "$WPGOVERN_STATE_FILE")"
    [[ "$failed_count" -ge 1 ]]
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "image inspect failed" ]] || { echo "Expected inspect-failed reason, got: $reason"; return 1; }
}

@test "images: failure path 3 — malformed digest records mark_phase_failed" {
    _make_docker_mock 0 0 "not-a-valid-digest"  # pull+inspect ok, digest malformed
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::stack::images::pin
    [[ "$status" -ne 0 ]]

    local failed_count reason
    failed_count="$(jq -r '.phases_failed | length' "$WPGOVERN_STATE_FILE")"
    [[ "$failed_count" -ge 1 ]]
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "digest format unexpected" ]] || { echo "Expected format-unexpected reason, got: $reason"; return 1; }
}

@test "images: pinned_at timestamp recorded in state after successful pin" {
    _make_docker_mock 0 0 "caddy:2@sha256:$(printf '%0.sa' {1..64})"
    PATH="${MOCK_BIN}:${PATH}"

    wpgovern::stack::images::pin

    local pinned_at
    pinned_at="$(wpgovern::state::get_fact "stack.images.pinned_at")"
    [[ -n "$pinned_at" ]] || { echo "stack.images.pinned_at not set"; return 1; }
}
