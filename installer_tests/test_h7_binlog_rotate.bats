#!/usr/bin/env bats
# test_h7_binlog_rotate.bats — encrypt→verify→delete ordering, error path

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"
    mkdir -p "${TEST_TMPDIR}/binlogs" "${TEST_TMPDIR}/backups/binlogs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/age.pub"
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/backups"
    export WPGOVERN_BINLOG_DIR="${TEST_TMPDIR}/binlogs"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_require_age() {
    command -v age >/dev/null 2>&1 || skip "age not available"
    command -v age-keygen >/dev/null 2>&1 || skip "age-keygen not available"
}

_setup_keys() {
    age-keygen -o "${TEST_TMPDIR}/age.key" 2>/dev/null
    age-keygen -y "${TEST_TMPDIR}/age.key" > "${TEST_TMPDIR}/age.pub" 2>/dev/null
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/age.key"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/age.pub"
    chmod 600 "${TEST_TMPDIR}/age.key"
}

_mock_docker_flush() {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
args="$*"
# SHOW MASTER STATUS — return a fake active binlog
if echo "$args" | grep -q "SHOW MASTER STATUS"; then
    echo "binlog.000099"$'\t'"12345"
    exit 0
fi
# FLUSH BINARY LOGS — just succeed
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    export WPGOVERN_DB_BACKUP_PASSWORD="test_backup_pw"
}

@test "H.7-3: plaintext binlog deleted after successful encryption" {
    _require_age
    _setup_keys
    _mock_docker_flush
    PATH="${MOCK_BIN}:${PATH}"

    # Create a fake binlog file with a sentinel
    local index="${TEST_TMPDIR}/binlogs/binlog.index"
    touch "$index"
    sleep 1
    local binlog="${TEST_TMPDIR}/binlogs/binlog.000001"
    printf 'fake binlog content\n' > "$binlog"

    source "${BACKUP_DIR}/binlog_rotate.sh"
    wpgovern::backup::rotate_binlogs || true  # may warn on flush

    # After rotation: .age file should exist, plaintext should be gone
    local age_files; age_files="$(ls "${TEST_TMPDIR}/backups/binlogs/"*.age 2>/dev/null | wc -l)"
    [[ "$age_files" -ge 1 ]] || { echo "No .age file created"; return 1; }
    [[ ! -f "$binlog" ]] || { echo "Plaintext binlog not deleted after encryption"; return 1; }
}

@test "H.7-3: plaintext binlog PRESERVED when encryption produces empty file" {
    _require_age
    _setup_keys
    _mock_docker_flush

    # Mock age to produce an empty file (simulates encryption failure)
    cat > "${MOCK_BIN}/age" << 'MOCK'
#!/usr/bin/env bash
# Write empty output file (simulates encryption failure)
for i in "$@"; do
    if [[ "${prev:-}" == "-o" ]]; then
        : > "$i"  # empty .age file
    fi
    prev="$i"
done
exit 0  # exits 0 but .age is empty — verified-before-deleted catches this
MOCK
    chmod +x "${MOCK_BIN}/age"
    PATH="${MOCK_BIN}:${PATH}"

    local index="${TEST_TMPDIR}/binlogs/binlog.index"
    touch "$index"
    sleep 1
    local binlog="${TEST_TMPDIR}/binlogs/binlog.000002"
    printf 'critical binlog data\n' > "$binlog"

    source "${BACKUP_DIR}/binlog_rotate.sh"
    wpgovern::backup::rotate_binlogs || true

    # Plaintext must be preserved (non-empty .age = verification fails)
    [[ -f "$binlog" ]] || { echo "CRITICAL: plaintext binlog deleted despite empty .age (data loss!)"; return 1; }
}

@test "H.7-3: rotate_binlogs records state facts" {
    _require_age
    _setup_keys
    _mock_docker_flush
    PATH="${MOCK_BIN}:${PATH}"

    touch "${TEST_TMPDIR}/binlogs/binlog.index"

    source "${BACKUP_DIR}/binlog_rotate.sh"
    wpgovern::backup::rotate_binlogs || true

    local ts; ts="$(wpgovern::state::get_fact "backup.last_binlog_rotated_at" 2>/dev/null || echo "")"
    [[ -n "$ts" ]] || { echo "backup.last_binlog_rotated_at not recorded"; return 1; }
}

@test "H.7-3: xtrace guard prevents credential leakage in rotate_binlogs" {
    _require_age
    _setup_keys
    local SENT="SENTINEL_DB_BINLOG_H73_ROTATE"
    export WPGOVERN_DB_BACKUP_PASSWORD="$SENT"

    local xtrace_out
    xtrace_out="$(bash -x -c "
        export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
        export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
        export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
        export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
        export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
        export WPGOVERN_BINLOG_DIR='${WPGOVERN_BINLOG_DIR}'
        export WPGOVERN_DB_BACKUP_PASSWORD='$SENT'
        mkdir -p '${WPGOVERN_LOG_DIR}'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        source '${BACKUP_DIR}/binlog_rotate.sh'
        wpgovern::backup::rotate_binlogs
    " 2>&1 || true)"

    local leak_count; leak_count="$(echo "$xtrace_out" | grep -cF "$SENT" || echo 0)"
    if [[ "$leak_count" -gt 2 ]]; then
        echo "CREDENTIAL LEAK in xtrace: $leak_count occurrences (expected ≤2 from env export+assignment)"
        return 1
    fi
}

@test "H.7-3: audit of encrypt-before-delete ordering in binlog_rotate.sh" {
    # Structural audit: rm must appear AFTER .age non-empty check in source
    local src="${BACKUP_DIR}/binlog_rotate.sh"
    local age_check_line rm_line
    age_check_line="$(grep -n '"\-s.*age_dest\|if.*age.*non.*empty\|\[\[ -s.*age_dest' "$src" | head -1 | cut -d: -f1)"
    rm_line="$(grep -n 'rm -f.*binlog_file' "$src" | head -1 | cut -d: -f1)"
    [[ -n "$age_check_line" ]] || { echo "Could not find -s .age verification in binlog_rotate.sh"; return 1; }
    [[ -n "$rm_line" ]] || { echo "Could not find rm plaintext in binlog_rotate.sh"; return 1; }
    [[ "$age_check_line" -lt "$rm_line" ]] || {
        echo "ORDERING VIOLATION: rm (line $rm_line) appears before .age verification (line $age_check_line)"
        return 1
    }
}
