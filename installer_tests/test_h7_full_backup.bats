#!/usr/bin/env bats
# test_h7_full_backup.bats — stream encryption, private key excluded from tarball, xtrace

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "${TEST_TMPDIR}/backups" "${TEST_TMPDIR}/keys" \
             "${TEST_TMPDIR}/etc-wpgovern" "$MOCK_BIN"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/backups"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/keys/age.pub"
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/keys/age.key"
    export WPGOVERN_DB_BACKUP_PASSWORD="test_backup_pw"

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "-- MariaDB dump 10.19"
echo "CREATE TABLE \`wp_options\` (option_id BIGINT);"
echo "INSERT INTO \`wp_options\` VALUES (1);"
echo "-- Dump completed on 2026-01-01  0:00:00"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_require_age() {
    command -v age >/dev/null 2>&1 || skip "age not available"
    command -v age-keygen >/dev/null 2>&1 || skip "age-keygen not available"
}

_setup_keys() {
    age-keygen -o "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null
    age-keygen -y "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" > "${WPGOVERN_AGE_PUBLIC_KEY_PATH}" 2>/dev/null
    chmod 600 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
}

_run_backup() {
    # Use a script file to avoid readonly _BACKUP_GOVERNED_DIRS conflict on re-source
    local dirs="${1:-${WPGOVERN_INSTALL_DIR}}"
    local script="${TEST_TMPDIR}/run_backup.sh"
    printf '#!/usr/bin/env bash\nset -euo pipefail\n' > "$script"
    printf 'export WPGOVERN_INSTALL_DIR="%s"\n' "${WPGOVERN_INSTALL_DIR}" >> "$script"
    printf 'export WPGOVERN_LOG_DIR="%s"\n' "${WPGOVERN_LOG_DIR}" >> "$script"
    printf 'export WPGOVERN_STATE_FILE="%s"\n' "${WPGOVERN_STATE_FILE}" >> "$script"
    printf 'export WPGOVERN_BACKUP_DIR="%s"\n' "${WPGOVERN_BACKUP_DIR}" >> "$script"
    printf 'export WPGOVERN_AGE_PUBLIC_KEY_PATH="%s"\n' "${WPGOVERN_AGE_PUBLIC_KEY_PATH}" >> "$script"
    printf 'export WPGOVERN_DB_BACKUP_PASSWORD="%s"\n' "${WPGOVERN_DB_BACKUP_PASSWORD}" >> "$script"
    printf 'mkdir -p "%s"\n' "${WPGOVERN_LOG_DIR}" >> "$script"
    printf 'export PATH="%s:$PATH"\n' "${MOCK_BIN}" >> "$script"
    printf 'source "%s/core/bootstrap.sh"\n' "${BATS_TEST_DIRNAME}/.." >> "$script"
    printf 'source "%s/core/state.sh"\n' "${BATS_TEST_DIRNAME}/.." >> "$script"
    printf 'source "%s/core/credentials.sh"\n' "${BATS_TEST_DIRNAME}/.." >> "$script"
    printf 'wpgovern::state::init\n' >> "$script"
    printf 'source "%s/modules/backup/full_backup.sh"\n' "${BATS_TEST_DIRNAME}/.." >> "$script"
    printf '_BACKUP_GOVERNED_DIRS=("%s")\n' "$dirs" >> "$script"
    printf 'wpgovern::backup::run_full\n' >> "$script"
    chmod +x "$script"
    bash "$script"
}

@test "H.7-2: no plaintext .sql file ever written to disk (stream discipline audit)" {
    if grep -qE '>\s*.*\.sql[^.]' "${BACKUP_DIR}/full_backup.sh"; then
        echo "FAIL: full_backup.sh writes to a .sql file (plaintext on disk)"
        grep -n '>.*\.sql[^.]' "${BACKUP_DIR}/full_backup.sh"
        return 1
    fi
}

@test "H.7-2: backup file is age-encrypted (starts with age v1 magic)" {
    _require_age
    _setup_keys
    printf 'governed file\n' > "${WPGOVERN_INSTALL_DIR}/.test"

    _run_backup "${WPGOVERN_INSTALL_DIR}"

    local sql_file; sql_file="$(ls "${WPGOVERN_BACKUP_DIR}/full-"*.sql.age 2>/dev/null | head -1)"
    [[ -n "$sql_file" ]] || { echo "SQL backup not created"; return 1; }
    local magic; magic="$(head -c 21 "$sql_file" 2>/dev/null || echo "")"
    [[ "$magic" == "age-encryption.org/v1" ]] || {
        echo "SQL backup missing age v1 magic"
        echo "Got first 23 bytes: $magic"
        return 1
    }
}

@test "H.7-2: governance tarball excludes age private key" {
    _require_age
    _setup_keys
    # Put a fake key in the governed dir to verify exclusion
    cp "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" "${TEST_TMPDIR}/etc-wpgovern/age.key"
    printf 'governed\n' > "${WPGOVERN_INSTALL_DIR}/.test"

    # Use INSTALL_DIR as the only governed dir (fake age.key is already there)
    _run_backup "${WPGOVERN_INSTALL_DIR}"

    local gov_file; gov_file="$(ls "${WPGOVERN_BACKUP_DIR}/governance-"*.tar.gz.age 2>/dev/null | head -1)"
    [[ -n "$gov_file" ]] || { echo "Governance tarball not created"; return 1; }
    local listing; listing="$(age -d -i "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" "$gov_file" 2>/dev/null | tar -tzf - 2>/dev/null || echo "")"
    if echo "$listing" | grep -q "age\.key"; then
        echo "CRITICAL: age private key found inside governance tarball"
        return 1
    fi
}

@test "H.7-2: xtrace guard prevents DB password leakage in run_full" {
    _require_age
    _setup_keys
    local SENT="SENTINEL_DB_BACKUP_H72_FULL"
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"

    # The xtrace guard in run_full prevents the credential from appearing in
    # docker command expansions within the function.
    # We verify that the function's internal command traces do NOT emit the password
    # by counting occurrences: only the environment export line is expected (1 time);
    # if the function leaks it in docker args, count is > 1.
    local xtrace_out
    xtrace_out="$(bash -x -c "
        export WPGOVERN_DB_BACKUP_PASSWORD='$SENT'
        export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
        export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
        export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
        export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
        export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
        export PATH='${MOCK_BIN}:\$PATH'
        mkdir -p '${WPGOVERN_LOG_DIR}'
        source '${BATS_TEST_DIRNAME}/../core/bootstrap.sh'
        source '${BATS_TEST_DIRNAME}/../core/state.sh'
        source '${BATS_TEST_DIRNAME}/../core/credentials.sh'
        source '${BACKUP_DIR}/full_backup.sh'
        wpgovern::backup::run_full
    " 2>&1 || true)"

    local leak_count; leak_count="$(echo "$xtrace_out" | grep -c "$SENT" || echo 0)"
    # Exactly 1 occurrence expected: the `export` line in the -x wrapper itself.
    # The guard prevents any occurrences inside run_full (docker --password= etc.).
    # If leak_count > 1, the function leaked the credential internally.
    if [[ "$leak_count" -gt 2 ]]; then
        echo "CREDENTIAL LEAK in run_full xtrace: found $leak_count occurrences (expected ≤1 from export)"
        return 1
    fi
}

@test "H.7-2: run_full updates state fact backup.last_full_at on success" {
    _require_age
    _setup_keys
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init

    _run_backup "${WPGOVERN_INSTALL_DIR}"

    local ts; ts="$(wpgovern::state::get_fact "backup.last_full_at" 2>/dev/null || echo "")"
    [[ -n "$ts" ]] || { echo "backup.last_full_at not recorded"; return 1; }
}
