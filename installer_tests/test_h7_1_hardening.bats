#!/usr/bin/env bats
# test_h7_1_hardening.bats — H.7.1 regression tests (13 items)

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    SHIM_PATH="${TEST_TMPDIR}/bin/wpgovern-restore"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "${TEST_TMPDIR}/backups/binlogs" "${TEST_TMPDIR}/keys" \
             "$MOCK_BIN" "${TEST_TMPDIR}/bin"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/backups"
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/keys/age.key"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/keys/age.pub"
    export WPGOVERN_DB_BACKUP_PASSWORD="test_backup_pw"
    export WPGOVERN_STATE_LOCK="${TEST_TMPDIR}/wpgovern-state.lock"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_require_age() {
    command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1 \
        || skip "age tools not available"
}
_setup_keys() {
    age-keygen -o "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null
    age-keygen -y "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" > "${WPGOVERN_AGE_PUBLIC_KEY_PATH}" 2>/dev/null
    chmod 600 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
}
_install_test_shim() {
    cat > "$SHIM_PATH" << SHIM
#!/usr/bin/env bash
export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"
export WPGOVERN_STATE_FILE="${WPGOVERN_STATE_FILE}"
export WPGOVERN_INSTALL_DIR="${WPGOVERN_INSTALL_DIR}"
export WPGOVERN_LOG_DIR="${WPGOVERN_LOG_DIR}"
export WPGOVERN_BACKUP_DIR="${WPGOVERN_BACKUP_DIR}"
export WPGOVERN_AGE_PRIVATE_KEY_PATH="${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
export WPGOVERN_AGE_PUBLIC_KEY_PATH="${WPGOVERN_AGE_PUBLIC_KEY_PATH}"
export WPGOVERN_DB_BACKUP_PASSWORD="${WPGOVERN_DB_BACKUP_PASSWORD}"
exec "${REPO_DIR}/modules/backup/restore_entry.sh" "\$@"
SHIM
    chmod 755 "$SHIM_PATH"
}

# H.7.1-1: backup user --------------------------------------------------------

@test "H.7.1-1: no backup_user in modules/backup/*.sh (must use wpbackup)" {
    local found
    found="$(grep -rn "backup_user" "${REPO_DIR}/modules/backup/"*.sh 2>/dev/null || true)"
    [[ -z "$found" ]] || { echo "FAIL: backup_user found: $found"; return 1; }
}

@test "H.7.1-1: all four backup modules reference wpbackup username" {
    for f in full_backup.sh binlog_rotate.sh restore.sh restore_test.sh; do
        grep -q "wpbackup" "${REPO_DIR}/modules/backup/${f}" || {
            echo "FAIL: wpbackup not in ${f}"; return 1
        }
    done
}

# H.7.1-2: keygen recovery -----------------------------------------------

@test "H.7.1-2: keygen fixes mode without rotating when key is at 0644" {
    _require_age
    source "${BACKUP_DIR}/keygen.sh"
    age-keygen -o "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null
    chmod 644 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
    local pre_hash; pre_hash="$(sha256sum "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" | awk '{print $1}')"

    wpgovern::backup::generate_keypair

    local mode; mode="$(stat -c '%a' "${WPGOVERN_AGE_PRIVATE_KEY_PATH}")"
    [[ "$mode" == "600" ]] || { echo "Expected 0600, got $mode"; return 1; }

    local post_hash; post_hash="$(sha256sum "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" | awk '{print $1}')"
    [[ "$pre_hash" == "$post_hash" ]] || {
        echo "FAIL: existing key ROTATED on wrong-mode recovery (data loss)"; return 1
    }
    [[ -f "${WPGOVERN_AGE_PUBLIC_KEY_PATH}" ]] || { echo "Public key not derived"; return 1; }
}

# H.7.1-3: governance tarball PIPESTATUS ---------------------------------

@test "H.7.1-3: governance tarball audit: no || true masking tar exit codes" {
    local hits
    hits="$(grep -Ev "^[[:space:]]*#" "${REPO_DIR}/modules/backup/full_backup.sh" \
        | grep -E "tar[^|]+\|\|[[:space:]]*true" || true)"
    [[ -z "$hits" ]] || { echo "FAIL: || true on tar pipeline: $hits"; return 1; }
}

@test "H.7.1-3: governance backup FAILS when tar exits 2" {
    _require_age; _setup_keys
    mkdir -p "${WPGOVERN_INSTALL_DIR}"
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"
    cat > "${MOCK_BIN}/tar" << 'MOCK'
#!/usr/bin/env bash
exit 2
MOCK
    chmod +x "${MOCK_BIN}/tar"
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "-- MariaDB dump"
echo "CREATE TABLE \`wp_options\` (option_id BIGINT);"
echo "-- Dump completed on 2026-01-01  0:00:00"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"

    run bash -c "
export PATH='${MOCK_BIN}:/usr/bin:/bin'
export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
export WPGOVERN_AGE_PRIVATE_KEY_PATH='${WPGOVERN_AGE_PRIVATE_KEY_PATH}'
export WPGOVERN_DB_BACKUP_PASSWORD='${WPGOVERN_DB_BACKUP_PASSWORD}'
mkdir -p '${WPGOVERN_LOG_DIR}'
source '${CORE_DIR}/bootstrap.sh'
source '${CORE_DIR}/state.sh'
source '${CORE_DIR}/credentials.sh'
wpgovern::state::init
source '${BACKUP_DIR}/full_backup.sh'
_BACKUP_GOVERNED_DIRS=('${WPGOVERN_INSTALL_DIR}')
wpgovern::backup::run_full
"
    [[ "$status" -ne 0 ]] || { echo "FAIL: backup succeeded with fatal tar exit 2"; return 1; }
}

# H.7.1-4: binlog discovery -----------------------------------------------

@test "H.7.1-4: binlog rotation uses SHOW MASTER STATUS (not -newer binlog.index)" {
    grep -q "SHOW MASTER STATUS" "${REPO_DIR}/modules/backup/binlog_rotate.sh" || {
        echo "FAIL: SHOW MASTER STATUS not in binlog_rotate.sh"; return 1
    }
    # Check only non-comment lines for the inverted predicate
    local hits; hits="$(grep -Ev "^[[:space:]]*#" "${REPO_DIR}/modules/backup/binlog_rotate.sh"         | grep -E "\-newer.*binlog.index" || true)"
    [[ -z "$hits" ]] || { echo "FAIL: -newer binlog.index still in production code: $hits"; return 1; }
}

@test "H.7.1-4: binlog rotation skips new-active binlog post-FLUSH" {
    _require_age; _setup_keys
    export WPGOVERN_BINLOG_DIR="${TEST_TMPDIR}/binlogs"
    mkdir -p "${WPGOVERN_BINLOG_DIR}"
    printf 'data1\n' > "${WPGOVERN_BINLOG_DIR}/binlog.000001"
    printf 'data2\n' > "${WPGOVERN_BINLOG_DIR}/binlog.000002"
    printf 'active\n' > "${WPGOVERN_BINLOG_DIR}/binlog.000003"

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if echo "$*" | grep -q "SHOW MASTER STATUS"; then
    printf "binlog.000003\t12345\n"; exit 0
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/binlog_rotate.sh"
    wpgovern::backup::rotate_binlogs || true

    [[ ! -f "${WPGOVERN_BINLOG_DIR}/binlog.000001" ]] || { echo "binlog.000001 not encrypted+deleted"; return 1; }
    [[ ! -f "${WPGOVERN_BINLOG_DIR}/binlog.000002" ]] || { echo "binlog.000002 not encrypted+deleted"; return 1; }
    [[ -f "${WPGOVERN_BINLOG_DIR}/binlog.000003" ]]   || { echo "Active binlog.000003 was deleted (wrong!)"; return 1; }
}

# H.7.1-5: PITR target-range -----------------------------------------------

@test "H.7.1-5: restore.sh reads binlog_file state fact for PITR range" {
    grep -q "backup\.\${backup_ts\}\.binlog_file\|backup\.\${ts\}\.binlog_file\|backup_ts.*binlog_file\|binlog_file.*backup_ts" \
        "${REPO_DIR}/modules/backup/restore.sh" || {
        echo "FAIL: no binlog_file state-fact read in restore.sh"; return 1
    }
}

@test "H.7.1-5: full_backup.sh records master-data binlog position as state fact" {
    grep -q "CHANGE MASTER TO\|MASTER_LOG_FILE\|binlog_file\|binlog_pos" \
        "${REPO_DIR}/modules/backup/full_backup.sh" || {
        echo "FAIL: no master-data position extraction in full_backup.sh"; return 1
    }
}

# H.7.1-6: decryptability validation ----------------------------------------

@test "H.7.1-6: validate phase exits 10 on undecryptable backup file" {
    _require_age; _setup_keys
    local ts="20260101T120000Z"
    printf 'not-age-data\n' > "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age"
    printf 'not-age-data\n' > "${WPGOVERN_BACKUP_DIR}/governance-${ts}.tar.gz.age"
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "running"; exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/restore.sh"
    run _restore_phase_validate "$ts"
    [[ "$status" -eq 10 ]] || { echo "Expected exit 10, got $status"; return 1; }
}

@test "H.7.1-6: validate phase exits 0 when backup is real age-encrypted" {
    _require_age; _setup_keys
    local ts="20260101T120000Z"
    local pub; pub="$(cat "${WPGOVERN_AGE_PUBLIC_KEY_PATH}")"
    printf 'sql\n' | age -r "$pub" -o "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age" 2>/dev/null
    printf 'gov\n' | age -r "$pub" -o "${WPGOVERN_BACKUP_DIR}/governance-${ts}.tar.gz.age" 2>/dev/null
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "running"; exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/restore.sh"
    run _restore_phase_validate "$ts"
    [[ "$status" -eq 0 ]] || { echo "Expected exit 0, got $status"; return 1; }
}

# H.7.1-7: state path discovery ---------------------------------------------

@test "H.7.1-7: resolve_default_state_file returns installer path when env unset" {
    local orig="${WPGOVERN_STATE_FILE:-}"
    unset WPGOVERN_STATE_FILE 2>/dev/null || true
    local install_dir="${TEST_TMPDIR}/t_install"
    mkdir -p "$install_dir"
    printf '{}' > "${install_dir}/.wpgovern-installer-state.json"
    local result
    result="$(WPGOVERN_INSTALL_DIR="$install_dir" wpgovern::state::resolve_default_state_file 2>/dev/null || true)"
    [[ "$result" == "${install_dir}/.wpgovern-installer-state.json" ]] || {
        echo "Expected installer default, got: $result"; return 1
    }
    [[ -n "$orig" ]] && export WPGOVERN_STATE_FILE="$orig" || true
}

@test "H.7.1-7: resolve_default_state_file respects WPGOVERN_STATE_FILE override" {
    export WPGOVERN_STATE_FILE="/custom/override.json"
    local result; result="$(wpgovern::state::resolve_default_state_file 2>/dev/null)"
    [[ "$result" == "/custom/override.json" ]] || {
        echo "Expected override, got: $result"; return 1
    }
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
}

@test "H.7.1-7: no /var/lib/wpgovern hardcoding in entry scripts (audit)" {
    local found; found="$(grep -n "/var/lib/wpgovern/.state.json" \
        "${REPO_DIR}/modules/audit/entry.sh" \
        "${REPO_DIR}/modules/backup/restore_entry.sh" \
        "${REPO_DIR}/modules/backup/restore.sh" 2>/dev/null || true)"
    [[ -z "$found" ]] || { echo "FAIL: hardcoded /var/lib path: $found"; return 1; }
}

# H.7.1-8: systemd fail-closed -----------------------------------------------

@test "H.7.1-8: install_systemd fails when systemctl fails" {
    cat > "${MOCK_BIN}/systemctl" << 'MOCK'
#!/usr/bin/env bash
exit 1
MOCK
    chmod +x "${MOCK_BIN}/systemctl"
    PATH="${MOCK_BIN}:${PATH}"
    source "${BACKUP_DIR}/install_systemd.sh"
    run wpgovern::backup::install_systemd
    [[ "$status" -ne 0 ]] || { echo "FAIL: succeeded with failing systemctl"; return 1; }
}

@test "H.7.1-8: no || true on systemctl calls in install_systemd.sh (audit)" {
    local hits; hits="$(grep -Ev "^[[:space:]]*#" "${REPO_DIR}/modules/backup/install_systemd.sh" \
        | grep -E "systemctl.*\|\|[[:space:]]*true" || true)"
    [[ -z "$hits" ]] || { echo "FAIL: || true on systemctl (non-comment): $hits"; return 1; }
}

# H.7.1-9: subcommand validation -------------------------------------------

@test "H.7.1-9: unknown subcommand exits 2" {
    _install_test_shim
    run "$SHIM_PATH" nonsense
    [[ "$status" -eq 2 ]] || { echo "Expected 2, got $status"; return 1; }
}

@test "H.7.1-9: malformed timestamp exits 2" {
    _install_test_shim
    run "$SHIM_PATH" "20260524"
    [[ "$status" -eq 2 ]] || { echo "Expected 2, got $status"; return 1; }
}

@test "H.7.1-9: valid timestamp proceeds past routing (not exit 2)" {
    _install_test_shim
    run "$SHIM_PATH" "20260524T030000Z"
    [[ "$status" -ne 2 ]] || { echo "Valid timestamp should not exit 2"; return 1; }
}

# H.7.1-10: restore_test cleanup -------------------------------------------

@test "H.7.1-10: restore_test.sh has EXIT backstop trap and explicit cleanup" {
    local src="${REPO_DIR}/modules/backup/restore_test.sh"
    grep -q "trap.*EXIT" "$src" || { echo "No EXIT trap"; return 1; }
    grep -q "_restore_test_cleanup" "$src" || { echo "No _restore_test_cleanup calls"; return 1; }
    grep -q "trap - EXIT" "$src" || { echo "No trap clearance"; return 1; }
}

# H.7.1-11: logical-completion verification ---------------------------------

@test "H.7.1-11: full_backup.sh verifies CREATE TABLE wp_options sentinel" {
    grep -q "wp_options" "${REPO_DIR}/modules/backup/full_backup.sh" || {
        echo "FAIL: no wp_options sentinel check in full_backup.sh"; return 1
    }
}

@test "H.7.1-11: full_backup.sh verifies Dump completed trailer sentinel" {
    grep -q "Dump completed on" "${REPO_DIR}/modules/backup/full_backup.sh" || {
        echo "FAIL: no Dump completed sentinel in full_backup.sh"; return 1
    }
}

@test "H.7.1-11: backup FAILS when dump has no wp_options table" {
    _require_age; _setup_keys
    mkdir -p "${WPGOVERN_INSTALL_DIR}"
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "-- MariaDB dump"
echo "-- Dump completed on 2026-01-01  0:00:00"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    run bash -c "
export PATH='${MOCK_BIN}:/usr/bin:/bin'
export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
export WPGOVERN_AGE_PRIVATE_KEY_PATH='${WPGOVERN_AGE_PRIVATE_KEY_PATH}'
export WPGOVERN_DB_BACKUP_PASSWORD='${WPGOVERN_DB_BACKUP_PASSWORD}'
mkdir -p '${WPGOVERN_LOG_DIR}'
source '${CORE_DIR}/bootstrap.sh'; source '${CORE_DIR}/state.sh'; source '${CORE_DIR}/credentials.sh'
wpgovern::state::init
source '${BACKUP_DIR}/full_backup.sh'
_BACKUP_GOVERNED_DIRS=('${WPGOVERN_INSTALL_DIR}')
wpgovern::backup::run_full"
    [[ "$status" -ne 0 ]] || { echo "FAIL: backup succeeded on logically-empty dump"; return 1; }
}

@test "H.7.1-11: backup FAILS when dump is truncated (no Dump completed trailer)" {
    _require_age; _setup_keys
    mkdir -p "${WPGOVERN_INSTALL_DIR}"
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "-- MariaDB dump"
echo "CREATE TABLE \`wp_options\` (option_id BIGINT);"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    run bash -c "
export PATH='${MOCK_BIN}:/usr/bin:/bin'
export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
export WPGOVERN_AGE_PUBLIC_KEY_PATH='${WPGOVERN_AGE_PUBLIC_KEY_PATH}'
export WPGOVERN_AGE_PRIVATE_KEY_PATH='${WPGOVERN_AGE_PRIVATE_KEY_PATH}'
export WPGOVERN_DB_BACKUP_PASSWORD='${WPGOVERN_DB_BACKUP_PASSWORD}'
mkdir -p '${WPGOVERN_LOG_DIR}'
source '${CORE_DIR}/bootstrap.sh'; source '${CORE_DIR}/state.sh'; source '${CORE_DIR}/credentials.sh'
wpgovern::state::init
source '${BACKUP_DIR}/full_backup.sh'
_BACKUP_GOVERNED_DIRS=('${WPGOVERN_INSTALL_DIR}')
wpgovern::backup::run_full"
    [[ "$status" -ne 0 ]] || { echo "FAIL: truncated dump accepted"; return 1; }
}

# H.7.1-12: state flock -----------------------------------------------------

@test "H.7.1-12: concurrent set_fact calls do not lose either update" {
    wpgovern::state::set_fact "race_key_a" "val_a" &
    local pa=$!
    wpgovern::state::set_fact "race_key_b" "val_b" &
    local pb=$!
    wait "$pa" "$pb"
    local ra; ra="$(jq -r '.host_facts.race_key_a // empty' "${WPGOVERN_STATE_FILE}")"
    local rb; rb="$(jq -r '.host_facts.race_key_b // empty' "${WPGOVERN_STATE_FILE}")"
    [[ "$ra" == "val_a" ]] || { echo "race_key_a lost (got: $ra)"; return 1; }
    [[ "$rb" == "val_b" ]] || { echo "race_key_b lost (got: $rb)"; return 1; }
}

@test "H.7.1-12: write functions have flock; get_fact does not (audit)" {
    local state_sh="${REPO_DIR}/core/state.sh"
    for fn in mark_phase_complete mark_phase_failed set_fact; do
        awk "/^wpgovern::state::${fn}/,/^}/" "$state_sh" | grep -q "flock" || {
            echo "FAIL: ${fn} missing flock"; return 1
        }
    done
    awk '/^wpgovern::state::get_fact/,/^}/' "$state_sh" | grep -q "flock" && {
        echo "FAIL: get_fact over-locked with flock"; return 1
    } || true
}

# H.7.1-13: container readiness polling ------------------------------------

@test "H.7.1-13: both entry scripts have mariadb-admin polling (structural)" {
    for f in full_backup_entry.sh binlog_rotate_entry.sh; do
        grep -q "mariadb-admin ping" "${REPO_DIR}/modules/backup/${f}" || {
            echo "FAIL: no mariadb-admin ping in ${f}"; return 1
        }
        grep -q "for _ready_check" "${REPO_DIR}/modules/backup/${f}" || {
            echo "FAIL: no for _ready_check loop in ${f}"; return 1
        }
    done
}
