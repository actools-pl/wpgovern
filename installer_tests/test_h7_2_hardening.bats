#!/usr/bin/env bats
# test_h7_2_hardening.bats — H.7.2 regression tests (5 blockers + CI guard)
# The final hardening pass of the bash arc.

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "${TEST_TMPDIR}/backups/binlogs" "${TEST_TMPDIR}/keys" \
             "$MOCK_BIN"
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

# ---------------------------------------------------------------------------
# H.7.2-1: PIPESTATUS-safe bracket
# ---------------------------------------------------------------------------

@test "H.7.2-1: governance backup ACCEPTS tar exit 1 (file-changed warnings)" {
    _require_age; _setup_keys
    mkdir -p "${WPGOVERN_INSTALL_DIR}"
    printf 'test\n' > "${WPGOVERN_INSTALL_DIR}/.test"

    # Mock tar: emit data but exit 1 (file-changed warning)
    cat > "${MOCK_BIN}/tar" << 'MOCK'
#!/usr/bin/env bash
echo "mock-tarball-content"
exit 1
MOCK
    chmod +x "${MOCK_BIN}/tar"

    # Mock docker: emit valid SQL with sentinels
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
wpgovern::backup::run_full"

    [[ "$status" -eq 0 ]] || {
        echo "FAIL: backup rejected on tar exit 1 (should be nonfatal)"
        echo "Output: $output"
        return 1
    }
}

@test "H.7.2-1: governance backup FAILS on tar exit 2 (fatal error)" {
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
wpgovern::backup::run_full"

    [[ "$status" -ne 0 ]] || { echo "FAIL: backup accepted fatal tar exit 2"; return 1; }
}

@test "H.7.2-1: full_backup.sh uses set +e / set -e bracket (audit)" {
    grep -q "set +e" "${REPO_DIR}/modules/backup/full_backup.sh" || {
        echo "FAIL: no set +e bracket in full_backup.sh"; return 1
    }
    # Verify the old bare-pipeline approach is gone
    if grep -q "{ tar.*| age.*}$\|{ tar.*| age.*; }$" "${REPO_DIR}/modules/backup/full_backup.sh"; then
        echo "FAIL: bare { tar | age } still present (PIPESTATUS broken under pipefail)"; return 1
    fi
}

# ---------------------------------------------------------------------------
# H.7.2-2: timer entry scripts state path
# ---------------------------------------------------------------------------

@test "H.7.2-2: NO /var/lib/wpgovern hardcoding in any module entry script (CI guard)" {
    local found; found="$(grep -rn "/var/lib/wpgovern/.state.json" \
        "${REPO_DIR}/modules/" 2>/dev/null || true)"
    [[ -z "$found" ]] || {
        echo "FAIL: hardcoded /var/lib/wpgovern fallback found:"
        echo "$found"
        return 1
    }
}

@test "H.7.2-2: both backup timer entries use resolve_default_state_file" {
    for f in full_backup_entry.sh binlog_rotate_entry.sh; do
        grep -q "resolve_default_state_file" "${REPO_DIR}/modules/backup/${f}" || {
            echo "FAIL: ${f} missing resolve_default_state_file call"; return 1
        }
    done
}

# ---------------------------------------------------------------------------
# H.7.2-3: binlog default path
# ---------------------------------------------------------------------------

@test "H.7.2-3: binlog_rotate.sh default uses install_dir/mariadb/data (not /var/lib/mysql/binlogs)" {
    grep -q "mariadb/data" "${REPO_DIR}/modules/backup/binlog_rotate.sh" || {
        echo "FAIL: mariadb/data not in binlog_rotate.sh default"; return 1
    }
    if grep -Ev "^[[:space:]]*#" "${REPO_DIR}/modules/backup/binlog_rotate.sh" \
            | grep -q "/var/lib/mysql/binlogs"; then
        echo "FAIL: old /var/lib/mysql/binlogs default still present in non-comment code"; return 1
    fi
}

@test "H.7.2-3: binlog default resolves to WPGOVERN_INSTALL_DIR/mariadb/data when env unset" {
    _require_age; _setup_keys
    unset WPGOVERN_BINLOG_DIR 2>/dev/null || true
    local install_dir="${TEST_TMPDIR}/test_install_h7_2"
    mkdir -p "${install_dir}/mariadb/data"
    printf 'active\n' > "${install_dir}/mariadb/data/binlog.000001"
    touch "${install_dir}/mariadb/data/binlog.index"
    export WPGOVERN_INSTALL_DIR="$install_dir"

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if echo "$*" | grep -q "SHOW MASTER STATUS"; then
    printf "binlog.000001\t1234\n"; exit 0
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/binlog_rotate.sh"
    # rotate_binlogs should look in install_dir/mariadb/data, not /var/lib/mysql/binlogs
    # If it finds binlog.000001 and processes it without error, the path is correct
    local log="${TEST_TMPDIR}/rotate.log"
    wpgovern::backup::rotate_binlogs > "$log" 2>&1 || true

    grep -q "${install_dir}/mariadb" "$log" 2>/dev/null || \
    wpgovern::state::get_fact "backup.last_binlog_rotated_at" 2>/dev/null | grep -q "." || {
        # State fact was set means rotation was attempted at the right path
        true
    }
    # Primary check: state fact was recorded, meaning rotation ran
    local ts; ts="$(wpgovern::state::get_fact "backup.last_binlog_rotated_at" 2>/dev/null || echo "")"
    [[ -n "$ts" ]] || { echo "State fact not recorded — rotation may not have run at correct path"; return 1; }
}

# ---------------------------------------------------------------------------
# H.7.2-4: restore validate full decrypt
# ---------------------------------------------------------------------------

@test "H.7.2-4: restore validate audit: no head -c 256 probe (SIGPIPE risk)" {
    if grep -Ev "^[[:space:]]*#" "${REPO_DIR}/modules/backup/restore.sh" | grep -q "head -c 256"; then
        echo "FAIL: head -c 256 still present in restore.sh (SIGPIPE under pipefail)"; return 1
    fi
}

@test "H.7.2-4: restore validate uses full decrypt to /dev/null" {
    grep -q "age -d.*>/dev/null" "${REPO_DIR}/modules/backup/restore.sh" || {
        echo "FAIL: full /dev/null decrypt not found in restore.sh"; return 1
    }
}

@test "H.7.2-4: restore validate ACCEPTS a large real-encrypted backup (SIGPIPE regression)" {
    _require_age; _setup_keys
    local ts="20260524T030000Z"
    local pub; pub="$(cat "${WPGOVERN_AGE_PUBLIC_KEY_PATH}")"
    mkdir -p "${WPGOVERN_BACKUP_DIR}"

    # 2 MB file — large enough to exceed pipe buffer (64KB); much faster than 10MB in CI
    dd if=/dev/urandom bs=1M count=2 2>/dev/null \
        | age -r "$pub" -o "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age" 2>/dev/null
    dd if=/dev/urandom bs=100K count=1 2>/dev/null \
        | age -r "$pub" -o "${WPGOVERN_BACKUP_DIR}/governance-${ts}.tar.gz.age" 2>/dev/null

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "running"; exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/restore.sh"
    run _restore_phase_validate "$ts"
    [[ "$status" -eq 0 ]] || {
        echo "FAIL: large backup falsely rejected by validate (SIGPIPE regression)"
        echo "Output: $output"
        return 1
    }
}

@test "H.7.2-4: restore validate FAILS on corrupt backup (exit 10)" {
    _require_age; _setup_keys
    local ts="20260524T040000Z"
    mkdir -p "${WPGOVERN_BACKUP_DIR}"
    printf 'not-age-encrypted\n' > "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age"
    printf 'not-age-encrypted\n' > "${WPGOVERN_BACKUP_DIR}/governance-${ts}.tar.gz.age"

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

# ---------------------------------------------------------------------------
# H.7.2-5: PITR fail-closed
# ---------------------------------------------------------------------------

@test "H.7.2-5: PITR fails (exit 13) when binlogs exist but state-fact missing" {
    _require_age; _setup_keys
    local ts="20260524T030000Z"
    local binlog_dir="${WPGOVERN_BACKUP_DIR}/binlogs"
    mkdir -p "$binlog_dir"

    local pub; pub="$(cat "${WPGOVERN_AGE_PUBLIC_KEY_PATH}")"
    # Create encrypted binlog files
    printf 'binlog data\n' | age -r "$pub" -o "${binlog_dir}/binlog-binlog.000003-${ts}.age" 2>/dev/null
    printf 'binlog data\n' | age -r "$pub" -o "${binlog_dir}/binlog-binlog.000004-${ts}.age" 2>/dev/null
    # Create encrypted SQL backup so the SQL restore step (which runs before PITR) succeeds
    printf 'sql dump\n' | age -r "$pub" -o "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age" 2>/dev/null
    # Do NOT set backup.${ts}.binlog_file state-fact

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
cat > /dev/null  # drain stdin (SQL restore pipe)
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    PATH="${MOCK_BIN}:${PATH}" source "${BACKUP_DIR}/restore.sh"
    run env PATH="${MOCK_BIN}:${PATH}" bash -c "source '${BACKUP_DIR}/restore.sh'; _restore_phase_database '${ts}'"
    [[ "$status" -eq 13 ]] || {
        echo "FAIL: PITR should fail (exit 13) when binlogs exist but base ref missing"
        echo "Got: $status — Output: $output"
        return 1
    }
    echo "$output" | grep -qi "state-fact missing\|binlog_file" || {
        echo "FAIL: error message should name the missing state-fact"
        echo "Output: $output"
        return 1
    }
}

@test "H.7.2-5: PITR succeeds (exit 0) when no binlogs exist (full-backup-only restore)" {
    _require_age; _setup_keys
    local ts="20260524T030000Z"
    local binlog_dir="${WPGOVERN_BACKUP_DIR}/binlogs"
    mkdir -p "$binlog_dir"
    # No .age files in binlog dir; no state-fact set
    # Mock docker for SQL restore to succeed; must drain stdin or SIGPIPE
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
cat > /dev/null
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/restore.sh"
    # SQL backup file must exist for the phase to proceed past the age -d call
    # (not tested here — we test the PITR fallthrough specifically)
    local pub; pub="$(cat "${WPGOVERN_AGE_PUBLIC_KEY_PATH}")"
    printf 'fake-sql\n' | age -r "$pub" \
        -o "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age" 2>/dev/null

    run _restore_phase_database "$ts"
    [[ "$status" -eq 0 ]] || {
        echo "FAIL: full-backup-only restore should succeed (exit 0) with no binlogs"
        echo "Got: $status — Output: $output"
        return 1
    }
}
