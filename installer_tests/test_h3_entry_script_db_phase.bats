#!/usr/bin/env bats
# =============================================================================
# test_h3_entry_script_db_phase.bats — Real entry-script integration for db phase
#
# H.3-10: copies installer to temp dir, mocks docker + age, verifies
# phases_complete includes "db" after successful run.
# Same shape as test_h2_entry_script_stack_phase.bats from H.2.1.
# =============================================================================

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    ENV_FILE="${TEST_TMPDIR}/wpgovern.env"
    cat > "$ENV_FILE" << ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
WPGOVERN_DOMAIN="test.example.com"
WPGOVERN_DB_ROOT_PASSWORD="testroot1234567890123456789012"
WPGOVERN_DB_WP_PASSWORD="testwp12345678901234567890123"
WPGOVERN_DB_BACKUP_PASSWORD="testbkup1234567890123456789012"
ENV

    STATE_FILE="${TEST_TMPDIR}/install/.state.json"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_db_mock_installer() {
    local tmprepo="$1"
    mkdir -p "${tmprepo}/core" "${tmprepo}/modules/host" \
             "${tmprepo}/modules/stack" "${tmprepo}/modules/db"

    cp "${REPO_DIR}/wpgovern-install.sh" "${tmprepo}/"
    cp "${REPO_DIR}/core/bootstrap.sh"   "${tmprepo}/core/"
    cp "${REPO_DIR}/core/state.sh"        "${tmprepo}/core/"
    cp "${REPO_DIR}/core/credentials.sh"   "${tmprepo}/core/"

    # No-op host modules
    for mod in packages kernel swap firewall docker logrotate; do
        cat > "${tmprepo}/modules/host/${mod}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::host::${mod}::install()    { return 0; }
wpgovern::host::${mod}::tune()       { return 0; }
wpgovern::host::${mod}::create()     { return 0; }
wpgovern::host::${mod}::configure()  { return 0; }
MOCK
    done

    # No-op stack modules
    cat > "${tmprepo}/modules/stack/credentials.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::credentials::ensure() { return 0; }
_wpgovern_credentials_persist() { return 0; }
MOCK
    for gen in images compose caddyfile mycnf; do
        cat > "${tmprepo}/modules/stack/${gen}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::${gen}::pin()      { return 0; }
wpgovern::stack::${gen}::generate() { return 0; }
MOCK
    done

    # No-op db modules — we test only that the entry script wiring is correct
    cat > "${tmprepo}/modules/db/wait.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::wait_for_ready() { return 0; }
MOCK
    cat > "${tmprepo}/modules/db/credentials.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::credentials::ensure_backup_password() { return 0; }
wpgovern::db::credentials::generate_age_key()       { return 0; }
wpgovern::db::credentials::encrypt_state()          { return 0; }
MOCK
    cat > "${tmprepo}/modules/db/users.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::users::verify_application_user() { return 0; }
wpgovern::db::users::create_backup_user()      { return 0; }
MOCK
    # No-op wp modules (H.4)
    mkdir -p "${tmprepo}/modules/wp"
    cat > "${tmprepo}/modules/wp/prepare.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::prepare() { return 0; }
MOCK
    cat > "${tmprepo}/modules/wp/provision.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::provision() { return 0; }
MOCK
    cat > "${tmprepo}/modules/wp/secure.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::secure::ensure_auth_keys() { return 0; }
wpgovern::wp::secure::generate_config()  { return 0; }
MOCK
}

@test "H.3-10: entry script db phase completes with phases_complete=[host,stack,db]" {
    local tmprepo="${TEST_TMPDIR}/installer_db"
    _make_db_mock_installer "$tmprepo"

    # Pre-seed host+stack complete
    cat > "$STATE_FILE" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local phases
    phases="$(jq -r '.phases_complete | sort | join(",")' "$STATE_FILE")"
    [[ "$phases" == "db,host,stack,wp" ]] || {
        echo "Expected db,host,stack — got: $phases"; return 1
    }
}

@test "H.3-10: db phase skips when already complete" {
    local tmprepo="${TEST_TMPDIR}/installer_db2"
    _make_db_mock_installer "$tmprepo"

    # Pre-seed all three phases complete
    cat > "$STATE_FILE" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack", "db", "wp"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already complete" ]]
}

@test "H.3-10: db phase dispatch sources all three db modules" {
    local installer="${REPO_DIR}/wpgovern-install.sh"
    grep -q "modules/db/wait.sh"        "$installer" || { echo "wait.sh not sourced"; return 1; }
    grep -q "modules/db/credentials.sh" "$installer" || { echo "credentials.sh not sourced"; return 1; }
    grep -q "modules/db/users.sh"       "$installer" || { echo "users.sh not sourced"; return 1; }
    grep -q "wpgovern::db::wait_for_ready"                 "$installer" || { echo "wait_for_ready not called"; return 1; }
    grep -q "wpgovern::db::credentials::ensure_backup_password" "$installer" || { echo "ensure_backup_password not called"; return 1; }
    grep -q "wpgovern::db::users::create_backup_user"     "$installer" || { echo "create_backup_user not called"; return 1; }
}

# ---------------------------------------------------------------------------
# H.3.1-1 — Cross-phase resumability test (real modules, not no-op stubs)
# H.3.1-2 — xtrace leak protection test
# ---------------------------------------------------------------------------

@test "H.3.1-1: db phase resumes with _wpgovern_credentials_persist available (real modules)" {
    # This is the regression test for the cross-phase helper defect.
    # Run the entry script with state showing host+stack complete so db phase runs.
    # Uses real db modules — not no-op stubs.
    local tmprepo="${TEST_TMPDIR}/installer_real_db"
    _make_db_mock_installer "$tmprepo"

    # Override db modules with REAL modules (not no-ops)
    cp "${REPO_DIR}/modules/db/wait.sh"        "${tmprepo}/modules/db/"
    cp "${REPO_DIR}/modules/db/credentials.sh" "${tmprepo}/modules/db/"
    cp "${REPO_DIR}/modules/db/users.sh"       "${tmprepo}/modules/db/"

    # Add age-keygen + age + docker mocks (all succeed)
    local mock_bin="${TEST_TMPDIR}/mock_real_db"
    mkdir -p "$mock_bin"

    cat > "${mock_bin}/docker" << 'DOCKERMOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then echo '{"State":"running"}'; exit 0; fi
if [[ "$1 $2" == "compose exec" ]]; then
    for arg in "$@"; do
        [[ "$arg" == *"SELECT 1 FROM"*"wpuser"* ]] && echo "1" && exit 0
        [[ "$arg" == *"SELECT 1 FROM"*"wpbackup"* ]] && exit 0
        [[ "$arg" == *"SELECT 1"* ]] && exit 0
        [[ "$arg" == *"USE wordpress"* ]] && exit 0
        [[ "$arg" == *"CREATE USER"* ]] && exit 0
    done
fi
exit 0
DOCKERMOCK
    chmod +x "${mock_bin}/docker"

    command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1 || {
        skip "age/age-keygen not installed"
    }

    # H.3.1.1: override env file with BLANK backup password to exercise the generation path.
    # setup() pre-populates WPGOVERN_DB_BACKUP_PASSWORD with a 30-char value; this test's
    # WHOLE POINT is to verify generation runs when the password IS BLANK.
    # Passwords ≥32 chars to pass validation.
    cat > "$ENV_FILE" << ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
WPGOVERN_DOMAIN="test.example.com"
WPGOVERN_DB_ROOT_PASSWORD="testroot1234567890123456789012abcd"
WPGOVERN_DB_WP_PASSWORD="testwp12345678901234567890123abcde"
WPGOVERN_DB_BACKUP_PASSWORD=
ENV
    chmod 600 "$ENV_FILE"

    # Pre-seed host + stack complete; db blank
    cat > "$STATE_FILE" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack"],
  "phases_failed": [],
  "host_facts": {"bootstrap.env_file_path": "${ENV_FILE}"}
}
STATE

    run bash -c "
        export PATH='${mock_bin}:/usr/bin:/bin'
        bash '${tmprepo}/wpgovern-install.sh' --env-file '${ENV_FILE}'
    "
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    # _wpgovern_credentials_persist must have run — backup password persisted to env file
    local bkup_pw
    bkup_pw="$(grep "^WPGOVERN_DB_BACKUP_PASSWORD=" "$ENV_FILE" | cut -d= -f2 | tr -d '"')"
    [[ -n "$bkup_pw" ]] || { echo "WPGOVERN_DB_BACKUP_PASSWORD not persisted to env file"; return 1; }
    [[ "${#bkup_pw}" -ge 32 ]] || { echo "Password too short: $bkup_pw"; return 1; }

    # db phase must be marked complete
    local phases
    phases="$(jq -r '.phases_complete | sort | join(",")' "$STATE_FILE")"
    [[ "$phases" =~ "db" ]] || { echo "db not in phases_complete: $phases"; return 1; }
}

@test "H.3.1-2: db phase under bash -x produces zero credential leaks" {
    # Sentinel passwords
    local SENT_ROOT="XTRACE_SENTINEL_ROOT_H31_AAAA"
    local SENT_WP="XTRACE_SENTINEL_WP_H31_BBBB__"
    local SENT_BACKUP="XTRACE_SENTINEL_BKP_H31_CCCC"

    # Mock docker: all commands succeed
    local mock_bin="${TEST_TMPDIR}/mock_xtrace"
    mkdir -p "$mock_bin"
    cat > "${mock_bin}/docker" << 'DOCKERMOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then echo '{"State":"running"}'; exit 0; fi
if [[ "$1 $2" == "compose exec" ]]; then
    for arg in "$@"; do
        [[ "$arg" == *"SELECT 1 FROM"*"wpuser"* ]] && echo "1" && exit 0
        [[ "$arg" == *"SELECT 1"* ]] && exit 0
        [[ "$arg" == *"USE wordpress"* ]] && exit 0
        [[ "$arg" == *"CREATE USER"* ]] && exit 0
    done
fi
exit 0
DOCKERMOCK
    chmod +x "${mock_bin}/docker"

    command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1 || {
        skip "age/age-keygen not installed"
    }

    local xtrace_state="${TEST_TMPDIR}/xtrace_state.json"
    local xtrace_env="${TEST_TMPDIR}/xtrace.env"
    cat > "$xtrace_env" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_LOG_DIR=${TEST_TMPDIR}/logs
WPGOVERN_STATE_FILE=${xtrace_state}
WPGOVERN_DOMAIN=test.example.com
WPGOVERN_DB_ROOT_PASSWORD=${SENT_ROOT}
WPGOVERN_DB_WP_PASSWORD=${SENT_WP}
WPGOVERN_DB_BACKUP_PASSWORD=${SENT_BACKUP}
ENV

    # H.3.1.1: export sentinels OUTSIDE bash -x scope so the test's own export statements
    # don't appear in xtrace output. The xtrace protection protects FUNCTIONS — not test setup.
    export PATH="${mock_bin}:/usr/bin:/bin"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${xtrace_state}"
    export WPGOVERN_ENV_FILE_PATH="${xtrace_env}"
    export WPGOVERN_DB_ROOT_PASSWORD="$SENT_ROOT"
    export WPGOVERN_DB_WP_PASSWORD="$SENT_WP"
    export WPGOVERN_DB_BACKUP_PASSWORD="$SENT_BACKUP"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

    # Enter bash -x only for function calls (env already populated above)
    local combined_output
    combined_output="$(bash -x << INNER 2>&1
source '${REPO_DIR}/core/bootstrap.sh'
source '${REPO_DIR}/core/state.sh'
source '${REPO_DIR}/core/credentials.sh'
wpgovern::state::init
wpgovern::state::set_fact 'bootstrap.env_file_path' '${xtrace_env}'
source '${REPO_DIR}/modules/db/wait.sh'
wpgovern::db::wait_for_ready
source '${REPO_DIR}/modules/db/credentials.sh'
wpgovern::db::credentials::generate_age_key
wpgovern::db::credentials::encrypt_state
source '${REPO_DIR}/modules/db/users.sh'
wpgovern::db::users::verify_application_user
wpgovern::db::users::create_backup_user
INNER
)"

    # WARNING must appear (xtrace protection activated)
    echo "$combined_output" | grep -q "xtrace.*active\|xtrace/debug mode" || {
        echo "Expected xtrace protection WARNING in output"
        return 1
    }

    # Scan ONLY output AFTER the WARNING line — that's when xtrace protection activated
    local after_warning
    after_warning="$(echo "$combined_output" | awk '/xtrace.*active|xtrace.debug mode/{found=1; next} found')"

    for sentinel in "$SENT_ROOT" "$SENT_WP" "$SENT_BACKUP"; do
        if echo "$after_warning" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK under xtrace AFTER protection activated: '$sentinel'"
            echo "--- leak context ---"
            echo "$after_warning" | grep -F "$sentinel" | head -3
            return 1
        fi
    done
}
