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
    [[ "$phases" == "db,host,stack" ]] || {
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
  "phases_complete": ["host", "stack", "db"],
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
