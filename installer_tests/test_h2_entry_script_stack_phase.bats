#!/usr/bin/env bats
# =============================================================================
# test_h2_entry_script_stack_phase.bats — Real integration: stack phase
#
# H.2.1-11: exercises the actual entry script with mocked docker compose.
# This test WOULD HAVE CAUGHT H.2.1-1 (top-level local runtime abort) had it
# existed in H.2. The test verifies that mark_phase_complete "stack" is
# recorded after a successful mock docker compose run.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

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

    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "$MOCK_BIN"
    REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_stack_mock_installer() {
    local tmprepo="$1"
    mkdir -p "${tmprepo}/core" "${tmprepo}/modules/host" "${tmprepo}/modules/stack"

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

    # No-op stack modules — entry script sources these; we verify stack phase
    # completes via state, not by running real generators
    cat > "${tmprepo}/modules/stack/credentials.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::credentials::ensure() { return 0; }
MOCK
    cat > "${tmprepo}/modules/stack/images.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::images::pin() { return 0; }
MOCK
    for gen in compose caddyfile mycnf; do
        cat > "${tmprepo}/modules/stack/${gen}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::${gen}::generate() { return 0; }
MOCK
    done

    # No-op db modules (H.3)
    mkdir -p "${tmprepo}/modules/db"
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

_make_docker_mock_healthy() {
    local mock_bin="$1"
    local call_count_file="${TEST_TMPDIR}/docker_calls"
    echo "0" > "$call_count_file"

    # docker compose: up -d succeeds; ps returns healthy JSON after 1 call
    cat > "${mock_bin}/docker" << MOCK
#!/usr/bin/env bash
# Count calls to docker compose ps
if [[ "\$1" == "compose" && "\$2" == "up" ]]; then
    exit 0
fi
if [[ "\$1" == "compose" && "\$2" == "ps" ]]; then
    # Return empty (no unhealthy containers) — health wait loop exits
    echo '[]'
    exit 0
fi
exit 0
MOCK
    chmod +x "${mock_bin}/docker"
}

@test "H.2.1-11: entry script stack phase completes with mocked docker compose" {
    local tmprepo="${TEST_TMPDIR}/installer_stack"
    _make_stack_mock_installer "$tmprepo"
    _make_docker_mock_healthy "$MOCK_BIN"

    # Pre-seed host phase as complete so we only test stack phase
    local state_file="${TEST_TMPDIR}/install/.state.json"
    cat > "$state_file" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "db"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash -c "
        export PATH='${MOCK_BIN}:/usr/bin:/bin'
        bash '${tmprepo}/wpgovern-install.sh' --env-file '${ENV_FILE}'
    "
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local phases
    phases="$(jq -r '.phases_complete | sort | join(",")' "$state_file")"
    [[ "$phases" == "db,host,stack" ]] || {
        echo "Expected db,host,stack — got: $phases. Output: $output"
        return 1
    }
}

@test "H.2.1-11: H.2.1-1 regression — health wait loop uses no top-level local" {
    # Direct assertion: no 'local' at top (non-function) scope in entry script
    # that would abort at runtime under set -euo pipefail
    local installer="${REPO_DIR}/wpgovern-install.sh"
    local violations
    violations=$(grep -nE '^local ' "$installer" || true)
    [[ -z "$violations" ]] || {
        echo "Found top-level 'local' (H.2.1-1 regression): $violations"
        return 1
    }
}

@test "H.2.1-11: stack phase skips when already complete" {
    local tmprepo="${TEST_TMPDIR}/installer_stack2"
    _make_stack_mock_installer "$tmprepo"

    # Pre-seed both phases complete
    local state_file="${TEST_TMPDIR}/install/.state.json"
    cat > "$state_file" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already complete" ]]
}
