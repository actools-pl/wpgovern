#!/usr/bin/env bats
# =============================================================================
# test_h1_entry_script.bats — Entry script dispatch and state-write tests
#
# Tests verify structural properties of the entry script: argument handling,
# help text, module sourcing pattern. Tests that require root/apt are skipped
# by mocking the sourced modules (Lesson 2: call-site coverage discipline).
# =============================================================================

INSTALLER="${BATS_TEST_DIRNAME}/../wpgovern-install.sh"
CORE_DIR="${BATS_TEST_DIRNAME}/../core"
MODULES_HOST_DIR="${BATS_TEST_DIRNAME}/../modules/host"

# ---------------------------------------------------------------------------
# Helper: create a minimal valid env file in a temp dir
# ---------------------------------------------------------------------------
setup() {
    TEST_TMPDIR="$(mktemp -d)"
    ENV_FILE="${TEST_TMPDIR}/wpgovern.env"
    cat > "$ENV_FILE" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
WPGOVERN_DOMAIN="test.example.com"
WPGOVERN_DB_ROOT_PASSWORD="testroot1234567890123456789012"
WPGOVERN_DB_WP_PASSWORD="testwp12345678901234567890123"
WPGOVERN_DB_BACKUP_PASSWORD="testbkup1234567890123456789012"
ENV
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

@test "entry script exists and is executable" {
    [[ -x "$INSTALLER" ]]
}

@test "entry script requires --env-file argument" {
    run bash "$INSTALLER"
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "--env-file is required" ]]
}

@test "entry script errors clearly when env file is missing" {
    run bash "$INSTALLER" --env-file /nonexistent/wpgovern.env
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "env file not found" ]] || [[ "$output" =~ "environment file not found" ]]
}

@test "entry script --help exits 0 with usage text" {
    run bash "$INSTALLER" --help
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "USAGE" ]]
    [[ "$output" =~ "--env-file" ]]
}

@test "entry script -h is alias for --help" {
    run bash "$INSTALLER" -h
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "USAGE" ]]
}

@test "entry script rejects unknown arguments" {
    run bash "$INSTALLER" --unknown-arg
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "unknown argument" ]]
}

# ---------------------------------------------------------------------------
# Structure tests (Lesson 2: call-site coverage at the wiring layer)
# ---------------------------------------------------------------------------

@test "entry script sets -euo pipefail" {
    grep -q "set -euo pipefail" "$INSTALLER"
}

@test "entry script sources core/bootstrap.sh" {
    grep -q "core/bootstrap.sh" "$INSTALLER"
}

@test "entry script sources core/state.sh" {
    grep -q "core/state.sh" "$INSTALLER"
}

@test "entry script calls wpgovern::bootstrap::load_env" {
    grep -q "wpgovern::bootstrap::load_env" "$INSTALLER"
}

@test "entry script calls wpgovern::state::init" {
    grep -q "wpgovern::state::init" "$INSTALLER"
}

@test "entry script calls wpgovern::state::phase_complete for host gate" {
    grep -q 'wpgovern::state::phase_complete "host"' "$INSTALLER"
}

@test "entry script calls wpgovern::state::mark_phase_complete for host" {
    grep -q 'wpgovern::state::mark_phase_complete "host"' "$INSTALLER"
}

@test "entry script sources all six host modules" {
    grep -q "modules/host/packages.sh"  "$INSTALLER"
    grep -q "modules/host/kernel.sh"    "$INSTALLER"
    grep -q "modules/host/swap.sh"      "$INSTALLER"
    grep -q "modules/host/firewall.sh"  "$INSTALLER"
    grep -q "modules/host/docker.sh"    "$INSTALLER"
    grep -q "modules/host/logrotate.sh" "$INSTALLER"
}

@test "entry script calls all six host module functions" {
    grep -q "wpgovern::host::packages::install"  "$INSTALLER"
    grep -q "wpgovern::host::kernel::tune"        "$INSTALLER"
    grep -q "wpgovern::host::swap::create"        "$INSTALLER"
    grep -q "wpgovern::host::firewall::configure" "$INSTALLER"
    grep -q "wpgovern::host::docker::install"     "$INSTALLER"
    grep -q "wpgovern::host::logrotate::configure" "$INSTALLER"
}

# ---------------------------------------------------------------------------
# State-write verification (mocked environment, no root required)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# H.1.1-13 — Real integration test (replaces manual orchestration tests)
# H.1.1-2 — CLI/env precedence test
# H.1.1-5 — jq preflight ordering test
# These tests ACTUALLY run bash wpgovern-install.sh with mocked modules.
# The manual orchestration tests reproduced the sequencing themselves —
# which is why the --force-firewall env-override bug escaped detection.
# ---------------------------------------------------------------------------

_make_mock_installer() {
    # Copy installer + core to tmprepo; replace host and stack modules with no-ops
    local tmprepo="$1"
    local env_file="$2"

    mkdir -p "${tmprepo}/core" "${tmprepo}/modules/host" "${tmprepo}/modules/stack"
    cp "${BATS_TEST_DIRNAME}/../wpgovern-install.sh" "${tmprepo}/"
    cp "${BATS_TEST_DIRNAME}/../core/bootstrap.sh"  "${tmprepo}/core/"
    cp "${BATS_TEST_DIRNAME}/../core/state.sh"       "${tmprepo}/core/"
    cp "${BATS_TEST_DIRNAME}/../core/credentials.sh"  "${tmprepo}/core/"

    # No-op host modules
    for mod in packages kernel swap firewall docker logrotate; do
        cat > "${tmprepo}/modules/host/${mod}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::host::packages::install()   { wpgovern::state::set_fact "host.packages_installed" "true"; return 0; }
wpgovern::host::kernel::tune()        { wpgovern::state::set_fact "host.kernel_tuned" "true"; return 0; }
wpgovern::host::swap::create()        { wpgovern::state::set_fact "host.swap_configured" "true"; return 0; }
wpgovern::host::firewall::configure() { wpgovern::state::set_fact "host.firewall_configured" "true"; return 0; }
wpgovern::host::docker::install()     { wpgovern::state::set_fact "host.docker_installed" "true"; return 0; }
wpgovern::host::logrotate::configure(){ wpgovern::state::set_fact "host.logrotate_configured" "true"; return 0; }
MOCK
    done

    # No-op stack modules — stack phase is gated; tests that only verify host phase
    # won't trigger these, but the entry script needs them to be sourceable
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
    # No-op ceremony modules (H.5)
    mkdir -p "${tmprepo}/modules/ceremony" "${tmprepo}/installer/vendor"
    cat > "${tmprepo}/modules/ceremony/install_python.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::ceremony::install_python() { return 0; }
MOCK
    cat > "${tmprepo}/modules/ceremony/byte_one.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::ceremony::byte_one() { return 0; }
MOCK
    # No-op audit module (H.6)
    mkdir -p "${tmprepo}/modules/audit"
    cat > "${tmprepo}/modules/audit/install_shim.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::audit::install_shim() { return 0; }
MOCK
}

@test "H.1.1-13: entry script run end-to-end writes phases_complete: host" {
    local tmprepo="${TEST_TMPDIR}/installer_copy"
    _make_mock_installer "$tmprepo" "$ENV_FILE"

    # Pre-seed stack as complete so test stays focused on host phase
    local state_file="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
    mkdir -p "${TEST_TMPDIR}/install"
    cat > "$state_file" <<STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["stack", "db", "wp", "ceremony", "audit"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]] || { echo "STDOUT: $output"; return 1; }

    local phases
    phases="$(jq -r '.phases_complete | sort | join(",")' "$state_file")"
    [[ "$phases" == "audit,ceremony,db,host,stack,wp" ]]
}

@test "H.1.1-13: entry script second run skips host phase (idempotent)" {
    local tmprepo="${TEST_TMPDIR}/installer_copy2"
    _make_mock_installer "$tmprepo" "$ENV_FILE"

    # Pre-seed both phases complete — verify second run skips both
    local state_file="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
    mkdir -p "${TEST_TMPDIR}/install"
    cat > "$state_file" <<STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack", "db", "wp", "ceremony", "audit"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already complete" ]]
}

@test "H.1.2-1: --force-firewall CLI overrides env-default false (real entry script)" {
    local tmprepo="${TEST_TMPDIR}/installer_ff"
    mkdir -p "$tmprepo/core" "$tmprepo/modules/host" "$tmprepo/modules/stack"

    cp "$BATS_TEST_DIRNAME/../wpgovern-install.sh" "$tmprepo/"
    cp "$BATS_TEST_DIRNAME/../core/bootstrap.sh"  "$tmprepo/core/"
    cp "$BATS_TEST_DIRNAME/../core/state.sh"       "$tmprepo/core/"
    cp "$BATS_TEST_DIRNAME/../core/credentials.sh"  "$tmprepo/core/"

    for mod in packages kernel swap docker logrotate; do
        cat > "$tmprepo/modules/host/${mod}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::host::${mod}::install()    { return 0; }
wpgovern::host::${mod}::tune()       { return 0; }
wpgovern::host::${mod}::create()     { return 0; }
wpgovern::host::${mod}::configure()  { return 0; }
MOCK
    done

    # Firewall module writes WPGOVERN_FORCE_FIREWALL to a witness file
    cat > "$tmprepo/modules/host/firewall.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::host::firewall::configure() {
    echo "\${WPGOVERN_FORCE_FIREWALL:-unset}" > "${TEST_TMPDIR}/witness_ff.txt"
    return 0
}
MOCK

    # No-op stack modules so the stack phase can be skipped via pre-seeded state
    for gen in credentials images compose caddyfile mycnf; do
        cat > "$tmprepo/modules/stack/${gen}.sh" << MOCK2
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::credentials::ensure() { return 0; }
wpgovern::stack::images::pin()          { return 0; }
wpgovern::stack::compose::generate()    { return 0; }
wpgovern::stack::caddyfile::generate()  { return 0; }
wpgovern::stack::mycnf::generate()      { return 0; }
MOCK2
    done

    # No-op db modules
    mkdir -p "$tmprepo/modules/db"
    cat > "$tmprepo/modules/db/wait.sh" << 'MOCK3'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::wait_for_ready() { return 0; }
MOCK3
    cat > "$tmprepo/modules/db/credentials.sh" << 'MOCK3'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::credentials::ensure_backup_password() { return 0; }
wpgovern::db::credentials::generate_age_key()       { return 0; }
wpgovern::db::credentials::encrypt_state()          { return 0; }
MOCK3
    cat > "$tmprepo/modules/db/users.sh" << 'MOCK3'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::db::users::verify_application_user() { return 0; }
wpgovern::db::users::create_backup_user()      { return 0; }
MOCK3

    # No-op wp modules
    mkdir -p "$tmprepo/modules/wp"
    cat > "$tmprepo/modules/wp/prepare.sh" << 'MOCK4'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::prepare() { return 0; }
MOCK4
    cat > "$tmprepo/modules/wp/provision.sh" << 'MOCK4'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::provision() { return 0; }
MOCK4
    cat > "$tmprepo/modules/wp/secure.sh" << 'MOCK4'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::wp::secure::ensure_auth_keys() { return 0; }
wpgovern::wp::secure::generate_config()  { return 0; }
MOCK4

    # Pre-seed stack+db+wp complete so the witness test stays focused on host/firewall
    local state_file="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
    mkdir -p "${TEST_TMPDIR}/install"
    cat > "$state_file" <<STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["stack", "db", "wp", "ceremony", "audit"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "$tmprepo/wpgovern-install.sh" --env-file "$ENV_FILE" --force-firewall
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$(cat "${TEST_TMPDIR}/witness_ff.txt")" == "true" ]]
}

@test "H.1.2-4: sh wpgovern-install.sh produces clear bash-required error" {
    run sh "$BATS_TEST_DIRNAME/../wpgovern-install.sh" --help
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "must be run with bash" ]]
}

@test "H.1.1-5: entry script jq preflight appears before state::init" {
    # The preflight check for jq must occur BEFORE state.sh is sourced/called
    local installer="${BATS_TEST_DIRNAME}/../wpgovern-install.sh"
    local jq_line state_line

    # Match the actual jq check/install line, not comment lines
    jq_line="$(grep -n '^\s*if ! command -v jq\|^\s*apt-get install.*jq' "$installer" | head -1 | cut -d: -f1)"
    state_line="$(grep -n '^\s*source.*state\.sh\|^\s*wpgovern::state::init' "$installer" | head -1 | cut -d: -f1)"

    [[ -n "$jq_line" ]] || { echo "jq preflight not found in entry script"; return 1; }
    [[ -n "$state_line" ]] || { echo "state.sh source not found in entry script"; return 1; }
    [[ "$jq_line" -lt "$state_line" ]] || {
        echo "jq preflight (line ${jq_line}) must come before state.sh source (line ${state_line})"
        return 1
    }
}
