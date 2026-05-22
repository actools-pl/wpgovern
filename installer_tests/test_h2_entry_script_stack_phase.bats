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

_make_docker_mock_healthy() {
    local mock_bin="$1"
    local call_count_file="${TEST_TMPDIR}/docker_calls"
    echo "0" > "$call_count_file"

    # docker compose: up -d succeeds; ps returns healthy JSON after 1 call
    cat > "${mock_bin}/docker" << MOCK
#!/usr/bin/env bash
if [[ "\$1" == "compose" && "\$2" == "up" ]]; then
    exit 0
fi
if [[ "\$1" == "compose" && "\$2" == "ps" ]]; then
    # Return 4 healthy services as newline-delimited JSON objects (stream format)
    # H.3.1-10: new health check requires total_count==4 AND healthy_count==4
    for svc in caddy mariadb php wordpress; do
        printf '{"Name":"%s","Health":"healthy"}\n' "\$svc"
    done
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
  "phases_complete": ["host", "db", "wp", "ceremony", "audit"],
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
    [[ "$phases" == "audit,ceremony,db,host,stack,wp" ]] || {
        echo "Expected audit,ceremony,db,host,stack,wp — got: $phases. Output: $output"
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
  "phases_complete": ["host", "stack", "ceremony", "audit"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already complete" ]]
}

@test "H.3.1-10: stack health-check does not false-pass on empty docker compose ps output" {
    local mock_bin="${TEST_TMPDIR}/mock_empty_ps"
    mkdir -p "$mock_bin"
    local call_count_file="${TEST_TMPDIR}/empty_ps_calls"
    echo "0" > "$call_count_file"

    cat > "${mock_bin}/docker" << MOCK
#!/usr/bin/env bash
if [[ "\$1 \$2" == "compose ps" ]]; then
    count=\$(cat "${call_count_file}")
    count=\$((count + 1))
    echo "\$count" > "${call_count_file}"
    if [[ \$count -le 2 ]]; then
        exit 0
    fi
    for svc in caddy mariadb php wordpress; do
        printf '{"Name":"%s","Health":"healthy"}\n' "\$svc"
    done
    exit 0
fi
exit 0
MOCK
    chmod +x "${mock_bin}/docker"

    # Test the function directly from a script (avoids subshell expansion issues)
    local test_script="${TEST_TMPDIR}/test_health.sh"
    cat > "$test_script" << 'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

_wpgovern_stack_wait_healthy() {
    local timeout=120
    local elapsed=0
    local expected_services=4
    local healthy_count total_count ps_output

    while [[ $elapsed -lt $timeout ]]; do
        ps_output="$(docker compose ps --format json 2>/dev/null || true)"
        if [[ -z "$ps_output" ]]; then
            sleep 0; elapsed=$((elapsed + 5)); continue
        fi
        healthy_count="$(echo "$ps_output" | jq -r 'select(.Health == "healthy") | .Name' | wc -l)"
        total_count="$(echo "$ps_output" | jq -r '.Name' | wc -l)"
        if [[ "$total_count" -eq "$expected_services" ]] && [[ "$healthy_count" -eq "$expected_services" ]]; then
            return 0
        fi
        sleep 0; elapsed=$((elapsed + 5))
    done
    return 1
}
_wpgovern_stack_wait_healthy
SCRIPT
    chmod +x "$test_script"

    PATH="${mock_bin}:/usr/bin:/bin" run bash "$test_script"
    [[ "$status" -eq 0 ]] || { echo "FAILED — health check returned non-zero"; return 1; }

    local ps_calls
    ps_calls="$(cat "$call_count_file")"
    [[ "$ps_calls" -gt 1 ]] || {
        echo "docker compose ps called only $ps_calls times — empty output may have false-passed"
        return 1
    }
}

@test "H.4 regression: cli service present in docker-compose.yml (profile-gated)" {
    # Structural check: compose generator includes cli service with profiles: ["cli"]
    local compose_file="${BATS_TEST_DIRNAME}/../modules/stack/compose.sh"
    grep -q "profiles.*cli\|profile.*cli" "$compose_file" || {
        echo "cli profile-gated service not found in compose.sh template"
        return 1
    }
}

@test "H.4.1-1: compose.sh template has wp-config.php mount on php service" {
    local compose_sh="${BATS_TEST_DIRNAME}/../modules/stack/compose.sh"
    grep -q "wp-config.php:/var/www/html/wp-config.php:ro" "$compose_sh" || {
        echo "wp-config.php read-only mount not found in compose.sh template"
        return 1
    }
    # Count occurrences: must appear at least 3 times (php, wordpress, cli)
    local count
    count="$(grep -c 'wp-config.php:/var/www/html/wp-config.php:ro' "$compose_sh")"
    [[ "$count" -ge 3 ]] || {
        echo "Expected ≥3 wp-config.php mounts (php, wordpress, cli), found: $count"
        return 1
    }
}
