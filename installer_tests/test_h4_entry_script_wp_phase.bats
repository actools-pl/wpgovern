#!/usr/bin/env bats
# =============================================================================
# test_h4_entry_script_wp_phase.bats — Real-module integration for wp phase
# Per Lesson 1 + H.3.1.1: NO no-op stubs for wp modules.
# Per Lesson 2 fourth refinement: every bash -c sourcing of wp modules
# also sources core/credentials.sh.
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
WPGOVERN_DB_ROOT_PASSWORD="testroot1234567890123456789012abcd"
WPGOVERN_DB_WP_PASSWORD="testwp12345678901234567890123abcde"
WPGOVERN_DB_BACKUP_PASSWORD="testbkup1234567890123456789012ab"
WPGOVERN_WP_ADMIN_USER="admin"
WPGOVERN_WP_ADMIN_PASSWORD="testadmin12345678901234567890ab"
WPGOVERN_WP_ADMIN_EMAIL="admin@example.com"
WPGOVERN_WP_SITE_TITLE="Test Site"
WPGOVERN_WP_AUTH_KEY=
WPGOVERN_WP_SECURE_AUTH_KEY=
WPGOVERN_WP_LOGGED_IN_KEY=
WPGOVERN_WP_NONCE_KEY=
WPGOVERN_WP_AUTH_SALT=
WPGOVERN_WP_SECURE_AUTH_SALT=
WPGOVERN_WP_LOGGED_IN_SALT=
WPGOVERN_WP_NONCE_SALT=
ENV
    chmod 600 "$ENV_FILE"
    STATE_FILE="${TEST_TMPDIR}/install/.state.json"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_wp_mock_installer() {
    local tmprepo="$1"
    mkdir -p "${tmprepo}/core" \
             "${tmprepo}/modules/host" \
             "${tmprepo}/modules/stack" \
             "${tmprepo}/modules/db" \
             "${tmprepo}/modules/wp"

    cp "${REPO_DIR}/wpgovern-install.sh"     "${tmprepo}/"
    cp "${REPO_DIR}/core/bootstrap.sh"       "${tmprepo}/core/"
    cp "${REPO_DIR}/core/state.sh"           "${tmprepo}/core/"
    cp "${REPO_DIR}/core/credentials.sh"     "${tmprepo}/core/"  # Lesson 2 fourth refinement

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

    cat > "${tmprepo}/modules/stack/credentials.sh" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::credentials::ensure() { return 0; }
MOCK
    for gen in images compose caddyfile mycnf; do
        cat > "${tmprepo}/modules/stack/${gen}.sh" << MOCK
#!/usr/bin/env bash
set -euo pipefail
wpgovern::stack::${gen}::pin()      { return 0; }
wpgovern::stack::${gen}::generate() { return 0; }
MOCK
    done

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

    # REAL wp modules (Lesson 1 + H.3.1.1: no stubs for the phase under test)
    cp "${REPO_DIR}/modules/wp/prepare.sh"   "${tmprepo}/modules/wp/"
    cp "${REPO_DIR}/modules/wp/provision.sh" "${tmprepo}/modules/wp/"
    cp "${REPO_DIR}/modules/wp/secure.sh"    "${tmprepo}/modules/wp/"

    # No-op ceremony modules (H.5) — wp phase test doesn't test ceremony
    mkdir -p "${tmprepo}/modules/ceremony"
    mkdir -p "${tmprepo}/installer/vendor"
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
}

_make_wp_docker_mock() {
    cat > "${MOCK_BIN}/docker" << 'DOCKERMOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then
    for svc in caddy mariadb php wordpress; do
        printf '{"Name":"%s","Health":"healthy"}\n' "$svc"
    done
    exit 0
fi
if [[ "$1 $2 $3" == "compose up -d" ]]; then exit 0; fi
if [[ "$1 $2 $3 $4 $5" == "compose --profile cli run" ]]; then
    shift 5; [[ "$1" == "--rm" ]] && shift; shift
    if echo "$@" | grep -q "is-installed"; then exit 1; fi  # not installed
    if echo "$@" | grep -q "core install"; then exit 0; fi  # install succeeds
fi
exit 0
DOCKERMOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "H.4-11: entry script wp phase completes from [host,stack,db] state" {
    local tmprepo="${TEST_TMPDIR}/installer_wp"
    _make_wp_mock_installer "$tmprepo"
    _make_wp_docker_mock

    cat > "$STATE_FILE" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack", "db", "ceremony"],
  "phases_failed": [],
  "host_facts": {"bootstrap.env_file_path": "${ENV_FILE}"}
}
STATE

    run bash -c "
        export PATH='${MOCK_BIN}:/usr/bin:/bin'
        bash '${tmprepo}/wpgovern-install.sh' --env-file '${ENV_FILE}'
    "
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    # wp-config.php exists with 640 perms
    [[ -f "${TEST_TMPDIR}/install/wp-config.php" ]] || {
        echo "wp-config.php not created"; return 1
    }
    local perms; perms="$(stat -c '%a' "${TEST_TMPDIR}/install/wp-config.php")"
    [[ "$perms" == "640" ]] || { echo "Expected 640 perms, got $perms"; return 1; }

    # wp in phases_complete
    local phases; phases="$(jq -r '.phases_complete | sort | join(",")' "$STATE_FILE")"
    [[ "$phases" =~ "wp" ]] || { echo "wp not in phases: $phases"; return 1; }

    # All 8 AUTH_KEYs persisted (were blank in env file)
    local missing=0
    for k in WPGOVERN_WP_AUTH_KEY WPGOVERN_WP_SECURE_AUTH_KEY \
              WPGOVERN_WP_LOGGED_IN_KEY WPGOVERN_WP_NONCE_KEY \
              WPGOVERN_WP_AUTH_SALT WPGOVERN_WP_SECURE_AUTH_SALT \
              WPGOVERN_WP_LOGGED_IN_SALT WPGOVERN_WP_NONCE_SALT; do
        local val; val="$(grep "^${k}=" "$ENV_FILE" | cut -d= -f2 | tr -d '"')"
        [[ -n "$val" ]] || { echo "$k not persisted"; missing=$((missing+1)); }
    done
    [[ "$missing" -eq 0 ]] || { echo "$missing AUTH_KEYs missing"; return 1; }
}

@test "H.4-11: idempotent re-run — wp phase already complete skips" {
    local tmprepo="${TEST_TMPDIR}/installer_wp2"
    _make_wp_mock_installer "$tmprepo"

    cat > "$STATE_FILE" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": ["host", "stack", "db", "wp", "ceremony"],
  "phases_failed": [],
  "host_facts": {}
}
STATE

    run bash "${tmprepo}/wpgovern-install.sh" --env-file "$ENV_FILE"
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already complete" ]]
}

@test "H.4-11: dispatch sources all three wp modules and calls expected functions" {
    grep -q "modules/wp/prepare.sh"              "${REPO_DIR}/wpgovern-install.sh"
    grep -q "modules/wp/provision.sh"            "${REPO_DIR}/wpgovern-install.sh"
    grep -q "modules/wp/secure.sh"               "${REPO_DIR}/wpgovern-install.sh"
    grep -q "wpgovern::wp::prepare"              "${REPO_DIR}/wpgovern-install.sh"
    grep -q "wpgovern::wp::provision"            "${REPO_DIR}/wpgovern-install.sh"
    grep -q "wpgovern::wp::secure::ensure_auth_keys" "${REPO_DIR}/wpgovern-install.sh"
    grep -q "wpgovern::wp::secure::generate_config"  "${REPO_DIR}/wpgovern-install.sh"
}
