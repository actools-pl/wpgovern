#!/usr/bin/env bash
# =============================================================================
# wpgovern-install.sh — WPGovern Installer Entry Point
#
# Usage:
#   sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env
#   sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env --force-firewall
# =============================================================================

# H.1.2-4: Guard against sh/dash invocation BEFORE any bash-specific syntax.
# Must use POSIX [ ... ] because [[ ... ]] is bash-only and would itself fail
# under sh/dash, producing [[: not found instead of the clear error message.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: wpgovern-install.sh must be run with bash, not sh or dash" >&2
    echo "  Try: sudo bash wpgovern-install.sh --env-file ..." >&2
    echo "  Or:  sudo ./wpgovern-install.sh --env-file ..." >&2
    exit 1
fi

set -euo pipefail

WPGOVERN_INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WPGOVERN_INSTALLER_DIR

# ---------------------------------------------------------------------------
# Parse arguments — collect flags but do NOT export yet (env file loads first)
# H.1.1-2: CLI overrides are applied AFTER env load so they always win.
# ---------------------------------------------------------------------------
_env_file=""
_force_firewall_cli=""   # empty = not set via CLI

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            _env_file="${2:-}"
            [[ -z "$_env_file" ]] && { echo "ERROR: --env-file requires a path argument" >&2; exit 1; }
            shift 2
            ;;
        --force-firewall)
            _force_firewall_cli="true"
            shift
            ;;
        --help|-h)
            cat <<USAGE
wpgovern-install.sh — WPGovern Installer (Phase H.1)

USAGE:
  sudo ./wpgovern-install.sh --env-file /path/to/wpgovern.env [options]

OPTIONS:
  --env-file <path>      Path to environment file (required)
  --force-firewall       Apply UFW rules without SSH safety check (CLI-only flag,
                         always overrides env file value)
  --help                 Show this help
USAGE
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "Run with --help for usage" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$_env_file" ]]; then
    echo "ERROR: --env-file is required" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# H.1.1-8: OS preflight — before any state writes
# ---------------------------------------------------------------------------
if [[ ! -f /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found — cannot verify host OS" >&2
    exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]] || [[ "${VERSION_ID:-}" != "24.04" ]]; then
    echo "ERROR: WPGovern requires Ubuntu 24.04 (found ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown})" >&2
    echo "  Supported: Ubuntu 24.04 LTS only in H.1" >&2
    exit 1
fi
_os_id="${ID}"
_os_version_id="${VERSION_ID}"
_os_kernel="$(uname -r)"

# ---------------------------------------------------------------------------
# Bootstrap: load env file FIRST (H.1.1-2: env loads before CLI overrides)
# ---------------------------------------------------------------------------
# shellcheck source=core/bootstrap.sh
source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
wpgovern::bootstrap::load_env "$_env_file"

# H.1.2-1: WPGOVERN_FORCE_FIREWALL is CLI-only.
# Force default to false after env load — guards against stale shell-inherited
# values and the v53.1 gap (whitelist removal without this reset).
export WPGOVERN_FORCE_FIREWALL="false"

if [[ -n "$_force_firewall_cli" ]]; then
    export WPGOVERN_FORCE_FIREWALL="true"
fi

wpgovern::bootstrap::validate_env
wpgovern::bootstrap::log_invocation

# ---------------------------------------------------------------------------
# H.1.1-5: jq preflight — before state::init which requires jq
# ---------------------------------------------------------------------------
# jq is installed by modules/host/packages.sh, but state::init runs first.
# If an interrupted first run created a state file before jq was installed,
# this preflight ensures recovery is automatic.
if ! command -v jq >/dev/null 2>&1; then
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "ERROR: jq is required for state recovery but is not installed." >&2
        echo "  Run installer as root (sudo) for automatic jq install." >&2
        exit 1
    fi
    wpgovern::bootstrap::log "jq not found — installing as preflight step"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y jq >/dev/null
    wpgovern::bootstrap::log "jq installed"
fi

# ---------------------------------------------------------------------------
# H.1.2-5: Acquire installer lock BEFORE state::init (first state mutation)
# Two concurrent runs must not race on state writes.
# ---------------------------------------------------------------------------
_lock_file="${WPGOVERN_INSTALL_DIR}/.wpgovern-installer.lock"
exec 9>"$_lock_file"
if ! flock -n 9; then
    echo "ERROR: another wpgovern installer run is active" >&2
    echo "  Lock file: ${_lock_file}" >&2
    echo "  If you're sure no other installer is running, delete the lock file and retry." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# State machine: initialize or load existing state
# ---------------------------------------------------------------------------
# shellcheck source=core/state.sh
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
# H.3.1-1: core/credentials.sh sourced unconditionally so _wpgovern_credentials_persist
# and _wpgovern_disable_xtrace_for_credentials are available across ALL phase boundaries
# shellcheck source=core/credentials.sh
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"
wpgovern::state::init

# H.2/H.3: record env file path in state for use across phase boundaries
wpgovern::state::set_fact "bootstrap.env_file_path" "${WPGOVERN_ENV_FILE_PATH:-}"

# Record OS facts in state (now that state is initialized)
wpgovern::state::set_fact "host.os.id" "$_os_id"
wpgovern::state::set_fact "host.os.version_id" "$_os_version_id"
wpgovern::state::set_fact "host.os.kernel" "$_os_kernel"

# ---------------------------------------------------------------------------
# Phase: host
# ---------------------------------------------------------------------------
if wpgovern::state::phase_complete "host"; then
    wpgovern::bootstrap::log "Host phase already complete — skipping (re-run is idempotent)"
else
    # shellcheck source=modules/host/packages.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/packages.sh"
    wpgovern::host::packages::install

    # shellcheck source=modules/host/kernel.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/kernel.sh"
    wpgovern::host::kernel::tune

    # shellcheck source=modules/host/swap.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/swap.sh"
    wpgovern::host::swap::create

    # shellcheck source=modules/host/firewall.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/firewall.sh"
    wpgovern::host::firewall::configure

    # shellcheck source=modules/host/docker.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/docker.sh"
    wpgovern::host::docker::install

    # shellcheck source=modules/host/logrotate.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/host/logrotate.sh"
    wpgovern::host::logrotate::configure

    wpgovern::state::mark_phase_complete "host"
fi

wpgovern::bootstrap::log "[H.1] host phase complete"

# ============================================================
# Stack phase: docker compose stack with digest-pinned images
# ============================================================
if wpgovern::state::phase_complete "stack"; then
    wpgovern::bootstrap::log "Stack phase already complete — skipping"
else
    wpgovern::bootstrap::log "[H.2] starting stack phase"

    # Step 1: Generate or read DB credentials (writes back to env if generated)
    # shellcheck source=modules/stack/credentials.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/stack/credentials.sh"
    wpgovern::stack::credentials::ensure

    # Step 2: Pin image digests (idempotent: persisted digest wins on re-run)
    # shellcheck source=modules/stack/images.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/stack/images.sh"
    wpgovern::stack::images::pin

    # Step 3: Generate governance-critical files (deterministic)
    # shellcheck source=modules/stack/compose.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/stack/compose.sh"
    wpgovern::stack::compose::generate

    # shellcheck source=modules/stack/caddyfile.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/stack/caddyfile.sh"
    wpgovern::stack::caddyfile::generate

    # shellcheck source=modules/stack/mycnf.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/stack/mycnf.sh"
    wpgovern::stack::mycnf::generate

    # Step 4: Bring stack up
    cd "$WPGOVERN_INSTALL_DIR"
    if ! docker compose up -d 2>&1 | tee -a "${WPGOVERN_LOG_DIR}/docker-compose-up.log"; then
        wpgovern::state::mark_phase_failed "stack" "docker compose up failed"
        exit 1
    fi

    # H.3.1-10: positive-state check — require expected_services ALL healthy
    # Prevents false-positive when docker compose ps returns empty (transient boot).
    _wpgovern_stack_wait_healthy() {
        local timeout=120
        local elapsed=0
        local expected_services=4   # caddy, mariadb, php, wordpress (H.2.1-2)
        local healthy_count total_count ps_output

        while [[ $elapsed -lt $timeout ]]; do
            ps_output="$(docker compose ps --format json 2>/dev/null || true)"

            # Empty output = containers not yet created — keep waiting
            if [[ -z "$ps_output" ]]; then
                sleep 5; elapsed=$((elapsed + 5)); continue
            fi

            healthy_count="$(echo "$ps_output" \
                | jq -r 'select(.Health == "healthy") | .Name' \
                | wc -l)"
            total_count="$(echo "$ps_output" \
                | jq -r '.Name' \
                | wc -l)"

            if [[ "$total_count" -eq "$expected_services" ]] && \
               [[ "$healthy_count" -eq "$expected_services" ]]; then
                return 0
            fi

            sleep 5; elapsed=$((elapsed + 5))
        done
        return 1
    }

    if ! _wpgovern_stack_wait_healthy; then
        wpgovern::state::mark_phase_failed "stack" \
            "stack failed to reach healthy state within 120s"
        exit 1
    fi

    wpgovern::state::mark_phase_complete "stack"
    wpgovern::bootstrap::log "[H.2] stack phase complete"
fi

# ============================================================
# DB phase: wait-for-ready + credentials + backup user
# ============================================================
if wpgovern::state::phase_complete "db"; then
    wpgovern::bootstrap::log "DB phase already complete — skipping"
else
    wpgovern::bootstrap::log "[H.3] starting db phase"

    # shellcheck source=modules/db/wait.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/db/wait.sh"
    wpgovern::db::wait_for_ready

    # shellcheck source=modules/db/credentials.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/db/credentials.sh"
    wpgovern::db::credentials::ensure_backup_password
    wpgovern::db::credentials::generate_age_key
    wpgovern::db::credentials::encrypt_state

    # shellcheck source=modules/db/users.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/db/users.sh"
    wpgovern::db::users::verify_application_user
    wpgovern::db::users::create_backup_user

    wpgovern::state::mark_phase_complete "db"
    wpgovern::bootstrap::log "[H.3] db phase complete"
fi

# ============================================================
# WP phase: prepare + provision + secure
# ============================================================
if wpgovern::state::phase_complete "wp"; then
    wpgovern::bootstrap::log "WP phase already complete — skipping"
else
    wpgovern::bootstrap::log "[H.4] starting wp phase"

    # shellcheck source=modules/wp/prepare.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/wp/prepare.sh"
    wpgovern::wp::prepare

    # shellcheck source=modules/wp/provision.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/wp/provision.sh"
    wpgovern::wp::provision

    # shellcheck source=modules/wp/secure.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/wp/secure.sh"
    wpgovern::wp::secure::ensure_auth_keys
    wpgovern::wp::secure::generate_config

    wpgovern::state::mark_phase_complete "wp"
    wpgovern::bootstrap::log "[H.4] wp phase complete"
fi

# ============================================================
# Ceremony phase: Python install + byte-one ceremony
# ============================================================
if wpgovern::state::phase_complete "ceremony"; then
    wpgovern::bootstrap::log "Ceremony phase already complete — skipping"
else
    wpgovern::bootstrap::log "[H.5] starting ceremony phase"

    # shellcheck source=modules/ceremony/install_python.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/ceremony/install_python.sh"
    wpgovern::ceremony::install_python

    # shellcheck source=modules/ceremony/byte_one.sh
    source "${WPGOVERN_INSTALLER_DIR}/modules/ceremony/byte_one.sh"
    wpgovern::ceremony::byte_one

    wpgovern::state::mark_phase_complete "ceremony"
    wpgovern::bootstrap::log "[H.5] ceremony phase complete — system is governed"
fi
