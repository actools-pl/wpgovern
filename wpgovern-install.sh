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
wpgovern::state::init

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

    # Step 5: Wait for all containers healthy (120s timeout)
    local _stack_timeout=120
    local _stack_elapsed=0
    while [[ $_stack_elapsed -lt $_stack_timeout ]]; do
        local _unhealthy_count
        _unhealthy_count=$(docker compose ps --format json 2>/dev/null \
            | jq -r 'select(.Health != null and .Health != "healthy") | .Name' \
            | wc -l)
        if [[ "$_unhealthy_count" -eq 0 ]]; then
            break
        fi
        sleep 5
        _stack_elapsed=$((_stack_elapsed + 5))
    done

    if [[ $_stack_elapsed -ge $_stack_timeout ]]; then
        wpgovern::state::mark_phase_failed "stack" \
            "stack failed to reach healthy state within ${_stack_timeout}s"
        exit 1
    fi

    wpgovern::state::mark_phase_complete "stack"
    wpgovern::bootstrap::log "[H.2] stack phase complete"
fi
