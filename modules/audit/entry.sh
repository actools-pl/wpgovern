#!/usr/bin/env bash
# =============================================================================
# modules/audit/entry.sh — wpgovern-install-audit entry script
# H.6.2-3: env-file discovery via precedence chain (CLI flag → state-fact →
# convention → no-op). Uses load_env_readonly (does NOT create directories).
# =============================================================================

set -euo pipefail

_WPGOVERN_AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WPGOVERN_INSTALLER_DIR="$(cd "${_WPGOVERN_AUDIT_DIR}/../.." && pwd)"
export WPGOVERN_INSTALLER_DIR

source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"

source "${_WPGOVERN_AUDIT_DIR}/probes.sh"
source "${_WPGOVERN_AUDIT_DIR}/behavioral.sh"
source "${_WPGOVERN_AUDIT_DIR}/infrastructure.sh"
source "${_WPGOVERN_AUDIT_DIR}/security.sh"
source "${_WPGOVERN_AUDIT_DIR}/formatters.sh"
source "${_WPGOVERN_AUDIT_DIR}/orchestrator.sh"

# ---------------------------------------------------------------------------
# Parse CLI flags (first pass: pull out --env-file before env-file discovery)
# ---------------------------------------------------------------------------
mode="complete"
cli_env_file=""
_remaining_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --complete) mode="complete"; shift ;;
        --security) mode="security"; shift ;;
        --ci)       mode="ci";       shift ;;
        --json)     mode="json";     shift ;;
        --env-file) cli_env_file="$2"; shift 2 ;;
        --version)
            echo "wpgovern-install-audit 1.0 (WPGovern H.6)"
            exit 0
            ;;
        -h|--help)
            cat << HELP
wpgovern-install-audit — WPGovern operational health command

Doctrine: boringly predictable, brutally honest, immediately useful.

Usage: wpgovern-install-audit [--complete | --security | --ci | --json]
                               [--env-file <path>]

  --complete          All layers 1, 1.5, 2, 3 (default)
  --security          Layer 3 + security-tagged Layer 1
  --ci                Machine-stable output, sorted by fix-ID, no colors
  --json              Structured JSON output
  --env-file <path>   Explicit path to wpgovern env file

Exit codes:
  0  No FAIL findings (warnings allowed)
  1  One or more FAIL findings
  2  Internal error (probe failed unexpectedly)

Fix-ID namespaces:
  WPG-WP-*      WordPress operational findings
  WPG-STACK-*   Infrastructure findings
  WPG-SEC-*     Security posture findings
  WPG-CFG-*     Configuration findings
  WPG-BKUP-*    Backup currency findings
HELP
            exit 0
            ;;
        *)
            echo "ERROR: unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# H.6.2-3: Env-file discovery — precedence chain
# 1. Explicit --env-file CLI flag
# 2. State-fact bootstrap.env_file_path recorded at install time
# 3. Convention: ${WPGOVERN_INSTALLER_DIR}/wpgovern.env
# Uses load_env_readonly (no mkdir, no strict validation)
# ---------------------------------------------------------------------------
_audit_env_file=""
_audit_env_source=""

if [[ -n "$cli_env_file" ]]; then
    _audit_env_file="$cli_env_file"
    _audit_env_source="--env-file"
else
    # Try state-fact
    _state_file="$(wpgovern::state::resolve_default_state_file 2>/dev/null)" || _state_file=""
    if [[ -f "$_state_file" ]]; then
        _state_env_path="$(jq -r \
            '.host_facts["bootstrap.env_file_path"] // .facts["bootstrap.env_file_path"] // ""' \
            "$_state_file" 2>/dev/null || echo "")"
        if [[ -n "$_state_env_path" && -f "$_state_env_path" ]]; then
            _audit_env_file="$_state_env_path"
            _audit_env_source="state"
        fi
    fi
fi

if [[ -z "$_audit_env_file" ]]; then
    _fallback="${WPGOVERN_INSTALLER_DIR}/wpgovern.env"
    if [[ -f "$_fallback" ]]; then
        _audit_env_file="$_fallback"
        _audit_env_source="convention"
    fi
fi

if [[ -n "$_audit_env_file" ]]; then
    # Read-only: does NOT mkdir log/install dirs, does NOT strict-validate
    wpgovern::bootstrap::load_env_readonly "$_audit_env_file" 2>/dev/null || true
fi

# Run the audit — full picture, no short-circuit
wpgovern::audit::run_full "$mode"
