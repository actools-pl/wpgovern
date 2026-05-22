#!/usr/bin/env bash
# =============================================================================
# modules/audit/entry.sh — wpgovern-install-audit entry script
# Executed by the shim at /usr/local/bin/wpgovern-install-audit.
# =============================================================================

set -euo pipefail

# Resolve installer root from this script's location (modules/audit/ is two levels down)
_WPGOVERN_AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WPGOVERN_INSTALLER_DIR="$(cd "${_WPGOVERN_AUDIT_DIR}/../.." && pwd)"
export WPGOVERN_INSTALLER_DIR

# Load core helpers
# shellcheck source=../../core/bootstrap.sh
source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
# shellcheck source=../../core/state.sh
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
# shellcheck source=../../core/credentials.sh
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"

# Load audit modules
# shellcheck source=probes.sh
source "${_WPGOVERN_AUDIT_DIR}/probes.sh"
# shellcheck source=behavioral.sh
source "${_WPGOVERN_AUDIT_DIR}/behavioral.sh"
# shellcheck source=infrastructure.sh
source "${_WPGOVERN_AUDIT_DIR}/infrastructure.sh"
# shellcheck source=security.sh
source "${_WPGOVERN_AUDIT_DIR}/security.sh"
# shellcheck source=formatters.sh
source "${_WPGOVERN_AUDIT_DIR}/formatters.sh"
# shellcheck source=orchestrator.sh
source "${_WPGOVERN_AUDIT_DIR}/orchestrator.sh"

# Load environment (best-effort — audit runs on live system, env may be pre-set)
if [[ -f "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" ]]; then
    wpgovern::bootstrap::load_env "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" 2>/dev/null || true
fi

# Parse CLI flags
mode="complete"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --complete) mode="complete"; shift ;;
        --security) mode="security"; shift ;;
        --ci)       mode="ci";       shift ;;
        --json)     mode="json";     shift ;;
        --version)
            echo "wpgovern-install-audit 1.0 (WPGovern H.6)"
            exit 0
            ;;
        -h|--help)
            cat << HELP
wpgovern-install-audit — WPGovern operational health command

Doctrine: boringly predictable, brutally honest, immediately useful.

Usage: wpgovern-install-audit [--complete | --security | --ci | --json]

  --complete   All layers 1, 1.5, 2, 3 (default)
  --security   Layer 3 + security-tagged Layer 1 findings
  --ci         Machine-stable output, sorted by fix-ID, no colors
  --json       Structured JSON output

Exit codes:
  0  No FAIL findings (warnings allowed)
  1  One or more FAIL findings
  2  Internal error

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

# Run the audit — full picture, no short-circuit
wpgovern::audit::run_full "$mode"
