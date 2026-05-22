#!/usr/bin/env bash
set -euo pipefail
WPGOVERN_INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export WPGOVERN_INSTALLER_DIR
source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"
_state="${WPGOVERN_STATE_FILE:-/var/lib/wpgovern/.state.json}"
_env_path="$(jq -r '.host_facts["bootstrap.env_file_path"] // ""' "$_state" 2>/dev/null || true)"
[[ -n "$_env_path" && -f "$_env_path" ]] && wpgovern::bootstrap::load_env_readonly "$_env_path" || \
    [[ -f "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" ]] && \
    wpgovern::bootstrap::load_env_readonly "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" || true
source "${WPGOVERN_INSTALLER_DIR}/modules/backup/binlog_rotate.sh"
wpgovern::backup::rotate_binlogs
