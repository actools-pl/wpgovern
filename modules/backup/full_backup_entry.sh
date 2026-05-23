#!/usr/bin/env bash
set -euo pipefail
WPGOVERN_INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export WPGOVERN_INSTALLER_DIR
source "${WPGOVERN_INSTALLER_DIR}/core/bootstrap.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/state.sh"
source "${WPGOVERN_INSTALLER_DIR}/core/credentials.sh"
# Load env from state-fact path or convention
_state="${WPGOVERN_STATE_FILE:-/var/lib/wpgovern/.state.json}"
_env_path="$(jq -r '.host_facts["bootstrap.env_file_path"] // ""' "$_state" 2>/dev/null || true)"
[[ -n "$_env_path" && -f "$_env_path" ]] && wpgovern::bootstrap::load_env_readonly "$_env_path" || \
    [[ -f "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" ]] && \
    wpgovern::bootstrap::load_env_readonly "${WPGOVERN_INSTALLER_DIR}/wpgovern.env" || true
source "${WPGOVERN_INSTALLER_DIR}/modules/backup/full_backup.sh"

# H.7.1-13: container readiness polling (boot-race mitigation).
# Persistent=true timers fire on next boot when their scheduled window was missed,
# but docker.service "started" != MariaDB container "accepting connections".
# Poll for up to 30s; if MariaDB stays unreachable, the backup module surfaces the failure.
wpgovern::bootstrap::log "Waiting for MariaDB container readiness (max 30s)..."
for _ready_check in $(seq 1 30); do
    if docker compose exec -T mariadb mariadb-admin ping --silent 2>/dev/null; then
        wpgovern::bootstrap::log "MariaDB ready after ${_ready_check}s"
        break
    fi
    sleep 1
done

wpgovern::backup::run_full
