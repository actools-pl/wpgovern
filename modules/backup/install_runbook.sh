#!/usr/bin/env bash
set -euo pipefail

wpgovern::backup::install_runbook() {
    local template="${WPGOVERN_INSTALLER_DIR}/modules/backup/runbook_template.md"
    local dest="${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}/RUNBOOK.md"
    [[ -f "$template" ]] || { wpgovern::bootstrap::log "WARN: runbook template not found at ${template}"; return 0; }
    install -m 0644 "$template" "$dest"
    wpgovern::state::set_fact "backup.runbook_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Operational runbook installed at ${dest}"
    return 0
}
