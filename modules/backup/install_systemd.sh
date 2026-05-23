#!/usr/bin/env bash
set -euo pipefail

wpgovern::backup::install_systemd() {
    _wpgovern_disable_xtrace_for_credentials
    local systemd_src="${WPGOVERN_INSTALLER_DIR}/modules/backup/systemd"
    local systemd_dst="/etc/systemd/system"

    for unit in wpgovern-backup-full.service wpgovern-backup-full.timer \
                wpgovern-backup-binlogs.service wpgovern-backup-binlogs.timer; do
        if [[ -f "${systemd_src}/${unit}" ]]; then
            cp "${systemd_src}/${unit}" "${systemd_dst}/${unit}"
        fi
    done

    # H.7.1-8: fail closed on systemctl errors — prior || true masked silent timer failures.
    if ! systemctl daemon-reload 2>&1; then
        wpgovern::state::mark_phase_failed "backup" "systemd: daemon-reload failed"
        return 1
    fi
    for timer in wpgovern-backup-full.timer wpgovern-backup-binlogs.timer; do
        if ! systemctl enable "$timer" 2>&1; then
            wpgovern::state::mark_phase_failed "backup" "systemd: enable ${timer} failed"
            return 1
        fi
        if ! systemctl start "$timer" 2>&1; then
            wpgovern::state::mark_phase_failed "backup" "systemd: start ${timer} failed"
            return 1
        fi
    done

    wpgovern::state::set_fact "backup.systemd_units_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "systemd backup timers installed and enabled"
    return 0
}
