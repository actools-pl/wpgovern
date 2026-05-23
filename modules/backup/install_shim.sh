#!/usr/bin/env bash
# H.4.1-3 + H.5.1-6 + H.6-7 discipline: atomic shim placement
set -euo pipefail

wpgovern::backup::install_shim() {
    _wpgovern_disable_xtrace_for_credentials
    local shim_target="/usr/local/bin/wpgovern-restore"
    local restore_entry="${WPGOVERN_INSTALLER_DIR}/modules/backup/restore_entry.sh"

    if [[ -x "$shim_target" ]] && "$shim_target" --version >/dev/null 2>&1; then
        wpgovern::bootstrap::log "wpgovern-restore shim already present — skipping"
        return 0
    fi
    [[ -f "$restore_entry" ]] || { wpgovern::state::mark_phase_failed "backup" "install_shim: restore_entry.sh not found"; return 1; }
    chmod +x "$restore_entry"

    local shim_tmp; shim_tmp="$(mktemp "${shim_target}.tmp.XXXXXX")"
    if ! cat > "$shim_tmp" << SHIM
#!/usr/bin/env bash
# wpgovern-restore — governance-aware restore command (H.7)
exec ${restore_entry} "\$@"
SHIM
    then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "backup" "install_shim: heredoc write failed"
        return 1
    fi
    if ! chmod 755 "$shim_tmp"; then rm -f "$shim_tmp"; wpgovern::state::mark_phase_failed "backup" "install_shim: chmod failed"; return 1; fi
    if ! mv "$shim_tmp" "$shim_target"; then rm -f "$shim_tmp"; wpgovern::state::mark_phase_failed "backup" "install_shim: mv failed"; return 1; fi
    if ! "$shim_target" --version >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "backup" "install_shim: post-install verification failed"
        return 1
    fi
    wpgovern::state::set_fact "backup.restore_shim_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "wpgovern-restore shim installed at ${shim_target}"
    return 0
}
