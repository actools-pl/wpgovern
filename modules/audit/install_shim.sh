#!/usr/bin/env bash
# =============================================================================
# modules/audit/install_shim.sh — Install wpgovern-install-audit shim
# Atomic shim placement (H.4.1-3 + H.5.1-6 discipline travels).
# =============================================================================

set -euo pipefail

wpgovern::audit::install_shim() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2 discipline

    local shim_target="/usr/local/bin/wpgovern-install-audit"
    local installer_dir="${WPGOVERN_INSTALLER_DIR}"
    local audit_entry="${installer_dir}/modules/audit/entry.sh"

    # Idempotency
    if [[ -x "$shim_target" ]] && "$shim_target" --version >/dev/null 2>&1; then
        wpgovern::bootstrap::log "install-audit shim already present — skipping"
        wpgovern::state::set_fact "audit.shim_installed_skipped_at" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    fi

    # Validate entry.sh exists
    if [[ ! -f "$audit_entry" ]]; then
        wpgovern::state::mark_phase_failed "audit" \
            "install_shim: audit entry.sh not found at ${audit_entry}"
        return 1
    fi
    chmod +x "$audit_entry"

    # Atomic shim placement — all four operations guarded (H.4.1-3 + H.5.1-6)
    local shim_tmp
    shim_tmp="$(mktemp "${shim_target}.tmp.XXXXXX")"

    # H.5.1-6: cat heredoc guarded
    if ! cat > "$shim_tmp" << SHIM
#!/usr/bin/env bash
# wpgovern-install-audit — WPGovern operational health command (H.6)
# Doctrine: boringly predictable, brutally honest, immediately useful.
exec ${audit_entry} "\$@"
SHIM
    then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "audit" \
            "install_shim: shim heredoc write failed"
        return 1
    fi

    if ! chmod 755 "$shim_tmp"; then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "audit" \
            "install_shim: chmod 755 on shim failed"
        return 1
    fi

    if ! mv "$shim_tmp" "$shim_target"; then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "audit" \
            "install_shim: mv shim to ${shim_target} failed"
        return 1
    fi

    # Post-install verification
    if ! "$shim_target" --version >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "audit" \
            "install_shim: post-install verification (--version) failed"
        return 1
    fi

    wpgovern::state::set_fact "audit.shim_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "audit.shim_path" "$shim_target"
    wpgovern::bootstrap::log "install-audit shim installed at ${shim_target}"
    return 0
}
