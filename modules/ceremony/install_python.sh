#!/usr/bin/env bash
# =============================================================================
# modules/ceremony/install_python.sh — Python control plane venv + shim install
#
# H.5.1-1: uses wheelhouse (pip --no-index --find-links) instead of sdist.
# H.5.1-6: heredoc cat write is guarded (discipline from H.4.1-3 travels here).
# All four operations (cat, chmod, chown, mv) have rm-f + mark_phase_failed.
# =============================================================================

set -euo pipefail

wpgovern::ceremony::install_python() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2

    local venv_dir="/opt/wpgovern/.venv"
    local wheelhouse_dir="${WPGOVERN_INSTALLER_DIR}/installer/vendor"
    local wpgovern_wheel="${wheelhouse_dir}/wpgovern-0.1.0-py3-none-any.whl"
    local shim_path="/usr/local/bin/wpgovern"

    # Idempotency: shim exists and works → skip
    if [[ -x "$shim_path" ]] && "$shim_path" version >/dev/null 2>&1; then
        wpgovern::bootstrap::log "Python control plane already installed — skipping"
        wpgovern::state::set_fact "ceremony.python_installed_skipped_at" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    fi

    # Validate wheelhouse contains wpgovern wheel (H.5.1-1 guard)
    if [[ ! -f "$wpgovern_wheel" ]]; then
        wpgovern::bootstrap::log "ERROR: wpgovern wheel not found at ${wpgovern_wheel}"
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: wpgovern wheel not found at ${wpgovern_wheel}"
        return 1
    fi

    # Create venv
    if ! python3 -m venv "$venv_dir" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: venv creation failed at ${venv_dir}"
        return 1
    fi

    # Hermetic install — no PyPI, wheels only (H.5.1-1)
    if ! "${venv_dir}/bin/pip" install --quiet --no-index \
            --find-links "$wheelhouse_dir" \
            "wpgovern==0.1.0" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: pip install --no-index from wheelhouse failed"
        return 1
    fi

    # Place shim atomically — all four operations guarded (H.4.1-3 + H.5.1-6)
    local shim_tmp
    shim_tmp="$(mktemp "${shim_path}.tmp.XXXXXX")"

    # H.5.1-6: cat heredoc write guarded
    if ! cat > "$shim_tmp" << 'SHIM'
#!/usr/bin/env bash
# WPGovern CLI shim — activates the Python venv and dispatches to the CLI.
exec /opt/wpgovern/.venv/bin/wpgovern "$@"
SHIM
    then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: shim heredoc write failed"
        return 1
    fi

    if ! chmod 755 "$shim_tmp"; then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: chmod 755 on shim failed"
        return 1
    fi

    if ! mv "$shim_tmp" "$shim_path"; then
        rm -f "$shim_tmp"
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: mv shim to ${shim_path} failed"
        return 1
    fi

    # Post-install verification
    if ! "$shim_path" version >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: post-install verification (wpgovern version) failed"
        return 1
    fi

    local installed_version
    installed_version="$("$shim_path" version 2>/dev/null)"
    wpgovern::state::set_fact "ceremony.python_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "ceremony.python_version" "$installed_version"
    wpgovern::bootstrap::log "Python control plane installed: ${installed_version}"
    return 0
}
