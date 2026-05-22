#!/usr/bin/env bash
# =============================================================================
# modules/ceremony/install_python.sh — Python control plane venv + shim install
#
# Installs the vendored wpgovern sdist into a venv at /opt/wpgovern/.venv/,
# places a shim at /usr/local/bin/wpgovern, and verifies the install.
#
# Atomic shim placement: mktemp → chmod → mv (H.4.1-3 discipline travels).
# =============================================================================

set -euo pipefail

wpgovern::ceremony::install_python() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2 discipline travels

    local venv_dir="/opt/wpgovern/.venv"
    local sdist_path="${WPGOVERN_INSTALLER_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz"
    local shim_path="/usr/local/bin/wpgovern"

    # Idempotency: if shim exists and reports version, skip install
    if [[ -x "$shim_path" ]] && "$shim_path" version >/dev/null 2>&1; then
        wpgovern::bootstrap::log "Python control plane already installed — skipping"
        wpgovern::state::set_fact "ceremony.python_installed_skipped_at" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    fi

    # Validate sdist exists
    if [[ ! -f "$sdist_path" ]]; then
        wpgovern::bootstrap::log "ERROR: vendored sdist not found at ${sdist_path}"
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: vendored sdist not found at ${sdist_path}"
        return 1
    fi

    # Create venv (python3 declared as host dependency in H.1 packages.sh)
    if ! python3 -m venv "$venv_dir" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: venv creation failed at ${venv_dir}"
        return 1
    fi

    # Install package from vendored sdist (--no-index: no PyPI fallback; hermetic)
    if ! "${venv_dir}/bin/pip" install --quiet --no-index "$sdist_path" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "install_python: pip install failed for ${sdist_path}"
        return 1
    fi

    # Place shim atomically (H.4.1-3 discipline: chmod-guarded + mv-guarded)
    local shim_tmp
    shim_tmp="$(mktemp "${shim_path}.tmp.XXXXXX")"

    cat > "$shim_tmp" << 'SHIM'
#!/usr/bin/env bash
# WPGovern CLI shim — activates the Python venv and dispatches to the CLI.
exec /opt/wpgovern/.venv/bin/wpgovern "$@"
SHIM

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
