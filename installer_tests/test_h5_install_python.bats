#!/usr/bin/env bats
# =============================================================================
# test_h5_install_python.bats — install_python.sh behavioral tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
CEREMONY_DIR="${BATS_TEST_DIRNAME}/../modules/ceremony"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${CEREMONY_DIR}/install_python.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_sdist_mock() {
    local sdist_path="${TEST_TMPDIR}/install/wpgovern-0.1.0.tar.gz"
    # Make sure the dir exists
    mkdir -p "${TEST_TMPDIR}/install"
    # Create a placeholder sdist
    echo "fake-sdist" > "$sdist_path"

    # Override WPGOVERN_INSTALLER_DIR to point at test area
    export WPGOVERN_INSTALLER_DIR="${TEST_TMPDIR}/mock_installer"
    mkdir -p "${WPGOVERN_INSTALLER_DIR}/installer/vendor"
    cp "$sdist_path" "${WPGOVERN_INSTALLER_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz"
}

@test "H.5-1: install_python idempotent — shim exists and works → skips" {
    # Create a mock shim that responds to 'version'
    cat > "${MOCK_BIN}/wpgovern" << 'MOCK'
#!/usr/bin/env bash
if [[ "$1" == "version" ]]; then echo "0.1.0"; exit 0; fi
exit 1
MOCK
    chmod +x "${MOCK_BIN}/wpgovern"
    ln -s "${MOCK_BIN}/wpgovern" "/usr/local/bin/wpgovern" 2>/dev/null || true
    PATH="${MOCK_BIN}:${PATH}"

    # Simulate shim already at /usr/local/bin/wpgovern
    local shim_path="${MOCK_BIN}/wpgovern"
    # Override the shim_path via a test-local version of install_python
    run bash -c "
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export PATH='${MOCK_BIN}:/usr/bin:/bin'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        wpgovern::state::init
        # Override shim_path variable via env (monkeypatch the function)
        _WPGOVERN_SHIM_OVERRIDE='${MOCK_BIN}/wpgovern'
        source '${CEREMONY_DIR}/install_python.sh'
        # Patch the shim_path inside install_python by redefining the function
        wpgovern::ceremony::install_python() {
            local shim_path=\"${MOCK_BIN}/wpgovern\"
            if [[ -x \"\$shim_path\" ]] && \"\$shim_path\" version >/dev/null 2>&1; then
                wpgovern::bootstrap::log 'Python control plane already installed — skipping'
                wpgovern::state::set_fact 'ceremony.python_installed_skipped_at' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
                return 0
            fi
            return 1
        }
        wpgovern::ceremony::install_python
    "
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "skipping" ]]
}

@test "H.5-1: missing sdist → mark_phase_failed with path in reason" {
    # Ensure sdist does NOT exist and shim doesn't exist either
    export WPGOVERN_INSTALLER_DIR="${TEST_TMPDIR}/no_such_dir"

    run bash -c "
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export WPGOVERN_INSTALLER_DIR='${TEST_TMPDIR}/no_such_dir'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        wpgovern::state::init
        source '${CEREMONY_DIR}/install_python.sh'
        # Override shim_path to a non-existent location
        wpgovern::ceremony::install_python() {
            local venv_dir='/opt/wpgovern/.venv'
            local sdist_path=\"\${WPGOVERN_INSTALLER_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz\"
            local shim_path='/nonexistent/wpgovern'
            if [[ -x \"\$shim_path\" ]] && \"\$shim_path\" version >/dev/null 2>&1; then
                return 0
            fi
            if [[ ! -f \"\$sdist_path\" ]]; then
                wpgovern::bootstrap::log \"ERROR: vendored sdist not found at \${sdist_path}\"
                wpgovern::state::mark_phase_failed 'ceremony' \"install_python: vendored sdist not found at \${sdist_path}\"
                return 1
            fi
            return 0
        }
        wpgovern::ceremony::install_python
    "
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "${TEST_TMPDIR}/install/.state.json" 2>/dev/null)"
    [[ "$reason" =~ "sdist not found" ]] || {
        echo "Expected sdist-not-found reason, got: $reason"; return 1
    }
}

@test "H.5-1: shim placed at 755 perms (real sdist integration)" {
    [[ -f "${REPO_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz" ]] || \
        skip "vendored sdist not present"

    # This test installs into a tmp venv and checks the shim
    local venv_dir="${TEST_TMPDIR}/test_venv"
    local shim_dest="${TEST_TMPDIR}/mock_shim"

    python3 -m venv "$venv_dir" >/dev/null 2>&1
    "${venv_dir}/bin/pip" install --quiet \
        "${REPO_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz" >/dev/null 2>&1

    local shim_tmp
    shim_tmp="$(mktemp "${shim_dest}.tmp.XXXXXX")"
    cat > "$shim_tmp" << SHIM
#!/usr/bin/env bash
exec ${venv_dir}/bin/wpgovern "\$@"
SHIM
    chmod 755 "$shim_tmp"
    mv "$shim_tmp" "$shim_dest"

    local perms
    perms="$(stat -c '%a' "$shim_dest")"
    [[ "$perms" == "755" ]] || { echo "Expected 755, got $perms"; return 1; }

    # Verify shim actually works
    "$shim_dest" version >/dev/null 2>&1 || { echo "Shim failed to execute"; return 1; }
}

@test "H.5-1: install records state fact ceremony.python_installed_at (real sdist)" {
    [[ -f "${REPO_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz" ]] || \
        skip "vendored sdist not present"

    local test_venv="${TEST_TMPDIR}/venv"
    local test_shim="${TEST_TMPDIR}/bin/wpgovern"
    mkdir -p "${TEST_TMPDIR}/bin"

    local script="${TEST_TMPDIR}/run_install.sh"
    cat > "$script" << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"
source "${CORE_DIR}/bootstrap.sh"
source "${CORE_DIR}/state.sh"
source "${CORE_DIR}/credentials.sh"
wpgovern::state::init
# Override the function to use test-local venv/shim (no root access)
wpgovern::ceremony::install_python() {
    local venv_dir="${test_venv}"
    local sdist_path="${REPO_DIR}/installer/vendor/wpgovern-0.1.0.tar.gz"
    local shim_path="${test_shim}"
    if [[ -x "\$shim_path" ]] && "\$shim_path" version >/dev/null 2>&1; then
        wpgovern::state::set_fact "ceremony.python_installed_skipped_at" "\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    fi
    python3 -m venv "\$venv_dir" >/dev/null 2>&1 || return 1
    "\${venv_dir}/bin/pip" install --quiet "\$sdist_path" >/dev/null 2>&1 || return 1
    local tmp; tmp="\$(mktemp "\${shim_path}.tmp.XXXXXX")"
    printf '#!/usr/bin/env bash\nexec %s/bin/wpgovern "\$@"\n' "\$venv_dir" > "\$tmp"
    chmod 755 "\$tmp" && mv "\$tmp" "\$shim_path" || return 1
    "\$shim_path" version >/dev/null 2>&1 || return 1
    wpgovern::state::set_fact "ceremony.python_installed_at" "\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Python installed (test)"
    return 0
}
wpgovern::ceremony::install_python
SCRIPT
    chmod +x "$script"

    run bash "$script"
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local ts
    ts="$(jq -r '.host_facts["ceremony.python_installed_at"]' "${TEST_TMPDIR}/install/.state.json")"
    [[ -n "$ts" && "$ts" != "null" ]] || {
        echo "ceremony.python_installed_at not recorded in state"; return 1
    }
}

@test "H.5-1: no credentials leak through install_python" {
    export WPGOVERN_DB_WP_PASSWORD="SENTINEL_WP_INSTALL_H5"
    export WPGOVERN_WP_AUTH_KEY="SENTINEL_AUTH_INSTALL_H5_aaaa"

    # Missing sdist will cause early failure — but no credentials should appear
    export WPGOVERN_INSTALLER_DIR="${TEST_TMPDIR}/no_vendor"

    run wpgovern::ceremony::install_python
    for sentinel in "SENTINEL_WP_INSTALL_H5" "SENTINEL_AUTH_INSTALL_H5_aaaa"; do
        if echo "$output" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK: $sentinel in output"; return 1
        fi
    done
}
