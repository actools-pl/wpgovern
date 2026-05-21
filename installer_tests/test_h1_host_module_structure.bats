#!/usr/bin/env bats
# =============================================================================
# test_h1_host_module_structure.bats — Host module structure tests
#
# Verifies each host module exists, has correct namespacing, uses strict mode,
# and defines the expected function. Lesson 2: call-site coverage discipline.
# =============================================================================

HOST_DIR="${BATS_TEST_DIRNAME}/../modules/host"

# ---------------------------------------------------------------------------
# Existence and executability
# ---------------------------------------------------------------------------

@test "modules/host/packages.sh exists" {
    [[ -f "${HOST_DIR}/packages.sh" ]]
}

@test "modules/host/kernel.sh exists" {
    [[ -f "${HOST_DIR}/kernel.sh" ]]
}

@test "modules/host/swap.sh exists" {
    [[ -f "${HOST_DIR}/swap.sh" ]]
}

@test "modules/host/firewall.sh exists" {
    [[ -f "${HOST_DIR}/firewall.sh" ]]
}

@test "modules/host/docker.sh exists" {
    [[ -f "${HOST_DIR}/docker.sh" ]]
}

@test "modules/host/logrotate.sh exists" {
    [[ -f "${HOST_DIR}/logrotate.sh" ]]
}

# ---------------------------------------------------------------------------
# Strict mode (call-site: each module uses set -euo pipefail)
# ---------------------------------------------------------------------------

@test "packages.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/packages.sh"
}

@test "kernel.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/kernel.sh"
}

@test "swap.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/swap.sh"
}

@test "firewall.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/firewall.sh"
}

@test "docker.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/docker.sh"
}

@test "logrotate.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "${HOST_DIR}/logrotate.sh"
}

# ---------------------------------------------------------------------------
# Function namespacing (call-site: wpgovern::host::<module>::<verb>)
# ---------------------------------------------------------------------------

@test "packages.sh defines wpgovern::host::packages::install" {
    grep -q "wpgovern::host::packages::install()" "${HOST_DIR}/packages.sh"
}

@test "kernel.sh defines wpgovern::host::kernel::tune" {
    grep -q "wpgovern::host::kernel::tune()" "${HOST_DIR}/kernel.sh"
}

@test "swap.sh defines wpgovern::host::swap::create" {
    grep -q "wpgovern::host::swap::create()" "${HOST_DIR}/swap.sh"
}

@test "firewall.sh defines wpgovern::host::firewall::configure" {
    grep -q "wpgovern::host::firewall::configure()" "${HOST_DIR}/firewall.sh"
}

@test "docker.sh defines wpgovern::host::docker::install" {
    grep -q "wpgovern::host::docker::install()" "${HOST_DIR}/docker.sh"
}

@test "logrotate.sh defines wpgovern::host::logrotate::configure" {
    grep -q "wpgovern::host::logrotate::configure()" "${HOST_DIR}/logrotate.sh"
}

# ---------------------------------------------------------------------------
# Idempotency guards — each module must have an idempotency check
# (call-site: verify the guard exists, not that apt runs correctly)
# ---------------------------------------------------------------------------

@test "packages.sh has idempotency check (already-installed guard)" {
    grep -q "already installed\|missing=\|dpkg -l" "${HOST_DIR}/packages.sh"
}

@test "kernel.sh has idempotency check (config file guard)" {
    grep -q "already configured\|sysctl_conf\|\-f.*sysctl" "${HOST_DIR}/kernel.sh"
}

@test "swap.sh has idempotency check (swapfile existence guard)" {
    grep -q "already active\|swapfile\|\-f.*swapfile\|swapon.*show" "${HOST_DIR}/swap.sh"
}

@test "firewall.sh has idempotency check (UFW status guard)" {
    grep -q "already active\|ufw status\|Status: active" "${HOST_DIR}/firewall.sh"
}

@test "docker.sh has idempotency check (command -v docker guard)" {
    grep -q "command -v docker\|already installed\|docker --version" "${HOST_DIR}/docker.sh"
}

@test "logrotate.sh has idempotency check (config file guard)" {
    grep -q "already configured\|\-f.*conf_file\|\-f.*logrotate" "${HOST_DIR}/logrotate.sh"
}

# ---------------------------------------------------------------------------
# State fact writes — each module records success in state
# ---------------------------------------------------------------------------

@test "packages.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/packages.sh"
}

@test "kernel.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/kernel.sh"
}

@test "swap.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/swap.sh"
}

@test "firewall.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/firewall.sh"
}

@test "docker.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/docker.sh"
}

@test "logrotate.sh writes a host fact on success" {
    grep -q "wpgovern::state::set_fact" "${HOST_DIR}/logrotate.sh"
}

# ---------------------------------------------------------------------------
# Syntax check
# ---------------------------------------------------------------------------

@test "all host modules pass bash syntax check" {
    for f in "${HOST_DIR}"/*.sh; do
        run bash -n "$f"
        [[ "$status" -eq 0 ]] || { echo "Syntax error in $f"; return 1; }
    done
}

# ---------------------------------------------------------------------------
# H.1.1-3 — Firewall SSH-port handling
# ---------------------------------------------------------------------------

@test "H.1.1-3: firewall.sh uses WPGOVERN_SSH_PORT variable in ufw allow rule" {
    grep -q 'ufw allow "${ssh_port}/tcp"' "${HOST_DIR}/firewall.sh"
}

@test "H.1.1-3: firewall.sh listener check uses exact-port ss filter" {
    grep -q 'sport = :' "${HOST_DIR}/firewall.sh"
}

@test "H.1.1-3: firewall.sh records ssh_port fact in state" {
    grep -q 'host.firewall.ssh_port' "${HOST_DIR}/firewall.sh"
}

# ---------------------------------------------------------------------------
# H.1.1-4 — Docker GPG fingerprint verification
# ---------------------------------------------------------------------------

@test "H.1.1-4: docker.sh verifies GPG fingerprint before install" {
    grep -q 'gpg --show-keys --with-colons' "${HOST_DIR}/docker.sh"
    grep -q 'expected_fpr\|_DOCKER_GPG_EXPECTED_FPR' "${HOST_DIR}/docker.sh"
}

@test "H.1.1-4: docker.sh fails closed on GPG fingerprint mismatch" {
    grep -q 'mark_phase_failed.*docker gpg\|docker gpg fingerprint mismatch' \
        "${HOST_DIR}/docker.sh"
}

@test "H.1.1-4: docker.sh records verified GPG fingerprint in state" {
    grep -q 'host.docker.gpg_fingerprint' "${HOST_DIR}/docker.sh"
}

# ---------------------------------------------------------------------------
# H.1.1-6 — logrotate fail-closed
# ---------------------------------------------------------------------------

@test "H.1.1-6: logrotate.sh checks logrotate binary before writing config" {
    grep -q 'command -v logrotate' "${HOST_DIR}/logrotate.sh"
}

@test "H.1.1-6: logrotate.sh calls mark_phase_failed on validation failure" {
    grep -q 'mark_phase_failed.*logrotate' "${HOST_DIR}/logrotate.sh"
}

@test "H.1.1-6: logrotate.sh records config path in state" {
    grep -q 'host.logrotate.config_path' "${HOST_DIR}/logrotate.sh"
}

# ---------------------------------------------------------------------------
# H.1.2-2 — UFW exact-field matching behavioral test
# ---------------------------------------------------------------------------

@test "H.1.2-2: UFW with 2222/tcp does NOT satisfy required 22/tcp" {
    # Source firewall.sh to get the helper function
    # Bootstrap and state stubs needed for sourcing
    export WPGOVERN_LOG_DIR="/tmp"
    source "${HOST_DIR}/../../../core/bootstrap.sh" 2>/dev/null || true
    source "${HOST_DIR}/firewall.sh"

    local fake_output
    fake_output="Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere"

    # 22/tcp must NOT be found (would have passed substring grep)
    run _wpgovern_ufw_rule_present "$fake_output" "22/tcp"
    [[ "$status" -ne 0 ]]

    # 2222/tcp IS present
    run _wpgovern_ufw_rule_present "$fake_output" "2222/tcp"
    [[ "$status" -eq 0 ]]

    # 80/tcp and 443/tcp are present
    run _wpgovern_ufw_rule_present "$fake_output" "80/tcp"
    [[ "$status" -eq 0 ]]
    run _wpgovern_ufw_rule_present "$fake_output" "443/tcp"
    [[ "$status" -eq 0 ]]
}

# ---------------------------------------------------------------------------
# H.1.2-3 — Docker GPG malformed-key behavioral test
# ---------------------------------------------------------------------------

@test "H.1.2-3: malformed Docker GPG key records mark_phase_failed in state" {
    local mock_bin
    mock_bin="$(mktemp -d)"
    local test_state_dir
    test_state_dir="$(mktemp -d)"
    local test_state_file="${test_state_dir}/.state.json"
    local repo_dir
    repo_dir="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

    # Mock curl: writes garbage to -o destination (simulates malformed key download)
    cat > "$mock_bin/curl" <<'MOCK'
#!/usr/bin/env bash
prev=""
for arg in "$@"; do
    if [[ "$prev" == "-o" ]]; then
        echo "not-a-gpg-key" > "$arg"
        exit 0
    fi
    prev="$arg"
done
exit 0
MOCK
    chmod +x "$mock_bin/curl"

    # Mock docker: always fails so idempotency check falls through to install path
    cat > "$mock_bin/docker" <<'MOCK'
#!/usr/bin/env bash
exit 127
MOCK
    chmod +x "$mock_bin/docker"

    run bash -c "
        export PATH='${mock_bin}:/usr/bin:/bin'
        export WPGOVERN_INSTALL_DIR='${test_state_dir}'
        export WPGOVERN_LOG_DIR='${test_state_dir}'
        export WPGOVERN_STATE_FILE='${test_state_file}'

        source '${repo_dir}/core/bootstrap.sh'
        source '${repo_dir}/core/state.sh'
        wpgovern::state::init

        source '${repo_dir}/modules/host/docker.sh'
        wpgovern::host::docker::install
    "

    # Function must return non-zero
    [[ "$status" -ne 0 ]] || { echo "Expected non-zero; got 0. State: $(cat "$test_state_file" 2>/dev/null)"; return 1; }

    # State must record failure
    [[ -f "$test_state_file" ]] || { echo "State file not created at ${test_state_file}"; return 1; }
    local failed_count
    failed_count="$(jq -r '.phases_failed | length' "$test_state_file")"
    [[ "$failed_count" -ge 1 ]] || { echo "phases_failed is empty. Reason: $(jq . "$test_state_file")"; return 1; }

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$test_state_file")"
    [[ "$reason" =~ "docker gpg" ]] || { echo "Expected 'docker gpg' in reason, got: $reason"; return 1; }

    rm -rf "$mock_bin" "$test_state_dir"
}
