#!/usr/bin/env bats
# =============================================================================
# test_h6_env_discovery.bats — H.6.2-3 env-file discovery + load_env_readonly
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.6.2-3: load_env_readonly does NOT create directories" {
    local env_file="${TEST_TMPDIR}/test.env"
    local nonexistent_log="${TEST_TMPDIR}/nonexistent_logs"
    cat > "$env_file" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_LOG_DIR=${nonexistent_log}
WPGOVERN_DOMAIN=test.example.com
ENV

    # load_env_readonly must not create the directory
    run wpgovern::bootstrap::load_env_readonly "$env_file"
    [[ "$status" -eq 0 ]]
    [[ ! -d "$nonexistent_log" ]] || {
        echo "FAIL: load_env_readonly created directory ${nonexistent_log}"
        return 1
    }
}

@test "H.6.2-3: load_env_readonly exports env vars correctly" {
    local env_file="${TEST_TMPDIR}/export_test.env"
    cat > "$env_file" << ENV
WPGOVERN_DOMAIN=mytest.example.com
WPGOVERN_OPERATOR_EMAIL=operator@mytest.com
ENV

    # Unset vars before loading
    unset WPGOVERN_DOMAIN WPGOVERN_OPERATOR_EMAIL 2>/dev/null || true
    wpgovern::bootstrap::load_env_readonly "$env_file"

    [[ "${WPGOVERN_DOMAIN:-}" == "mytest.example.com" ]] || {
        echo "WPGOVERN_DOMAIN not exported: ${WPGOVERN_DOMAIN:-unset}"; return 1
    }
    [[ "${WPGOVERN_OPERATOR_EMAIL:-}" == "operator@mytest.com" ]] || {
        echo "WPGOVERN_OPERATOR_EMAIL not exported: ${WPGOVERN_OPERATOR_EMAIL:-unset}"; return 1
    }
}

@test "H.6.2-3: load_env_readonly strips surrounding quotes from values" {
    local env_file="${TEST_TMPDIR}/quoted.env"
    cat > "$env_file" << 'ENV'
WPGOVERN_DOMAIN="quoted.example.com"
ENV
    unset WPGOVERN_DOMAIN 2>/dev/null || true
    wpgovern::bootstrap::load_env_readonly "$env_file"
    [[ "${WPGOVERN_DOMAIN:-}" == "quoted.example.com" ]] || {
        echo "Quotes not stripped: ${WPGOVERN_DOMAIN:-unset}"; return 1
    }
}

@test "H.6.2-3: load_env_readonly has xtrace protection (credential-safe)" {
    local env_file="${TEST_TMPDIR}/cred_test.env"
    local SENT="XTRACE_SENTINEL_LOAD_READONLY_H62"
    cat > "$env_file" << ENV
WPGOVERN_DB_WP_PASSWORD=${SENT}
ENV

    local xtrace_output
    xtrace_output="$(bash -x -c "
        source '${CORE_DIR}/bootstrap.sh'
        wpgovern::bootstrap::load_env_readonly '${env_file}'
    " 2>&1)"

    if echo "$xtrace_output" | grep -qF "$SENT"; then
        echo "CREDENTIAL LEAK under xtrace: sentinel found in trace output"
        return 1
    fi
}

@test "H.6.2-3: entry.sh reads env path from state bootstrap.env_file_path" {
    # Set up state file with a custom env path
    local custom_env="${TEST_TMPDIR}/custom.env"
    cat > "$custom_env" << ENV
WPGOVERN_DOMAIN=from-state-fact.example.com
WPGOVERN_OPERATOR_EMAIL=state@example.com
ENV

    local state_file="${TEST_TMPDIR}/install/.state.json"
    cat > "$state_file" << STATE
{
  "started_at": "2026-01-01T00:00:00Z",
  "last_run_at": "2026-01-01T00:00:00Z",
  "phases_complete": [],
  "phases_failed": [],
  "host_facts": {"bootstrap.env_file_path": "${custom_env}"}
}
STATE

    # Invoke entry.sh directly (not via shim) with state pointing to custom env
    run bash -c "
        export WPGOVERN_STATE_FILE='${state_file}'
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export NO_COLOR=1
        # Override INSTALLER_DIR to a test mirror with no-op audit modules
        MOCK_DIR='${TEST_TMPDIR}/mock_installer'
        mkdir -p \"\$MOCK_DIR/modules/audit\" \"\$MOCK_DIR/core\"
        cp '${REPO_DIR}/core/bootstrap.sh' \"\$MOCK_DIR/core/\"
        cp '${REPO_DIR}/core/state.sh' \"\$MOCK_DIR/core/\"
        cp '${REPO_DIR}/core/credentials.sh' \"\$MOCK_DIR/core/\"
        cp '${REPO_DIR}/modules/audit/entry.sh' \"\$MOCK_DIR/modules/audit/\"
        # Create no-op audit modules
        for mod in probes behavioral infrastructure security formatters orchestrator; do
            cat > \"\$MOCK_DIR/modules/audit/\${mod}.sh\" << 'MOCK'
#!/usr/bin/env bash
set -euo pipefail
wpgovern::audit::layer1()     { true; }
wpgovern::audit::layer1_5()   { true; }
wpgovern::audit::layer2()     { true; }
wpgovern::audit::layer3()     { true; }
wpgovern::audit::layer1_security_subset() { true; }
wpgovern::audit::format_human() { echo \"DOMAIN=\${WPGOVERN_DOMAIN:-unset}\"; }
wpgovern::audit::format_ci()   { echo \"DOMAIN=\${WPGOVERN_DOMAIN:-unset}\"; }
wpgovern::audit::format_json() { printf '{\"domain\":\"%s\"}' \"\${WPGOVERN_DOMAIN:-unset}\"; }
wpgovern::audit::run_full()    {
    _WPGOVERN_AUDIT_FINDINGS=''; _WPGOVERN_AUDIT_INTERNAL_ERROR=0
    wpgovern::audit::format_human; return 0
}
MOCK
        done
        bash \"\$MOCK_DIR/modules/audit/entry.sh\" --complete
    "
    [[ "$status" -eq 0 ]] || { echo "entry.sh failed: $output"; return 1; }
    # Verify DOMAIN came from the custom env file (state-fact path)
    echo "$output" | grep -q "from-state-fact.example.com" || {
        echo "Expected DOMAIN from state-fact env path"
        echo "Output: $output"
        return 1
    }
}
