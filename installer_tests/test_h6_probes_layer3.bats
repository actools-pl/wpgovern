#!/usr/bin/env bats
# =============================================================================
# test_h6_probes_layer3.bats — Layer 3 security probes
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
AUDIT_DIR="${BATS_TEST_DIRNAME}/../modules/audit"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export NO_COLOR=1

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${AUDIT_DIR}/orchestrator.sh"
    source "${AUDIT_DIR}/security.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.6-4: HTTP 301 redirect to HTTPS → WPG-SEC-002 PASS" {
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
echo "301"
echo "https://test.example.com/"
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_https_enforced
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-002" | grep -q "|PASS|" || {
        echo "Expected PASS for 301 redirect"; return 1
    }
}

@test "H.6-4: HTTP 200 (no redirect) → WPG-SEC-002 FAIL" {
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
echo "200"
echo ""
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_https_enforced
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-002" | grep -q "|FAIL|" || {
        echo "Expected FAIL for HTTP 200"; return 1
    }
}

@test "H.6-4: server header with version → WPG-SEC-005 FAIL" {
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
printf 'HTTP/2 200\r\nServer: caddy/2.7.4\r\n\r\n'
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_server_header_hidden
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-005" | grep -q "|FAIL|" || {
        echo "Expected FAIL for version-leaking server header"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-005" | grep -q "caddy/2.7.4" || {
        echo "Expected version in message"; return 1
    }
}

@test "H.6-4: server header version-stripped → WPG-SEC-005 WARN" {
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
printf 'HTTP/2 200\r\nServer: Caddy\r\n\r\n'
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_server_header_hidden
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-005" | grep -q "|WARN|" || {
        echo "Expected WARN for version-stripped server header"; return 1
    }
}

@test "H.6-4: all images digest-pinned → WPG-SEC-009 PASS" {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "    image: caddy:2@sha256:aaaa"
echo "    image: wordpress:6.5-php8.2-fpm@sha256:bbbb"
echo "    image: mariadb:10.11@sha256:cccc"
echo "    image: wordpress:cli@sha256:dddd"
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_docker_images_pinned
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-009" | grep -q "|PASS|" || {
        echo "Expected PASS for digest-pinned images"; return 1
    }
}

@test "H.6-4: image without digest → WPG-SEC-009 FAIL" {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "    image: caddy:2"
echo "    image: wordpress:6.5-php8.2-fpm@sha256:bbbb"
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_docker_images_pinned
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-009" | grep -q "|FAIL|" || {
        echo "Expected FAIL for unpinned image"; return 1
    }
}

@test "H.6.2-7: server_header probe PASS when Server header absent (no abort under set -e)" {
    # Headers without Server: — grep returning 1 should not abort the function
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
printf 'HTTP/2 200\r\nContent-Type: text/html\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n'
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"

    # Call under a stricter subshell to verify || true prevents abort
    run bash -c "
        set -euo pipefail
        export WPGOVERN_DOMAIN='test.example.com'
        export NO_COLOR=1
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        source '${AUDIT_DIR}/orchestrator.sh'
        source '${AUDIT_DIR}/security.sh'
        export PATH='${MOCK_BIN}:${PATH}'
        _audit_probe_server_header_hidden
        echo \"findings:\$_WPGOVERN_AUDIT_FINDINGS\"
    "
    [[ "$status" -eq 0 ]] || { echo "Function aborted under set -e when Server header absent: $output"; return 1; }
    echo "$output" | grep -q "WPG-SEC-005" || { echo "Missing WPG-SEC-005 finding"; return 1; }
    # No Server header → PASS (best practice)
    echo "$output" | grep "WPG-SEC-005" | grep -q "PASS" || {
        echo "Expected PASS when Server header absent"
        echo "Output: $output"
        return 1
    }
}
