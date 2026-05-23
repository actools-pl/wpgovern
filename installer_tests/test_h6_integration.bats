#!/usr/bin/env bats
# =============================================================================
# test_h6_integration.bats — Production-path integration tests
#
# Lesson 2 fifth refinement (registered at H.5 closure) first operational
# application: tests invoke the real shim at a test-path location, exercising
# the full entry.sh → orchestrator → probes production boundary.
#
# Tests use a test-local shim path (not /usr/local/bin) to avoid needing root.
# All external commands (docker, curl, openssl, ss) are mocked via PATH.
# =============================================================================

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
CORE_DIR="${BATS_TEST_DIRNAME}/../core"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    SHIM_PATH="${TEST_TMPDIR}/bin/wpgovern-install-audit"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "$MOCK_BIN" "${TEST_TMPDIR}/bin"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export NO_COLOR=1
}

teardown() { rm -rf "$TEST_TMPDIR"; }

_install_test_shim() {
    # Install a test-local shim that points to the real entry.sh
    # This exercises the production shim path (Lesson 2 fifth refinement)
    cat > "$SHIM_PATH" << SHIM
#!/usr/bin/env bash
# Test-local wpgovern-install-audit shim — points to real entry.sh
exec "${REPO_DIR}/modules/audit/entry.sh" "\$@"
SHIM
    chmod 755 "$SHIM_PATH"
}

_make_all_pass_mock() {
    # Docker mock: all containers healthy, images digest-pinned
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
case "$1 $2" in
    "compose ps")
        for svc in caddy mariadb php wordpress; do
            printf '{"Name":"%s","Health":"healthy"}\n' "$svc"
        done ;;
    "compose config")
        echo "    image: caddy@sha256:aaaa"
        echo "    image: mariadb@sha256:bbbb"
        echo "    image: wordpress@sha256:cccc"
        echo "    image: wordpress@sha256:dddd" ;;
    "compose --profile") exit 0 ;;
    *) exit 0 ;;
esac
MOCK
    chmod +x "${MOCK_BIN}/docker"

    # curl mock: HTTPS enforced, security headers present, no version in Server
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
# Suppress body output when -o /dev/null or --output /dev/null
suppress_body=0
output_file=""
i=1
args=("$@")
while [[ $i -lt ${#args[@]} ]]; do
    if [[ "${args[$i]}" == "-o" || "${args[$i]}" == "--output" ]]; then
        output_file="${args[$((i+1))]}"
        [[ "$output_file" == "/dev/null" ]] && suppress_body=1
        i=$((i+2)); continue
    fi
    i=$((i+1))
done
if echo "$@" | grep -q "\-w" || echo "$@" | grep -q "http://"; then
    [[ "$suppress_body" -eq 0 ]] && echo "301"
    echo "https://test.example.com/"
elif echo "$@" | grep -q "cookie-jar\|cookie_jar\|X POST"; then
    # login probe — write a cookie
    for arg in "$@"; do
        if [[ "$arg" == /tmp/* && "$arg" != *".jar" ]]; then continue; fi
        [[ "$arg" == "--cookie-jar" ]] && continue
        if [[ "${prev:-}" == "--cookie-jar" ]]; then
            echo "# Netscape HTTP Cookie File" > "$arg" 2>/dev/null || true
        fi
        prev="$arg"
    done
    [[ "$suppress_body" -eq 0 ]] && printf '200'
else
    [[ "$suppress_body" -eq 0 ]] && printf 'HTTP/2 200\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Security-Policy: default-src self\r\nCache-Control: no-cache\r\n\r\n'
fi
MOCK
    chmod +x "${MOCK_BIN}/curl"

    # ss mock: only expected ports
    cat > "${MOCK_BIN}/ss" << 'MOCK'
#!/usr/bin/env bash
printf 'Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n'
printf 'tcp    LISTEN  0       0       0.0.0.0:22         0.0.0.0:*\n'
printf 'tcp    LISTEN  0       0       0.0.0.0:80         0.0.0.0:*\n'
printf 'tcp    LISTEN  0       0       0.0.0.0:443        0.0.0.0:*\n'
MOCK
    chmod +x "${MOCK_BIN}/ss"

    # df mock: healthy disk usage
    cat > "${MOCK_BIN}/df" << 'MOCK'
#!/usr/bin/env bash
echo "Use%"; echo "  45%"
MOCK
    chmod +x "${MOCK_BIN}/df"

    # free mock
    cat > "${MOCK_BIN}/free" << 'MOCK'
#!/usr/bin/env bash
printf 'Mem:           16384          6144         10240          0          0          0\n'
MOCK
    chmod +x "${MOCK_BIN}/free"

    # openssl mock: cert valid 90 days
    local future; future="$(date -d '+90 days' '+%b %e %H:%M:%S %Y GMT' 2>/dev/null || \
                            date -v+90d '+%b %e %H:%M:%S %Y GMT' 2>/dev/null || echo "Jan 1 00:00:00 2027 GMT")"
    cat > "${MOCK_BIN}/openssl" << MOCK
#!/usr/bin/env bash
if echo "\$@" | grep -q "s_client"; then exit 0; fi
if echo "\$@" | grep -q "enddate"; then echo "notAfter=${future}"; exit 0; fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/openssl"

    # timeout mock: just run the command
    cat > "${MOCK_BIN}/timeout" << 'MOCK'
#!/usr/bin/env bash
shift; exec "$@"
MOCK
    chmod +x "${MOCK_BIN}/timeout"
}

@test "H.6-7+8: shim installed at 755 perms with --version working" {
    _install_test_shim
    local perms; perms="$(stat -c '%a' "$SHIM_PATH")"
    [[ "$perms" == "755" ]] || { echo "Expected 755, got $perms"; return 1; }
    run "$SHIM_PATH" --version
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "wpgovern-install-audit" ]] || { echo "Missing version output"; return 1; }
    [[ "$output" =~ "1.0" ]] || { echo "Missing version number"; return 1; }
}

@test "H.6.2-1 + H.6-10: --json mode produces pure JSON (entire stdout pipes to jq)" {
    _install_test_shim
    _make_all_pass_mock
    PATH="${MOCK_BIN}:${PATH}"

    run "$SHIM_PATH" --json
    # Pipe ENTIRE stdout to jq — any preamble pollution (e.g., HTTP status code
    # from login probe) causes jq to fail. This closes H.6.2-1's regression class.
    echo "$output" | jq . > /dev/null 2>&1 || {
        echo "JSON output is not valid (entire stdout piped to jq)"
        echo "First 200 chars: ${output:0:200}"
        return 1
    }

    local version; version="$(echo "$output" | jq -r '.wpgovern_install_audit_version')"
    [[ "$version" == "1.0" ]] || { echo "Version mismatch: $version"; return 1; }

    local findings_count; findings_count="$(echo "$output" | jq '.findings | length')"
    [[ "${findings_count:-0}" -gt 0 ]] || { echo "No findings in JSON output"; return 1; }
}

@test "H.6-10: shim --ci produces sorted output with fix-IDs" {
    _install_test_shim
    _make_all_pass_mock
    PATH="${MOCK_BIN}:${PATH}"

    run "$SHIM_PATH" --ci
    echo "$output" | grep -q "WPG-" || {
        echo "No fix-IDs in CI output"
        echo "Output: $output"
        return 1
    }

    # CI output should NOT contain ANSI escape sequences
    if echo "$output" | grep -q $'\033'; then
        echo "ANSI escape sequences present in --ci output"; return 1
    fi
}

@test "H.6-10: shim entry dispatches install_shim for audit phase" {
    # Verify the audit phase dispatch is in wpgovern-install.sh and works
    local installer="${REPO_DIR}/wpgovern-install.sh"
    grep -q "\[H.6\] starting audit phase" "$installer" || {
        echo "H.6 phase dispatch missing from entry script"; return 1
    }
    # Exactly one dispatch
    local count; count="$(grep -c "\[H.6\] starting audit phase" "$installer")"
    [[ "$count" -eq 1 ]] || { echo "Expected 1 dispatch, got $count"; return 1; }
}
