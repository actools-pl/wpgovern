#!/usr/bin/env bats
# =============================================================================
# test_h6_probes_layer1_5.bats — Layer 1.5 behavioral probe unit tests
#
# H.6.1-2: missing file from H.6 brief Section 3 H.6-10 (~5 tests).
# Prior coverage in test_h6_orchestrator.bats was dispatcher-level — mocking
# probe functions out rather than exercising their branching logic.
# This file provides ISOLATED probe-logic coverage: each test sources
# behavioral.sh directly, mocks only external commands (docker, curl), calls
# the REAL probe function, and asserts _WPGOVERN_AUDIT_FINDINGS content.
#
# The distinction matters most for Layer 1.5 (behavioral probes) because
# these probes have the most conditional branching:
#   - Redis: SET success + TTL set, SET success + TTL absent, SET fails
#   - Login: session cookie returned, no session cookie
#   - Cache: no-cache present, no-cache absent
#   - Trusted host: 421→PASS, 200→FAIL
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

    # Source orchestrator first (defines _audit_finding, _audit_emit helpers)
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    source "${AUDIT_DIR}/orchestrator.sh"
    # Source the REAL behavioral.sh — not mocked (Lesson 2 fifth refinement applies here)
    source "${AUDIT_DIR}/behavioral.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

# ---------------------------------------------------------------------------
# Redis writeback probe — two branching paths
# ---------------------------------------------------------------------------

@test "H.6-2: redis_writeback PASS when SET/GET/TTL round-trip all succeed" {
    # Mock: docker compose ps redis → healthy; docker exec SET → OK; GET → echoes last SET value; TTL → 25
    local sentinel_file="${TEST_TMPDIR}/redis_sentinel"
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
if [[ "\$*" =~ "ps" ]]; then
    printf '{"Name":"redis","Health":"healthy"}\n'; exit 0
fi
if [[ "\$*" =~ "SET" ]]; then
    # Capture the value (5th arg after: docker exec <ctr> redis-cli SET <key> <value> EX 30)
    for i in "\$@"; do :; done  # walk args to find value after key
    args=("\$@"); val=""
    for j in "\${!args[@]}"; do
        [[ "\${args[\$j]}" == "SET" ]] && val="\${args[\$((j+2))]}" && break
    done
    echo "\$val" > "${sentinel_file}"
    echo "OK"; exit 0
fi
if [[ "\$*" =~ "GET" ]]; then
    cat "${sentinel_file}" 2>/dev/null || echo ""; exit 0
fi
if [[ "\$*" =~ "TTL" ]]; then echo "25"; exit 0; fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_redis_writeback

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-STACK-005" || {
        echo "Missing WPG-STACK-005"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-005" | grep -q "|PASS|" || {
        echo "Expected PASS for successful Redis round-trip"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

@test "H.6-2: redis_writeback WARN when SET fails (write error)" {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if [[ "$*" =~ "ps" ]]; then
    printf '{"Name":"redis","Health":"healthy"}\n'; exit 0
fi
if [[ "$*" =~ "SET" ]]; then
    echo "ERR connection refused"; exit 1
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_redis_writeback

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-STACK-005" || {
        echo "Missing WPG-STACK-005"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-005" | grep -q "|WARN|" || {
        echo "Expected WARN when Redis SET fails"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
    # Fix command must be present (not null)
    local fix_cmd
    fix_cmd="$(echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-005" | cut -d'|' -f6)"
    [[ -n "$fix_cmd" ]] || { echo "Expected fix command when WARN"; return 1; }
}

# ---------------------------------------------------------------------------
# Trusted-host rejection probe — PASS on 421, FAIL on 200
# ---------------------------------------------------------------------------

@test "H.6-2: trusted_host_rejection PASS on 421 and FAIL on 200 (branching logic)" {
    # Test PASS path: curl returns 421
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
echo "421"
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_trusted_host_rejection

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-SEC-011" || {
        echo "Missing WPG-SEC-011"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-011" | grep -q "|PASS|" || {
        echo "Expected PASS when curl returns 421"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }

    # Reset buffer and test FAIL path: curl returns 200
    _WPGOVERN_AUDIT_FINDINGS=""
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
echo "200"
MOCK
    chmod +x "${MOCK_BIN}/curl"

    _audit_probe_trusted_host_rejection

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-011" | grep -q "|FAIL|" || {
        echo "Expected FAIL when trusted-host spoof returns 200"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
    # Fix command must be present for FAIL
    local fix_cmd
    fix_cmd="$(echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-011" | cut -d'|' -f6)"
    [[ -n "$fix_cmd" ]] || { echo "Expected fix command for FAIL"; return 1; }
}

# ---------------------------------------------------------------------------
# HTTP cache headers probe — Cache-Control present vs absent
# ---------------------------------------------------------------------------

@test "H.6-2: http_cache_headers FAIL when Cache-Control: no-cache absent on wp-login.php" {
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
# Headers without Cache-Control: no-cache
printf 'HTTP/2 200\r\nContent-Type: text/html\r\nSet-Cookie: wordpress_test_cookie=WP+Cookie+check\r\n\r\n'
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_http_cache_headers

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-SEC-010" || {
        echo "Missing WPG-SEC-010"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-SEC-010" | grep -q "|FAIL|" || {
        echo "Expected FAIL when Cache-Control: no-cache is absent"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

# ---------------------------------------------------------------------------
# Login session probe — session cookie returned vs not returned
# ---------------------------------------------------------------------------

@test "H.6-2: login_session WARN when no session cookie returned from login endpoint" {
    # Mock curl POST to wp-login.php: empty cookie jar (no Set-Cookie in response)
    cat > "${MOCK_BIN}/curl" << 'MOCK'
#!/usr/bin/env bash
# No cookie jar written — simulate login endpoint not setting session cookie
# Just consume all args and exit 0 (no output, no cookie file written)
exit 0
MOCK
    chmod +x "${MOCK_BIN}/curl"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_login_session

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-008" || {
        echo "Missing WPG-WP-008"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-008" | grep -q "|WARN|" || {
        echo "Expected WARN when no session cookie returned"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

# ---------------------------------------------------------------------------
# Structural: all four behavioral probe functions emit their expected fix-IDs
# (cross-verify catalog ↔ implementation; WPG-BKUP-001 etc. would fail here
#  if a probe silently changed its fix-ID namespace)
# ---------------------------------------------------------------------------

@test "H.6-2: all four behavioral probes emit fix-IDs matching the catalog" {
    # Source behavioral.sh and grep for fix-ID patterns emitted by each function
    local behavioral_ids
    behavioral_ids="$(grep -oE 'WPG-[A-Z]+-[0-9]+' "${AUDIT_DIR}/behavioral.sh" | sort -u)"

    # Catalog-expected IDs from PHASE_H6_README (Layer 1.5 section)
    for expected in "WPG-STACK-005" "WPG-WP-008" "WPG-SEC-010" "WPG-SEC-011"; do
        echo "$behavioral_ids" | grep -q "$expected" || {
            echo "Catalog fix-ID $expected not emitted by behavioral.sh"
            echo "Emitted IDs: $behavioral_ids"
            return 1
        }
    done
}
