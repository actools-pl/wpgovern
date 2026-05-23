#!/usr/bin/env bats
# =============================================================================
# test_h7_final_security.bats — Deployment-close gate
#
# If this file passes, the bash arc is shippable.
# Tests H.1-H.7 cross-cutting security properties.
# =============================================================================

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

@test "H.7-10: no BW01 warnings across all installer tests" {
    # Structural audit: no top-level `local` declarations outside functions
    run bash -c "grep -rn '^local ' '${REPO_DIR}/modules/' '${REPO_DIR}/core/' 2>/dev/null | grep -v 'test\|#'"
    [[ "$status" -ne 0 || -z "$output" ]] || {
        echo "BW01: top-level local declarations found:"
        echo "$output"
        return 1
    }
}

@test "H.7-10: single backup phase dispatch in entry script" {
    local count; count="$(grep -c '\[H.7\] starting backup phase' "${REPO_DIR}/wpgovern-install.sh")"
    [[ "$count" -eq 1 ]] || { echo "Expected 1 backup phase dispatch, got $count"; return 1; }
}

@test "H.7-10: single audit phase dispatch in entry script" {
    local count; count="$(grep -c '\[H.6\] starting audit phase' "${REPO_DIR}/wpgovern-install.sh")"
    [[ "$count" -eq 1 ]] || { echo "Expected 1 audit phase dispatch, got $count"; return 1; }
}

@test "H.7-10: all 7 phases present in entry script" {
    local script="${REPO_DIR}/wpgovern-install.sh"
    for phase in "\[H.1\]\|\[H.2\]" "\[H.3\]" "\[H.4\]" "\[H.5\]" "\[H.6\]" "\[H.7\]"; do
        grep -q "$phase" "$script" || { echo "Missing phase $phase in entry script"; return 1; }
    done
}

@test "H.7-10: age private key NOT included in governance tarball logic" {
    # Structural audit: full_backup.sh must contain --exclude with private key path
    grep -q "\-\-exclude.*\${WPGOVERN_AGE_PRIVATE_KEY_PATH\|age\.key}" \
        "${REPO_DIR}/modules/backup/full_backup.sh" || {
        echo "CRITICAL: governance tarball does not exclude age private key"
        return 1
    }
}

@test "H.7-10: all credential-touching backup functions have xtrace guard" {
    # Each function reading credentials must have the case "$-" guard
    for fn_file in full_backup binlog_rotate restore_test restore; do
        local src="${REPO_DIR}/modules/backup/${fn_file}.sh"
        [[ -f "$src" ]] || continue
        # Check for credential variables being read
        if grep -q "WPGOVERN_DB_BACKUP_PASSWORD\|WPGOVERN_AGE_PRIVATE_KEY" "$src"; then
            # Must have xtrace guard
            grep -q 'case "\$-" in \*x\*)' "$src" || {
                echo "MISSING xtrace guard in ${fn_file}.sh (reads credentials)"
                return 1
            }
        fi
    done
}

@test "H.7-10: restore.sh enforces governance-BEFORE-database phase ordering" {
    # Structural audit: _restore_phase_governance_state must appear before _restore_phase_database
    local src="${REPO_DIR}/modules/backup/restore.sh"
    local gov_line db_line
    gov_line="$(grep -n '_restore_phase_governance_state' "$src" | grep -v '#' | head -1 | cut -d: -f1)"
    db_line="$(grep -n '_restore_phase_database' "$src" | grep -v '#\|_restore_phase_database()' | head -1 | cut -d: -f1)"
    [[ -n "$gov_line" && -n "$db_line" ]] || {
        echo "Could not find governance or database phase in restore.sh"; return 1
    }
    [[ "$gov_line" -lt "$db_line" ]] || {
        echo "ORDERING VIOLATION: governance phase (line $gov_line) after database phase (line $db_line)"
        return 1
    }
}

@test "H.7-10: stream encryption — no intermediate .sql temp file in full_backup.sh" {
    # No plaintext SQL files should be written (Decision 1: stream encryption)
    local src="${REPO_DIR}/modules/backup/full_backup.sh"
    if grep -qE '>\s*/[^ ]*\.sql[^.]' "$src"; then
        echo "FAIL: plaintext SQL file write found in full_backup.sh"
        grep -n '> .*.sql' "$src"
        return 1
    fi
}

@test "H.7-10: verified-before-deleted ordering in binlog_rotate.sh" {
    local src="${REPO_DIR}/modules/backup/binlog_rotate.sh"
    local check_line rm_line
    check_line="$(grep -n '\-s .*age_dest' "$src" | head -1 | cut -d: -f1)"
    rm_line="$(grep -n 'rm -f.*binlog_file' "$src" | head -1 | cut -d: -f1)"
    [[ -n "$check_line" && -n "$rm_line" ]] || {
        echo "Could not find size check or rm in binlog_rotate.sh"; return 1
    }
    [[ "$check_line" -lt "$rm_line" ]] || {
        echo "ORDERING: rm (line $rm_line) before size check (line $check_line)"
        return 1
    }
}

@test "H.7-10: WPG-DR-01 PASS message uses 'acknowledged' not 'verified'" {
    # Wording audit: must not claim WPGovern verified off-server backup
    local src="${REPO_DIR}/modules/audit/security.sh"
    grep -A5 "WPG-DR-01.*PASS" "$src" | grep -qi "WPGovern.*verif" && {
        echo "FAIL: DR-01 PASS message implies WPGovern verified the backup (it cannot)"
        return 1
    } || true
    grep -A5 "WPG-DR-01.*PASS" "$src" | grep -qi "acknowledged" || {
        echo "Expected 'acknowledged' in WPG-DR-01 PASS message"
        return 1
    }
}

@test "H.7-10: all module files have syntax OK (bash -n)" {
    local errors=0
    while IFS= read -r f; do
        if ! bash -n "$f" 2>/dev/null; then
            echo "SYNTAX ERROR: $f"
            bash -n "$f"
            errors=$((errors+1))
        fi
    done < <(find "${REPO_DIR}/modules/" "${REPO_DIR}/core/" \
                  -name "*.sh" 2>/dev/null || true)
    [[ "$errors" -eq 0 ]] || { echo "$errors file(s) with syntax errors"; return 1; }
}
