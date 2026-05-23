#!/usr/bin/env bats
# =============================================================================
# test_ci_hygiene.bats — Structural CI guards for installer hygiene
#
# H.4.1-6: no stale test artifacts (*.old, *.bak, *~, *.orig)
# H.4.1-7: each phase dispatched exactly once in entry script
# =============================================================================

REPO_DIR="${BATS_TEST_DIRNAME}/.."

@test "CI guard: no stale test artifacts in installer_tests/" {
    local stale_files
    stale_files="$(find "${BATS_TEST_DIRNAME}" -maxdepth 1 \
        \( -name '*.old' -o -name '*.bak' -o -name '*~' -o -name '*.orig' \) \
        2>/dev/null)"
    [[ -z "$stale_files" ]] || {
        echo "Stale test artifacts present:"
        echo "$stale_files"
        return 1
    }
}

@test "CI guard: exactly one WP phase dispatch in entry script" {
    local count
    count="$(grep -c '\[H.4\] starting wp phase' "${REPO_DIR}/wpgovern-install.sh")"
    [[ "$count" -eq 1 ]] || {
        echo "Expected exactly 1 WP phase dispatch, found: $count"
        return 1
    }
}

@test "CI guard: each phase dispatch appears at most once in entry script" {
    local script="${REPO_DIR}/wpgovern-install.sh"
    for phase in "H.1" "H.2" "H.3" "H.4"; do
        local count
        count="$(grep -cE "\[${phase}\] starting" "$script" 2>/dev/null || echo "0")"
        if [[ "$count" -gt 1 ]]; then
            echo "Phase $phase has $count dispatches in entry script (expected ≤1)"
            return 1
        fi
    done
}
