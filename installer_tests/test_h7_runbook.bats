#!/usr/bin/env bats
# test_h7_runbook.bats — runbook installation

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${BACKUP_DIR}/install_runbook.sh"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.7-9: runbook template exists at modules/backup/runbook_template.md" {
    [[ -f "${REPO_DIR}/modules/backup/runbook_template.md" ]] || {
        echo "runbook template not found"; return 1
    }
}

@test "H.7-9: install_runbook places RUNBOOK.md at WPGOVERN_INSTALL_DIR with mode 0644" {
    wpgovern::backup::install_runbook
    local dest="${WPGOVERN_INSTALL_DIR}/RUNBOOK.md"
    [[ -f "$dest" ]] || { echo "RUNBOOK.md not installed at ${dest}"; return 1; }
    local mode; mode="$(stat -c '%a' "$dest")"
    [[ "$mode" == "644" ]] || { echo "Expected 0644, got $mode"; return 1; }
}
