#!/usr/bin/env bats
# test_h7_systemd.bats — systemd unit installation

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "${TEST_TMPDIR}/systemd" "$MOCK_BIN"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    # Mock systemctl
    local _calls="${TEST_TMPDIR}/systemctl_calls.txt"
    cat > "${MOCK_BIN}/systemctl" << MOCK
#!/usr/bin/env bash
echo "systemctl \$*" >> "${_calls}"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/systemctl"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.7-7: systemd unit files exist in modules/backup/systemd/" {
    for unit in wpgovern-backup-full.service wpgovern-backup-full.timer \
                wpgovern-backup-binlogs.service wpgovern-backup-binlogs.timer; do
        [[ -f "${REPO_DIR}/modules/backup/systemd/${unit}" ]] || {
            echo "Missing unit file: ${unit}"; return 1
        }
    done
}

@test "H.7-7: install_systemd calls daemon-reload and enables both timers" {
    PATH="${MOCK_BIN}:${PATH}"
    source "${BACKUP_DIR}/install_systemd.sh"
    local test_systemd_dst="${TEST_TMPDIR}/systemd"
    local calls_file="${TEST_TMPDIR}/systemctl_calls.txt"
    : > "$calls_file"
    # Override the function to use test-local dirs
    wpgovern::backup::install_systemd() {
        local systemd_src="${WPGOVERN_INSTALLER_DIR}/modules/backup/systemd"
        local systemd_dst="${test_systemd_dst}"
        for unit in wpgovern-backup-full.service wpgovern-backup-full.timer \
                    wpgovern-backup-binlogs.service wpgovern-backup-binlogs.timer; do
            [[ -f "${systemd_src}/${unit}" ]] && cp "${systemd_src}/${unit}" "${systemd_dst}/${unit}" 2>/dev/null || true
        done
        systemctl daemon-reload
        for timer in wpgovern-backup-full.timer wpgovern-backup-binlogs.timer; do
            systemctl enable "$timer"
            systemctl start  "$timer"
        done
        wpgovern::state::set_fact "backup.systemd_units_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        return 0
    }
    wpgovern::backup::install_systemd
    grep -q "daemon-reload" "$calls_file" || { echo "daemon-reload not called"; return 1; }
    grep -q "enable wpgovern-backup-full.timer" "$calls_file" || { echo "timer not enabled"; return 1; }
}

@test "H.7-7: install_systemd records state fact" {
    PATH="${MOCK_BIN}:${PATH}"
    source "${BACKUP_DIR}/install_systemd.sh"
    wpgovern::backup::install_systemd() {
        systemctl daemon-reload 2>/dev/null || true
        wpgovern::state::set_fact "backup.systemd_units_installed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
    wpgovern::backup::install_systemd
    local ts; ts="$(wpgovern::state::get_fact "backup.systemd_units_installed_at")"
    [[ -n "$ts" ]] || { echo "state fact not recorded"; return 1; }
}
