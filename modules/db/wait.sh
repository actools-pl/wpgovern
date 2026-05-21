#!/usr/bin/env bash
# =============================================================================
# modules/db/wait.sh — Wait for MariaDB to be ready
#
# Three failure paths, each records state honestly:
#   1. Container not running → mark_phase_failed "wait_for_ready: container not running"
#   2. Timeout → mark_phase_failed "wait_for_ready: timeout after ${timeout}s"
#   3. wordpress DB missing → mark_phase_failed "wait_for_ready: wordpress database missing"
#
# Credentials discipline: every mariadb invocation uses >/dev/null 2>&1 so
# the password (-p"$WPGOVERN_DB_ROOT_PASSWORD") never reaches the log.
# =============================================================================

set -euo pipefail

wpgovern::db::wait_for_ready() {
    local timeout=180
    local elapsed=0
    local interval=5

    # Step 1: container running?
    # errexit-safe: grep exits 1 on no match — || true prevents abort
    local container_state
    container_state="$(docker compose ps mariadb --format json 2>/dev/null \
        | jq -r '.State // empty' || true)"
    if [[ "$container_state" != "running" ]]; then
        wpgovern::bootstrap::log "ERROR: mariadb container is not running (state: '${container_state}')"
        wpgovern::state::mark_phase_failed "db" "wait_for_ready: container not running"
        return 1
    fi

    # Step 2: accept connections within timeout
    # >/dev/null 2>&1 mandatory — mariadb may echo password in error output
    while [[ $elapsed -lt $timeout ]]; do
        if docker compose exec -T mariadb mariadb \
            -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
            -e "SELECT 1" >/dev/null 2>&1; then
            break
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    if [[ $elapsed -ge $timeout ]]; then
        wpgovern::bootstrap::log "ERROR: mariadb did not accept connections within ${timeout}s"
        wpgovern::state::mark_phase_failed "db" "wait_for_ready: timeout after ${timeout}s"
        return 1
    fi

    # Step 3: wordpress database exists?
    # >/dev/null 2>&1 mandatory on every mariadb invocation
    if ! docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -e "USE wordpress" >/dev/null 2>&1; then
        wpgovern::bootstrap::log "ERROR: wordpress database does not exist"
        wpgovern::state::mark_phase_failed "db" "wait_for_ready: wordpress database missing"
        return 1
    fi

    wpgovern::state::set_fact "db.wait_for_ready.completed_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "db.wait_for_ready.elapsed_seconds" "$elapsed"
    wpgovern::bootstrap::log "MariaDB ready after ${elapsed}s"
    return 0
}
