#!/usr/bin/env bash
# =============================================================================
# modules/db/users.sh — Application user verification + backup user creation
#
# Credentials discipline: >/dev/null 2>&1 on every mariadb invocation.
# The CREATE USER statement contains the backup password literal — without
# redirection mariadb may echo it in error output.
# =============================================================================

set -euo pipefail

wpgovern::db::users::verify_application_user() {
    # errexit-safe: command substitution whose result is then checked
    local check
    check="$(docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -sNe "SELECT 1 FROM mysql.user WHERE User = 'wpuser' AND Host = '%'" \
        2>/dev/null || true)"

    if [[ "$check" != "1" ]]; then
        wpgovern::bootstrap::log "ERROR: application user 'wpuser' does not exist"
        wpgovern::bootstrap::log "  This indicates the mariadb image first-run did not complete."
        wpgovern::state::mark_phase_failed "db" "users: application user wpuser missing"
        return 1
    fi

    wpgovern::state::set_fact "db.users.app_user_verified_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Application user 'wpuser' verified"
    return 0
}

wpgovern::db::users::create_backup_user() {
    local backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:?WPGOVERN_DB_BACKUP_PASSWORD is required}"

    # Idempotency check first — errexit-safe
    local check
    check="$(docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -sNe "SELECT 1 FROM mysql.user WHERE User = 'wpbackup' AND Host = '%'" \
        2>/dev/null || true)"

    if [[ "$check" == "1" ]]; then
        wpgovern::bootstrap::log "Backup user 'wpbackup' already exists — skipping creation"
        wpgovern::state::set_fact "db.users.backup_user_exists" "true"
        return 0
    fi

    # CREATE USER + GRANT + FLUSH as a single atomic invocation
    # Privileges per strategic plan: REPLICATION CLIENT, SELECT, LOCK TABLES, PROCESS
    # >/dev/null 2>&1 mandatory: CREATE statement contains password literal
    if ! docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -e "CREATE USER 'wpbackup'@'%' IDENTIFIED BY '${backup_pw}'; \
            GRANT REPLICATION CLIENT, SELECT, LOCK TABLES, PROCESS ON *.* TO 'wpbackup'@'%'; \
            FLUSH PRIVILEGES;" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "db" "users: backup user creation failed"
        return 1
    fi

    wpgovern::state::set_fact "db.users.backup_created_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "db.users.backup_user_exists" "true"
    wpgovern::bootstrap::log "Backup user 'wpbackup' created with REPLICATION CLIENT, SELECT, LOCK TABLES, PROCESS"
    return 0
}
