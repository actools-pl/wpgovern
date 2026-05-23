#!/usr/bin/env bash
# =============================================================================
# modules/db/users.sh — Application user verification + backup user creation
#
# H.3.1-2: xtrace protection at every function.
# H.3.1-3: existing wpbackup user verified for correct grants, not just existence.
# H.3.1-4: backup user grants split — operational on *.*, data on wordpress.*.
#
# Credentials discipline: >/dev/null 2>&1 on every mariadb invocation.
# =============================================================================

set -euo pipefail

wpgovern::db::users::verify_application_user() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2
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

# H.3.1-3: verify wpbackup grants match exactly the expected least-privilege set.
# Returns 0 if correct, 1 if missing required / has forbidden privileges.
_wpgovern_db_verify_backup_grants() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2

    local grants
    grants="$(docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -sNe "SHOW GRANTS FOR 'wpbackup'@'%'" \
        2>/dev/null || true)"

    if [[ -z "$grants" ]]; then
        wpgovern::bootstrap::log "ERROR: wpbackup has no grants (empty SHOW GRANTS output)"
        return 1
    fi

    # Required: operational privileges global, data privileges scoped to wordpress.*
    if ! echo "$grants" | grep -qF "REPLICATION CLIENT"; then
        wpgovern::bootstrap::log "ERROR: wpbackup missing required global grant: REPLICATION CLIENT"
        return 1
    fi
    if ! echo "$grants" | grep -qF "PROCESS"; then
        wpgovern::bootstrap::log "ERROR: wpbackup missing required global grant: PROCESS"
        return 1
    fi
    # H.3.1-4: SELECT and LOCK TABLES must be scoped to wordpress.*, not *.*
    if ! echo "$grants" | grep -qE '`wordpress`\.\*.*`wpbackup`|`wpbackup`.*`wordpress`\.'; then
        wpgovern::bootstrap::log "ERROR: wpbackup missing required wordpress.* scoped grants"
        return 1
    fi

    # Forbidden privilege check — fail closed on any dangerous privilege
    local forbidden=("ALL PRIVILEGES" "GRANT OPTION" "SUPER" "FILE"
                     "RELOAD" "SHUTDOWN" "CREATE ROUTINE" "ALTER")
    local f
    for f in "${forbidden[@]}"; do
        if echo "$grants" | grep -qF "$f"; then
            wpgovern::bootstrap::log "ERROR: wpbackup has forbidden privilege: $f"
            return 1
        fi
    done

    return 0
}

wpgovern::db::users::create_backup_user() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2
    local backup_pw="${WPGOVERN_DB_BACKUP_PASSWORD:?WPGOVERN_DB_BACKUP_PASSWORD is required}"

    # Idempotency check — errexit-safe
    local check
    check="$(docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -sNe "SELECT 1 FROM mysql.user WHERE User = 'wpbackup' AND Host = '%'" \
        2>/dev/null || true)"

    if [[ "$check" == "1" ]]; then
        # H.3.1-3: user exists — verify grants are correct before skipping
        if ! _wpgovern_db_verify_backup_grants; then
            wpgovern::state::mark_phase_failed "db" \
                "users: backup user exists with incorrect grants"
            return 1
        fi
        wpgovern::bootstrap::log "Backup user 'wpbackup' exists with correct grants — skipping creation"
        wpgovern::state::set_fact "db.users.backup_user_exists" "true"
        return 0
    fi

    # H.3.1-4: split grants — operational on *.*, data scoped to wordpress.*
    # >/dev/null 2>&1 mandatory: CREATE statement contains password literal
    if ! docker compose exec -T mariadb mariadb \
        -uroot -p"${WPGOVERN_DB_ROOT_PASSWORD}" \
        -e "CREATE USER 'wpbackup'@'%' IDENTIFIED BY '${backup_pw}'; \
            GRANT REPLICATION CLIENT, PROCESS ON *.* TO 'wpbackup'@'%'; \
            GRANT SELECT, LOCK TABLES ON \`wordpress\`.* TO 'wpbackup'@'%'; \
            FLUSH PRIVILEGES;" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "db" "users: backup user creation failed"
        return 1
    fi

    wpgovern::state::set_fact "db.users.backup_created_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "db.users.backup_user_exists" "true"
    wpgovern::bootstrap::log \
        "Backup user 'wpbackup' created: REPLICATION CLIENT+PROCESS on *.*, SELECT+LOCK TABLES on wordpress.*"
    return 0
}
