#!/usr/bin/env bash
# =============================================================================
# modules/host/logrotate.sh — logrotate configuration
#
# Configures rotation for:
#   - WPGovern installer logs ($WPGOVERN_LOG_DIR/*.log)
#   - Docker container logs (/var/lib/docker/containers/*/*.log)
#
# Rotation policy: daily, 14 days retained, gzip after 1 day.
# =============================================================================

set -euo pipefail

wpgovern::host::logrotate::configure() {
    local conf_dir="/etc/logrotate.d"
    local conf_file="${conf_dir}/wpgovern"

    # Idempotency: skip if our config already exists
    if [[ -f "$conf_file" ]]; then
        wpgovern::bootstrap::log "logrotate already configured — skipping"
        wpgovern::state::set_fact "host.logrotate_configured" "true"
        return 0
    fi

    wpgovern::bootstrap::log "Configuring logrotate..."

    # H.1.1-6: verify logrotate binary is present before writing config
    if ! command -v logrotate >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "host" "logrotate binary missing"
        return 1
    fi

    cat > "$conf_file" <<LOGROTATE
# wpgovern installer and Docker log rotation
${WPGOVERN_LOG_DIR}/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}

/var/lib/docker/containers/*/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGROTATE

    # H.1.1-6: validation failure fails the module (fail closed, not warn-and-continue)
    if ! logrotate --debug "$conf_file" >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "host" "logrotate config validation failed: $conf_file"
        return 1
    fi

    wpgovern::state::set_fact "host.logrotate_configured_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "host.logrotate_configured" "true"
    wpgovern::state::set_fact "host.logrotate.config_path" "$conf_file"
    wpgovern::bootstrap::log "logrotate configured (daily, 14-day retention)"
}
