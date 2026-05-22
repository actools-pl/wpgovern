#!/usr/bin/env bash
# =============================================================================
# modules/backup/keygen.sh — age keypair generation (idempotent)
#
# MUST NOT rotate keys on re-run: existing backups are encrypted to the
# current public key. Rotating silently would make all existing backups
# unrecoverable. Idempotency check: private key exists + mode 0600.
# Lesson 2 sixth refinement: xtrace guard at function entry (keys ARE credentials).
# =============================================================================

set -euo pipefail

wpgovern::backup::generate_keypair() {
    # Lesson 2 sixth refinement: xtrace guard — private key path + contents are credentials
    case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac

    local privkey_path="${WPGOVERN_AGE_PRIVATE_KEY_PATH:-/etc/wpgovern/age.key}"
    local pubkey_path="${WPGOVERN_AGE_PUBLIC_KEY_PATH:-/etc/wpgovern/age.pub}"

    # Idempotency: skip if private key already exists with correct mode
    if [[ -f "$privkey_path" && "$(stat -c '%a' "$privkey_path" 2>/dev/null)" == "600" ]]; then
        wpgovern::bootstrap::log "age keypair already present at ${privkey_path} — skipping generation"
        wpgovern::state::set_fact "backup.age_keypair_skipped_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 0
    fi

    # Ensure key directory exists with restrictive permissions
    local key_dir; key_dir="$(dirname "$privkey_path")"
    if ! mkdir -p "$key_dir"; then
        wpgovern::state::mark_phase_failed "backup" \
            "keygen: could not create key directory ${key_dir}"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    chmod 700 "$key_dir"

    # Generate keypair — age-keygen writes private key to stdout, public key as comment
    local keygen_output
    if ! keygen_output="$(age-keygen 2>/dev/null)"; then
        wpgovern::state::mark_phase_failed "backup" \
            "keygen: age-keygen failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Write private key (mode 0600) atomically
    local priv_tmp; priv_tmp="$(mktemp "${privkey_path}.tmp.XXXXXX")"
    if ! printf '%s\n' "$keygen_output" > "$priv_tmp"; then
        rm -f "$priv_tmp"
        wpgovern::state::mark_phase_failed "backup" "keygen: private key write failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    if ! chmod 600 "$priv_tmp"; then
        rm -f "$priv_tmp"
        wpgovern::state::mark_phase_failed "backup" "keygen: chmod 600 on private key failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    if ! mv "$priv_tmp" "$privkey_path"; then
        rm -f "$priv_tmp"
        wpgovern::state::mark_phase_failed "backup" "keygen: mv private key to ${privkey_path} failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    # Extract and write public key (mode 0644)
    local pubkey
    pubkey="$(grep '^# public key:' "$privkey_path" 2>/dev/null | sed 's/^# public key: //' || true)"
    if [[ -z "$pubkey" ]]; then
        # age-keygen format may vary; derive from the key file directly
        pubkey="$(age-keygen -y "$privkey_path" 2>/dev/null || true)"
    fi
    if [[ -z "$pubkey" ]]; then
        wpgovern::state::mark_phase_failed "backup" "keygen: could not derive public key"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    local pub_tmp; pub_tmp="$(mktemp "${pubkey_path}.tmp.XXXXXX")"
    if ! printf '%s\n' "$pubkey" > "$pub_tmp"; then
        rm -f "$pub_tmp"
        wpgovern::state::mark_phase_failed "backup" "keygen: public key write failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi
    chmod 644 "$pub_tmp"
    if ! mv "$pub_tmp" "$pubkey_path"; then
        rm -f "$pub_tmp"
        wpgovern::state::mark_phase_failed "backup" "keygen: mv public key to ${pubkey_path} failed"
        [[ -n "${_restore_xtrace:-}" ]] && set -x
        return 1
    fi

    wpgovern::state::set_fact "backup.age_keypair_generated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.age_public_key_fingerprint" "$pubkey"
    wpgovern::bootstrap::log "age keypair generated: ${privkey_path} (0600), ${pubkey_path} (0644)"

    [[ -n "${_restore_xtrace:-}" ]] && set -x
    return 0
}
