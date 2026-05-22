#!/usr/bin/env bash
# =============================================================================
# modules/ceremony/byte_one.sh — Byte-one governance ceremony (nine steps)
#
# The bash module orchestrates; the Python CLI is the authority.
# Each step: idempotency check → invoke wpgovern → record state fact.
#
# Output capture vs fire-and-forget discipline (H.5 methodology pattern 2):
#   - $(wpgovern ... 2>/dev/null)       when stdout value IS needed
#   - wpgovern ... >/dev/null 2>&1      when stdout value is NOT needed
# Never use 2>&1 on a captured-stdout invocation — conflates streams.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helper: build consistent actor/reason flags for every wpgovern invocation
# ---------------------------------------------------------------------------
_wpgovern_ceremony_actor_args() {
    local actor_id="${WPGOVERN_ACTOR_ID:-installer}"
    local reason="${WPGOVERN_CEREMONY_REASON:-byte-one bootstrap}"
    printf '%s' "--actor-id ${actor_id} --reason ${reason}"
}

# ---------------------------------------------------------------------------
# Step 1 — Generate runtime trust key
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_1_generate_runtime_key() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.runtime_key_id" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 1: runtime-1 key already generated — skipping"
        return 0
    fi

    local key_id="runtime-1"
    # fire-and-forget: key_id is fixed, no need to capture
    # shellcheck disable=SC2086
    if ! wpgovern trust-key-generate "$key_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_1: trust-key-generate runtime-1 failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.runtime_key_id" "$key_id"
    wpgovern::state::set_fact "ceremony.step_1_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 1/9 complete: generated runtime key ${key_id}"
    return 0
}

# ---------------------------------------------------------------------------
# Step 2 — Activate runtime trust key
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_2_activate_runtime_key() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.step_2_completed_at" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 2: runtime-1 key already activated — skipping"
        return 0
    fi

    local key_id
    key_id="$(wpgovern::state::get_fact "ceremony.runtime_key_id")"
    if [[ -z "$key_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_2: ceremony.runtime_key_id not recorded — step 1 must have failed"
        return 1
    fi

    # shellcheck disable=SC2086
    if ! wpgovern trust-key-activate "$key_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_2: trust-key-activate ${key_id} failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.step_2_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 2/9 complete: activated runtime key ${key_id}"
    return 0
}

# ---------------------------------------------------------------------------
# Step 3 — Generate journal trust key
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_3_generate_journal_key() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.journal_key_id" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 3: journal-1 key already generated — skipping"
        return 0
    fi

    local key_id="journal-1"
    # shellcheck disable=SC2086
    if ! wpgovern journal-key-generate "$key_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_3: journal-key-generate journal-1 failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.journal_key_id" "$key_id"
    wpgovern::state::set_fact "ceremony.step_3_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 3/9 complete: generated journal key ${key_id}"
    return 0
}

# ---------------------------------------------------------------------------
# Step 4 — Activate journal trust key
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_4_activate_journal_key() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.step_4_completed_at" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 4: journal-1 key already activated — skipping"
        return 0
    fi

    local key_id
    key_id="$(wpgovern::state::get_fact "ceremony.journal_key_id")"
    if [[ -z "$key_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_4: ceremony.journal_key_id not recorded — step 3 must have failed"
        return 1
    fi

    # shellcheck disable=SC2086
    if ! wpgovern journal-key-activate "$key_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_4: journal-key-activate ${key_id} failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.step_4_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 4/9 complete: activated journal key ${key_id}"
    return 0
}

# ---------------------------------------------------------------------------
# Step 5 — Create signed draft baseline (capture: baseline_id needed for step 6)
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_5_baseline_create() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.baseline_id" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 5: baseline already created — skipping"
        return 0
    fi

    local baseline_id
    # Capture stdout only (2>/dev/null discards stderr to prevent stream conflation)
    # shellcheck disable=SC2086
    if ! baseline_id="$(wpgovern baseline-create \
            $(_wpgovern_ceremony_actor_args) 2>/dev/null)"; then
        wpgovern::state::mark_phase_failed "ceremony" "step_5: baseline-create failed"
        return 1
    fi

    if [[ -z "$baseline_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_5: baseline-create returned empty baseline_id"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.baseline_id" "$baseline_id"
    wpgovern::state::set_fact "ceremony.step_5_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 5/9 complete: baseline created (${baseline_id})"
    return 0
}

# ---------------------------------------------------------------------------
# Step 6 — Submit baseline
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_6_baseline_submit() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.step_6_completed_at" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 6: baseline already submitted — skipping"
        return 0
    fi

    local baseline_id
    baseline_id="$(wpgovern::state::get_fact "ceremony.baseline_id")"
    if [[ -z "$baseline_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_6: ceremony.baseline_id not recorded — step 5 must have failed"
        return 1
    fi

    # shellcheck disable=SC2086
    if ! wpgovern baseline-submit "$baseline_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_6: baseline-submit ${baseline_id} failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.step_6_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 6/9 complete: baseline submitted (${baseline_id})"
    return 0
}

# ---------------------------------------------------------------------------
# Step 7 — Approve baseline (self-approval; documented bootstrap exception)
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_7_baseline_approve() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.approval_id" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 7: baseline already approved — skipping"
        return 0
    fi

    local baseline_id
    baseline_id="$(wpgovern::state::get_fact "ceremony.baseline_id")"
    if [[ -z "$baseline_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_7: ceremony.baseline_id not recorded — step 5 must have failed"
        return 1
    fi

    local approval_id
    # Capture stdout only — approval_id needed for step 8
    # shellcheck disable=SC2086
    if ! approval_id="$(wpgovern baseline-approve "$baseline_id" \
            $(_wpgovern_ceremony_actor_args) 2>/dev/null)"; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_7: baseline-approve ${baseline_id} failed (self-approval bootstrap)"
        return 1
    fi

    if [[ -z "$approval_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_7: baseline-approve returned empty approval_id"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.approval_id" "$approval_id"
    wpgovern::state::set_fact "ceremony.step_7_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 7/9 complete: baseline approved (${approval_id})"
    return 0
}

# ---------------------------------------------------------------------------
# Step 8 — Activate baseline
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_8_baseline_activate() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.activated_at" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 8: baseline already activated — skipping"
        return 0
    fi

    local baseline_id approval_id
    baseline_id="$(wpgovern::state::get_fact "ceremony.baseline_id")"
    approval_id="$(wpgovern::state::get_fact "ceremony.approval_id")"

    if [[ -z "$baseline_id" || -z "$approval_id" ]]; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_8: baseline_id or approval_id not recorded in state"
        return 1
    fi

    # shellcheck disable=SC2086
    if ! wpgovern baseline-activate "$baseline_id" "$approval_id" \
            $(_wpgovern_ceremony_actor_args) >/dev/null 2>&1; then
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_8: baseline-activate ${baseline_id} ${approval_id} failed"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.activated_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "ceremony.step_8_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log "Step 8/9 complete: baseline activated (${baseline_id})"
    return 0
}

# ---------------------------------------------------------------------------
# Step 9 — Governance check (system crosses the governance threshold)
# ---------------------------------------------------------------------------
wpgovern::ceremony::step_9_governance_check() {
    if [[ -n "$(wpgovern::state::get_fact "ceremony.governance_check_passed_at" 2>/dev/null)" ]]; then
        wpgovern::bootstrap::log "Step 9: governance-check already passed — skipping"
        return 0
    fi

    if ! wpgovern governance-check >/dev/null 2>&1; then
        local exit_code=$?
        wpgovern::state::mark_phase_failed "ceremony" \
            "step_9: governance-check returned exit ${exit_code}"
        return 1
    fi

    wpgovern::state::set_fact "ceremony.step_9_completed_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "ceremony.governance_check_passed_at" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::bootstrap::log \
        "Step 9/9 complete: governance-check exit 0 — system is governed"
    return 0
}

# ---------------------------------------------------------------------------
# byte_one — runs the nine-step ceremony in sequence
# ---------------------------------------------------------------------------
wpgovern::ceremony::byte_one() {
    _wpgovern_disable_xtrace_for_credentials  # H.3.1-2: db passwords + auth keys in env

    # Hard requirement: WPGOVERN_INSTALL_DIR must match the Python control plane's
    # hardcoded install_dir (/opt/wpgovern-install). If they differ, baseline-create
    # would hash files from the wrong path and the governance-check would never agree.
    if [[ "${WPGOVERN_INSTALL_DIR:-}" != "/opt/wpgovern-install" ]]; then
        wpgovern::bootstrap::log \
            "ERROR: WPGOVERN_INSTALL_DIR must be /opt/wpgovern-install"
        wpgovern::bootstrap::log \
            "  Python control plane's hardcoded path: /opt/wpgovern-install"
        wpgovern::bootstrap::log \
            "  Got: ${WPGOVERN_INSTALL_DIR:-<unset>}"
        wpgovern::state::mark_phase_failed "ceremony" \
            "byte-one: WPGOVERN_INSTALL_DIR must be /opt/wpgovern-install; got ${WPGOVERN_INSTALL_DIR:-<unset>}"
        return 1
    fi

    # Nine-step sequence — each step handles its own idempotency and state recording
    wpgovern::ceremony::step_1_generate_runtime_key  || return 1
    wpgovern::ceremony::step_2_activate_runtime_key  || return 1
    wpgovern::ceremony::step_3_generate_journal_key  || return 1
    wpgovern::ceremony::step_4_activate_journal_key  || return 1
    wpgovern::ceremony::step_5_baseline_create       || return 1
    wpgovern::ceremony::step_6_baseline_submit       || return 1
    wpgovern::ceremony::step_7_baseline_approve      || return 1
    wpgovern::ceremony::step_8_baseline_activate     || return 1
    wpgovern::ceremony::step_9_governance_check      || return 1

    return 0
}
