# Phase H.1 — Bash Installer Skeleton: Host Foundation

**Status:** Complete  
**Foundation:** WPGovern v52.1 (Python control plane; H.0 closed after seven hardening rounds)  
**Bats tests:** 81 (all passing)  
**Python tests:** 776 (unchanged from v52.1)  

---

## What H.1 delivered

H.1 is the first bash phase of the WPGovern installer arc. It brings a fresh Hetzner Ubuntu 24.04 server to "host phase complete": packages installed, kernel tuned, swap configured, firewall up, Docker CE installed, log rotation configured.

### Files created

| File | Purpose |
|------|---------|
| `wpgovern-install.sh` | Top-level entry point. Parses args, loads env, runs host phase. |
| `core/bootstrap.sh` | Env file loading, validation, logging. |
| `core/state.sh` | JSON state machine: phase tracking, facts, atomic writes. |
| `modules/host/packages.sh` | apt package installation. |
| `modules/host/kernel.sh` | sysctl parameter tuning for Caddy + MariaDB + WordPress. |
| `modules/host/swap.sh` | 2GB swap file creation on CX22. |
| `modules/host/firewall.sh` | UFW: default deny, allow 22/80/443. SSH lockout protection. |
| `modules/host/docker.sh` | Docker CE + compose plugin from official Docker apt repository. |
| `modules/host/logrotate.sh` | Log rotation for installer and Docker container logs. |
| `installer_tests/test_h1_entry_script.bats` | Entry script dispatch and state-write tests. |
| `installer_tests/test_h1_state_machine.bats` | State machine round-trip and atomic write tests. |
| `installer_tests/test_h1_host_module_structure.bats` | Module structure, namespacing, idempotency guard tests. |
| `installer_tests/test_h1_bootstrap.bats` | Env loading and validation tests. |
| `wpgovern.env.example` | Annotated env template for operators. |
| `.gitignore` | H.1 additions: secrets, state file, logs, generated files. |

### Function namespacing

All functions follow `wpgovern::<subsystem>::<module>::<verb>`:

| Module | Function |
|--------|---------|
| Entry script orchestration | `wpgovern::state::init`, `wpgovern::state::phase_complete`, `wpgovern::state::mark_phase_complete` |
| Bootstrap | `wpgovern::bootstrap::load_env`, `wpgovern::bootstrap::validate_env`, `wpgovern::bootstrap::log`, `wpgovern::bootstrap::log_invocation` |
| State | `wpgovern::state::init`, `wpgovern::state::phase_complete`, `wpgovern::state::mark_phase_complete`, `wpgovern::state::mark_phase_failed`, `wpgovern::state::set_fact`, `wpgovern::state::get_fact` |
| Host packages | `wpgovern::host::packages::install` |
| Host kernel | `wpgovern::host::kernel::tune` |
| Host swap | `wpgovern::host::swap::create` |
| Host firewall | `wpgovern::host::firewall::configure` |
| Host Docker | `wpgovern::host::docker::install` |
| Host logrotate | `wpgovern::host::logrotate::configure` |

**Note on actools reference:** The function namespacing pattern (`wpgovern::module::submodule::verb`) was applied following the colon-double-colon convention shown in the H.1 brief. Direct access to the actoolsDrupal-main codebase was not available during implementation; the brief's illustrative contract snippets were used as the reference for naming convention. If a future review against actoolsDrupal-main finds a deviation, the deviation should be documented in the next phase brief.

---

## State machine

**State file location:** `${WPGOVERN_STATE_FILE}` (default: `${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json`)

**Schema:**

```json
{
  "started_at": "2026-05-20T10:00:00Z",
  "last_run_at": "2026-05-20T10:05:23Z",
  "phases_complete": ["host"],
  "phases_failed": [],
  "host_facts": {
    "host.packages_installed": "true",
    "host.packages_installed_at": "2026-05-20T10:00:15Z",
    "host.kernel_tuned": "true",
    "host.kernel_tuned_at": "2026-05-20T10:00:16Z",
    "host.swap_configured": "true",
    "host.swap_size_mb": "2048",
    "host.firewall_configured": "true",
    "host.docker_installed": "true",
    "host.docker_version": "Docker version 26.x.x",
    "host.logrotate_configured": "true"
  }
}
```

All writes are atomic: `jq ... > .tmp && mv .tmp statefile` — same pattern as v52.1 Python control plane.

---

## How to run

```bash
# 1. Copy and edit env file
cp wpgovern.env.example wpgovern.env
chmod 600 wpgovern.env
$EDITOR wpgovern.env    # set WPGOVERN_OPERATOR_EMAIL at minimum

# 2. Run (as root)
sudo ./wpgovern-install.sh --env-file wpgovern.env

# 3. Re-running is safe — host phase is skipped if already complete
sudo ./wpgovern-install.sh --env-file wpgovern.env

# 4. Force UFW even on automated/console installs
sudo ./wpgovern-install.sh --env-file wpgovern.env --force-firewall
```

---

## What H.1 does NOT do

Per the brief's scope discipline:

- **No Docker Compose stack generation** — that is H.2
- **No Caddyfile, my.cnf** — H.2
- **No wp-config.php** — H.4
- **No WordPress installation, MariaDB setup, PHP builds** — H.2/H.3/H.4
- **No Python WPGovern invocation** — H.5 (baseline ceremony)
- **No backups or DR** — H.6
- **No observability beyond logrotate** — H.7
- **No "production-ready" claim** — state machine writes `phases_complete: ["host"]` but full production readiness requires H.1 through H.7

---

## Methodology continuity

Eight lessons from the Python arc travel into the bash arc:

- **Lesson 1 (integration tests at every wiring layer):** `test_h1_entry_script.bats` tests dispatch and state writes end-to-end; `test_h1_host_module_structure.bats` tests each call site independently.
- **Lesson 2 (call-site coverage discipline, v52 refinement):** Each test targets a specific call site (`grep -q "wpgovern::host::packages::install"` in entry script, not just "runs without error").
- **Lesson 7 (glob filtering):** No glob patterns on artifact directories with sidecars in H.1 bash tests. The v51.1 sidecar-filtering lesson is encoded in `test_h1_host_module_structure.bats` (no `.sig.json` equivalent exists for bash, but explicit filtering discipline was followed for any filesystem listing).
- **Atomic writes:** State machine uses `.tmp` + `mv` — same discipline as Python control plane.

---

## What H.2 begins next

H.2 adds the Docker Compose stack generation phase:
- `docker-compose.yml` generation (Caddy, WordPress/PHP-FPM, MariaDB, Redis)
- `Caddyfile` generation  
- `my.cnf` generation
- Image digest pinning (governance contract: no `:latest` tags)
- `modules/stack/` alongside `modules/host/`
- State machine gains `phases_complete: ["host", "stack"]`
