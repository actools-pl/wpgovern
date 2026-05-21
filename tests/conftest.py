"""
Pytest configuration for the WPGovern reconstruction test suite.

The package is installed in editable mode (``pip install -e .``) before
running tests, so ``import wpgovern`` resolves without any sys.path
manipulation here.  This conftest is the single place to add shared
fixtures as phases progress.
"""

import pytest


# H.0-A: most v47 tests call BaselineService.create_draft() without setting up
# the four config files that H.0 now requires. Patch _compute_config_file_hashes
# to return a canonical fake dict so all pre-H.0 tests stay green without
# modification. H.0 tests that want real hashing opt out by using the
# setup helpers in test_config_file_hashing.py.
_FAKE_CONFIG_HASHES = {
    "docker-compose.yml": "sha256:" + "a" * 64,
    "Caddyfile":          "sha256:" + "b" * 64,
    "my.cnf":             "sha256:" + "c" * 64,
    "wp-config.php":      "sha256:" + "d" * 64,
}


@pytest.fixture(autouse=True)
def _patch_compute_config_file_hashes(monkeypatch):
    """Prevent _compute_config_file_hashes from touching the filesystem in tests.

    Pre-H.0 tests do not set up the four config files under install_dir.
    This autouse fixture patches the function globally so all existing tests
    keep working without modification (optional-field discipline: H.0-A).
    """
    import wpgovern.core.baseline as _baseline_mod
    monkeypatch.setattr(
        _baseline_mod,
        "_compute_config_file_hashes",
        lambda install_dir: dict(_FAKE_CONFIG_HASHES),
    )
