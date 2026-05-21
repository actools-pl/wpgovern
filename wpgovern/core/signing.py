"""
WPGovern signing and verification service.

``SigningService`` wraps openssl ed25519 sign/verify for governance artifacts.
All signing uses the active private key in the appropriate trust domain.
Verification uses an explicit fail-closed allow-list:

    VALID_VERIFY_STATUSES = {"active", "retired_verify_only"}

Any key whose status is not in this set cannot be used for verification,
regardless of what that status is. This prevents a key in an unknown,
disabled, or future state from accidentally verifying signatures.

Signature format
----------------
Each signed file gets a JSON sidecar at ``<file>.sig.json``::

    {
      "algorithm": "ed25519",
      "key_id": "<key_id>",
      "value_b64": "<base64-encoded raw signature>"
    }

The sidecar is written atomically: staged to ``.sig.json.tmp``, then
``os.replace``'d to the final path.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

from wpgovern.core.trust import TrustService
from wpgovern.errors import IntegrityError, NotFoundError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.time import utc_now_iso

# Fail-closed allow-list. Any key status not in this set cannot verify.
VALID_VERIFY_STATUSES: frozenset[str] = frozenset({"active", "retired_verify_only"})


class SigningService:
    """Signing and verification service for WPGovern governance artifacts.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance. Derived from ``config`` if not provided.
        trust / trust_service: ``TrustService`` instance. Both parameter
            names are accepted for call-site compatibility.
    """

    def __init__(
        self,
        config: object = None,
        paths: Paths | None = None,
        trust: TrustService | None = None,
        trust_service: TrustService | None = None,
    ) -> None:
        self.config = config
        self.paths = paths or build_paths(config)
        self.trust = trust or trust_service or TrustService(paths=self.paths)

    # ------------------------------------------------------------------
    # Runtime-artifact helpers
    # ------------------------------------------------------------------

    def sign_runtime_artifact(self, path: Path) -> Path:
        """Sign ``path`` with the active runtime key. Returns the sig path."""
        return self.sign_file(Path(path), domain="runtime")

    def verify_runtime_artifact(self, path: Path) -> None:
        """Verify ``path`` against the runtime trust domain."""
        self.verify_file(Path(path), domain="runtime")

    # ------------------------------------------------------------------
    # Core sign / verify
    # ------------------------------------------------------------------

    def sign_file(self, path: Path, domain: str = "runtime") -> Path:
        """Sign ``path`` with the active key in ``domain``.

        Writes the signature to ``<path>.sig.json`` atomically.
        Returns the signature file path.

        F5: raw signature bytes are written to a private tempfile.mkdtemp()
        directory instead of a deterministic path in the governed directory.
        This closes the symlink-race window that existed when the predictable
        path `.{filename}.sig.raw` was written alongside the artifact.
        """
        path = Path(path)
        private_key = self.trust.active_private_key_path(domain)
        key_id = private_key.stem
        sig_path = Path(str(path) + ".sig.json")
        tmp_path = sig_path.with_name(f".{sig_path.name}.tmp")

        # F5: use a private temp directory outside the governed directory.
        with tempfile.TemporaryDirectory(prefix="wpgovern_sign_") as _tmpdir:
            raw_path = Path(_tmpdir) / "sig.raw"
            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
                 "-rawin", "-in", str(path), "-out", str(raw_path)],
                check=True,
            )
            payload = {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value_b64": base64.b64encode(raw_path.read_bytes()).decode("ascii"),
            }
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, sig_path)
        tmp_path.unlink(missing_ok=True)
        return sig_path

    def sign_staged(
        self,
        staged_data_path: Path,
        final_data_path: Path,
        domain: str = "runtime",
    ) -> tuple[Path, Path]:
        """Sign a staged data file, producing a staged signature alongside it.

        F5: raw signature bytes written to a private temp dir, not alongside the data.
        Returns ``(staged_sig_path, final_sig_path)``.
        """
        staged_data_path = Path(staged_data_path)
        final_data_path = Path(final_data_path)

        private_key = self.trust.active_private_key_path(domain)
        key_id = private_key.stem
        staged_sig_path = staged_data_path.with_name(f"{staged_data_path.name}.sig.json")
        final_sig_path = Path(str(final_data_path) + ".sig.json")

        with tempfile.TemporaryDirectory(prefix="wpgovern_sign_") as _tmpdir:
            raw_path = Path(_tmpdir) / "sig.raw"
            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
                 "-rawin", "-in", str(staged_data_path), "-out", str(raw_path)],
                check=True,
            )
            payload = {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value_b64": base64.b64encode(raw_path.read_bytes()).decode("ascii"),
            }
        with staged_sig_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(staged_sig_path, 0o600)
        return staged_sig_path, final_sig_path

    def verify_file(self, path: Path, domain: str = "runtime") -> None:
        """Verify the signature of ``path`` against the trust domain.

        Raises:
            NotFoundError: if the artifact or signature file is missing.
            IntegrityError: if the signature is invalid, the key is not in
                VALID_VERIFY_STATUSES, or the payload is malformed.
        """
        path = Path(path)
        sig_path = Path(str(path) + ".sig.json")

        if not path.exists():
            if path.name == "manifest.json":
                raise NotFoundError(f"Manifest missing: {path}")
            raise NotFoundError(f"Artifact missing: {path}")
        if not sig_path.exists():
            raise NotFoundError(f"Signature file missing: {sig_path}")

        try:
            payload = json.loads(sig_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"Signature payload is not valid JSON: {exc}") from exc

        key_id = str(payload.get("key_id") or "")
        if not key_id:
            raise IntegrityError("Signature missing key_id")

        # η-5: reject any signature whose algorithm field is not exactly "ed25519".
        # Missing field and wrong values (e.g. "rsa-sha256") are both rejected.
        algorithm = payload.get("algorithm")
        if algorithm != "ed25519":
            raise IntegrityError(
                f"Signature algorithm {algorithm!r} is not supported; "
                "only 'ed25519' is accepted"
            )

        status = self.trust.key_status(domain, key_id)
        if status not in VALID_VERIFY_STATUSES:
            raise IntegrityError(
                f"Key {key_id!r} has status {status!r}; "
                f"valid statuses for verification are {sorted(VALID_VERIFY_STATUSES)}"
            )

        public_key = self.trust.public_key_for_key_id(domain, key_id)

        # F5: write decoded signature to private temp dir, not alongside the artifact.
        with tempfile.TemporaryDirectory(prefix="wpgovern_verify_") as _tmpdir:
            raw_path = Path(_tmpdir) / "sig.raw"
            try:
                raw_path.write_bytes(
                    base64.b64decode(payload["value_b64"], validate=True)
                )
            except Exception as exc:
                raise IntegrityError("Invalid base64 signature payload") from exc

            try:
                subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                     "-rawin", "-in", str(path), "-sigfile", str(raw_path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as exc:
                raise IntegrityError(
                    f"Signature verification failed for {path}"
                ) from exc
        # TemporaryDirectory cleaned up automatically on exit

    def sign_bytes(self, data: bytes, domain: str = "runtime") -> dict:
        """Sign ``data`` bytes with the active key in ``domain``.

        Returns a dict with keys ``algorithm``, ``key_id``, ``value_b64``.
        This is the inline-signature form used by audit checkpoint records —
        the signature travels with the record in the audit chain rather than
        as a sidecar file alongside the append-only log.
        """
        import tempfile
        private_key = self.trust.active_private_key_path(domain)
        key_id = private_key.stem

        # η-4: use TemporaryDirectory so data and sig.raw files are never
        # in a predictable path — eliminates the symlink-race window that
        # existed when NamedTemporaryFile + with_suffix put both files
        # at deterministic adjacent paths in the OS temp directory.
        with tempfile.TemporaryDirectory(prefix="wpgovern_sign_bytes_") as _tmpdir:
            data_path = Path(_tmpdir) / "data.bin"
            raw_path = Path(_tmpdir) / "sig.raw"
            data_path.write_bytes(data)
            subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
                 "-rawin", "-in", str(data_path), "-out", str(raw_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value_b64": base64.b64encode(raw_path.read_bytes()).decode("ascii"),
            }

    def verify_bytes(self, data: bytes, signature: dict, domain: str = "runtime") -> None:
        """Verify a signature produced by ``sign_bytes``.

        ``signature`` is the dict returned by ``sign_bytes``:
        ``{"algorithm": "ed25519", "key_id": "...", "value_b64": "..."}``.

        Raises IntegrityError on any verification failure.
        """
        import tempfile
        key_id = str(signature.get("key_id") or "")
        if not key_id:
            raise IntegrityError("Signature missing key_id")

        # η-5: reject non-ed25519 algorithm — same rule as verify_file.
        algorithm = signature.get("algorithm")
        if algorithm != "ed25519":
            raise IntegrityError(
                f"Signature algorithm {algorithm!r} is not supported; "
                "only 'ed25519' is accepted"
            )

        status = self.trust.key_status(domain, key_id)
        if status not in VALID_VERIFY_STATUSES:
            raise IntegrityError(
                f"Key {key_id!r} has status {status!r}; "
                f"valid statuses for verification are {sorted(VALID_VERIFY_STATUSES)}"
            )

        public_key = self.trust.public_key_for_key_id(domain, key_id)

        # η-4: use TemporaryDirectory — same pattern as sign_bytes.
        with tempfile.TemporaryDirectory(prefix="wpgovern_verify_bytes_") as _tmpdir:
            data_path = Path(_tmpdir) / "data.bin"
            raw_path = Path(_tmpdir) / "sig.raw"
            data_path.write_bytes(data)
            try:
                raw_path.write_bytes(
                    base64.b64decode(signature["value_b64"], validate=True)
                )
            except Exception as exc:
                raise IntegrityError("Invalid base64 signature payload") from exc
            try:
                subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                     "-rawin", "-in", str(data_path), "-sigfile", str(raw_path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as exc:
                raise IntegrityError(
                    f"Checkpoint signature verification failed for key {key_id!r}"
                ) from exc

    def verify_active_pointer(self) -> None:
        """Verify the active pointer signature and that the referenced baseline exists
        and is in the active status.

        F1: Prior to this fix, only signature and file existence were verified.
        A crash or corruption that left the pointer referencing a draft/submitted/
        approved baseline would pass this check and allow supersession records
        to be built against an inactive predecessor — breaking the audit trail.
        """
        self.verify_runtime_artifact(self.paths.active_pointer)
        payload = json.loads(self.paths.active_pointer.read_text(encoding="utf-8"))
        baseline_id = payload.get("baseline_id")
        if not baseline_id:
            raise IntegrityError("Active pointer missing baseline_id")
        baseline_path = self.paths.baselines_dir / f"{baseline_id}.json"
        if not baseline_path.exists():
            raise IntegrityError(
                f"Active pointer references missing baseline: {baseline_id}"
            )
        # F1: verify the referenced baseline is actually in active status.
        try:
            baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise IntegrityError(
                f"Active pointer references unreadable baseline {baseline_id}: {exc}"
            ) from exc
        baseline_status = baseline_payload.get("status", "")
        if baseline_status != "active":
            raise IntegrityError(
                f"Active pointer references baseline {baseline_id!r} which has "
                f"status {baseline_status!r} instead of 'active'. "
                "The governance state may be corrupted — check the audit log."
            )

    # ------------------------------------------------------------------
    # Release signing
    # ------------------------------------------------------------------

    def _validate_release_manifest_contract(self, manifest: Path) -> list[dict]:
        """Validate a release manifest against the full contract.

        Used by both sign_release() and verify_release() — the same rules
        apply whether we are creating or verifying a signed manifest. This
        prevents the asymmetry where sign_release is strict and verify_release
        is loose (accepting manifests that sign_release would refuse).

        Raises ValidationError on any violation. Returns the artifacts list
        on success for the caller to use.
        """
        import hashlib as _hashlib
        import re as _re
        from wpgovern.errors import ValidationError

        if not manifest.exists():
            raise ValidationError(
                f"Release manifest missing: {manifest}. "
                "Create a manifest with a non-empty artifacts list before signing."
            )
        try:
            content = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Release manifest is not valid JSON: {exc}") from exc

        if not isinstance(content, dict) or not content:
            raise ValidationError(
                f"Release manifest is empty: {manifest}. "
                "A manifest must be a non-empty JSON object."
            )
        artifacts = content.get("artifacts")
        if not artifacts or not isinstance(artifacts, list):
            raise ValidationError(
                f"Release manifest has no 'artifacts' list: {manifest}. "
                "Each artifact must include 'path' and 'sha256' fields."
            )
        for entry in artifacts:
            if not isinstance(entry, dict):
                raise ValidationError(
                    f"Each artifact entry must be a dict, got: {entry!r}"
                )
            if "path" not in entry or "sha256" not in entry:
                raise ValidationError(
                    f"Artifact entry missing 'path' or 'sha256': {entry!r}"
                )
            artifact_path_str = str(entry["path"])
            if ".." in artifact_path_str or artifact_path_str.startswith("/"):
                raise ValidationError(
                    f"Artifact path '{artifact_path_str}' contains path traversal "
                    "or is absolute. Use relative paths within the dist directory."
                )
            sha256_claim = str(entry.get("sha256", ""))
            if not _re.fullmatch(r"[0-9a-f]{64}", sha256_claim):
                raise ValidationError(
                    f"Artifact sha256 for '{artifact_path_str}' is not valid "
                    f"(expected 64 lowercase hex chars): {sha256_claim!r}"
                )
            artifact_file = manifest.parent / artifact_path_str
            if not artifact_file.exists():
                raise ValidationError(
                    f"Artifact file not found: {artifact_file}. "
                    "All artifacts listed in the manifest must exist on disk."
                )
            # Reject symlinks — a symlink can point outside the release directory,
            # allowing the manifest to sign or verify external file content.
            if artifact_file.is_symlink():
                raise ValidationError(
                    f"Artifact '{artifact_path_str}' is a symlink. "
                    "Release artifacts must be real files within the dist directory."
                )
            # Reject resolved paths that escape the manifest directory.
            try:
                artifact_file.resolve().relative_to(manifest.parent.resolve())
            except ValueError:
                raise ValidationError(
                    f"Artifact '{artifact_path_str}' resolves outside the "
                    "manifest directory. Path escape not permitted."
                )
            actual_sha256 = _hashlib.sha256(artifact_file.read_bytes()).hexdigest()
            if actual_sha256 != sha256_claim:
                raise ValidationError(
                    f"Artifact hash mismatch for '{artifact_path_str}': "
                    f"manifest says {sha256_claim!r}, computed {actual_sha256!r}"
                )
        return artifacts

    def sign_release(
        self,
        manifest_path: Path | str | None = None,
        dist_dir: Path | str | None = None,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> Path:
        """Sign a release manifest in the release trust domain.

        Validates the full manifest contract before signing — refuses to
        sign a missing, empty, schema-invalid, or hash-mismatched manifest.
        """
        from wpgovern.errors import ValidationError
        manifest = self._release_manifest(manifest_path, dist_dir)
        self._validate_release_manifest_contract(manifest)
        sig_path = self.sign_file(manifest, domain="release")
        if audit_logger is not None and actor_context is not None:
            audit_logger.emit(
                event_type="release.sign",
                actor=str(actor_context.get("actor_id") or ""),
                outcome="success",
                details={**actor_context, "target_id": str(manifest)},
            )
        return sig_path

    def verify_release(
        self,
        manifest_path: Path | str | None = None,
        dist_dir: Path | str | None = None,
    ) -> None:
        """Verify a release manifest and all artifact hashes.

        Uses the same strict contract as sign_release() — both paths
        validate the full manifest schema and all artifact hashes. A signed
        manifest that would have been refused by sign_release() is also
        refused by verify_release().
        """
        manifest = self._release_manifest(manifest_path, dist_dir)
        if not manifest.exists():
            raise NotFoundError(f"Manifest missing: {manifest}")
        self.verify_file(manifest, domain="release")
        # Re-validate the full contract after signature check. This catches
        # manifests signed under old (looser) tooling or by compromised tooling.
        self._validate_release_manifest_contract(manifest)

    def _release_manifest(
        self,
        manifest_path: Path | str | None,
        dist_dir: Path | str | None,
    ) -> Path:
        if dist_dir is not None:
            base = Path(dist_dir)
            if manifest_path is not None and not str(manifest_path).endswith("manifest.json"):
                return base / str(manifest_path) / "manifest.json"
            direct = base / "manifest.json"
            if direct.exists():
                return direct
            version_manifests = sorted(base.glob("*/manifest.json"))
            if len(version_manifests) == 1:
                return version_manifests[0]
            return direct
        if manifest_path is not None:
            candidate = Path(manifest_path)
            if candidate.is_dir() or candidate.name != "manifest.json":
                return candidate / "manifest.json"
            return candidate
        return self.paths.root / "dist" / "manifest.json"
