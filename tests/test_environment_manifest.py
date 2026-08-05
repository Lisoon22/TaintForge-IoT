import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from taintforge_env.attempt import ExecutionStage
from taintforge_env.environment_manifest import (
    EnvironmentManifest,
    EnvironmentManifestError,
    EnvironmentManifestStore,
    EvidenceKind,
    LifecycleScope,
    ManifestConfidence,
    ManifestEntry,
    ManifestEntryStatus,
    ManifestEvidence,
    ManifestResourceKind,
)


SAMPLE_SHA256 = "a" * 64
EVIDENCE_SHA256 = "b" * 64
VALUE_SHA256 = "c" * 64


class EnvironmentManifestTests(unittest.TestCase):
    def make_entry(
        self,
        resource_id: str = "fs:/var/run/mirai",
    ) -> ManifestEntry:
        evidence = ManifestEvidence(
            evidence_id="attempt-000:event-17",
            kind=EvidenceKind.RUNTIME_EVENT,
            attempt_id="attempt-000",
            artifact_sha256=EVIDENCE_SHA256,
        )
        return ManifestEntry(
            resource_id=resource_id,
            kind=ManifestResourceKind.DIRECTORY,
            lifecycle_scope=LifecycleScope.REBUILD_ONLY,
            first_seen_stage=ExecutionStage.PRE_OEP_DISCOVERY,
            first_seen_attempt_id="attempt-000",
            provider="static_directory",
            value_id="directory-0755-v1",
            value_sha256=VALUE_SHA256,
            evidence=(evidence,),
            confidence=ManifestConfidence.VALIDATED,
            status=ManifestEntryStatus.ACTIVE,
            consumer_pc="0x401234",
        )

    def make_seed(self) -> EnvironmentManifest:
        return EnvironmentManifest(
            sample_sha256=SAMPLE_SHA256,
            manifest_version=0,
            rootfs_snapshot_id="env_0123456789abcdef",
            entries=(self.make_entry(),),
            created_by_attempt_id="preflight",
            change_reason="static ELF bootstrap and sparse seed environment",
        )

    def test_round_trip_preserves_evidence_and_hashes(self) -> None:
        seed = self.make_seed()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "environment_manifest_v0000.json"
            seed.save(path)
            loaded = EnvironmentManifest.load(path)

        self.assertEqual(loaded, seed)
        self.assertEqual(loaded.sample_id, "packed-sample-aaaaaaaaaaaaaaaa")
        self.assertEqual(len(loaded.manifest_sha256), 64)
        self.assertTrue(loaded.manifest_id.startswith("manifest-v0000-"))

    def test_derive_records_parent_and_diff(self) -> None:
        seed = self.make_seed()
        file_entry = replace(
            self.make_entry("fs:/etc/device.conf"),
            kind=ManifestResourceKind.FILE,
            provider="static_file",
            value_id="device-conf-v1",
        )
        child = seed.derive(
            rootfs_snapshot_id="env_fedcba9876543210",
            entries=(*seed.entries, file_entry),
            created_by_attempt_id="attempt-000",
            change_reason="promoted validated file provider",
        )
        diff = child.diff(seed)

        self.assertEqual(child.manifest_version, 1)
        self.assertEqual(child.parent_manifest_id, seed.manifest_id)
        self.assertEqual(diff.added, ("fs:/etc/device.conf",))
        self.assertTrue(diff.rootfs_changed)
        self.assertFalse(diff.is_empty)

    def test_store_is_append_only_and_verifies_chain(self) -> None:
        seed = self.make_seed()
        child = seed.derive(
            rootfs_snapshot_id="env_fedcba9876543210",
            entries=seed.entries,
            created_by_attempt_id="attempt-000",
            change_reason="rootfs repair snapshot",
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = EnvironmentManifestStore(Path(temporary) / "manifests")
            store.save(seed)
            store.save(child)
            verified = store.verify_chain()

        self.assertEqual(
            [manifest.manifest_version for manifest in verified], [0, 1]
        )
        self.assertEqual(verified[-1].parent_manifest_id, verified[0].manifest_id)

    def test_store_rejects_conflicting_version(self) -> None:
        seed = self.make_seed()
        conflicting = replace(
            seed,
            rootfs_snapshot_id="env_ffffffffffffffff",
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = EnvironmentManifestStore(Path(temporary) / "manifests")
            store.save(seed)
            with self.assertRaisesRegex(
                EnvironmentManifestError, "immutable"
            ):
                store.save(conflicting)

    def test_store_rejects_broken_parent_id(self) -> None:
        seed = self.make_seed()
        child = seed.derive(
            rootfs_snapshot_id="env_fedcba9876543210",
            entries=seed.entries,
            created_by_attempt_id="attempt-000",
            change_reason="repair",
        )
        child = replace(
            child,
            parent_manifest_id="manifest-v0000-deadbeefdeadbeef",
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = EnvironmentManifestStore(Path(temporary) / "manifests")
            store.save(seed)
            with self.assertRaisesRegex(
                EnvironmentManifestError, "parent id mismatch"
            ):
                store.save(child)

    def test_duplicate_resources_are_rejected(self) -> None:
        entry = self.make_entry()
        with self.assertRaisesRegex(
            EnvironmentManifestError, "duplicate resource_id"
        ):
            EnvironmentManifest(
                sample_sha256=SAMPLE_SHA256,
                manifest_version=0,
                rootfs_snapshot_id="env_0123456789abcdef",
                entries=(entry, entry),
                created_by_attempt_id="preflight",
                change_reason="invalid duplicate",
            )

    def test_tampered_entry_is_rejected(self) -> None:
        seed = self.make_seed()
        raw = seed.to_dict()
        raw["entries"][0]["value_sha256"] = "d" * 64

        with self.assertRaisesRegex(
            EnvironmentManifestError, "entry digest mismatch"
        ):
            EnvironmentManifest.from_dict(raw)

    def test_active_entry_cannot_be_rejected(self) -> None:
        with self.assertRaisesRegex(
            EnvironmentManifestError,
            "active manifest entry cannot have rejected confidence",
        ):
            replace(
                self.make_entry(),
                confidence=ManifestConfidence.REJECTED,
            )


if __name__ == "__main__":
    unittest.main()
