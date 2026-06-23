from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.replay_store import (
    ReplayEntryExistsError,
    ReplayStore,
    ReplayStoreValidationError,
)


class ReplayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temp.name) / "replay"
        self.store = ReplayStore(self.store_path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_initialize_creates_empty_store(self) -> None:
        self.store.initialize()
        self.assertTrue((self.store_path / "index.json").is_file())
        self.assertEqual(self.store.load_entries(), [])

    def test_add_and_lookup_exact_request(self) -> None:
        entry = self.store.add(
            transport="tcp",
            remote_ip="91.200.10.5",
            remote_port=5555,
            request_bytes=b"hello",
            response_bytes=b"world",
            protocol_hint="c2_binary",
        )

        result = self.store.lookup(
            transport="tcp",
            remote_ip="91.200.10.5",
            remote_port=5555,
            request_bytes=b"hello",
            protocol_hint="c2_binary",
        )

        self.assertTrue(result.hit)
        self.assertEqual(result.entry, entry)
        self.assertEqual(result.response_bytes, b"world")

    def test_different_payload_is_miss(self) -> None:
        self.store.add(
            transport="tcp",
            remote_ip="91.200.10.5",
            remote_port=5555,
            request_bytes=b"hello",
            response_bytes=b"world",
        )

        result = self.store.lookup(
            transport="tcp",
            remote_ip="91.200.10.5",
            remote_port=5555,
            request_bytes=b"different",
        )

        self.assertFalse(result.hit)
        self.assertIsNone(result.response_bytes)

    def test_duplicate_requires_replace(self) -> None:
        self.store.add(
            transport="udp",
            remote_ip="8.8.8.8",
            remote_port=53,
            request_bytes=b"dns-query",
            response_bytes=b"dns-response",
        )

        with self.assertRaises(ReplayEntryExistsError):
            self.store.add(
                transport="udp",
                remote_ip="8.8.8.8",
                remote_port=53,
                request_bytes=b"dns-query",
                response_bytes=b"dns-response",
            )

    def test_tampered_response_is_detected(self) -> None:
        entry = self.store.add(
            transport="tcp",
            remote_ip="1.1.1.1",
            remote_port=80,
            request_bytes=b"GET / HTTP/1.0\r\n\r\n",
            response_bytes=b"HTTP/1.0 200 OK\r\n\r\nbody",
        )

        response_path = self.store_path / entry.response.blob_path
        response_path.write_bytes(b"tampered")

        with self.assertRaises(ReplayStoreValidationError):
            self.store.validate()


if __name__ == "__main__":
    unittest.main()
