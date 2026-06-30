from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_c2_record_capture import (
    CaptureValidationError,
    validate_capture,
)


class CaptureValidatorTests(unittest.TestCase):
    def create_capture(
        self,
        root: Path,
        *,
        request: bytes = b"hello",
        response: bytes = b"world",
    ) -> Path:
        out_dir = root / "out"
        session_dir = (
            out_dir
            / "captures"
            / "run-1"
            / "session-1"
        )
        session_dir.mkdir(parents=True)

        (session_dir / "client_to_server.bin").write_bytes(
            request
        )
        (session_dir / "server_to_client.bin").write_bytes(
            response
        )

        summary = {
            "schema_version": 1,
            "run_id": "run-1",
            "session_id": "session-1",
            "capture_kind": "local_test",
            "close_reason": "upstream_closed",
            "error": None,
            "original_remote_ip": "198.51.100.10",
            "original_remote_port": 48101,
            "upstream_ip": "127.0.0.1",
            "upstream_port": 49001,
            "client_to_server": {
                "bytes": len(request),
                "chunks": 1,
                "sha256": hashlib.sha256(
                    request
                ).hexdigest(),
                "path": "client_to_server.bin",
            },
            "server_to_client": {
                "bytes": len(response),
                "chunks": 1,
                "sha256": hashlib.sha256(
                    response
                ).hexdigest(),
                "path": "server_to_client.bin",
            },
        }

        (session_dir / "session.json").write_text(
            json.dumps(summary),
            encoding="utf-8",
        )
        (session_dir / "events.jsonl").write_text(
            "\n".join(
                json.dumps({"event": name})
                for name in [
                    "session_started",
                    "upstream_connected",
                    "stream_chunk",
                    "session_finished",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        return out_dir

    def test_valid_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out_dir = self.create_capture(Path(temp))

            session_dir = validate_capture(
                out_dir=out_dir,
                expected_request=b"hello",
                expected_response=b"world",
            )

            self.assertEqual(
                session_dir.name,
                "session-1",
            )

    def test_payload_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out_dir = self.create_capture(
                Path(temp),
                response=b"wrong",
            )

            with self.assertRaises(
                CaptureValidationError
            ):
                validate_capture(
                    out_dir=out_dir,
                    expected_request=b"hello",
                    expected_response=b"world",
                )


if __name__ == "__main__":
    unittest.main()
