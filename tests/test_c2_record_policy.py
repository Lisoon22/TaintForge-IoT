from __future__ import annotations

import unittest

from taintforge_env.c2_record_policy import (
    C2RecordPolicyError,
    parse_c2_record_policy,
)


def local_policy() -> dict:
    return {
        "schema_version": 1,
        "mode": "brokered_record",
        "capture_kind": "local_test",
        "default_action": "deny",
        "listen_port": 41000,
        "target": {
            "original_ip": "198.51.100.10",
            "original_port": 48101,
            "upstream_ip": "127.0.0.1",
            "upstream_port": 49001,
        },
        "limits": {
            "max_connections": 1,
            "connect_timeout_seconds": 2,
            "session_timeout_seconds": 10,
            "idle_timeout_seconds": 2,
            "max_client_bytes": 4096,
            "max_server_bytes": 4096,
        },
    }


class C2RecordPolicyTests(unittest.TestCase):
    def test_local_policy_is_valid(self) -> None:
        policy = parse_c2_record_policy(local_policy())
        self.assertEqual(policy.capture_kind, "local_test")
        self.assertEqual(policy.target.upstream_ip, "127.0.0.1")

    def test_live_requires_acknowledgement(self) -> None:
        raw = local_policy()
        raw["capture_kind"] = "live"
        raw["target"] = {
            "original_ip": "8.8.8.8",
            "original_port": 443,
            "upstream_ip": "8.8.8.8",
            "upstream_port": 443,
        }
        with self.assertRaises(C2RecordPolicyError):
            parse_c2_record_policy(raw)

    def test_live_requires_exact_upstream_identity(self) -> None:
        raw = local_policy()
        raw["capture_kind"] = "live"
        raw["live_capture_acknowledged"] = True
        raw["target"] = {
            "original_ip": "8.8.8.8",
            "original_port": 443,
            "upstream_ip": "1.1.1.1",
            "upstream_port": 443,
        }
        with self.assertRaises(C2RecordPolicyError):
            parse_c2_record_policy(raw)

    def test_default_action_must_be_deny(self) -> None:
        raw = local_policy()
        raw["default_action"] = "allow"
        with self.assertRaises(C2RecordPolicyError):
            parse_c2_record_policy(raw)


if __name__ == "__main__":
    unittest.main()
