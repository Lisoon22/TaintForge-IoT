import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.egress_policy import (
    EgressPolicyError,
    load_egress_policy,
)


BASE_POLICY = {
    "schema_version": 1,
    "mode": "brokered_fetch",
    "default_action": "deny",
    "block_non_global_ips": True,
    "allowed_destinations": [
        {
            "name": "example",
            "match": {"hosts": ["example.com"], "ips": []},
            "schemes": ["https"],
            "ports": [443],
            "methods": ["GET", "HEAD"],
        }
    ],
}


class EgressPolicyTests(unittest.TestCase):
    def load(self, raw: dict):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            return load_egress_policy(path)

    def test_exact_get_is_allowed(self):
        policy = self.load(BASE_POLICY)
        decision = policy.evaluate_request(
            host="example.com",
            ip=None,
            scheme="https",
            port=443,
            method="GET",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.rule_name, "example")

    def test_post_is_denied(self):
        policy = self.load(BASE_POLICY)
        decision = policy.evaluate_request(
            host="example.com",
            ip=None,
            scheme="https",
            port=443,
            method="POST",
        )
        self.assertFalse(decision.allowed)

    def test_private_ip_is_denied(self):
        raw = dict(BASE_POLICY)
        raw["allowed_destinations"] = [{
            "name": "private",
            "match": {"hosts": [], "ips": ["10.10.0.1"]},
            "schemes": ["http"],
            "ports": [80],
            "methods": ["GET"],
        }]
        policy = self.load(raw)
        decision = policy.evaluate_request(
            host=None,
            ip="10.10.0.1",
            scheme="http",
            port=80,
            method="GET",
        )
        self.assertFalse(decision.allowed)
        self.assertIn("destination_ip_blocked", decision.reason)

    def test_unlisted_host_is_denied(self):
        policy = self.load(BASE_POLICY)
        decision = policy.evaluate_request(
            host="not-example.com",
            ip=None,
            scheme="https",
            port=443,
            method="GET",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "no_matching_allow_rule")

    def test_wildcard_host_is_rejected(self):
        raw = dict(BASE_POLICY)
        raw["allowed_destinations"] = [{
            "name": "wildcard",
            "match": {"hosts": ["*.example.com"], "ips": []},
            "schemes": ["https"],
            "ports": [443],
            "methods": ["GET"],
        }]
        with self.assertRaises(EgressPolicyError):
            self.load(raw)


if __name__ == "__main__":
    unittest.main()
