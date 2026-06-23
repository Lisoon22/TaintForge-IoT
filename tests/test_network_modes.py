import unittest

from taintforge_env.network_modes import (
    NetworkMode,
    normalize_network_mode,
    requires_egress_policy,
)


class NetworkModeTests(unittest.TestCase):
    def test_auto_with_dependencies_is_emulated(self):
        self.assertEqual(
            normalize_network_mode(
                "auto",
                has_network_dependencies=True,
            ),
            NetworkMode.EMULATED,
        )

    def test_auto_without_dependencies_is_none(self):
        self.assertEqual(
            normalize_network_mode(
                "auto",
                has_network_dependencies=False,
            ),
            NetworkMode.NONE,
        )

    def test_controlled_alias_is_emulated(self):
        self.assertEqual(
            normalize_network_mode(
                "controlled",
                has_network_dependencies=False,
            ),
            NetworkMode.EMULATED,
        )

    def test_brokered_fetch_requires_policy(self):
        self.assertTrue(
            requires_egress_policy(NetworkMode.BROKERED_FETCH)
        )
        self.assertFalse(
            requires_egress_policy(NetworkMode.EMULATED)
        )


if __name__ == "__main__":
    unittest.main()
