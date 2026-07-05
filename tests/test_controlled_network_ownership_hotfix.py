from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from taintforge_env.controlled_network_backend import (
    ControlledNetworkBackend,
    ControlledNetworkConfig,
    ControlledNetworkPlan,
    NetworkServiceMapping,
)


class ControlledNetworkOwnershipHotfixTests(unittest.TestCase):
    def make_backend(self, root: Path) -> tuple[ControlledNetworkBackend, MagicMock]:
        run_dir = root / "run"
        (run_dir / "config").mkdir(parents=True)
        (run_dir / "logs").mkdir()
        policy = root / "policy.json"
        policy.write_text("{}", encoding="utf-8")
        executor = MagicMock()
        executor.run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        config = ControlledNetworkConfig(
            project_root=root,
            run_dir=run_dir,
            template_policy_path=policy,
            session_id="session",
            iteration_index=0,
            self_test=False,
        )
        return ControlledNetworkBackend(config, executor=executor), executor

    def test_privilege_drop_command_uses_invoking_uid_gid(self) -> None:
        command = ControlledNetworkBackend._drop_privileges_command()
        self.assertEqual(
            command,
            [
                "setpriv",
                "--reuid",
                str(os.getuid()),
                "--regid",
                str(os.getgid()),
                "--clear-groups",
            ],
        )

    def test_prepares_user_owned_log_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, _executor = self.make_backend(Path(tmp))
            backend._prepare_service_log_directories()
            for name in (
                "network_host",
                "network_loopback",
                "network_transparent",
            ):
                path = backend.logs_dir / name
                self.assertTrue(path.is_dir())
                self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertEqual(path.stat().st_gid, os.getgid())
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_low_loopback_port_sets_namespace_local_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, executor = self.make_backend(Path(tmp))
            plan = ControlledNetworkPlan(
                namespace_name="tf-test",
                veth_host="tfh-test",
                veth_namespace="tfn-test",
                host_ip="10.203.1.1",
                namespace_ip="10.203.1.2",
                host_cidr="10.203.1.1/24",
                namespace_cidr="10.203.1.2/24",
                catch_all_enabled=True,
                catch_all_tcp_port=40000,
                catch_all_udp_port=40001,
                loopback_services=(
                    NetworkServiceMapping(
                        service_type="tcp",
                        role="http",
                        remote_ip="127.0.0.1",
                        remote_port=80,
                        protocol_hint="text",
                        placement="namespace_loopback",
                        bind_ip="127.0.0.1",
                        bind_port=80,
                    ),
                ),
            )
            backend._configure_namespace_service_privileges(plan)
            command = executor.run.call_args.args[0]
            self.assertEqual(command[:6], [
                "sudo", "-n", "ip", "netns", "exec", "tf-test"
            ])
            self.assertIn(
                "net.ipv4.ip_unprivileged_port_start=80",
                command,
            )


if __name__ == "__main__":
    unittest.main()
