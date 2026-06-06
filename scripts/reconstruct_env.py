import argparse
from pathlib import Path
from taintforge_env.parser import load_taint_log
from taintforge_env.stub_generator import StubFilesystemGenerator
from taintforge_env.network_policy import (
    build_network_policy,
    save_network_policy,
)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--taint", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--bind-ip", default="127.0.0.1")
    args = parser.parse_args()

    out_dir = Path(args.out)
    config_dir = out_dir / "config"
    logs_dir = out_dir / "logs"

    config_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    taint = load_taint_log(args.taint)

    fs_generator = StubFilesystemGenerator(out_dir=Path(args.out), arch=taint.arch)

    fs_generator.generate(taint.file_dependencies)

    network_policy = build_network_policy(taint=taint, mode = "local_test", default_bind_ip = args.bind_ip)

    network_policy_path = config_dir / "network_policy.json"
    save_network_policy(network_policy, network_policy_path)

    print(f"Generated rootfs at {Path(args.out) / 'rootfs'}")
    print(f"Network policy saved at {network_policy_path}")
    print(f"Logs dir: {logs_dir}")

    if network_policy.services:
        print("Network services:")
        for service in network_policy.services:
            print(
                f"    {service.service_type.upper()} "
                f"{service.remote_ip}:{service.remote_port} "
                f"-> {service.bind_ip}:{service.bind_port} "
                f"role={service.role}"
            )
    else:
        print("No network services genenrated")

if __name__ == "__main__":
    main()


