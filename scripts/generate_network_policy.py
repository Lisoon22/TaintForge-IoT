import argparse
from pathlib import Path
from taintforge_env.parser import load_taint_log
from taintforge_env.network_policy import (build_network_policy, save_network_policy)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--taint", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--bind-ip", default = "127.0.0.1")
    args = parser.parse_args()

    taint = load_taint_log(args.taint)

    policy = build_network_policy(taint = taint, mode = "local test", default_bind_ip = args.bind_ip)

    out_path = Path(args.out)

    save_network_policy(policy, out_path)

    print(f"Network policy saved in: {out_path}")
    print (f"Services: {len(policy.services)}")

    for service in policy.services:
        print(
            f"    {service.service_type.upper()} "
            f"{service.remote_ip}:{service.remote_port} "
            f"-> {service.bind_ip}:{service.bind_port} "
            f"role={service.role}"
        )

if __name__ == "__main__":
    main()
