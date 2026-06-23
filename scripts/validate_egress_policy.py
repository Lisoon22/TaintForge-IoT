import argparse

from taintforge_env.egress_policy import (
    EgressPolicyError,
    load_egress_policy,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a TaintForge brokered-egress policy"
    )
    parser.add_argument("policy")
    args = parser.parse_args()

    try:
        policy = load_egress_policy(args.policy)
    except EgressPolicyError as exc:
        print(f"Invalid egress policy: {exc}")
        raise SystemExit(1)

    print("Valid egress policy")
    print(f"    schema_version: {policy.schema_version}")
    print(f"    mode:           {policy.mode.value}")
    print(f"    default_action: {policy.default_action}")
    print(f"    allow rules:    {len(policy.rules)}")
    print(f"    blocked ports:  {len(policy.blocked_ports)}")
    print(
        "    global limits: "
        f"connections={policy.global_limits.max_connections}, "
        f"download={policy.global_limits.max_downloaded_bytes} bytes"
    )

    for rule in policy.rules:
        print(
            f"    - {rule.name}: "
            f"hosts={list(rule.hosts)} "
            f"ips={list(rule.ips)} "
            f"schemes={list(rule.schemes)} "
            f"ports={list(rule.ports)} "
            f"methods={list(rule.methods)}"
        )


if __name__ == "__main__":
    main()
