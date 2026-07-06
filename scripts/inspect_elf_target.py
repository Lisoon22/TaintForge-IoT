#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from taintforge_env.elf_target import ElfTargetError, inspect_elf_target


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect an ELF target for TaintForge execution planning"
    )
    parser.add_argument("binary")
    args = parser.parse_args()

    try:
        descriptor = inspect_elf_target(args.binary)
    except ElfTargetError as exc:
        print(f"[!] ELF inspection failed: {exc}")
        raise SystemExit(1) from exc

    print(json.dumps(descriptor.to_dict(), indent=2))


if __name__ == "__main__":
    main()
