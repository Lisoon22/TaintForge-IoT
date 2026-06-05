import argparse
from pathlib import Path

from taintforge_env.elf_analyzer import ELFAnalysisError, analyze_elf
from taintforge_env.library_planner import (
    build_library_plan,
    save_library_plan,
)
from taintforge_env.parser import load_taint_log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--taint", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    taint = load_taint_log(args.taint)

    try:
        elf_info = analyze_elf(
            path=args.binary,
            arch_hint=taint.sample.arch,
        )
    except ELFAnalysisError as e:
        print(f"[-] ELF analysis failed: {e}")
        raise SystemExit(1)

    plan = build_library_plan(
        taint=taint,
        elf_info=elf_info,
    )

    out_path = Path(args.out)
    save_library_plan(plan, out_path)

    print("[+] ELF analysis")
    print(f"    dynamic: {elf_info.is_dynamic}")
    print(f"    interpreter: {elf_info.interpreter}")
    print(f"    needed: {', '.join(elf_info.needed_libraries) or '-'}")

    print()
    print(f"[+] Library plan saved to: {out_path}")
    print(f"[+] Requirements: {len(plan.requirements)}")

    for req in plan.requirements:
        print(
            f"    - {req.name} "
            f"kind={req.kind} "
            f"guest_path={req.guest_path} "
            f"sources={','.join(req.sources)}"
        )


if __name__ == "__main__":
    main()
