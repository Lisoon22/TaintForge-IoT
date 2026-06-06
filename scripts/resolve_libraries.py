import argparse
from pathlib import Path

from taintforge_env.lib_resolver import LibraryResolver
from taintforge_env.library_planner import load_library_plan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--sysroot", action="append", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    plan = load_library_plan(args.plan)

    resolver = LibraryResolver(rootfs=Path(args.rootfs), sysroot_dirs=[Path(item) for item in args.sysroot])

    report = resolver.resolve_plan(plan)

    out_path = Path(args.out)
    resolver.save_report(report, out_path)

    print(f" Library resolution report saved to: {out_path}")
    print(f" Resolved: {len(report.resolved)}")
    print(f" Missing: {len(report.missing)}")

    if report.resolved:
        print()
        print(" Resolved libraries:")
        for item in report.resolved:
            print(
                f"    - {item.name} "
                f"{item.source_path} -> {item.guest_path}"
            )

    if report.missing:
        print()
        print(" Missing libraries:")
        for item in report.missing:
            print(
                f"    - {item.name} "
                f"kind={item.kind} "
                f"guest_path={item.guest_path} "
                f"sources={','.join(item.sources)}"
            )


if __name__ == "__main__":
    main()
