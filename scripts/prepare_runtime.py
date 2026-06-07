import argparse
from pathlib import Path

from taintforge_env.parser import load_taint_log
from taintforge_env.runtime_preparer import (
    RuntimePreparationError,
    RuntimePreparer,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--taint", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--library-resolution")
    parser.add_argument("--allow-missing-libraries", action="store_true")

    args = parser.parse_args()

    taint = load_taint_log(args.taint)

    preparer = RuntimePreparer(out_dir=Path(args.out), arch=taint.arch, binary_path=Path(args.binary), library_resolution_path=args.library_resolution, allow_missing_libraries=args.allow_missing_libraries)

    try:
        config = preparer.prepare()
    except RuntimePreparationError as e:
        print(f" Runtime preparation failed: {e}")
        raise SystemExit(1)

    print(" Runtime prepared")
    print(f"    arch: {config.arch}")
    print(f"    rootfs: {config.rootfs}")
    print(f"    guest binary: {config.guest_binary_path}")
    print(f"    libraries ok: {config.libraries_ok}")
    print(f"    qemu required: {config.qemu_required}")

    if config.qemu_required:
        print(f"    qemu host: {config.qemu_host_path}")
        print(f"    qemu guest: {config.qemu_guest_path}")


if __name__ == "__main__":
    main()
