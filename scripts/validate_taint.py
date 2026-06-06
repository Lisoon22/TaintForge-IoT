import argparse
import sys

from taintforge_env.parser import load_taint_log
from taintforge_env.validators import TaintLogValidationError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("taint_log")
    args = parser.parse_args()

    try:
        taint = load_taint_log(args.taint_log)
    except (TaintLogValidationError, FileNotFoundError) as e:
        print(f"Invalid taint log: {e}")
        sys.exit(1)

    print("Valid taint log")
    print(f"    arch={taint.arch}")
    print(f"    oep={taint.oep}")
    print(f"    base={taint.base}")
    print(f"    regions={len(taint.regions)}")
    print(f"    files={len(taint.file_dependencies)}")
    print(f"    network={len(taint.network_dependencies)}")
    print(f"    libraries={len(taint.library_dependencies)}")


if __name__ == "__main__":
    main()
