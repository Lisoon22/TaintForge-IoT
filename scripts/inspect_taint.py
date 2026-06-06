import argparse

from taintforge_env.parser import load_taint_log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("taint_log")
    args = parser.parse_args()

    taint = load_taint_log(args.taint_log)

    print(" Taint log loaded")
    print(f"    arch: {taint.arch}")
    print(f"    oep:  {taint.oep}")
    print(f"    base: {taint.base}")

    print()
    print(" Memory regions:")
    for region in taint.regions:
        print(
            f"    - addr={region.addr} "
            f"size={region.size} "
            f"prot={region.prot} "
            f"offset={region.offset}"
        )

    print()
    print(" File dependencies:")
    for dep in taint.file_dependencies:
        mode = "write" if dep.write else "read"
        print(f"    - {dep.path} ({mode})")

    print()
    print(" Network dependencies:")
    for dep in taint.network_dependencies:
        print(
            f"    - {dep.type} "
            f"{dep.ip}:{dep.port} "
            f"transport={dep.transport()} "
            f"sample_bytes={dep.sample_bytes}"
        )

    print()
    print(" Libraries:")
    for lib in taint.library_dependencies:
        print(f"    - {lib.name}")

    print()
    print(" Anti-analysis:")
    print(f"    cpuinfo_check={taint.anti_analysis.cpuinfo_check}")
    print(f"    uname_check={taint.anti_analysis.uname_check}")
    print(f"    ptrace_traceme={taint.anti_analysis.ptrace_traceme}")


if __name__ == "__main__":
    main()
