import argparse

from taintforge_env.parser import load_taint_log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("taint_log")
    args = parser.parse_args()

    taint = load_taint_log(args.taint_log)

    print("[+] Taint log loaded")
    print(f"    schema: {taint.schema_version}")
    print(f"    sample: {taint.sample.name}")
    print(f"    arch:   {taint.sample.arch}")
    print(f"    binary: {taint.sample.binary}")
    print(f"    oep:    {taint.sample.oep}")

    print()
    print("[+] File dependencies:")
    for path in taint.required_paths():
        print(f"    - {path}")

    print()
    print("[+] Network dependencies:")
    for dep in taint.network_dependencies:
        if dep.type in {"tcp", "udp"}:
            print(f"    - {dep.type.upper()} {dep.ip}:{dep.port} role={dep.role}")
        elif dep.type == "dns":
            print(f"    - DNS {dep.domain} -> {dep.response_ip}")
        else:
            print(f"    - {dep}")

    print()
    print("[+] Libraries:")
    for lib in taint.library_dependencies:
        symbols = ", ".join(lib.symbols[:5])
        if len(lib.symbols) > 5:
            symbols += ", ..."
        print(f"    - {lib.name}: {symbols}")

    print()
    print("[+] Syscalls:")
    print("    " + ", ".join(taint.syscall_names()))


if __name__ == "__main__":
    main()
