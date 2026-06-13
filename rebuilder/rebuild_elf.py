#python3 rebuild_elf.py -b unpacked.bin -j unpacked.json -e original.elf -o rebuilt.elf
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description="Rebuild ELF from unpacker dump with original reference"
    )
    parser.add_argument(
        "-b", "--bin", required=True,
        help="Path to unpacked binary (raw memory dump)"
    )
    parser.add_argument(
        "-j", "--json", required=True,
        help="Path to unpacked json"
    )
    parser.add_argument(
        "-e", "--elf", required=True,
        help="Path to original packed ELF"
    )
    parser.add_argument(
        "-o", "--output", default="rebuilt.elf",
        help="Output path for rebuilt ELF (default: rebuilt.elf)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print detailed merge log"
    )
    
    args = parser.parse_args()
    
    # Validate inputs exist
    for path_attr, label in [("bin", "Dump binary"), ("json", "JSON metadata"), ("elf", "Original ELF")]:
        import os
        if not os.path.exists(getattr(args, path_attr)):
            print(f"[-] Error: {label} not found: {getattr(args, path_attr)}", file=sys.stderr)
            sys.exit(1)
    
    return args


def main():
    args = parse_args()
    print(f"[+] Dump binary : {args.bin}")
    print(f"[+] JSON metadata: {args.json}")
    print(f"[+] Original ELF : {args.elf}")
    print(f"[+] Output       : {args.output}")
if __name__ == "__main__":
    main()
