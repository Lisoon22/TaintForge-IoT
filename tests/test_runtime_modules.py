import pytest

from taintforge_env.parser import parse_taint_log
from taintforge_env.validators import TaintLogValidationError


def make_base_log() -> dict:
    return {
        "oep": "0x4010fb",
        "arch": "x86",
        "base": "0x400000",
        "regions": [],
        "file_dependencies": [],
        "network_dependencies": [],
        "library_dependencies": [],
    }


def test_parse_runtime_modules_and_translate_addresses() -> None:
    raw = make_base_log()

    raw["runtime_modules"] = [
        {
            "module_id": "main",
            "kind": "main",
            "path": "/sample",
            "load_bias": "0x400000",
            "mappings": [
                {
                    "start": "0x400000",
                    "end": "0x401000",
                    "prot": 1,
                    "offset": 0,
                },
                {
                    "start": "0x401000",
                    "end": "0x405000",
                    "prot": 5,
                    "offset": 4096,
                },
            ],
        },
        {
            "module_id": "libc",
            "kind": "shared_library",
            "path": "/usr/lib32/libc.so.6",
            "soname": "libc.so.6",
            "load_bias": "0x4088e000",
            "build_id": "test-build-id",
            "sha256": "a" * 64,
            "mappings": [
                {
                    "start": "0x4088e000",
                    "end": "0x40a29000",
                    "prot": 5,
                    "offset": 0,
                }
            ],
        },
    ]

    taint = parse_taint_log(raw)

    assert len(taint.runtime_modules) == 2

    main = taint.runtime_modules[0]
    libc = taint.runtime_modules[1]

    assert main.runtime_start() == 0x400000
    assert main.runtime_end() == 0x405000
    assert main.va_to_rva(0x4010FB) == 0x10FB
    assert main.rva_to_va(0x10FB) == 0x4010FB

    assert libc.va_to_rva(0x4089E000) == 0x10000
    assert libc.rva_to_va(0x10000) == 0x4089E000


def test_runtime_module_rejects_overlapping_mappings() -> None:
    raw = make_base_log()

    raw["runtime_modules"] = [
        {
            "module_id": "main",
            "kind": "main",
            "load_bias": "0x400000",
            "mappings": [
                {
                    "start": "0x400000",
                    "end": "0x402000",
                    "prot": 5,
                },
                {
                    "start": "0x401000",
                    "end": "0x403000",
                    "prot": 3,
                },
            ],
        }
    ]

    with pytest.raises(
        TaintLogValidationError,
        match="mappings overlap",
    ):
        parse_taint_log(raw)


def test_runtime_modules_require_exactly_one_main() -> None:
    raw = make_base_log()

    raw["runtime_modules"] = [
        {
            "module_id": "libc",
            "kind": "shared_library",
            "load_bias": "0x70000000",
            "mappings": [
                {
                    "start": "0x70000000",
                    "end": "0x70100000",
                    "prot": 5,
                }
            ],
        }
    ]

    with pytest.raises(
        TaintLogValidationError,
        match="exactly one main",
    ):
        parse_taint_log(raw)


def test_invalid_hex_runtime_address_is_rejected() -> None:
    raw = make_base_log()

    raw["runtime_modules"] = [
        {
            "module_id": "main",
            "kind": "main",
            "load_bias": "not-an-address",
            "mappings": [
                {
                    "start": "0x400000",
                    "end": "0x401000",
                    "prot": 5,
                }
            ],
        }
    ]

    with pytest.raises(
        TaintLogValidationError,
        match="must start with 0x",
    ):
        parse_taint_log(raw)
