from __future__ import annotations
import re 
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

@dataclass(slots=True)
class ELFInfo:
    path: str
    arch_hint: str
    is_dynamic: bool
    interpreter: Optional[str] = None
    needed_libraries: list[str] = field(default_factory=list)

class ELFAnalysisError(RuntimeError):
    pass

def run_command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    except FileNotFoundError as e:
        raise ELFAnalysisError(f"Command not found: {args[0]}. Install binutils/readelf") from e

    except subprocess.CalledProcessError as e:
        raise ELFAnalysisError(f"Command failed: {' '.join(args)}\n{e.stderr}") from e

    return result.stdout

def analyze_elf(path: str | Path, arch_hint: str) -> ELFInfo:
    path = Path(path)

    if not path.exists():
        raise ELFAnalysisError(f"ELF not found: {path}")

    if not path.is_file():
        raise ELFAnalysisError(f"ELF path is not a file: {path}")

    program_headers = run_command(["readelf", "-l", str(path)])
    dynamic_section = run_command(["readelf", "-d", str(path)])

    interpreter = parse_interpreter(program_headers)
    needed_libraries = parse_needed_libraries(dynamic_section)

    is_dynamic = interpreter is not None or bool(needed_libraries)

    return ELFInfo(path=str(path), arch_hint=arch_hint, is_dynamic=is_dynamic, interpreter=interpreter, needed_libraries=needed_libraries)

def parse_interpreter(readelf_l_output: str) -> Optional[str]:
    for line in readelf_l_output.splitlines():
        if "Requesting program interpreter" not in line:
            continue

        match = re.search(r"\[(.*?)\]", line)
        if not match:
            continue

        value = match.group(1).strip()

        prefix = "Requesting program interpreter:"
        if value.startswith(prefix):
            value = value[len(prefix):].strip()

        return value

    return None
   

def parse_needed_libraries(readelf_d_output: str) -> list[str]:
    needed: list[str] = []

    for line in readelf_d_output.splitlines():
        if "(NEEDED)" not in line:
            continue

        match = re.search(r"\[(.*?)\]", line)
        if match:
            needed.append(match.group(1).strip())

    return needed
