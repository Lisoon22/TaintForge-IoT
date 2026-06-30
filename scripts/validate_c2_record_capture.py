from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


class CaptureValidationError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CaptureValidationError(
            f"{name} must be a JSON object"
        )

    return value


def find_single_session(out_dir: Path) -> Path:
    matches = sorted(
        out_dir.glob("captures/*/*/session.json")
    )

    if len(matches) != 1:
        raise CaptureValidationError(
            "expected exactly one captured session, "
            f"found {len(matches)}: "
            + ", ".join(str(path) for path in matches)
        )

    return matches[0].parent


def validate_direction(
    *,
    summary: dict[str, Any],
    key: str,
    session_dir: Path,
    expected: bytes,
) -> None:
    direction = require_dict(
        summary.get(key),
        key,
    )

    relative_path = direction.get("path")

    if not isinstance(relative_path, str):
        raise CaptureValidationError(
            f"{key}.path must be a string"
        )

    payload_path = session_dir / relative_path

    if not payload_path.is_file():
        raise CaptureValidationError(
            f"missing payload: {payload_path}"
        )

    actual = payload_path.read_bytes()

    if actual != expected:
        raise CaptureValidationError(
            f"{key} payload mismatch: "
            f"expected={expected.hex()} "
            f"actual={actual.hex()}"
        )

    expected_size = direction.get("bytes")

    if expected_size != len(actual):
        raise CaptureValidationError(
            f"{key}.bytes mismatch: "
            f"metadata={expected_size}, "
            f"actual={len(actual)}"
        )

    expected_sha256 = direction.get("sha256")
    actual_sha256 = sha256_bytes(actual)

    if expected_sha256 != actual_sha256:
        raise CaptureValidationError(
            f"{key}.sha256 mismatch: "
            f"metadata={expected_sha256}, "
            f"actual={actual_sha256}"
        )

    chunks = direction.get("chunks")

    if not isinstance(chunks, int) or chunks < 1:
        raise CaptureValidationError(
            f"{key}.chunks must be >= 1"
        )


def validate_capture(
    *,
    out_dir: Path,
    expected_request: bytes,
    expected_response: bytes,
) -> Path:
    session_dir = find_single_session(out_dir)
    summary_path = session_dir / "session.json"

    try:
        summary = json.loads(
            summary_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise CaptureValidationError(
            f"unable to read {summary_path}: {exc}"
        ) from exc

    summary = require_dict(summary, "session")

    if summary.get("capture_kind") != "local_test":
        raise CaptureValidationError(
            "capture_kind is not local_test"
        )

    if (
        summary.get("original_remote_ip")
        != "198.51.100.10"
    ):
        raise CaptureValidationError(
            "unexpected original_remote_ip"
        )

    if summary.get("original_remote_port") != 48101:
        raise CaptureValidationError(
            "unexpected original_remote_port"
        )

    if summary.get("upstream_ip") != "127.0.0.1":
        raise CaptureValidationError(
            "unexpected upstream_ip"
        )

    if summary.get("upstream_port") != 49001:
        raise CaptureValidationError(
            "unexpected upstream_port"
        )

    close_reason = summary.get("close_reason")

    if close_reason not in {
        "upstream_closed",
        "client_closed",
        "completed",
    }:
        raise CaptureValidationError(
            f"unexpected close_reason: {close_reason}"
        )

    if summary.get("error") not in {None, ""}:
        raise CaptureValidationError(
            f"session contains error: {summary.get('error')}"
        )

    validate_direction(
        summary=summary,
        key="client_to_server",
        session_dir=session_dir,
        expected=expected_request,
    )
    validate_direction(
        summary=summary,
        key="server_to_client",
        session_dir=session_dir,
        expected=expected_response,
    )

    events_path = session_dir / "events.jsonl"

    if not events_path.is_file():
        raise CaptureValidationError(
            f"missing events file: {events_path}"
        )

    event_names: set[str] = set()

    for line_number, line in enumerate(
        events_path.read_text(
            encoding="utf-8"
        ).splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CaptureValidationError(
                f"invalid JSONL at line "
                f"{line_number}: {exc}"
            ) from exc

        if isinstance(event, dict):
            event_name = event.get("event")

            if isinstance(event_name, str):
                event_names.add(event_name)

    required_events = {
        "session_started",
        "upstream_connected",
        "stream_chunk",
        "session_finished",
    }
    missing_events = required_events - event_names

    if missing_events:
        raise CaptureValidationError(
            "missing session events: "
            + ", ".join(sorted(missing_events))
        )

    runtime_status = (
        out_dir / "logs" / "runtime_status.json"
    )

    if runtime_status.is_file():
        status = json.loads(
            runtime_status.read_text(encoding="utf-8")
        )

        exit_code = status.get("exit_code")

        if exit_code != 0:
            raise CaptureValidationError(
                f"sample exit_code is not zero: "
                f"{exit_code}"
            )

        if status.get("timed_out") is True:
            raise CaptureValidationError(
                "sample timed out"
            )

    stdout_path = (
        out_dir / "logs" / "runtime_stdout.log"
    )

    if stdout_path.is_file():
        stdout = stdout_path.read_bytes()

        if expected_response not in stdout:
            raise CaptureValidationError(
                "expected response was not found "
                "in runtime stdout"
            )

    return session_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the local brokered-record "
            "end-to-end capture"
        )
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--expected-request-hex",
        default="68656c6c6f",
    )
    parser.add_argument(
        "--expected-response-hex",
        default="776f726c64",
    )
    args = parser.parse_args()

    try:
        request = bytes.fromhex(
            args.expected_request_hex
        )
        response = bytes.fromhex(
            args.expected_response_hex
        )
    except ValueError as exc:
        parser.error(f"invalid expected hex: {exc}")

    try:
        session_dir = validate_capture(
            out_dir=args.out.resolve(),
            expected_request=request,
            expected_response=response,
        )
    except CaptureValidationError as exc:
        print(f"[-] Capture validation failed: {exc}")
        raise SystemExit(1)

    print("[+] C2 record capture is valid")
    print(f"    session: {session_dir}")
    print(f"    request: {request!r}")
    print(f"    response: {response!r}")


if __name__ == "__main__":
    main()
