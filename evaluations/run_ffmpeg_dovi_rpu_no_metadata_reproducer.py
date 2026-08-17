"""Prove the DOVI RPU no-metadata crash and its exact repair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.dovi-rpu-no-metadata-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
REPAIR_COMMIT = "534f16d866c732a85c34ac576d66d578669578f1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-build-dir", type=Path, required=True)
    parser.add_argument("--repaired-build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_dovi_rpu_no_metadata_reproducer.c"),
    )
    parser.add_argument("--vulnerable-binary-output", type=Path, required=True)
    parser.add_argument("--repaired-binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _compile_command(harness: Path, binary: Path) -> list[str]:
    return [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
        "libavcodec/libavcodec.a",
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
    ]


def _validate_build(path: Path, expected_commit: str) -> None:
    required = (
        path / "libavcodec/libavcodec.a",
        path / "libavutil/libavutil.a",
        path / "libavcodec/bsf/dovi_rpu.c",
        path / "config_components.h",
    )
    if _head(path) != expected_commit or not all(item.is_file() for item in required):
        raise ValueError(f"configured FFmpeg build must be at {expected_commit}")
    components = (path / "config_components.h").read_text(encoding="utf-8", errors="replace")
    if "#define CONFIG_DOVI_RPU_BSF 1" not in components:
        raise ValueError("configured build must enable the dovi_rpu bitstream filter")


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run(binary: Path, cwd: Path, timeout: float) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    try:
        result = subprocess.run(
            [str(binary)],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "timed_out": False,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "timed_out": True,
            "returncode": None,
            "stdout": _text(error.stdout),
            "stderr": _text(error.stderr),
        }


def _compile_and_run(
    build: Path, harness: Path, binary: Path, timeout: float
) -> tuple[list[str], subprocess.CompletedProcess[str], dict[str, Any]]:
    command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        command,
        cwd=build,
        check=False,
        capture_output=True,
        text=True,
    )
    run = (
        _run(binary, build, timeout)
        if compile_result.returncode == 0
        else {
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "compile failed",
        }
    )
    return command, compile_result, run


def main() -> None:
    args = _arguments()
    vulnerable_build = args.vulnerable_build_dir.expanduser().resolve()
    repaired_build = args.repaired_build_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    vulnerable_binary = args.vulnerable_binary_output.expanduser().resolve()
    repaired_binary = args.repaired_binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if args.timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if not harness.is_file():
        raise ValueError("harness must exist")
    _validate_build(vulnerable_build, VULNERABLE_COMMIT)
    _validate_build(repaired_build, REPAIR_COMMIT)

    vulnerable_binary.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    vulnerable_command, vulnerable_compile, vulnerable_run = _compile_and_run(
        vulnerable_build,
        harness,
        vulnerable_binary,
        args.timeout_seconds,
    )
    repaired_command, repaired_compile, repaired_run = _compile_and_run(
        repaired_build,
        harness,
        repaired_binary,
        args.timeout_seconds,
    )

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/bsf/dovi_rpu.c",
        ],
        cwd=vulnerable_build,
        check=False,
        capture_output=True,
        text=True,
    )
    vulnerable_source = (vulnerable_build / "libavcodec/bsf/dovi_rpu.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repaired_source = (repaired_build / "libavcodec/bsf/dovi_rpu.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repair_text = repair_result.stdout
    source_indicators = {
        "vulnerable_no_metadata_returns_null_zero_rpu": all(
            term in vulnerable_source
            for term in (
                "if (ret == 0 /* no metadata */)",
                "*out_rpu = NULL;",
                "*out_size = 0;",
            )
        ),
        "vulnerable_av1_path_uses_invalid_null_result": all(
            term in vulnerable_source
            for term in (
                "ref = av_buffer_create(rpu, rpu_size",
                "t35->payload = rpu + 1;",
                "t35->payload_size = rpu_size - 1;",
            )
        ),
        "vulnerable_source_lacks_no_rpu_guard": (
            "if (!rpu || rpu_size <= 1)" not in vulnerable_source
        ),
        "repair_adds_exact_av1_no_rpu_guard": (
            repair_result.returncode == 0
            and "handle update_rpu() returning no RPU" in repair_text
            and "Fixes: out of array access" in repair_text
            and "if (!rpu || rpu_size <= 1)" in repaired_source
            and "av_free(rpu);" in repaired_source
            and "continue;" in repaired_source
        ),
    }

    vulnerable_stderr = vulnerable_run["stderr"]
    repaired_stderr = repaired_run["stderr"]
    runtime_indicators = {
        "vulnerable_harness_compiled": vulnerable_compile.returncode == 0,
        "vulnerable_public_bsf_path_reached": all(
            term in vulnerable_run["stdout"]
            for term in (
                "entry=av_bsf_init codec=av1 ret=0",
                "packet_size=56 rpu_type=0 metadata_expected=absent",
                "send_ret=0 entering=av_bsf_receive_packet",
            )
        ),
        "vulnerable_parser_returned_without_metadata": (
            "Unrecognized RPU type 0, ignoring" in vulnerable_stderr
        ),
        "vulnerable_serializer_crashed_at_address_one": (
            vulnerable_run["returncode"] not in (None, 0)
            and "AddressSanitizer: SEGV" in vulnerable_stderr
            and "unknown address 0x000000000001" in vulnerable_stderr
            and "in cbs_av1_write_obu" in vulnerable_stderr
        ),
        "repaired_harness_compiled": repaired_compile.returncode == 0,
        "repaired_parser_returned_without_metadata": (
            "Unrecognized RPU type 0, ignoring" in repaired_stderr
        ),
        "repaired_filter_emitted_packet": (
            repaired_run["returncode"] == 0
            and "receive_ret=0 output_size=56" in repaired_run["stdout"]
        ),
        "repaired_run_has_no_sanitizer_failure": (
            "AddressSanitizer" not in repaired_stderr and "runtime error:" not in repaired_stderr
        ),
    }
    expected_observed = all(source_indicators.values()) and all(runtime_indicators.values())

    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "vulnerable_build_dir": str(vulnerable_build),
        "vulnerable_commit": _head(vulnerable_build) or None,
        "repaired_build_dir": str(repaired_build),
        "repaired_commit": _head(repaired_build) or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "timeout_seconds": args.timeout_seconds,
        "vulnerable_compile_command": vulnerable_command,
        "vulnerable_compile_returncode": vulnerable_compile.returncode,
        "vulnerable_compile_stdout": vulnerable_compile.stdout,
        "vulnerable_compile_stderr": vulnerable_compile.stderr,
        "vulnerable_binary": str(vulnerable_binary),
        "vulnerable_binary_sha256": (
            _sha256(vulnerable_binary) if vulnerable_binary.is_file() else None
        ),
        "vulnerable_run": vulnerable_run,
        "repaired_compile_command": repaired_command,
        "repaired_compile_returncode": repaired_compile.returncode,
        "repaired_compile_stdout": repaired_compile.stdout,
        "repaired_compile_stderr": repaired_compile.stderr,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "repaired_run": repaired_run,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(0 if expected_observed else 1)


if __name__ == "__main__":
    main()
