"""Prove the RTP/ASF zero-size object loop and its later repair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.rtp-asf-zero-chunk-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
REPAIR_COMMIT = "11d5f475be95d22d5f0692220cc772b116abc632"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--repaired-checkout", type=Path, required=True)
    parser.add_argument("--repaired-build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rtp_asf_zero_chunk_reproducer.c"),
    )
    parser.add_argument("--vulnerable-binary-output", type=Path, required=True)
    parser.add_argument("--repaired-binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=1.5)
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
    command = [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DZLIB_CONST",
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
        "libavformat/libavformat.a",
        "libavcodec/libavcodec.a",
        "libswresample/libswresample.a",
        "libswscale/libswscale.a",
        "libavutil/libavutil.a",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
                "-liconv",
                "-framework",
                "AudioToolbox",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
            ]
        )
    command.append("-pthread")
    return command


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


def _validate_tree(path: Path, expected_commit: str) -> None:
    required = (
        path / "libavformat/libavformat.a",
        path / "libavcodec/libavcodec.a",
        path / "libswresample/libswresample.a",
        path / "libswscale/libswscale.a",
        path / "libavutil/libavutil.a",
        path / "libavformat/rtpdec_asf.c",
    )
    if _head(path) != expected_commit or not all(item.is_file() for item in required):
        raise ValueError(f"configured FFmpeg tree must be at {expected_commit}")


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    build_dir = args.build_dir.expanduser().resolve()
    repaired_checkout = args.repaired_checkout.expanduser().resolve()
    repaired_build_dir = args.repaired_build_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    vulnerable_binary = args.vulnerable_binary_output.expanduser().resolve()
    repaired_binary = args.repaired_binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if args.timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if not harness.is_file():
        raise ValueError("harness must exist")
    if _head(checkout) != VULNERABLE_COMMIT or _head(build_dir) != VULNERABLE_COMMIT:
        raise ValueError("vulnerable checkout and build must use the pinned commit")
    if _head(repaired_checkout) != REPAIR_COMMIT:
        raise ValueError("repaired checkout must use the exact repair commit")
    _validate_tree(build_dir, VULNERABLE_COMMIT)
    _validate_tree(repaired_build_dir, REPAIR_COMMIT)

    vulnerable_binary.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    vulnerable_compile_command = _compile_command(harness, vulnerable_binary)
    vulnerable_compile = subprocess.run(
        vulnerable_compile_command,
        cwd=build_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    vulnerable_run = (
        _run(vulnerable_binary, build_dir, args.timeout_seconds)
        if vulnerable_compile.returncode == 0
        else {
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "compile failed",
        }
    )

    repaired_compile_command = _compile_command(harness, repaired_binary)
    repaired_compile = subprocess.run(
        repaired_compile_command,
        cwd=repaired_build_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    repaired_run = (
        _run(repaired_binary, repaired_build_dir, max(args.timeout_seconds, 5.0))
        if repaired_compile.returncode == 0
        else {
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "compile failed",
        }
    )

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/rtpdec_asf.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    vulnerable_source = (checkout / "libavformat/rtpdec_asf.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repaired_source = (repaired_checkout / "libavformat/rtpdec_asf.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repair_text = repair_result.stdout
    source_indicators = {
        "production_wms_sdp_entry_decodes_attacker_data": all(
            term in vulnerable_source
            for term in (
                "int ff_wms_parse_sdp_a_line(AVFormatContext *s, const char *p)",
                "pgmpu:data:application/vnd.ms.wms-hdr.asfv1;base64,",
                "av_base64_decode(buf, p, len);",
                "rtp_asf_fix_header(buf, len)",
            )
        ),
        "unknown_object_uses_unbounded_zero_progress_advance": all(
            term in vulnerable_source
            for term in (
                "uint64_t chunksize = AV_RL64(p + sizeof(ff_asf_guid));",
                "if (chunksize > end - p)",
                "p += chunksize;",
                "continue;",
            )
        ),
        "vulnerable_source_lacks_minimum_chunk_guard": (
            "if (chunksize < sizeof(ff_asf_guid) + 8)" not in vulnerable_source
        ),
        "repair_explicitly_identifies_infinite_loop": (
            repair_result.returncode == 0
            and "reject ASF objects smaller than their header" in repair_text
            and "Fixes: infinite loop" in repair_text
        ),
        "repair_adds_exact_progress_guard": (
            "if (chunksize < sizeof(ff_asf_guid) + 8)" in repaired_source
            and "return -1;" in repaired_source
        ),
    }

    vulnerable_output = vulnerable_run["stdout"] + vulnerable_run["stderr"]
    repaired_output = repaired_run["stdout"] + repaired_run["stderr"]
    entry_marker = (
        "decoded_len=54 object_offset=30 object_size=0 " "entering=ff_wms_parse_sdp_a_line"
    )
    runtime_indicators = {
        "vulnerable_harness_compiled": vulnerable_compile.returncode == 0,
        "vulnerable_production_entry_reached": entry_marker in vulnerable_output,
        "vulnerable_call_exceeded_timeout": vulnerable_run["timed_out"],
        "vulnerable_call_never_returned": "returned=" not in vulnerable_output,
        "repaired_harness_compiled": repaired_compile.returncode == 0,
        "repaired_production_entry_reached": entry_marker in repaired_output,
        "repaired_call_completed": (
            not repaired_run["timed_out"] and repaired_run["returncode"] == 0
        ),
        "repaired_header_was_rejected": (
            "Failed to fix invalid RTSP-MS/ASF min_pktsize" in repaired_output
            and "returned=-1094995529" in repaired_output
        ),
    }
    expected_observed = all(source_indicators.values()) and all(runtime_indicators.values())

    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout) or None,
        "build_dir": str(build_dir),
        "build_commit": _head(build_dir) or None,
        "repaired_checkout": str(repaired_checkout),
        "repaired_checkout_commit": _head(repaired_checkout) or None,
        "repaired_build_dir": str(repaired_build_dir),
        "repaired_build_commit": _head(repaired_build_dir) or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "timeout_seconds": args.timeout_seconds,
        "vulnerable_compile_command": vulnerable_compile_command,
        "vulnerable_compile_returncode": vulnerable_compile.returncode,
        "vulnerable_compile_stdout": vulnerable_compile.stdout,
        "vulnerable_compile_stderr": vulnerable_compile.stderr,
        "vulnerable_binary": str(vulnerable_binary),
        "vulnerable_binary_sha256": (
            _sha256(vulnerable_binary) if vulnerable_binary.is_file() else None
        ),
        "vulnerable_run": vulnerable_run,
        "repaired_compile_command": repaired_compile_command,
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
