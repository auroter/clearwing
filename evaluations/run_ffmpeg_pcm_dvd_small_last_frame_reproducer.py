"""Build, run, and record the undersized PCM-DVD frame reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.pcm-dvd-small-last-frame-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_pcm_dvd_small_last_frame_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O0",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibswscale",
        "-Llibavutil",
        "-lavcodec",
        "-lswresample",
        "-lswscale",
        "-lavutil",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    config = checkout / "config.h"
    if not harness.is_file() or not (
        checkout / "libavcodec/libavcodec.a"
    ).is_file() or not config.is_file():
        raise ValueError(
            "harness and configured FFmpeg static libraries must exist"
        )

    configuration = config.read_text(encoding="utf-8", errors="replace")
    semantics_preserving_build = (
        "--disable-optimizations" in configuration
        and "-Dav_always_inline=" in configuration
    )
    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command,
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0 and semantics_preserving_build:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    elif compile_result.returncode == 0:
        run_result = subprocess.CompletedProcess(
            [str(binary)],
            126,
            "",
            "FFmpeg must use --disable-optimizations and -Dav_always_inline=",
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    combined = run_result.stdout + run_result.stderr
    indicators = {
        "public_small_last_frame": (
            "codec=pcm_dvd sample_fmt=s32 channels=6 nb_samples=1 "
            "input_bytes=24 frame_size=28 small_last_frame=1" in combined
        ),
        "semantics_preserving_build": semantics_preserving_build,
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "four_byte_read": "READ of size 4" in combined,
        "read_after_six_samples": "0 bytes after 24-byte region" in combined,
        "pcm_dvd_encoder_in_trace": (
            "pcm-dvdenc.c:158" in combined
            and "in pcm_dvd_encode_frame" in combined
        ),
        "encoder_aborted": run_result.returncode != 0,
    }
    expected_observed = compile_result.returncode == 0 and all(
        indicators.values()
    )
    commit_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": commit_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public PCM-DVD encoder advertises small last frames and "
            "accepts one interleaved S32 sample per channel in 5.1 layout. "
            "Integer division makes blocks zero, but the do-while encoder "
            "body still attempts a complete 24-sample block and reads beyond "
            "the exact six-sample AVFrame allocation. The no-inline, "
            "unoptimized ASan build preserves C argument evaluation without "
            "changing FFmpeg source."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
