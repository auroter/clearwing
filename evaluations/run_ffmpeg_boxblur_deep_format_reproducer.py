"""Build and record boxblur's greater-than-16-bit heap overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.boxblur-deep-format-reproducer.v1"
REPAIR_COMMIT = "2ec918330eee04f6069e9561a0d3950b7b52fc5e"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_boxblur_deep_format_reproducer.c"
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
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "-Llibavfilter",
        "-Llibavcodec",
        "-Llibavutil",
        "-lavfilter",
        "-lavcodec",
        "-lavutil",
        "-lm",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "Security",
                "-liconv",
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
    source = checkout / "libavfilter/vf_boxblur.c"
    components = checkout / "config_components.h"
    if (
        not harness.is_file()
        or not source.is_file()
        or not components.is_file()
        or not (checkout / "libavfilter/libavfilter.a").is_file()
    ):
        raise ValueError(
            "harness, boxblur source, configuration, and archives must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        environment["UBSAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        )
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    configured_components = components.read_text(
        encoding="utf-8", errors="replace"
    )
    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavfilter/vf_boxblur.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "boxblur_filter_enabled": (
            "#define CONFIG_BOXBLUR_FILTER 1" in configured_components
        ),
        "deep_planar_formats_accepted": (
            "desc->comp[0].depth <= 16" not in source_text
        ),
        "temporary_storage_is_two_bytes_per_sample": (
            "av_malloc(2*FFMAX(w, h))" in source_text
        ),
        "all_non_byte_formats_use_blur16": (
            "else              blur16" in source_text
        ),
        "exact_repair_present": (
            repair_result.returncode == 0
            and "reject pixel formats deeper than 16 bits" in repair_text
            and "Fixes: heap buffer overflow" in repair_text
            and "desc->comp[0].depth <= 16" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_grayf32le_frame": (
            "frame=4x4 format=grayf32le depth=32 pixel_size=4" in combined
        ),
        "eight_byte_temporary": "temp_bytes_per_dimension=8" in combined,
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "production_blur_in_trace": " in blur+" in combined,
        "filter_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
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
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_result.stdout,
        "expected_observed": expected_observed,
        "scope": (
            "A public tight 4x4 GRAYF32LE frame is accepted by boxblur. The "
            "filter allocates only two temporary bytes per dimension and "
            "routes every non-byte format through blur16 with four-byte "
            "strides, producing an ASan heap write beyond the temporary."
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
