"""Build and record the DHAV virtual-end duration over-read."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.dhav-duration-overflow-reproducer.v1"
REPAIR_COMMIT = "50e65074f5cca638d6dd4cf9db4b6dcf4f0a863e"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_dhav_duration_overflow_reproducer.c"),
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
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    build_dir = args.build_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/dhav.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (build_dir / "libavformat/libavformat.a").is_file()
        or not (build_dir / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, DHAV source, and configured archives must exist")
    if _head(checkout) != _head(build_dir):
        raise ValueError("checkout and configured build must use the same commit")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command,
        cwd=build_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        run_result = subprocess.run(
            [str(binary)],
            cwd=build_dir,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/dhav.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "tail_buffer_is_capped_at_one_megabyte": all(
            term in source_text
            for term in (
                "#define MAX_DURATION_BUFFER_SIZE (1024*1024)",
                "buffer_size = FFMIN(MAX_DURATION_BUFFER_SIZE, size);",
            )
        ),
        "footer_controls_candidate_position": (
            "pos = buffer_pos + offset - seek_back + 8;" in source_text
        ),
        "vulnerable_bound_adds_to_candidate": (
            "if (pos < buffer_pos || pos + 20 > buffer_pos + buffer_size)" in source_text
        ),
        "unchecked_index_reads_date": (
            "date = AV_RL32(buffer + (pos - buffer_pos) + 16);" in source_text
        ),
        "later_repair_uses_subtraction_form": (
            repair_result.returncode == 0
            and "Fix second integer overflow in get_duration()" in repair_text
            and "pos - buffer_pos > buffer_size - 20" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_virtual_geometry": (
            "format=dhav virtual_size=9223372036854775807 "
            "duration_buffer=1048576 footer_offset=1048568 "
            "seek_back=0 candidate_pos=9223372036854775807" in combined
        ),
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in combined,
        "four_byte_read": "READ of size 4" in combined,
        "read_sixteen_bytes_after_tail_buffer": ("16 bytes after 1048576-byte region" in combined),
        "dhav_header_in_trace": "dhav_read_header" in combined,
        "process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout) or None,
        "build_dir": str(build_dir),
        "build_commit": _head(build_dir) or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
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
        "returncode": run_result.returncode,
        "geometry": {
            "virtual_size": 2**63 - 1,
            "duration_buffer_bytes": 1024 * 1024,
            "footer_offset": 1024 * 1024 - 8,
            "footer_seek_back": 0,
            "candidate_position": 2**63 - 1,
            "date_read_offset_after_allocation": 16,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A seekable DHAV input can expose a logical size of INT64_MAX without "
            "allocating that storage. A final dhav footer with seek_back zero makes "
            "get_duration derive pos=INT64_MAX. The vulnerable pos+20 bound wraps, "
            "so the subsequent date load reads four bytes sixteen bytes beyond the "
            "one-megabyte tail allocation. The production demuxer aborts under ASan, "
            "and later repair 50e65074f5 rewrites the exact bound using subtraction."
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
