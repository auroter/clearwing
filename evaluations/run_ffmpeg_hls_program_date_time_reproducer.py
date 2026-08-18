"""Build and record the HLS program-date-time out-of-range crash."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.hls-program-date-time-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_hls_program_date_time_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavformat",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DHLSPLAYLIST_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "libavformat/libavformat.a",
        "libavcodec/libavcodec.a",
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-Wl,-dead_strip",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "AudioToolbox",
                "-framework",
                "Security",
            ]
        )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/hlsplaylist.c"
    caller_source = checkout / "libavformat/hlsenc.c"
    archives = [
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    ]
    if any(not path.is_file() for path in [harness, source, caller_source, *archives]):
        raise ValueError("harness, HLS sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, source, binary)
    compile_result = _run(compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if compile_result.returncode == 0:
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")

    master_result = _run(["git", "show", "master:libavformat/hlsplaylist.c"], cwd=checkout)
    source_text = source.read_text(encoding="utf-8", errors="replace")
    caller_text = caller_source.read_text(encoding="utf-8", errors="replace")
    master_text = master_result.stdout
    source_indicators = {
        "append_playlist_duration_is_unchecked_double": (
            "vs->duration = atof(ptr);" in caller_text
            and "hls_append_segment(s, hls, vs, vs->duration" in caller_text
        ),
        "program_date_accumulates_segment_duration": (
            "*prog_date_time += duration;" in source_text
            and "vs->initial_prog_date_time += en->duration;" in caller_text
        ),
        "time_conversion_has_no_range_or_null_check": (
            "tt = (int64_t)*prog_date_time;" in source_text
            and "tm = localtime_r(&tt, &tmpbuf);" in source_text
            and 'strftime(buf0, sizeof(buf0), "%Y-%m-%dT%H:%M:%S", tm)' in source_text
            and "if (!tm)" not in source_text
        ),
        "current_master_remains_unchecked": (
            master_result.returncode == 0
            and "tm = localtime_r(&tt, &tmpbuf);" in master_text
            and "if (!tm)" not in master_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "proof_value_is_in_int64_but_out_of_calendar_range": (
            "program_date_time=9223372036854774784 "
            "int64_max=9223372036854775807 localtime_range_check=absent" in combined
        ),
        "asan_deadly_signal": "AddressSanitizer:DEADLYSIGNAL" in combined,
        "null_read_crash": (
            "SEGV on unknown address 0x000000000014" in combined
            and "caused by a READ memory access" in combined
            and "address points to the zero page" in combined
        ),
        "strftime_in_trace": "strftime" in combined,
        "vulnerable_process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "current_master_checked": master_result.returncode == 0,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": {
            "libavformat/hlsplaylist.c": _sha256(source),
            "libavformat/hlsenc.c": _sha256(caller_source),
        },
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "HLS append-list parsing accepts EXTINF through atof without a "
            "finite or range check, retains that duration, and accumulates it "
            "into program-date-time state. The playlist writer converts the "
            "double to time_t and passes localtime_r's unchecked NULL result "
            "to strftime. The exact-source proof uses the greatest binary64 "
            "integer below 2^63; it is representable in int64_t but outside "
            "the platform calendar range, and ASan records strftime reading "
            "through NULL."
        ),
        "run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
