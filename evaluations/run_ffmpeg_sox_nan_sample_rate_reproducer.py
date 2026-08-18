"""Build and record the SoX NaN sample-rate conversion proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.sox-nan-sample-rate-reproducer.v1"
REPAIR_COMMIT = "d2d79dca9a36a3e89880c389161934598d62690a"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_sox_nan_sample_rate_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(
    *, harness: Path, source: Path, checkout: Path, binary: Path
) -> list[str]:
    return [
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
        f'-DSOXDEC_SOURCE="{source}"',
        "-fsanitize=address,undefined,float-cast-overflow",
        "-fno-sanitize-recover=undefined,float-cast-overflow",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wl,-dead_strip",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
        str(checkout / "libavformat/libavformat.a"),
        str(checkout / "libavcodec/libavcodec.a"),
        str(checkout / "libavutil/libavutil.a"),
        "-lm",
        "-pthread",
    ]


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/soxdec.c"
    archives = (
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if not harness.is_file() or not source.is_file() or any(
        not archive.is_file() for archive in archives
    ):
        raise ValueError("harness, pinned SoX source, and FFmpeg archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-soxdec.c")

    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavformat/soxdec.c"], cwd=checkout
    )
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(
        harness=harness, source=source, checkout=checkout, binary=binary
    )
    repaired_compile_command = _compile_command(
        harness=harness,
        source=repaired_source,
        checkout=checkout,
        binary=repaired_binary,
    )
    compile_result = _run(compile_command, cwd=checkout)
    if repaired_source.is_file():
        repaired_compile_result = _run(repaired_compile_command, cwd=checkout)
    else:
        repaired_compile_result = subprocess.CompletedProcess(
            repaired_compile_command, 127, "", "repair source extraction failed"
        )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if compile_result.returncode == 0:
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")
    if repaired_compile_result.returncode == 0:
        repaired_run_result = _run([str(repaired_binary)], cwd=checkout, env=environment)
    else:
        repaired_run_result = subprocess.CompletedProcess(
            [str(repaired_binary)], 127, "", "repaired compile failed"
        )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        ["git", "show", "--format=", REPAIR_COMMIT, "--", "libavformat/soxdec.c"],
        cwd=checkout,
    )
    repair_message = _run(
        ["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout
    )
    source_indicators = {
        "sample_rate_is_media_owned_double": (
            "av_int2double(avio_rl64(pb))" in source_text
            and "av_int2double(avio_rb64(pb))" in source_text
        ),
        "nan_bypasses_vulnerable_range_check": (
            "if (sample_rate <= 0 || sample_rate > INT_MAX)" in source_text
            and "sample_rate > INT_MAX || isnan(sample_rate)" not in source_text
        ),
        "unchecked_conversion_reaches_int_field": (
            "st->codecpar->sample_rate           = sample_rate;" in source_text
        ),
        "exact_repair_rejects_nan": (
            repair_diff.returncode == 0
            and "sample_rate > INT_MAX || isnan(sample_rate)" in repair_diff.stdout
            and "Check sample_rate for nan" in repair_message.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "input_contains_quiet_nan": (
            "sample_rate_bits=0x7ff8000000000000 decoded_is_nan=1" in combined
        ),
        "vulnerable_range_check_accepts_nan": (
            "truncating fractional part of sample rate (nan)" in combined
        ),
        "ubsan_reports_nan_to_int_conversion": (
            "runtime error: nan is outside the range of representable values of type 'int'"
            in combined
            and "libavformat/soxdec.c:125" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_source_rejects_input": (
            repaired_run_result.returncode == 0
            and "invalid sample rate (nan)" in repaired_combined
            and "read_header_result=" in repaired_combined
            and "runtime error:" not in repaired_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and repaired_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "repair_commit": REPAIR_COMMIT,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": _sha256(source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (
            _sha256(repaired_binary) if repaired_binary.is_file() else None
        ),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile_result.returncode,
        "repaired_compile_stdout": repaired_compile_result.stdout,
        "repaired_compile_stderr": repaired_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A SoX file controls the raw IEEE-754 sample-rate field. A quiet NaN "
            "makes both vulnerable numeric comparisons false, survives the "
            "fractional-rate path, and is converted to int when assigned to "
            "AVCodecParameters.sample_rate. The harness executes the exact pinned "
            "sox_read_header function and UBSan aborts at that production assignment. "
            "Exact repair d2d79dca9a adds isnan() to the range check; the identical "
            "input is then rejected cleanly. This is one low-severity malformed-media "
            "availability root."
        ),
        "vulnerable_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "repaired_run": {
            "command": [str(repaired_binary)],
            "returncode": repaired_run_result.returncode,
            "stdout": repaired_run_result.stdout,
            "stderr": repaired_run_result.stderr,
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
