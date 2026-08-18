"""Build and record H.264/H.265 ambient side-data initialization UAF."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.h2645-ambient-side-data-uaf-reproducer.v1"
REPAIR_COMMIT = "f435ce22e10e2c93fc8027cc72eeb09eba50ab8d"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_h2645_ambient_side_data_uaf_reproducer.c"
        ),
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
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DH2645_SEI_SOURCE="{source}"',
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
        "-Llibavcodec",
        "-Llibavutil",
        "-lavcodec",
        "-lavutil",
        "-lm",
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
                "-liconv",
            ]
        )
    else:
        command.append("-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/h2645_sei.c"
    decode_source = checkout / "libavcodec/decode.c"
    required = (
        harness,
        source,
        decode_source,
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError(
            "harness, pinned H.264/H.265 side-data sources, and archives must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-h2645_sei.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavcodec/h2645_sei.c"], cwd=checkout
    )
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(harness, source, binary)
    repaired_compile_command = _compile_command(
        harness, repaired_source, repaired_binary
    )
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = (
        _run(repaired_compile_command, cwd=checkout)
        if repaired_source.is_file()
        else _failed(repaired_compile_command, "repair source extraction failed")
    )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    repaired_run_result = (
        _run([str(repaired_binary)], cwd=checkout, env=environment)
        if repaired_compile_result.returncode == 0
        else _failed([str(repaired_binary)], "repaired compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    decode_text = decode_source.read_text(encoding="utf-8", errors="replace")
    harness_text = harness.read_text(encoding="utf-8", errors="replace")
    repair_result = _run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/h2645_sei.c",
        ],
        cwd=checkout,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "packet_preference_consumes_new_side_data": all(
            term in decode_text
            for term in (
                "if (side_data_pref(avctx, sd, nb_sd, type))",
                "goto finish;",
                "finish:\n    av_buffer_unref(buf);",
            )
        ),
        "ambient_buffer_initialized_after_consuming_helper": all(
            term in source_text
            for term in (
                "av_ambient_viewing_environment_alloc(&size)",
                "ff_frame_new_side_data_from_buf_ext(avctx, sd, nb_sd,",
                "dst_env->ambient_illuminance = av_make_q",
            )
        )
        and source_text.index("ff_frame_new_side_data_from_buf_ext")
        < source_text.index("dst_env->ambient_illuminance = av_make_q"),
        "proof_helper_matches_preference_branch": all(
            term in harness_text
            for term in (
                "proof_preferred_side_data_consumer",
                "av_buffer_unref(buf);",
                "existing_packet_side_data=1",
                "prefer_packet=1",
            )
        ),
        "exact_repair_initializes_before_consumption": (
            repair_result.returncode == 0
            and "Initialize side data before deallocation" in repair_text
            and "Fixes: use after free" in repair_text
            and repair_text.index("+        dst_env->ambient_illuminance")
            < repair_text.index("ret = ff_frame_new_side_data_from_buf_ext")
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "reachable_preference_state_replayed": (
            "ambient_present=1 existing_packet_side_data=1 "
            "prefer_packet=1 helper_consumes_new_buffer=1" in combined
        ),
        "asan_heap_use_after_free": (
            "AddressSanitizer: heap-use-after-free" in combined
        ),
        "eight_byte_write_to_freed_ambient_metadata": (
            "WRITE of size 8" in combined
            and "0 bytes inside of 24-byte region" in combined
        ),
        "production_allocation_and_sink_in_trace": (
            "av_ambient_viewing_environment_alloc" in combined
            and "in h2645_sei_to_side_data" in combined
            and "proof_preferred_side_data_consumer" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_initialization_completes": (
            repaired_run_result.returncode == 0
            and "helper_consumes_new_buffer=1" in repaired_combined
            and "Sanitizer" not in repaired_combined
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
        "decode_source_sha256": _sha256(decode_source),
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
            "When container-provided ambient-viewing side data already exists and "
            "side_data_prefer_packet selects it, FFmpeg's helper consumes the newly "
            "allocated coded-side-data buffer without attaching it. The vulnerable "
            "H.264/H.265 SEI transfer initializes that freed 24-byte object afterward. "
            "The harness executes the exact production allocation and faulting "
            "h2645_sei_to_side_data code; its proof-only helper reproduces only the "
            "exact documented preference branch from decode.c. ASan reports the first "
            "eight-byte write into freed ambient metadata. Exact repair f435ce22e1 "
            "moves all initialization before the consuming helper, and the identical "
            "replay exits cleanly. The repair names a public modified-hvcc MP4 proof."
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
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
