"""Build and record the ASS muxer's trailing-newline underflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.assenc-newline-underflow-reproducer.v1"
REPAIR_COMMIT = "aa1f4ed774d0e885f64b61ea89fdcce702814798"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_assenc_newline_underflow_reproducer.c"),
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
        "-ffunction-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
    ]
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.extend(
        [
            "libavformat/libavformat.a",
            "libavcodec/libavcodec.a",
            "libswresample/libswresample.a",
            "libswscale/libswscale.a",
            "libavutil/libavutil.a",
            "-lm",
            "-lbz2",
            "-lz",
        ]
    )
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
    source = checkout / "libavformat/assenc.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, ASS muxer source, and configured FFmpeg archives must exist")

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
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
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
            "libavformat/assenc.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "packet_data_is_text_start": "char *p = pkt->data;" in source_text,
        "text_length_uses_strlen": "text_len = strlen(p);" in source_text,
        "unparenthesized_or_reaches_negative_index": (
            "while (text_len > 0 && p[text_len - 1] == '\\r' || "
            "p[text_len - 1] == '\\n')" in source_text
        ),
        "later_repair_adds_exact_parentheses": (
            repair_result.returncode == 0
            and "avformat/assenc: Add the missing parentheses" in repair_text
            and "while (text_len > 0 && (p[text_len - 1] == '\\r' || "
            "p[text_len - 1] == '\\n'))" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_one_byte_newline_state": (
            "packet_size=1 text_offset=0 initial_text_len=1 "
            "expected_final_text_len=0 underflow_index=-1" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "one_byte_read": "READ of size 1" in combined,
        "read_immediately_precedes_padded_packet": (
            "65-byte region" in combined
            and ("1 bytes before" in combined or "1 byte to the left" in combined)
        ),
        "production_function_in_trace": "in write_packet" in combined,
        "process_aborted": run_result.returncode != 0,
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
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {str(source.relative_to(checkout)): _sha256(source)},
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "logical_packet_bytes": 1,
            "packet_padding_bytes": 64,
            "allocated_region_bytes": 65,
            "text_offset": 0,
            "initial_text_len": 1,
            "final_text_len": 0,
            "faulting_index": -1,
            "observed_read_bytes_before_packet": 1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A one-byte newline packet makes both strtol calls leave the ASS "
            "text pointer at the packet start. The first loop test strips the "
            "newline and decrements text_len to zero. On the next test, && "
            "binds more tightly than ||, so the newline operand still reads "
            "p[-1]. The harness calls the pinned production write_packet "
            "function; ASan reports a one-byte heap read immediately before "
            "the 65-byte logical-plus-padding packet allocation. Later commit "
            "aa1f4ed774 adds the exact missing parentheses and names a real "
            "ada-1-poc.mkv trigger."
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
