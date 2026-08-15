"""Build and record RTP/JPEG's oversized quantization-table overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rtp-jpeg-qtable-length-reproducer.v1"
REPAIR_COMMIT = "d84bec2bd6f4e5ffe2a747d1d6d7bdc3c8d46e8e"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rtp_jpeg_qtable_length_reproducer.c"),
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
    source = checkout / "libavformat/rtpdec_jpeg.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, RTP/JPEG source, and configured archives must exist")

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
            "libavformat/rtpdec_jpeg.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "packet_controls_qtable_length": all(
            term in source_text
            for term in (
                "qtable_len = AV_RB16(buf + 2);",
                "if (len < qtable_len)",
                "qtables = buf;",
            )
        ),
        "header_uses_fixed_stack_buffer": all(
            term in source_text
            for term in (
                "uint8_t hdr[1024];",
                "qtable_len / 64, dri",
            )
        ),
        "raw_backpatch_follows_checked_writer": all(
            term in source_text
            for term in (
                "dht_size_ptr = pbc.buffer;",
                "AV_WB16(dht_size_ptr, dht_size);",
            )
        ),
        "vulnerable_source_has_no_qtable_cap": ("qtable_len > 4*64" not in source_text),
        "later_repair_adds_exact_length_cap": (
            repair_result.returncode == 0
            and "check qtable_len" in repair_text
            and "Fixes: out of array access" in repair_text
            and "qtable_len > 4*64" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_oversized_table_state": (
            "q=255 qtable_length=1024 header_capacity=1024 "
            "qtable_count=16 packet_length=1036" in combined
        ),
        "asan_stack_buffer_overflow": ("AddressSanitizer: stack-buffer-overflow" in combined),
        "write_overflow": "WRITE of size" in combined,
        "header_function_in_trace": (
            "jpeg_create_header" in combined or "jpeg_parse_packet rtpdec_jpeg.c:333" in combined
        ),
        "header_stack_object_identified": "'hdr'" in combined,
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
            "q": 255,
            "qtable_bytes": 1024,
            "qtable_count": 16,
            "header_stack_capacity": 1024,
            "packet_bytes": 1036,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "An RTP/JPEG start packet can declare a complete 1024-byte "
            "quantization-table section. The parser bounds that section only "
            "against the packet, then asks jpeg_create_header to serialize "
            "sixteen tables into its fixed 1024-byte stack buffer. Checked "
            "bytestream writes saturate at the buffer end, but the following "
            "raw DHT-size backpatch writes through that end pointer. The full "
            "production parse entry aborts under ASan in jpeg_create_header. "
            "Later repair d84bec2bd6 caps table data at four 64-byte tables "
            "and explicitly identifies the out-of-array access."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
