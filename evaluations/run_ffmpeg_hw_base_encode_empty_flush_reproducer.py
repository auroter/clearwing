"""Build, run, and record the hardware encoder empty-flush crash."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.hw-base-encode-empty-flush-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_hw_base_encode_empty_flush_reproducer.c"
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
        "-ffunction-sections",
        "-g",
        "-O2",
        "-std=c17",
        "-fPIC",
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
            "libavutil/libavutil.a",
            "-lm",
            "-pthread",
            "-lz",
        ]
    )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/hw_base_encode.c"
    avutil = checkout / "libavutil/libavutil.a"
    if not harness.is_file() or not avutil.is_file() or not source.is_file():
        raise ValueError(
            "harness, configured FFmpeg libavutil archive, and source must exist"
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
    if compile_result.returncode == 0:
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
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "generic_eof_becomes_null_frame": (
            "if (err == AVERROR_EOF)" in source_text
            and "frame = NULL;" in source_text
        ),
        "null_frame_sent_before_empty_queue_check": (
            "err = hw_base_encode_send_frame(avctx, ctx, frame);"
            in source_text
            and "if (!ctx->pic_start)" in source_text
        ),
        "empty_flush_sets_end_of_stream": "ctx->end_of_stream = 1;"
        in source_text,
        "empty_flush_dereferences_pic_end": (
            "if (ctx->input_order <= ctx->decode_delay)" in source_text
            and "ctx->dts_pts_diff = ctx->pic_end->pts - ctx->first_pts;"
            in source_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_empty_state": (
            "empty_flush_state=1 input_order=0 decode_delay=0 "
            "pic_start_null=1 pic_end_null=1" in combined
        ),
        "ubsan_null_member_access": (
            "runtime error: member access within null pointer" in combined
        ),
        "source_line_508": "hw_base_encode.c:508:47" in combined,
        "asan_segv": "AddressSanitizer: SEGV" in combined,
        "send_frame_in_trace": "in hw_base_encode_send_frame" in combined,
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
            "input_order": 0,
            "decode_delay": 0,
            "queued_pictures": 0,
            "pic_end": None,
            "null_read_offset": 40,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public VAAPI/D3D12 receive path converts an empty encoder's "
            "generic EOF into a NULL frame and calls hw_base_encode_send_frame "
            "before checking pic_start. With input_order and decode_delay both "
            "zero, the flush path dereferences pic_end even though no picture "
            "was ever queued. The direct production-function harness reproduces "
            "the null read without requiring hardware on this host."
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
