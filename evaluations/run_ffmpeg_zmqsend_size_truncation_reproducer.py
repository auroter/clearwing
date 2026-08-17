"""Build, run, and record zmqsend's reply-size truncation proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.zmqsend-size-truncation-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_zmqsend_size_truncation_reproducer.c"),
    )
    parser.add_argument(
        "--zmq-stub-dir",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_zmqsend_stub"),
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _compile_command(harness: Path, stub_directory: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        f"-I{stub_directory}",
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
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "-Llibavutil",
        "-lavutil",
        "-lm",
    ]
    if platform.system() == "Darwin":
        command.extend(["-framework", "CoreFoundation", "-liconv"])
    command.append("-pthread")
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    stub_directory = args.zmq_stub_dir.expanduser().resolve()
    stub_header = stub_directory / "zmq.h"
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "tools/zmqsend.c"
    required = (harness, stub_header, source, checkout / "libavutil/libavutil.a")
    if _head(checkout) != VULNERABLE_COMMIT or not all(path.is_file() for path in required):
        raise ValueError(f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}")

    source_text = source.read_text(encoding="utf-8", errors="replace")
    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, stub_directory, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
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

    source_indicators = {
        "size_t_reply_stored_in_int": ("recv_buf_size = zmq_msg_size(&msg) + 1;" in source_text),
        "truncated_size_controls_allocation": (
            "recv_buf = av_malloc(recv_buf_size);" in source_text
        ),
        "truncated_size_controls_copy": (
            "memcpy(recv_buf, zmq_msg_data(&msg), recv_buf_size - 1);" in source_text
        ),
        "truncated_size_controls_terminator": ("recv_buf[recv_buf_size-1] = 0;" in source_text),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_truncation_boundary": (
            "reply_size=4294967295 size_plus_one=4294967296 truncated_int=0 "
            "copy_size=18446744073709551615" in combined
        ),
        "asan_negative_size": ("AddressSanitizer: negative-size-param: (size=-1)" in combined),
        "zmqsend_in_trace": "ffmpeg_zmqsend_main" in combined,
        "tool_aborted": run_result.returncode != 0,
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
        "checkout_commit": _head(checkout),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "zmq_stub_header": str(stub_header),
        "zmq_stub_header_sha256": _sha256(stub_header),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source": str(source),
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The harness stubs the external ZMQ transport with its valid "
            "size_t message-size contract and a virtually mapped reply, while "
            "executing pinned tools/zmqsend.c. A 2^32-1-byte reply makes the "
            "size-plus-terminator truncate to int zero, av_malloc(0) return a "
            "one-byte allocation, and the derived copy size become SIZE_MAX."
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
