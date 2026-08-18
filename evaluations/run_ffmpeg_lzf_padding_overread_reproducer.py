"""Build and record the LZF output-padding over-read proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.lzf-padding-overread-reproducer.v1"
REPAIR_COMMIT = "fe47696aa1eb3b4f2359b9c4416c529912deee38"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_lzf_padding_overread_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(*, harness: Path, source: Path, archive: Path, binary: Path) -> list[str]:
    return [
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
        "-fsanitize=address",
        "-fno-sanitize-recover=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
        str(source),
        str(archive),
        "-lm",
        "-pthread",
    ]


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/lzf.c"
    header = checkout / "libavcodec/lzf.h"
    consumer = checkout / "libavcodec/notchlc.c"
    archive = checkout / "libavutil/libavutil.a"
    required = (harness, source, header, consumer, archive)
    if any(not path.is_file() for path in required):
        raise ValueError("harness, pinned LZF sources, consumer, and libavutil must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-lzf.c")

    repair_source_result = _run(["git", "show", f"{REPAIR_COMMIT}:libavcodec/lzf.c"], cwd=checkout)
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(
        harness=harness, source=source, archive=archive, binary=binary
    )
    repaired_compile_command = _compile_command(
        harness=harness,
        source=repaired_source,
        archive=archive,
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
    header_text = header.read_text(encoding="utf-8", errors="replace")
    consumer_text = consumer.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        [
            "git",
            "show",
            "--format=",
            REPAIR_COMMIT,
            "--",
            "libavcodec/lzf.c",
            "libavcodec/lzf.h",
        ],
        cwd=checkout,
    )
    repair_message = _run(["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout)
    source_indicators = {
        "vulnerable_growth_has_no_padding": (
            "ret = lzf_realloc(buf, len + s, allocated_size);" in source_text
            and "ret = lzf_realloc(buf, len + l, allocated_size);" in source_text
            and "AV_INPUT_BUFFER_PADDING_SIZE" not in source_text
        ),
        "vulnerable_contract_does_not_promise_padding": (
            "AV_INPUT_BUFFER_PADDING_SIZE" not in header_text
        ),
        "notchlc_wraps_lzf_output_in_bit_reader": (
            "bytestream2_init(gb, s->lzf_buffer, uncompressed_size);" in consumer_text
            and "init_get_bits8(&bit, dgb.buffer" in consumer_text
        ),
        "exact_repair_allocates_and_zeros_padding": (
            repair_diff.returncode == 0
            and "len + s + AV_INPUT_BUFFER_PADDING_SIZE" in repair_diff.stdout
            and "len + l + AV_INPUT_BUFFER_PADDING_SIZE" in repair_diff.stdout
            and "memset(*buf + len, 0, AV_INPUT_BUFFER_PADDING_SIZE);" in repair_diff.stdout
            and "out of array read" in repair_message.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "tight_vulnerable_output_fills_allocation": (
            "compressed=69 output=66 allocated=66" in combined
        ),
        "asan_heap_overread": (
            "AddressSanitizer: heap-buffer-overflow" in combined
            and "READ of size 4" in combined
            and "1 bytes after 66-byte region" in combined
        ),
        "production_lzf_allocator_in_trace": "ff_lzf_uncompress" in combined,
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_output_is_readable": (
            repaired_run_result.returncode == 0
            and "compressed=69 output=66 allocated=" in repaired_combined
            and "tail=16449" in repaired_combined
            and "AddressSanitizer" not in repaired_combined
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
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile_result.returncode,
        "repaired_compile_stdout": repaired_compile_result.stdout,
        "repaired_compile_stderr": repaired_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The pinned LZF helper returns decompressed storage without the "
            "mandatory bit-reader padding promised by FFmpeg packet buffers. "
            "NotchLC wraps that output in a GetBitContext. Two 32-byte literal "
            "runs followed by two bytes fill av_fast_realloc's exact 66-byte "
            "allocation; a legal final 16-bit read makes the 32-bit cache load "
            "cross the heap boundary. The harness executes the production LZF "
            "helper and inline bit reader, and ASan reports the heap over-read. "
            "Exact repair fe47696aa1 reserves and zeroes 64 padding bytes; the "
            "same harness then exits cleanly and reads the intended tail value."
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
