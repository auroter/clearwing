"""Build, run, and record the IAMF FLAC short-extradata overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.iamf-flac-short-extradata-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_iamf_flac_short_extradata_reproducer.c"
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
        "-O1",
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
    source = checkout / "libavformat/iamf_writer.c"
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
        "flac_rewrite_uses_reported_size": (
            "init_get_bits8(&gb, codec_config->extradata, "
            "codec_config->extradata_size)" in source_text
        ),
        "thirteen_byte_unconditional_copy": (
            "uint8_t buf[13];" in source_text
            and "memcpy(codec_config->extradata, buf, sizeof(buf));" in source_text
        ),
        "initial_extradata_is_exact_sized": (
            "codec_config->extradata = av_memdup(st->codecpar->extradata, "
            "st->codecpar->extradata_size);" in source_text
        ),
        "replacement_extradata_is_exact_sized": (
            "codec_config->extradata = av_memdup(new_extradata, "
            "new_extradata_size);" in source_text
        ),
        "no_flac_minimum_size_guard": (
            "extradata_size < 13" not in source_text
            and "extradata_size < sizeof(buf)" not in source_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "padded_source_exact_short_duplicate": (
            "codec=flac source_padding=64 extradata_size=12 "
            "rewrite_size=13 duplicated_allocation_size=12"
            in combined
        ),
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow"
        in combined,
        "asan_read": "READ of size" in combined,
        "update_extradata_in_trace": "in update_extradata" in combined,
        "fill_codec_config_in_trace": "in fill_codec_config" in combined,
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
            "codec": "flac",
            "source_padding_size": 64,
            "duplicated_allocation_size": 12,
            "reported_extradata_size": 12,
            "rewrite_size": 13,
            "overflow_size": 1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "IAMF accepts caller- or packet-supplied FLAC extradata without a "
            "13-byte minimum and strips the required input padding when it "
            "duplicates the data into an exact-sized heap buffer. The FLAC "
            "rewrite first reads beyond that duplicate and then unconditionally "
            "copies 13 bytes back. A padded 12-byte public codec configuration "
            "therefore causes a heap-buffer overflow in the production "
            "fill_codec_config to update_extradata path."
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
