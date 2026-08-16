"""Build and record the TrueMotion2RT unchecked-reader packet over-read."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.truemotion2rt-unchecked-reader-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_truemotion2rt_unchecked_reader_reproducer.c"),
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
        "libavcodec/libavcodec.a",
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
    source = checkout / "libavcodec/truemotion2rt.c"
    config = build_dir / "config.h"
    if (
        not harness.is_file()
        or not source.is_file()
        or not config.is_file()
        or not (build_dir / "libavcodec/libavcodec.a").is_file()
        or not (build_dir / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, source, config, and configured archives must exist")
    if _head(checkout) != _head(build_dir):
        raise ValueError("checkout and configured build must use the same commit")

    config_text = config.read_text(encoding="utf-8", errors="replace")
    if "#define CONFIG_SAFE_BITSTREAM_READER 0" not in config_text:
        raise ValueError("build must use --disable-safe-bitstream-reader")

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
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    get_bits_text = (checkout / "libavcodec/get_bits.h").read_text(
        encoding="utf-8", errors="replace"
    )
    source_indicators = {
        "configured_unchecked_reader": ("#define CONFIG_SAFE_BITSTREAM_READER 0" in config_text),
        "guard_allows_four_times_packet_bits": ("avpkt->size * 8LL * 4" in source_text),
        "reader_excludes_header_bytes": (
            "init_get_bits8(gb, avpkt->data + ret, avpkt->size - ret)" in source_text
        ),
        "decoder_skips_and_consumes_per_pixel_bits": all(
            term in source_text
            for term in (
                "skip_bits(gb, 32);",
                "get_bits(gb, s->delta_size)",
            )
        ),
        "unchecked_reader_does_not_clamp_index": all(
            term in get_bits_text
            for term in (
                "#define UNCHECKED_BITSTREAM_READER !CONFIG_SAFE_BITSTREAM_READER",
                "#   define SKIP_COUNTER(name, gb, num) name ## _index += (num)",
            )
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_packet_geometry": (
            "decoder=truemotion2rt safe_bitstream_reader=0 packet_size=50 "
            "header_offset=10 payload_bytes=40 width=20 height=20 "
            "delta_bits=4 luma_bits=1600 guard_limit_bits=1600" in combined
        ),
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in combined,
        "four_byte_read": "READ of size 4" in combined,
        "read_starts_after_packet_and_padding": ("0 bytes after 114-byte region" in combined),
        "get_bits_in_trace": "get_bits" in combined,
        "decoder_in_trace": "truemotion2rt_decode_frame" in combined,
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
        "required_configure_option": "--disable-safe-bitstream-reader",
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
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "packet_bytes": 50,
            "header_offset": 10,
            "bitreader_payload_bytes": 40,
            "packet_padding_bytes": 64,
            "width": 20,
            "height": 20,
            "delta_bits": 4,
            "luma_bits": 1600,
            "guard_limit_bits": 1600,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "TrueMotion2RT compares luma demand with four times the complete "
            "packet's bit count, then initializes its reader after the header and "
            "also consumes chroma and a 32-bit prefix. The default safe reader "
            "clamps this malformed stream, but FFmpeg's supported "
            "--disable-safe-bitstream-reader configuration permits the index to "
            "advance. A public 50-byte packet then makes get_bits read four bytes "
            "immediately after the packet's 64-byte padding."
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
