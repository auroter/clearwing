"""Build and record the CLLC unsafe-bitreader short-packet reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.cllc-short-packet-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_cllc_short_packet_reproducer.c"),
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


def _compile_command(checkout: Path, harness: Path, binary: Path) -> list[str]:
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
        str(checkout / "libavcodec/bswapdsp.c"),
        str(checkout / "libavcodec/canopus.c"),
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibswscale",
        "-Llibavutil",
        "-lavcodec",
        "-lswresample",
        "-lswscale",
        "-lavutil",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "decoder": checkout / "libavcodec/cllc.c",
        "bitreader": checkout / "libavcodec/get_bits.h",
        "configure": checkout / "configure",
        "components": checkout / "config_components.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError("harness, sources, and configured FFmpeg static libraries must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(checkout, harness, binary)
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

    decoder = sources["decoder"].read_text(encoding="utf-8", errors="replace")
    bitreader = sources["bitreader"].read_text(encoding="utf-8", errors="replace")
    configure = sources["configure"].read_text(encoding="utf-8", errors="replace")
    components = sources["components"].read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "one_bit_per_pixel_guard": ("get_bits_left(&gb) < avctx->height * avctx->width" in decoder),
        "argb_decodes_four_vlc_symbols": all(
            term in decoder
            for term in (
                "GET_VLC(code, bits, gb, vlc[0].table",
                "GET_VLC(code, bits, gb, vlc[1].table",
                "GET_VLC(code, bits, gb, vlc[2].table",
                "GET_VLC(code, bits, gb, vlc[3].table",
            )
        ),
        "pixel_loops_have_no_remaining_bit_check": (
            "for (i = 0; i < ctx->avctx->width; i++)" in decoder and "BITS_AVAILABLE" not in decoder
        ),
        "unsafe_reader_is_supported_configuration": (
            "safe_bitstream_reader" in configure
            and "UNCHECKED_BITSTREAM_READER !CONFIG_SAFE_BITSTREAM_READER" in bitreader
        ),
        "pinned_decoder_omitted_but_source_compiled_into_harness": (
            "#define CONFIG_CLLC_DECODER 0" in components
            and '#include "libavcodec/cllc.c"'
            in harness.read_text(encoding="utf-8", errors="replace")
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_decode_reached": (
            "codec=cllc safe_bitstream_reader=0 coding_type=argb "
            "width=64 height=64 packet_bits=4096 guard_bits=4096 "
            "header_bits=136 decode_bits=16384" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "four_byte_overread": "READ of size 4" in combined,
        "cllc_decoder_in_trace": (
            "decode_argb_frame cllc.c" in combined and "cllc_decode_frame cllc.c" in combined
        ),
        "read_starts_at_allocation_end": ("0 bytes after 644-byte region" in combined),
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
        "source_sha256": {name: _sha256(path) for name, path in sources.items()},
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "width": 64,
            "height": 64,
            "packet_bits": 4096,
            "guard_bits": 4096,
            "header_bits": 136,
            "argb_decode_bits": 16384,
            "safe_bitstream_reader": False,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "FFmpeg exposes safe_bitstream_reader as a configurable feature. "
            "With that feature disabled, CLLC must keep optimized VLC reads "
            "inside the packet plus padding. Its one-bit-per-pixel guard is "
            "insufficient for valid attacker-defined one-bit ARGB tables that "
            "consume four symbols per pixel. The public avcodec harness passes "
            "the guard exactly, then ASan observes a four-byte read starting "
            "at the end of the decoder's padded swap allocation."
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
