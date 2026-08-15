"""Build and record the raw-RGB stride-overflow reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.raw-rgb-stride-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_raw_rgb_stride_overflow_reproducer.c"),
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
        "-Llibavformat",
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibswscale",
        "-Llibavutil",
        "-lavformat",
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
        "reshuffler": checkout / "libavformat/rawutils.c",
        "avi_caller": checkout / "libavformat/avienc.c",
        "components": checkout / "config_components.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError("harness, sources, and configured FFmpeg static libraries must exist")

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

    reshuffler = sources["reshuffler"].read_text(encoding="utf-8", errors="replace")
    avi_caller = sources["avi_caller"].read_text(encoding="utf-8", errors="replace")
    components = sources["components"].read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "avi_stride_derived_from_public_width": (
            "int expected_stride = ((par->width * bpc + 31) >> 5)*4" in avi_caller
        ),
        "destination_size_uses_int_product": (
            "av_new_packet(new_pkt, expected_stride * par->height)" in reshuffler
        ),
        "row_offsets_use_unwrapped_stride": all(
            term in reshuffler
            for term in (
                "new_pkt->data + y*expected_stride",
                "expected_stride - padding, 0, padding",
            )
        ),
        "missing_packet_size_bounds": all(
            term not in reshuffler
            for term in (
                "par->height <= 0",
                "expected_stride > (INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE)",
            )
        ),
        "pinned_avi_muxer_omitted_but_source_compiled_into_harness": (
            "#define CONFIG_AVI_MUXER 0" in components
            and '#include "libavformat/rawutils.c"' in harness_source
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "overflow_geometry_reached": (
            "raw_rgb_width=477218589 height=3 bpc=24 "
            "expected_stride=1431655768 source_stride=72 source_size=216 "
            "wrapped_destination_size=8 padded_destination_size=72 "
            "padding_write_size=1431655696" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "oversized_padding_write": "WRITE of size 1431655696" in combined,
        "reshuffler_in_trace": "ff_reshuffle_raw_rgb" in combined,
        "write_starts_at_padded_allocation_end": ("0 bytes after 72-byte region" in combined),
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
            "width": 477_218_589,
            "height": 3,
            "bits_per_coded_sample": 24,
            "expected_stride": 1_431_655_768,
            "source_stride": 72,
            "source_size": 216,
            "wrapped_destination_size": 8,
            "padded_destination_size": 72,
            "padding_write_size": 1_431_655_696,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The production AVI stride formula maps a public raw-video width "
            "and 24-bit depth to a 1,431,655,768-byte row. Multiplying that "
            "int stride by three rows wraps the destination packet size to "
            "eight bytes, while the reshuffle loop retains the original row "
            "stride. A valid 216-byte source packet reaches the padding memset "
            "after filling the destination payload and its mandatory 64-byte "
            "tail. ASan reports a 1,431,655,696-byte write starting exactly at "
            "the end of that 72-byte padded allocation."
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
