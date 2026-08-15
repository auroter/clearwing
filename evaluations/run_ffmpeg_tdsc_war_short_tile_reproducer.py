"""Build and record the TD-SC short WAR-tile overread reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.tdsc-war-short-tile-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_tdsc_war_short_tile_reproducer.c"),
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
        "-ffunction-sections",
        "-fdata-sections",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
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
                "-Wl,-dead_strip",
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
        "decoder": checkout / "libavcodec/tdsc.c",
        "copy_primitive": checkout / "libavutil/imgutils.c",
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

    decoder = sources["decoder"].read_text(encoding="utf-8", errors="replace")
    components = sources["components"].read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "tile_size_only_checked_against_packet": (
            "bytestream2_get_bytes_left(&ctx->gbc) < tile_size" in decoder
        ),
        "tilebuffer_allocated_to_tile_size": (
            "av_reallocp(&ctx->tilebuffer, tile_size)" in decoder
        ),
        "war_copy_uses_geometry": all(
            term in decoder
            for term in (
                "tile_mode == MKTAG(' ','W','A','R')",
                "ctx->tilebuffer,\n                                w * 3, w * 3, h",
            )
        ),
        "missing_raw_tile_size_guard": ("3LL * w * h > tile_size" not in decoder),
        "pinned_decoder_omitted_but_source_compiled_into_harness": (
            "#define CONFIG_TDSC_DECODER 0" in components
            and '#include "libavcodec/tdsc.c"' in harness_source
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "production_tile_decoder_reached": (
            "codec=tdsc tile_mode=WAR width=64 height=64 tile_size=4 "
            "copy_bytes=12288 first_row_read=192" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "wide_read_from_short_tile": "READ of size 192" in combined,
        "production_sink_in_trace": (
            "tdsc_decode_tiles" in combined and "av_image_copy_plane" in combined
        ),
        "read_starts_at_allocation_end": ("0 bytes after 4-byte region" in combined),
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
            "tile_size": 4,
            "raw_bytes_required": 64 * 64 * 3,
            "first_row_bytes": 64 * 3,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The direct production-function harness supplies one TD-SC raw "
            "WAR tile whose public bitstream geometry requires 12,288 bytes "
            "but whose independently encoded tile_size allocates only four. "
            "The vulnerable decoder accepts both fields and passes the short "
            "heap tilebuffer to av_image_copy_plane. ASan reports the first "
            "192-byte row read beginning at the allocation boundary."
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
