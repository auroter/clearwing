"""Build and record Screenpresso's short-deflate heap disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.screenpresso-short-output-disclosure-reproducer.v1"
REPAIR_COMMIT = "c22667d0fd7916a33fd3e79685b7246fc48f1a62"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_screenpresso_short_output_disclosure_reproducer.c"
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
    config = checkout / "config.h"
    components = checkout / "config_components.h"
    source_path = checkout / "libavcodec/screenpresso.c"
    if not harness.is_file() or not (
        checkout / "libavcodec/libavcodec.a"
    ).is_file() or not config.is_file() or not components.is_file() or not (
        source_path.is_file()
    ):
        raise ValueError(
            "harness, source, and configured FFmpeg static libraries must exist"
        )

    configuration = config.read_text(encoding="utf-8", errors="replace")
    configured_components = components.read_text(
        encoding="utf-8", errors="replace"
    )
    source = source_path.read_text(encoding="utf-8", errors="replace")
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
            "halt_on_error=1:abort_on_error=1:detect_leaks=0:"
            "malloc_fill_byte=165:max_malloc_fill_size=1048576"
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

    repair_result = subprocess.run(
        ["git", "show", "--format=fuller", "--no-ext-diff", REPAIR_COMMIT, "--", str(source_path.relative_to(checkout))],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    combined = run_result.stdout + run_result.stderr
    repair_text = repair_result.stdout + repair_result.stderr
    indicators = {
        "screenpresso_decoder_enabled": (
            "#define CONFIG_SCREENPRESSO_DECODER 1" in configured_components
            and "#define CONFIG_ZLIB 1" in configuration
        ),
        "nonzeroed_inflate_allocation": (
            "ctx->inflated_buf  = av_malloc(ctx->inflated_size);" in source
        ),
        "short_output_guard_absent": (
            "if (length < src_linesize * avctx->height)" not in source
        ),
        "full_visible_plane_copy": "av_image_copy_plane" in source,
        "decoder_accepted_short_output": run_result.returncode == 0,
        "public_short_output_geometry": (
            "codec=screenpresso width=4 height=1 component_size=3 "
            "inflated_capacity=16 decompressed=3 copied=12 disclosed=9"
            in combined
        ),
        "nine_allocator_fill_bytes_disclosed": (
            "allocator_fill=a5 decoded_prefix=112233 "
            "disclosed_fill_bytes=9 expected=9" in combined
        ),
        "sanitizer_clean": "Sanitizer" not in combined,
        "exact_repair_present": (
            repair_result.returncode == 0
            and "reject deflate output shorter than the frame" in repair_text
            and "Fixes: use of uninitialized memory" in repair_text
            and "if (length < src_linesize * avctx->height)" in repair_text
        ),
    }
    expected_observed = compile_result.returncode == 0 and all(indicators.values())
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
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_result.stdout,
        "repair_commit_stderr": repair_result.stderr,
        "scope": (
            "A public 4x1 BGR24 Screenpresso keyframe contains a valid zlib "
            "stream that expands to three bytes. The decoder's nonzeroed "
            "16-byte inflate allocation retains nine untouched bytes inside "
            "the 12-byte visible row, but the decoder copies and publishes "
            "that complete row. ASan malloc-fill deterministically marks the "
            "disclosed heap bytes; the exact later repair rejects short output."
        ),
        "source_sha256": _sha256(source_path),
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
