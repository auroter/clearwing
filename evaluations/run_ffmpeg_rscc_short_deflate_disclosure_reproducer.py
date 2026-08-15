"""Build and record RSCC's short-deflate heap disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rscc-short-deflate-disclosure-reproducer.v1"
REPAIR_COMMIT = "a5fe21a1a410a680fe93c33b0dd696b7e1c3aea4"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rscc_short_deflate_disclosure_reproducer.c"),
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
            "libavcodec/libavcodec.a",
            "libavutil/libavutil.a",
            "-lm",
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
    source = checkout / "libavcodec/rscc.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, RSCC source, and configured FFmpeg archives must exist")

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
            "libavcodec/rscc.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "inflated_capacity_uses_full_frame": (
            "ctx->inflated_size = avctx->width * avctx->height * "
            "ctx->component_size" in source_text
        ),
        "uncompress_length_is_not_checked": all(
            term in source_text
            for term in (
                "uLongf len = ctx->inflated_size;",
                "uncompress(ctx->inflated_buf, &len, gbc->buffer, packed_size)",
                "pixels = ctx->inflated_buf;",
            )
        )
        and "if (len < pixel_size)" not in source_text,
        "full_declared_tile_is_copied": all(
            term in source_text
            for term in (
                "av_image_copy_plane(dst,",
                "raw, ctx->tiles[i].w * ctx->component_size",
                "ctx->tiles[i].h);",
            )
        ),
        "later_repair_names_heap_disclosure": (
            repair_result.returncode == 0
            and "rscc_short_deflate_heap_disclosure.avi" in repair_text
            and "memset(ctx->inflated_buf + len, 0, pixel_size - len);" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_short_deflate_state": (
            "width=2 height=2 pixel_size=16 inflated_len=4 stale_bytes=12" in combined
        ),
        "full_production_decode_returned_frame": (
            "decoded_marker_bytes=12 got_frame=1" in combined
        ),
        "process_succeeded": run_result.returncode == 0,
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
            "width": 2,
            "height": 2,
            "component_bytes": 4,
            "declared_pixel_bytes": 16,
            "inflated_bytes": 4,
            "stale_heap_bytes": 12,
            "decoded_marker_bytes": 12,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A valid zlib stream expands to four bytes while a single 2x2 BGR0 "
            "tile declares sixteen bytes. The decoder supplies the full-frame "
            "capacity to uncompress but ignores its returned length, then "
            "copies the full tile from the reusable heap buffer. The harness "
            "opens the pinned production decoder, marks the buffer as prior "
            "heap contents, decodes the crafted packet, and observes all twelve "
            "untouched marker bytes in the returned frame. Later repair "
            "a5fe21a1a4 names the heap disclosure and zero-fills exactly this "
            "short expansion."
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
