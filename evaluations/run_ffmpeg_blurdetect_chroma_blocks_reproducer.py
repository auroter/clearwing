"""Record the vf_blurdetect chroma block-array heap overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.blurdetect-chroma-blocks-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    output = args.output.expanduser().resolve()
    unstripped_ffmpeg = checkout / "ffmpeg_g"
    ffmpeg = unstripped_ffmpeg if unstripped_ffmpeg.is_file() else checkout / "ffmpeg"
    source = checkout / "libavfilter/vf_blurdetect.c"
    if not ffmpeg.is_file() or not source.is_file():
        raise ValueError("ASan FFmpeg executable and vf_blurdetect.c must exist")

    filtergraph = (
        "nullsrc=s=19x19:r=1,format=yuv420p,"
        "geq=lum=128:cb='128+127*sin(X*PI/3)+0*Y':cr=128,"
        "blurdetect=block_width=10:block_height=10:planes=2:radius=3"
    )
    command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        filtergraph,
        "-frames:v",
        "1",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "luma_floor_sized_allocation": (
            "av_calloc((inlink->w / s->block_width) * "
            "(inlink->h / s->block_height)" in source_text
        ),
        "per_plane_rounded_block_width": (
            "int block_width  = AV_CEIL_RSHIFT(s->block_width,  hsub);"
            in source_text
        ),
        "per_plane_rounded_block_height": (
            "int block_height = AV_CEIL_RSHIFT(s->block_height, vsub);"
            in source_text
        ),
        "unchecked_block_write": (
            "blks[blkcnt] = block_total_width / block_count;" in source_text
        ),
    }
    combined = result.stdout + result.stderr
    runtime_indicators = {
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "asan_four_byte_write": "WRITE of size 4" in combined,
        "one_float_allocation_exhausted": (
            "0 bytes after 4-byte region" in combined
        ),
        "process_aborted": result.returncode != 0,
    }
    geometry = {
        "pixel_format": "yuv420p",
        "frame_width": 19,
        "frame_height": 19,
        "configured_block_width": 10,
        "configured_block_height": 10,
        "selected_planes_mask": 2,
        "luma_allocated_block_count": (19 // 10) * (19 // 10),
        "chroma_width": (19 + 1) // 2,
        "chroma_height": (19 + 1) // 2,
        "chroma_block_width": (10 + 1) // 2,
        "chroma_block_height": (10 + 1) // 2,
        "chroma_possible_block_count": (10 // 5) * (10 // 5),
    }
    expected_observed = (
        all(source_indicators.values())
        and all(runtime_indicators.values())
        and geometry["luma_allocated_block_count"] == 1
        and geometry["chroma_possible_block_count"] == 4
    )
    commit_result = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": commit_result.stdout.strip() or None,
        "source": str(source),
        "source_sha256": _sha256(source),
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": result.returncode,
        "geometry": geometry,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "vf_blurdetect allocates its block-score array using floor-divided "
            "full-resolution geometry. For a selected subsampled chroma plane, "
            "it independently rounds the plane and block dimensions upward, "
            "which can produce more blocks than the allocation. Edge-bearing "
            "chroma data then writes additional float scores past the heap "
            "allocation in calculate_blur."
        ),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
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
