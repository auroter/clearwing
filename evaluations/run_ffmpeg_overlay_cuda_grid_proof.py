"""Record the overlay_cuda rounded-grid out-of-bounds write geometry."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.overlay-cuda-grid-proof.v1"


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


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    output = args.output.expanduser().resolve()
    host_source = checkout / "libavfilter/vf_overlay_cuda.c"
    kernel_source = checkout / "libavfilter/vf_overlay_cuda.cu"
    allocator_source = checkout / "libavutil/hwcontext_cuda.c"
    sources = (host_source, kernel_source, allocator_source)
    if any(not source.is_file() for source in sources):
        raise ValueError("the pinned FFmpeg CUDA overlay sources must exist")

    host_text = host_source.read_text(encoding="utf-8", errors="replace")
    kernel_text = kernel_source.read_text(encoding="utf-8", errors="replace")
    allocator_text = allocator_source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "block_width_32": "#define BLOCK_X 32" in host_text,
        "block_height_16": "#define BLOCK_Y 16" in host_text,
        "grid_rounds_main_dimensions_up": (
            "DIV_UP(main_width, BLOCK_X), DIV_UP(main_height, BLOCK_Y)" in host_text
        ),
        "kernel_checks_overlay_rectangle": all(
            term in kernel_text
            for term in (
                "x >= overlay_w + x_position",
                "y >= overlay_h + y_position",
                "x < x_position",
                "y < y_position",
            )
        ),
        "kernel_writes_main_by_grid_coordinate": ("main[x + y*main_linesize] =" in kernel_text),
        "kernel_has_no_main_dimension_parameters": (
            "main_width" not in kernel_text and "main_height" not in kernel_text
        ),
        "cuda_pool_uses_exact_image_geometry": (
            "av_image_get_buffer_size(ctx->sw_format, ctx->width, ctx->height," in allocator_text
        ),
        "cuda_pool_uses_computed_size": "cu->cuMemAlloc(&data, size)" in allocator_text,
    }

    block_width = 32
    block_height = 16
    main_width = 32
    main_height = 18
    overlay_width = 32
    overlay_height = 32
    pitch = 32
    luma_rows = main_height
    chroma_rows = _ceil_div(main_height, 2)
    allocation_size = pitch * (luma_rows + chroma_rows)

    luma_grid_width = _ceil_div(main_width, block_width) * block_width
    luma_grid_height = _ceil_div(main_height, block_height) * block_height
    luma_last_x = min(luma_grid_width, overlay_width) - 1
    luma_last_y = min(luma_grid_height, overlay_height) - 1
    luma_last_write = luma_last_y * pitch + luma_last_x

    chroma_main_height = main_height // 2
    chroma_overlay_height = overlay_height // 2
    chroma_grid_width = _ceil_div(main_width, block_width) * block_width
    chroma_grid_height = _ceil_div(chroma_main_height, block_height) * block_height
    chroma_last_x = min(chroma_grid_width, overlay_width) - 1
    chroma_last_y = min(chroma_grid_height, chroma_overlay_height) - 1
    chroma_plane_offset = pitch * luma_rows
    chroma_last_write = chroma_plane_offset + chroma_last_y * pitch + chroma_last_x

    geometry = {
        "pixel_format": "nv12",
        "x_position": 0,
        "y_position": 0,
        "main_width": main_width,
        "main_height": main_height,
        "overlay_width": overlay_width,
        "overlay_height": overlay_height,
        "block_width": block_width,
        "block_height": block_height,
        "normalized_pitch": pitch,
        "normalized_allocation_size": allocation_size,
        "luma_grid_width": luma_grid_width,
        "luma_grid_height": luma_grid_height,
        "luma_last_permitted_thread": [luma_last_x, luma_last_y],
        "luma_last_write_offset": luma_last_write,
        "luma_overflow_bytes": luma_last_write - allocation_size + 1,
        "chroma_main_height_argument": chroma_main_height,
        "chroma_overlay_height_argument": chroma_overlay_height,
        "chroma_grid_width": chroma_grid_width,
        "chroma_grid_height": chroma_grid_height,
        "chroma_plane_offset": chroma_plane_offset,
        "chroma_last_permitted_thread": [chroma_last_x, chroma_last_y],
        "chroma_last_write_offset": chroma_last_write,
        "chroma_overflow_bytes": chroma_last_write - allocation_size + 1,
    }
    expected_observed = (
        all(source_indicators.values())
        and luma_grid_height > main_height
        and luma_last_y < overlay_height
        and luma_last_write >= allocation_size
        and chroma_grid_height > chroma_main_height
        and chroma_last_y < chroma_overlay_height
        and chroma_last_write >= allocation_size
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
        "source_sha256": {str(path): _sha256(path) for path in sources},
        "source_indicators": source_indicators,
        "geometry": geometry,
        "expected_observed": expected_observed,
        "scope": (
            "overlay_cuda rounds the launch grid up to complete 32x16 blocks, "
            "while its kernel only clips threads to the overlay rectangle and "
            "has no main-frame dimensions. A valid overlay taller than an "
            "18-row NV12 main frame therefore leaves rounded luma and chroma "
            "threads enabled beyond the exact CUDA image allocation. Offsets "
            "are normalized to the minimum 32-byte pitch; multiplying every "
            "row offset and allocation row by a larger CUDA pitch preserves "
            "the out-of-bounds relationship."
        ),
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
