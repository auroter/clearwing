"""Record colorspace_cuda's rounded-grid source over-read geometry."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.colorspace-cuda-grid-proof.v1"


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
    host_source = checkout / "libavfilter/vf_colorspace_cuda.c"
    kernel_source = checkout / "libavfilter/vf_colorspace_cuda.cu"
    allocator_source = checkout / "libavutil/hwcontext_cuda.c"
    image_source = checkout / "libavutil/imgutils.c"
    sources = (host_source, kernel_source, allocator_source, image_source)
    if any(not source.is_file() for source in sources):
        raise ValueError("the pinned FFmpeg CUDA colorspace sources must exist")

    host_text = host_source.read_text(encoding="utf-8", errors="replace")
    kernel_text = kernel_source.read_text(encoding="utf-8", errors="replace")
    allocator_text = allocator_source.read_text(encoding="utf-8", errors="replace")
    image_text = image_source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "yuv444p_is_supported": "AV_PIX_FMT_YUV444P" in host_text,
        "block_width_32": "#define BLOCKX 32" in host_text,
        "block_height_16": "#define BLOCKY 16" in host_text,
        "yuv444p_preserves_full_plane_dimensions": (
            "case AV_PIX_FMT_YUV444P:\n            break;" in host_text
        ),
        "grid_rounds_plane_dimensions_up": (
            "DIV_UP(width, BLOCKX),\n                DIV_UP(height, BLOCKY)" in host_text
        ),
        "input_pointer_and_pitch_are_kernel_arguments": (
            "void* args[] = {&in->data[i], &out->data[i], &in->linesize[i],"
            in host_text
        ),
        "output_height_only_is_aligned_to_32": (
            "out_ctx->height = FFALIGN(height, 32);" in host_text
        ),
        "kernel_has_no_dimension_parameters": all(
            signature in kernel_text
            for signature in (
                "int pitch, int comp_id)",
                "src[x + y * pitch]",
                "dst[x + y * pitch]",
            )
        )
        and "int width" not in kernel_text
        and "int height" not in kernel_text,
        "cuda_pool_uses_exact_input_context_geometry": (
            "av_image_get_buffer_size(ctx->sw_format, ctx->width, ctx->height,"
            in allocator_text
            and "cu->cuMemAlloc(&data, size)" in allocator_text
        ),
        "image_size_is_full_pitch_times_each_plane_height": (
            "sizes[0] = linesizes[0] * (size_t)height;" in image_text
            and "sizes[i] = (size_t)h * linesizes[i];" in image_text
        ),
    }

    block_width = 32
    block_height = 16
    width = 32
    height = 1
    normalized_pitch = 32
    plane_count = 3
    input_plane_size = normalized_pitch * height
    input_allocation_size = input_plane_size * plane_count
    output_aligned_height = 32
    output_allocation_size = normalized_pitch * output_aligned_height * plane_count
    grid_width = _ceil_div(width, block_width) * block_width
    grid_height = _ceil_div(height, block_height) * block_height
    last_x = grid_width - 1
    last_y = grid_height - 1
    plane_offsets = [plane * input_plane_size for plane in range(plane_count)]
    last_read_offsets = [
        plane_offset + last_y * normalized_pitch + last_x
        for plane_offset in plane_offsets
    ]
    last_write_offsets = [
        plane * normalized_pitch * output_aligned_height
        + last_y * normalized_pitch
        + last_x
        for plane in range(plane_count)
    ]
    geometry = {
        "pixel_format": "yuv444p",
        "public_input_width": width,
        "public_input_height": height,
        "block_width": block_width,
        "block_height": block_height,
        "normalized_pitch": normalized_pitch,
        "input_plane_count": plane_count,
        "input_plane_size": input_plane_size,
        "input_plane_offsets": plane_offsets,
        "input_allocation_size": input_allocation_size,
        "output_aligned_height": output_aligned_height,
        "output_allocation_size": output_allocation_size,
        "launch_grid_width": grid_width,
        "launch_grid_height": grid_height,
        "last_launched_thread": [last_x, last_y],
        "last_read_offsets": last_read_offsets,
        "luma_read_overflow_bytes": last_read_offsets[0] - input_allocation_size + 1,
        "last_write_offsets": last_write_offsets,
        "writes_fit_aligned_output": all(
            offset < output_allocation_size for offset in last_write_offsets
        ),
    }
    expected_observed = (
        all(source_indicators.values())
        and grid_width == width
        and grid_height > height
        and last_read_offsets[0] >= input_allocation_size
        and all(offset < output_allocation_size for offset in last_write_offsets)
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
        "evidence_level": "source_and_geometry_confirmed",
        "scope": (
            "A public 32x1 YUV444P CUDA frames context has three one-row "
            "planes in one exact 3*pitch allocation. colorspace_cuda rounds "
            "each full-resolution plane launch to a 32x16 block, but its "
            "kernel receives no width or height and reads every launched "
            "coordinate. The luma launch alone reads through 15*pitch+31, "
            "past the end of all three input planes for every pitch >= 32. "
            "The separately allocated output is height-aligned to 32 rows, "
            "so the source read is the vulnerable side. Offsets are "
            "normalized to the minimum 32-byte pitch; larger CUDA texture "
            "alignment preserves and increases the over-read."
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
