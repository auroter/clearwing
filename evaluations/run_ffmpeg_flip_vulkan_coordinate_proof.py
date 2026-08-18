"""Record flip_vulkan's missing-minus-one image coordinates."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.flip-vulkan-coordinate-proof.v1"


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
    source = checkout / "libavfilter/vf_flip_vulkan.c"
    if not source.is_file():
        raise ValueError("the pinned FFmpeg flip_vulkan source must exist")

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "dispatch_is_guarded_by_output_size": (
            "size = imageSize(output_image" in source_text
            and "if (IS_WITHIN(pos, size))" in source_text
        ),
        "horizontal_omits_last_coordinate_adjustment": (
            "ivec2(size.x - pos.x, pos.y)" in source_text
            and "ivec2(size.x - 1 - pos.x, pos.y)" not in source_text
        ),
        "vertical_omits_last_coordinate_adjustment": (
            "ivec2(pos.x, size.y - pos.y)" in source_text
            and "ivec2(pos.x, size.y - 1 - pos.y)" not in source_text
        ),
        "both_axes_omit_last_coordinate_adjustment": (
            "ivec2(size.xy - pos.xy)" in source_text
            and "ivec2(size.xy - ivec2(1) - pos.xy)" not in source_text
        ),
        "transformed_coordinate_reaches_image_load": (
            "imageLoad(input_image" in source_text
        ),
        "output_uses_negotiated_frame_dimensions": (
            "ff_get_video_buffer(outlink, outlink->w, outlink->h)"
            in source_text
        ),
    }

    width = 4
    height = 3
    invocations = [(x, y) for y in range(height) for x in range(width)]
    transforms = {
        "horizontal": lambda x, y: (width - x, y),
        "vertical": lambda x, y: (x, height - y),
        "both": lambda x, y: (width - x, height - y),
    }
    modes = {}
    for name, transform in transforms.items():
        coordinates = [
            {
                "invocation": [x, y],
                "image_coordinate": list(transform(x, y)),
            }
            for x, y in invocations
        ]
        out_of_bounds = [
            coordinate
            for coordinate in coordinates
            if coordinate["image_coordinate"][0] >= width
            or coordinate["image_coordinate"][1] >= height
        ]
        modes[name] = {
            "out_of_bounds_invocation_count": len(out_of_bounds),
            "first_out_of_bounds": out_of_bounds[0],
            "all_out_of_bounds": out_of_bounds,
        }

    expected_observed = (
        all(source_indicators.values())
        and modes["horizontal"]["out_of_bounds_invocation_count"] == height
        and modes["vertical"]["out_of_bounds_invocation_count"] == width
        and modes["both"]["out_of_bounds_invocation_count"]
        == width + height - 1
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
        "source_indicators": source_indicators,
        "example_geometry": {
            "width": width,
            "height": height,
            "valid_x": [0, width - 1],
            "valid_y": [0, height - 1],
            "modes": modes,
        },
        "expected_observed": expected_observed,
        "evidence_level": "source_and_geometry_confirmed",
        "scope": (
            "The public Vulkan flip filters dispatch every valid zero-based "
            "output coordinate, then calculate a mirrored source coordinate "
            "as dimension - position instead of dimension - 1 - position. "
            "Every horizontal frame therefore reads x=width along its first "
            "column, every vertical frame reads y=height along its first "
            "row, and flip_both does both. A Vulkan runtime was not available "
            "locally, so this artifact records the exact shader and exhaustive "
            "small-frame coordinate proof without claiming a dynamic fault."
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
