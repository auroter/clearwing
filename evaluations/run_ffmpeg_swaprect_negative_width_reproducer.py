"""Record the vf_swaprect negative-width copy-size failure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.swaprect-negative-width-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
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
    ffmpeg = args.ffmpeg.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/vf_swaprect.c"
    if not ffmpeg.is_file() or not source.is_file():
        raise ValueError("ASan FFmpeg executable and vf_swaprect.c must exist")

    filtergraph = "nullsrc=s=17x16:r=1,format=nv12," "swaprect=w=-1:h=16:x1=0:y1=0:x2=0:y2=0"
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
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    result = subprocess.run(
        command,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    width_eval = source_text.split("ret = av_expr_parse_and_eval(&dw, s->w,", 1)[1].split(
        "ret = av_expr_parse_and_eval(&dh, s->h,", 1
    )[0]
    geometry_block = source_text.split("w = dw; h = dh; x1[0] = dx1;", 1)[1].split(
        "return ff_filter_frame(outlink, in);", 1
    )[0]
    source_indicators = {
        "width_is_runtime_string_expression": all(
            term in source_text
            for term in (
                "OFFSET(w),  AV_OPT_TYPE_STRING",
                "AV_OPT_FLAG_RUNTIME_PARAM",
            )
        ),
        "width_expression_has_no_positive_range_check": (
            "ret = av_expr_parse_and_eval(&dw, s->w," in source_text
            and "if (dw" not in width_eval
            and "av_clip(dw" not in width_eval
        ),
        "minimum_only_caps_width_above": (
            "w = FFMIN3(w, inlink->w - x1[0], inlink->w - x2[0]);" in geometry_block
            and "FFMAX"
            not in geometry_block.split("w = FFMIN3(w, inlink->w - x1[0], inlink->w - x2[0]);", 1)[
                0
            ]
        ),
        "negative_width_reaches_copy_size": (
            "memcpy(s->temp, src, pw[p] * s->pixsteps[p]);" in geometry_block
        ),
    }
    combined = result.stdout + result.stderr
    runtime_indicators = {
        "asan_negative_size": "AddressSanitizer: negative-size-param" in combined,
        "exact_negative_one_size": "negative-size-param: (size=-1)" in combined,
        "filter_graph_path_in_trace": (
            "filter_frame" in combined
            or ("avfilter_license" in combined and "ff_filter_activate" in combined)
        ),
        "process_aborted": result.returncode != 0,
    }
    expected_observed = all(source_indicators.values()) and all(runtime_indicators.values())
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
        "ffmpeg": str(ffmpeg),
        "ffmpeg_sha256": _sha256(ffmpeg),
        "source": str(source),
        "source_sha256": _sha256(source),
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": result.returncode,
        "geometry": {
            "pixel_format": "nv12",
            "frame_width": 17,
            "frame_height": 16,
            "configured_rectangle_width": -1,
            "configured_rectangle_height": 16,
            "luma_pixel_step": 1,
            "first_copy_size": -1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "vf_swaprect accepts its rectangle width as a runtime expression, converts "
            "the result to int, and caps it only with FFMIN. A width of -1 therefore "
            "survives into the per-plane byte count. The public CLI graph passes -1 "
            "to memcpy as size_t, and ASan aborts with negative-size-param before the "
            "enormous copy can corrupt memory."
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
