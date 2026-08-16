"""Record the vf_swaprect odd-width NV12 temporary-row overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.swaprect-odd-nv12-reproducer.v1"
REPAIR_COMMIT = "a7e38b617b32f996beaa371bbf04b39907d7a527"


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

    filtergraph = "nullsrc=s=17x16:r=1,format=nv12," "swaprect=w=17:h=16:x1=0:y1=0:x2=0:y2=0"
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

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavfilter/vf_swaprect.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "temp_uses_luma_width_and_step": (
            "s->temp = av_malloc_array(inlink->w, s->pixsteps[0]);" in source_text
        ),
        "copy_uses_each_planes_width_and_step": (
            "memcpy(s->temp, src, pw[p] * s->pixsteps[p]);" in source_text
        ),
        "nv12_is_accepted_by_generic_format_query": all(
            term in source_text
            for term in (
                "ff_formats_pixdesc_filter(0, reject_flags)",
                "AV_PIX_FMT_FLAG_PAL",
                "AV_PIX_FMT_FLAG_HWACCEL",
                "AV_PIX_FMT_FLAG_BITSTREAM",
            )
        ),
        "later_repair_sizes_for_widest_plane": (
            repair_result.returncode == 0
            and "Fixes: out of array access" in repair_text
            and "size = FFMAX(size, width * s->pixsteps[p]);" in repair_text
            and "s->temp = av_malloc(size);" in repair_text
        ),
    }
    combined = result.stdout + result.stderr
    runtime_indicators = {
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in combined,
        "eighteen_byte_write": "WRITE of size 18" in combined,
        "write_starts_after_seventeen_byte_allocation": (
            "0 bytes after 17-byte region" in combined
        ),
        "filter_graph_path_in_trace": (
            ("filter_frame" in combined and "config_input" in combined)
            or ("avfilter_license" in combined and "ff_filter_activate" in combined)
        ),
        "process_aborted": result.returncode != 0,
    }
    geometry = {
        "pixel_format": "nv12",
        "frame_width": 17,
        "frame_height": 16,
        "luma_pixel_step": 1,
        "allocated_temp_bytes": 17,
        "chroma_width": (17 + 1) // 2,
        "chroma_pixel_step": 2,
        "chroma_copy_bytes": ((17 + 1) // 2) * 2,
        "overflow_bytes": 1,
    }
    expected_observed = (
        all(source_indicators.values())
        and all(runtime_indicators.values())
        and geometry["allocated_temp_bytes"] == 17
        and geometry["chroma_copy_bytes"] == 18
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
        "ffmpeg": str(ffmpeg),
        "ffmpeg_sha256": _sha256(ffmpeg),
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
            "vf_swaprect allocates its temporary row as input width times the "
            "first plane's pixel step. On an odd-width NV12 frame, the interleaved "
            "chroma plane is ceil(width / 2) samples at two bytes each, so a "
            "17-byte temporary buffer receives an 18-byte memcpy. The public CLI "
            "filter graph triggers the resulting one-byte heap overflow under ASan."
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
