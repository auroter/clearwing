"""Build and record the segment-filter maximum-timestamp reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.segment-max-pts-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_segment_max_pts_reproducer.c"),
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
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "-Llibavfilter",
        "-Llibavformat",
        "-Llibavcodec",
        "-Llibswscale",
        "-Llibswresample",
        "-Llibavutil",
        "-lavfilter",
        "-lavformat",
        "-lavcodec",
        "-lswscale",
        "-lswresample",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "Foundation",
                "-framework",
                "AudioToolbox",
                "-framework",
                "CoreAudio",
                "-framework",
                "AVFoundation",
                "-framework",
                "CoreGraphics",
                "-framework",
                "OpenGL",
                "-framework",
                "Metal",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreImage",
                "-framework",
                "AppKit",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
                "-framework",
                "Security",
                "-liconv",
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
        "filter": checkout / "libavfilter/f_segment.c",
        "avutil": checkout / "libavutil/avutil.h",
        "components": checkout / "config_components.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavfilter/libavfilter.a").is_file()
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

    filter_source = sources["filter"].read_text(encoding="utf-8", errors="replace")
    avutil_header = sources["avutil"].read_text(encoding="utf-8", errors="replace")
    components = sources["components"].read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "appends_maximum_timestamp_sentinel": (
            "s->points[s->nb_points - 1] = INT64_MAX;" in filter_source
        ),
        "while_rechecks_without_bound": (
            "while (current_segment_finished(ctx, frame))" in filter_source
            and "s->current_point++;" in filter_source
        ),
        "post_loop_bound_is_too_late": ("if (s->current_point >= s->nb_points)" in filter_source),
        "condition_indexes_current_point": (
            "frame->pts >= s->points[s->current_point]" in filter_source
        ),
        "only_minimum_timestamp_is_reserved_for_no_pts": (
            "AV_NOPTS_VALUE" in avutil_header and "UINT64_C(0x8000000000000000)" in avutil_header
        ),
        "pinned_filter_omitted_but_source_compiled_into_harness": (
            "#define CONFIG_SEGMENT_FILTER 0" in components
            and '#include "libavfilter/f_segment.c"' in harness_source
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_graph_reached": (
            "filter=segment split_timestamp=0 "
            "sentinel=9223372036854775807 "
            "frame_pts=9223372036854775807 points=2" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "eight_byte_overread": "READ of size 8" in combined,
        "segment_activate_in_trace": "activate f_segment.c:228" in combined,
        "read_starts_at_allocation_end": ("0 bytes after 16-byte region" in combined),
        "public_buffersink_in_trace": (
            "av_buffersink_get_frame" in combined or "get_frame_internal buffersink.c" in combined
        ),
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
            "split_timestamp": 0,
            "frame_pts": 9223372036854775807,
            "sentinel": 9223372036854775807,
            "point_count": 2,
            "point_allocation_bytes": 16,
            "out_of_bounds_index": 2,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The segment filter appends INT64_MAX as its final output sentinel. "
            "INT64_MAX is a valid AVFrame timestamp because only INT64_MIN is "
            "reserved as AV_NOPTS_VALUE. A public buffer-to-segment graph with "
            "one split point advances across both the configured point and the "
            "sentinel, then the while condition re-evaluates before the later "
            "bound check. ASan observes the resulting points[2] read exactly "
            "after the 16-byte point allocation."
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
