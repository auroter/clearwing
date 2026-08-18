"""Build and record Alphamerge's dynamic-frame size mismatch overread."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.alphamerge-dynamic-size-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_alphamerge_dynamic_size_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavfilter",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DALPHAMERGE_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "libavfilter/libavfilter.a",
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-Wl,-dead_strip",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "AudioToolbox",
                "-framework",
                "Security",
            ]
        )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/vf_alphamerge.c"
    buffersrc_source = checkout / "libavfilter/buffersrc.c"
    avfilter_source = checkout / "libavfilter/avfilter.c"
    assert_header = checkout / "libavutil/avassert.h"
    configuration = checkout / "config.h"
    archives = [
        checkout / "libavfilter/libavfilter.a",
        checkout / "libavutil/libavutil.a",
    ]
    if any(
        not path.is_file()
        for path in [
            harness,
            source,
            buffersrc_source,
            avfilter_source,
            assert_header,
            configuration,
            *archives,
        ]
    ):
        raise ValueError("harness, filter sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, source, binary)
    compile_result = _run(compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if compile_result.returncode == 0:
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")

    master_result = _run(["git", "show", "master:libavfilter/vf_alphamerge.c"], cwd=checkout)
    source_text = source.read_text(encoding="utf-8", errors="replace")
    buffersrc_text = buffersrc_source.read_text(encoding="utf-8", errors="replace")
    avfilter_text = avfilter_source.read_text(encoding="utf-8", errors="replace")
    assert_text = assert_header.read_text(encoding="utf-8", errors="replace")
    configuration_text = configuration.read_text(encoding="utf-8", errors="replace")
    master_text = master_result.stdout
    source_indicators = {
        "buffersrc_accepts_dynamic_video_sizes_with_warning": (
            "Changing video frame properties on the fly is not supported by all filters."
            in buffersrc_text
            and "CHECK_VIDEO_PARAM_CHANGE(ctx, s, frame->width, frame->height" in buffersrc_text
        ),
        "configured_geometry_assertions_are_disabled": (
            "av_assert1(frame->width         == link->w);" in avfilter_text
            and "#define av_assert1(cond) ((void)0)" in assert_text
            and "#define ASSERT_LEVEL" not in configuration_text
        ),
        "configuration_checks_only_negotiated_link_sizes": (
            "if (mainlink->w != alphalink->w || mainlink->h != alphalink->h)" in source_text
        ),
        "packed_copy_uses_current_main_geometry": (
            "for (y = 0; y < main_buf->height; y++)" in source_text
            and "for (x = 0; x < main_buf->width; x++)" in source_text
        ),
        "packed_copy_reads_alpha_without_current_size_check": (
            "pin = alpha_buf->data[0] + y * alpha_buf->linesize[0];" in source_text
            and "*pout = *pin;" in source_text
            and "main_buf->width != alpha_buf->width" not in source_text
        ),
        "current_master_remains_unchecked": (
            master_result.returncode == 0
            and "*pout = *pin;" in master_text
            and "main_buf->width != alpha_buf->width" not in master_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "negotiated_sizes_match_but_runtime_sizes_differ": (
            "configured_main=1x1 configured_alpha=1x1 "
            "runtime_main=8x8 runtime_alpha=1x1" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "one_byte_read_after_alpha_plane": (
            "READ of size 1" in combined and "0 bytes after 1-byte region" in combined
        ),
        "production_alphamerge_sink_in_trace": "in do_alphamerge" in combined,
        "vulnerable_process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "current_master_checked": master_result.returncode == 0,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": {
            "libavfilter/vf_alphamerge.c": _sha256(source),
            "libavfilter/buffersrc.c": _sha256(buffersrc_source),
            "libavfilter/avfilter.c": _sha256(avfilter_source),
            "libavutil/avassert.h": _sha256(assert_header),
            "config.h": _sha256(configuration),
        },
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Alphamerge validates only the two negotiated link sizes during "
            "configuration. Buffersrc explicitly permits dynamic video "
            "geometry with a warning. When a later packed-RGBA main frame is "
            "8x8 but its synchronized GRAY8 alpha frame remains 1x1, the "
            "production copy loops over the main frame's current geometry and "
            "reads the one-byte alpha plane as if it were 8x8. ASan reports "
            "the first one-byte read immediately after that allocation."
        ),
        "run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
