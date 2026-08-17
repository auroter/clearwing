"""Build, run, and record the OpenColorIO output-format contract reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.opencolorio-format-mismatch-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_opencolorio_format_mismatch_reproducer.c"),
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


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
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "libavfilter/vf_geq.c",
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
    ocio_source = checkout / "libavfilter/vf_opencolorio.c"
    geq_source = checkout / "libavfilter/vf_geq.c"
    required = (
        harness,
        ocio_source,
        geq_source,
        checkout / "config.h",
        checkout / "libavfilter/libavfilter.a",
    )
    if _head(checkout) != VULNERABLE_COMMIT or not all(path.is_file() for path in required):
        raise ValueError(f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}")

    ocio_text = ocio_source.read_text(encoding="utf-8", errors="replace")
    geq_text = geq_source.read_text(encoding="utf-8", errors="replace")
    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
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

    source_indicators = {
        "common_input_output_format_set": (
            "return ff_set_common_formats(ctx, ff_make_format_list(pix_fmts));" in ocio_text
        ),
        "option_selects_independent_output_format": (
            "s->output_format = av_get_pix_fmt(s->out_format_string);" in ocio_text
        ),
        "frame_allocated_in_selected_format": (
            "output_frame->format = s->output_format;" in ocio_text
        ),
        "selected_frame_sent_on_negotiated_link": (
            "return ff_filter_frame(ctx->outputs[0], output_frame);" in ocio_text
        ),
        "geq_uses_negotiated_plane_count": (
            "for (plane = 0; plane < geq->planes && out->data[plane]; plane++)" in geq_text
        ),
        "geq_sum_dereferences_selected_plane": (
            "linesum += src32[xi + yi * linesize];" in geq_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "format_contract_mismatch": ("negotiated=gbrpf32le selected=rgb24" in combined),
        "asan_deadly_signal": "AddressSanitizer:DEADLYSIGNAL" in combined,
        "zero_page": "address points to the zero page" in combined,
        "read_fault": "caused by a READ memory access" in combined,
        "geq_in_trace": "geq_filter_frame" in combined,
        "filter_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "sources": {
            str(ocio_source): _sha256(ocio_source),
            str(geq_source): _sha256(geq_source),
        },
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A public GBRPF32 buffer -> ocio=format=rgb24 -> geq -> "
            "buffersink graph uses the pinned FFmpeg filter code. The local "
            "build lacks libOpenColorIO, so only the successful external "
            "transform call is stubbed; FFmpeg still negotiates GBRPF32, "
            "allocates RGB24, emits it on the GBRPF32 link, and GEQ "
            "zero-page faults while summing the missing float plane."
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
