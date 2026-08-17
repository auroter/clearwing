"""Build, run, and record deblock's tight-stride ASan reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.deblock-tight-stride-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_deblock_tight_stride_reproducer.c"),
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
    source = checkout / "libavfilter/vf_deblock.c"
    required = (harness, source, checkout / "libavfilter/libavfilter.a")
    if _head(checkout) != VULNERABLE_COMMIT or not all(path.is_file() for path in required):
        raise ValueError(f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}")
    source_text = source.read_text(encoding="utf-8", errors="replace")
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
        "writable_frames_are_modified_in_place": ("if (av_frame_is_writable(in))" in source_text),
        "vertical_boundaries_include_partial_tail": (
            "for (x = block; x < width; x += block)" in source_text
        ),
        "strong_kernel_reads_two_pixels_right": "F = dst[+2];" in source_text,
        "strong_kernel_writes_two_pixels_right": ("dst[+2] = av_clip(f, 0, max);" in source_text),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "tight_tail_boundary": (
            "input_width=9 input_height=8 linesize=9 buffer_size=72 "
            "block=8 final_boundary_x=8 strong_right_radius=2" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "one_byte_read": "READ of size 1" in combined,
        "read_after_tight_buffer": "0 bytes after 72-byte region" in combined,
        "deblock_kernel_in_trace": "deblockv8_strong" in combined,
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
        "source": str(source),
        "source_sha256": _sha256(source),
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
            "A valid refcounted 9x8 gray frame with a tight 9-byte stride is "
            "moved into the public buffer->deblock->buffersink graph. The "
            "writable frame is filtered in place. At x=8 the strong vertical "
            "kernel reads and conditionally writes two pixels to the right, "
            "crossing the 72-byte allocation on the last processed row."
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
