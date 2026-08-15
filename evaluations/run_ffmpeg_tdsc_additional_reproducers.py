"""Build and record five additional TD-SC memory-safety reproducers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.tdsc-additional-reproducers.v1"
SCENARIOS = ("jpeg", "cursor", "resize", "truncated", "position")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_tdsc_additional_reproducers.c"),
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
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-ffunction-sections",
        "-fdata-sections",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibswscale",
        "-Llibavutil",
        "-lavcodec",
        "-lswresample",
        "-lswscale",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-Wl,-dead_strip",
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
    sources = {
        "decoder": checkout / "libavcodec/tdsc.c",
        "components": checkout / "config_components.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
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
    run_results: dict[str, subprocess.CompletedProcess[str]] = {}
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0:"
            "malloc_fill_byte=165:max_malloc_fill_size=1048576"
        )
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        for scenario in SCENARIOS:
            run_results[scenario] = subprocess.run(
                [str(binary), scenario],
                cwd=checkout,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
    else:
        for scenario in SCENARIOS:
            run_results[scenario] = subprocess.CompletedProcess(
                [str(binary), scenario], 127, "", "compile failed"
            )

    decoder = sources["decoder"].read_text(encoding="utf-8", errors="replace")
    components = sources["components"].read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "jpeg_dimensions_not_checked": (
            "ctx->jpgframe->format != AV_PIX_FMT_YUVJ420P" in decoder
            and "w > ctx->jpgframe->width" not in decoder
        ),
        "mono_cursor_has_double_stride_adjustment": (
            decoder.count("dst += ctx->cursor_stride - ctx->cursor_w * 4;") == 4
        ),
        "tile_header_not_in_size_check": (
            "bytestream2_get_bytes_left(&ctx->gbc) < tile_size" in decoder
            and "tile_size + 24LL" not in decoder
        ),
        "resize_reuses_frame_without_unref": (
            "ctx->refframe->width  = ctx->width  = w;" in decoder
            and "av_frame_unref(ctx->refframe);" not in decoder
        ),
        "cursor_position_uses_signed_clip_arithmetic": (
            "int x = ctx->cursor_x - ctx->cursor_hot_x;" in decoder
            and "(unsigned)ctx->cursor_x >= ctx->width" not in decoder
        ),
        "pinned_decoder_omitted_but_source_compiled_into_harness": (
            "#define CONFIG_TDSC_DECODER 0" in components
            and '#include "libavcodec/tdsc.c"' in harness_source
        ),
    }
    combined = {scenario: result.stdout + result.stderr for scenario, result in run_results.items()}
    runtime_indicators = {
        "jpeg_dimension_mismatch_heap_overread": all(
            term in combined["jpeg"]
            for term in (
                "tdsc_scenario=jpeg_dimension_mismatch",
                "AddressSanitizer: heap-buffer-overflow",
                "READ of size 1",
                "0 bytes after 1-byte region",
            )
        )
        and run_results["jpeg"].returncode != 0,
        "mono_cursor_heap_overwrite": all(
            term in combined["cursor"]
            for term in (
                "tdsc_scenario=mono_cursor_stride",
                "AddressSanitizer: heap-buffer-overflow",
                "WRITE of size 1",
                "tdsc_load_cursor",
                "0 bytes after 256-byte region",
            )
        )
        and run_results["cursor"].returncode != 0,
        "resize_stale_stride_heap_overwrite": all(
            term in combined["resize"]
            for term in (
                "tdsc_scenario=resize_stale_stride",
                "AddressSanitizer: heap-buffer-overflow",
                "WRITE of size 1",
                "0 bytes after 3328-byte region",
            )
        )
        and run_results["resize"].returncode != 0,
        "truncated_tile_discloses_allocator_fill": (
            "tdsc_scenario=truncated_tile_disclosure tile_size=24 "
            "header_bytes_after_size=24 payload_bytes=0 "
            "allocator_fill_observed=1 disclosed_bytes=24"
            in combined["truncated"]
            and "Sanitizer" not in combined["truncated"]
            and run_results["truncated"].returncode == 0
        ),
        "cursor_position_signed_overflow": all(
            term in combined["position"]
            for term in (
                "tdsc_scenario=cursor_position_overflow",
                "runtime error: signed integer overflow",
                "2147483647 + 1",
                "tdsc_paint_cursor",
            )
        )
        and run_results["position"].returncode != 0,
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
        "run_commands": {scenario: [str(binary), scenario] for scenario in SCENARIOS},
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncodes": {scenario: result.returncode for scenario, result in run_results.items()},
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Five direct production-function scenarios cover independent "
            "TD-SC roots beyond the raw WAR-tile size mismatch: a JPEG tile "
            "dimension overread, a monochrome cursor double-stride overwrite, "
            "a stale-linesize overwrite after frame resize, disclosure of 24 "
            "uninitialized tile bytes when the header consumes the nominal "
            "payload, and signed cursor-position overflow before clipping."
        ),
        "runs": {
            scenario: {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            for scenario, result in run_results.items()
        },
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
