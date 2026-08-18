"""Build and record the x86 GBRP conversion's untouched visible-row tail."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.yuv2rgb-gbrp-tail-disclosure-reproducer.v1"
REPAIR_COMMIT = "e1be70dcac1f84e425f00c32d012e8e10b20c082"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_yuv2rgb_gbrp_tail_disclosure_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
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
        f'-DYUV2RGB_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-fdata-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
        "libswscale/libswscale.a",
        "libavutil/libavutil.a",
    ]
    command.append(
        "-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections"
    )
    command.extend(["-lm", "-pthread"])
    return command


def _result_payload(
    result: subprocess.CompletedProcess[str],
) -> dict[str, object]:
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libswscale/x86/yuv2rgb.c"
    swscale_header = checkout / "libswscale/swscale.h"
    required = (
        harness,
        source,
        swscale_header,
        checkout / "libswscale/libswscale.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError(
            "harness, exact swscale sources, and configured archives must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-yuv2rgb.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libswscale/x86/yuv2rgb.c"],
        cwd=checkout,
    )
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(harness, source, binary)
    repaired_compile_command = _compile_command(
        harness, repaired_source, repaired_binary
    )
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = (
        _run(repaired_compile_command, cwd=checkout)
        if repaired_source.is_file()
        else _failed(repaired_compile_command, "repair source extraction failed")
    )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    environment["UBSAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    )
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    repaired_run_result = (
        _run([str(repaired_binary)], cwd=checkout, env=environment)
        if repaired_compile_result.returncode == 0
        else _failed([str(repaired_binary)], "repaired compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    swscale_text = swscale_header.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libswscale/x86/yuv2rgb.c",
        ],
        cwd=checkout,
    )
    source_indicators = {
        "public_scaler_accepts_caller_destination_planes": (
            "int sws_scale(" in swscale_text
            and "uint8_t *const dst[]" in swscale_text
            and "const int dstStride[]" in swscale_text
        ),
        "gbrp_wrapper_uses_packed_depth_boundary_test": (
            "static inline int yuv420_gbrp_ssse3" in source_text
            and "if (h_size * 3 > FFABS(dstStride[0]))" in source_text
        ),
        "gbrp_wrapper_dispatches_all_three_visible_planes": (
            "ff_yuv_420_gbrp24_ssse3(index, dst_g, dst_b, dst_r" in source_text
        ),
        "x86_dispatch_selects_wrapper_for_gbrp": (
            "case AV_PIX_FMT_GBRP:" in source_text
            and "return yuv420_gbrp_ssse3;" in source_text
        ),
        "exact_repair_uses_planar_stride_boundary": (
            repair_diff.returncode == 0
            and "fix planar GBRP boundary check" in repair_diff.stdout
            and "-    if (h_size * 3 > FFABS(dstStride[0]))"
            in repair_diff.stdout
            and "+    if (h_size > FFABS(dstStride[0]))" in repair_diff.stdout
            and "rightmost 8 pixels" in repair_diff.stdout
            and "completely uninitialized" in repair_diff.stdout
        ),
    }
    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "vulnerable_wrapper_converts_only_half_the_row": (
            "width=16 height=1 stride=16 assembly_pixels=8" in combined
        ),
        "all_three_visible_tails_retain_prior_bytes": (
            "visible_marker_bytes=24 result=1" in combined
        ),
        "vulnerable_replay_is_sanitizer_clean": (
            run_result.returncode == 0
            and "Sanitizer" not in combined
            and "runtime error:" not in combined
        ),
        "exact_repair_initializes_complete_visible_row": (
            repaired_run_result.returncode == 0
            and "width=16 height=1 stride=16 assembly_pixels=16 "
            "visible_marker_bytes=0 result=1"
            in repaired_combined
            and "Sanitizer" not in repaired_combined
            and "runtime error:" not in repaired_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and repaired_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "repair_commit": REPAIR_COMMIT,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "commands": {
            "compile": compile_command,
            "repaired_compile": repaired_compile_command,
        },
        "results": {
            "compile": _result_payload(compile_result),
            "repaired_compile": _result_payload(repaired_compile_result),
            "run": _result_payload(run_result),
            "repaired_run": _result_payload(repaired_run_result),
        },
    }
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
