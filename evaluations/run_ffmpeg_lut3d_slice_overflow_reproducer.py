"""Build and record LUT3D's overflowing x86 row-slice proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.lut3d-slice-overflow-reproducer.v1"
REPAIR_COMMIT = "f7368f97b92a0afe8dc8368a4b6749704b740317"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_lut3d_slice_overflow_reproducer.c"
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


def _compile_command(
    *,
    harness: Path,
    source: Path,
    binary: Path,
    sanitizers: str,
    guarded_replay: bool,
) -> list[str]:
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
        f'-DLUT3D_SOURCE="{source}"',
        f"-fsanitize={sanitizers}",
    ]
    if guarded_replay:
        command.append("-DLUT3D_GUARDED_REPLAY=1")
    if "undefined" in sanitizers:
        command.append("-fno-sanitize-recover=undefined")
    command.extend(
        [
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-ffunction-sections",
            "-fdata-sections",
            "-g",
            "-O1",
            "-std=c17",
            "-o",
            str(binary),
            str(harness),
            "libavfilter/libavfilter.a",
            "libavutil/libavutil.a",
            "-lm",
        ]
    )
    command.append("-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _result_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
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
    source = checkout / "libavfilter/x86/vf_lut3d_init.c"
    filter_source = checkout / "libavfilter/vf_lut3d.c"
    graph_source = checkout / "libavfilter/avfiltergraph.c"
    image_source = checkout / "libavutil/imgutils.c"
    required = (
        harness,
        source,
        filter_source,
        graph_source,
        image_source,
        checkout / "libavfilter/libavfilter.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact filter sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    asan_binary = binary.with_name(binary.name + "-asan")
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-vf_lut3d_init.c")
    repaired_filters = binary.with_name(binary.name + "-repaired-filters.h")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/x86/vf_lut3d_init.c"],
        cwd=checkout,
    )
    repair_filters_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/filters.h"], cwd=checkout
    )
    if repair_filters_result.returncode == 0:
        repaired_filters.write_text(repair_filters_result.stdout, encoding="utf-8")
    if repair_source_result.returncode == 0 and repaired_filters.is_file():
        repaired_source.write_text(
            repair_source_result.stdout.replace(
                '#include "libavfilter/filters.h"',
                f'#include "{repaired_filters}"',
            ),
            encoding="utf-8",
        )

    compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=binary,
        sanitizers="address,undefined",
        guarded_replay=False,
    )
    asan_compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=asan_binary,
        sanitizers="address",
        guarded_replay=True,
    )
    repaired_compile_command = _compile_command(
        harness=harness,
        source=repaired_source,
        binary=repaired_binary,
        sanitizers="address,undefined",
        guarded_replay=True,
    )
    compile_result = _run(compile_command, cwd=checkout)
    asan_compile_result = _run(asan_compile_command, cwd=checkout)
    repaired_compile_result = (
        _run(repaired_compile_command, cwd=checkout)
        if repaired_source.is_file() and repaired_filters.is_file()
        else _failed(repaired_compile_command, "repair source extraction failed")
    )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    )
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    asan_run_result = (
        _run([str(asan_binary)], cwd=checkout, env=environment)
        if asan_compile_result.returncode == 0
        else _failed([str(asan_binary)], "ASan compile failed")
    )
    repaired_run_result = (
        _run([str(repaired_binary)], cwd=checkout, env=environment)
        if repaired_compile_result.returncode == 0
        else _failed([str(repaired_binary)], "repaired compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    filter_text = filter_source.read_text(encoding="utf-8", errors="replace")
    graph_text = graph_source.read_text(encoding="utf-8", errors="replace")
    image_text = image_source.read_text(encoding="utf-8", errors="replace")
    repaired_filters_text = repaired_filters.read_text(
        encoding="utf-8", errors="replace"
    )
    repair_diff = _run(
        [
            "git",
            "show",
            "--format=",
            REPAIR_COMMIT,
            "--",
            "libavfilter/x86/vf_lut3d_init.c",
        ],
        cwd=checkout,
    )
    source_indicators = {
        "public_thread_option_accepts_selected_job_count": (
            '"Maximum number of threads"' in graph_text and "0, INT_MAX" in graph_text
        ),
        "framework_dispatches_jobs_up_to_height_and_threads": (
            "FFMIN(outlink->h, ff_filter_get_nb_threads(ctx))" in filter_text
        ),
        "image_validator_accepts_tall_narrow_frames": (
            "stride*(h + 128ULL) >= INT_MAX" in image_text
        ),
        "x86_callback_uses_unchecked_signed_products": (
            "(in->height *  jobnr   ) / nb_jobs" in source_text
            and "(in->height * (jobnr+1)) / nb_jobs" in source_text
        ),
        "exact_repair_uses_int64_slice_helper": (
            "return (int)((int64_t)total * jobnr / nb_jobs);"
            in repaired_filters_text
            and "ff_slice_pos(in->height, jobnr, nb_jobs)" in repair_diff.stdout
            and "ff_slice_pos(in->height, jobnr + 1, nb_jobs)"
            in repair_diff.stdout
        ),
    }
    combined = run_result.stdout + run_result.stderr
    asan_combined = asan_run_result.stdout + asan_run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "proof_geometry_passes_image_validation": (
            "width=1 height=2080410 explicit_threads=2065 jobnr=2064 "
            "start_product=4293966240 end_product=4296046650 image_check=0"
            in combined
        ),
        "ubsan_reports_exact_start_product_overflow": (
            "signed integer overflow: 2080410 * 2064" in combined
            and "libavfilter/x86/vf_lut3d_init.c:53" in combined
        ),
        "ubsan_process_aborted": run_result.returncode != 0,
        "wrapped_slice_starts_before_frame": (
            "simd_slice_start=-484 simd_slice_end=522" in asan_combined
        ),
        "asan_reports_pre_frame_read": (
            "AddressSanitizer: use-after-poison" in asan_combined
            and "READ of size 2" in asan_combined
            and "consume_slice" in asan_combined
        ),
        "asan_process_aborted": asan_run_result.returncode != 0,
        "exact_repair_processes_last_slice_cleanly": (
            repaired_run_result.returncode == 0
            and "simd_slice_start=2079402 simd_slice_end=2080410"
            in repaired_combined
            and "filter_result=0" in repaired_combined
            and "Sanitizer" not in repaired_combined
            and "runtime error:" not in repaired_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and asan_compile_result.returncode == 0
        and repaired_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
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
            "asan_compile": asan_compile_command,
            "repaired_compile": repaired_compile_command,
        },
        "results": {
            "compile": _result_payload(compile_result),
            "asan_compile": _result_payload(asan_compile_result),
            "repaired_compile": _result_payload(repaired_compile_result),
            "run": _result_payload(run_result),
            "asan_run": _result_payload(asan_run_result),
            "repaired_run": _result_payload(repaired_run_result),
        },
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
