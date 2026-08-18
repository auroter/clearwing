"""Build and record ColorChannelMixer's overflowing slice-boundary proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.colorchannelmixer-slice-overflow-reproducer.v1"
REPAIR_COMMIT = "f7368f97b92a0afe8dc8368a4b6749704b740317"
HEIGHT = 2_080_410
JOBNR = 2_064
NB_JOBS = 2_065


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_colorchannelmixer_slice_overflow_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(
    *,
    harness: Path,
    source: Path,
    filters_header: Path,
    binary: Path,
    sanitizers: str,
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
        f'-DCOLORCHANNELMIXER_SOURCE="{source}"',
        f'-DFILTERS_HEADER="{filters_header}"',
        f"-fsanitize={sanitizers}",
    ]
    if "undefined" in sanitizers:
        command.append("-fno-sanitize-recover=undefined")
    command.extend(
        [
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,-dead_strip",
            "-g",
            "-O1",
            "-std=c17",
            "-o",
            str(binary),
            str(harness),
            "-lm",
        ]
    )
    return command


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/vf_colorchannelmixer.c"
    template = checkout / "libavfilter/colorchannelmixer_template.c"
    filters_header = checkout / "libavfilter/filters.h"
    graph_source = checkout / "libavfilter/avfiltergraph.c"
    image_source = checkout / "libavutil/imgutils.c"
    required = (
        harness,
        source,
        template,
        filters_header,
        graph_source,
        image_source,
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness and pinned ColorChannelMixer/thread/geometry sources must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    asan_binary = binary.with_name(binary.name + "-asan")
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-vf_colorchannelmixer.c")
    repaired_template = binary.with_name(binary.name + "-repaired-colorchannelmixer_template.c")
    repaired_filters = binary.with_name(binary.name + "-repaired-filters.h")

    repair_source_result = _run(
        [
            "git",
            "show",
            f"{REPAIR_COMMIT}:libavfilter/vf_colorchannelmixer.c",
        ],
        cwd=checkout,
    )
    repair_template_result = _run(
        [
            "git",
            "show",
            f"{REPAIR_COMMIT}:libavfilter/colorchannelmixer_template.c",
        ],
        cwd=checkout,
    )
    if repair_template_result.returncode == 0:
        repaired_template.write_text(repair_template_result.stdout, encoding="utf-8")
    if repair_source_result.returncode == 0 and repaired_template.is_file():
        repaired_source.write_text(
            repair_source_result.stdout.replace(
                '#include "colorchannelmixer_template.c"',
                f'#include "{repaired_template}"',
            ),
            encoding="utf-8",
        )
    repair_filters_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/filters.h"], cwd=checkout
    )
    if repair_filters_result.returncode == 0:
        repaired_filters.write_text(repair_filters_result.stdout, encoding="utf-8")

    compile_command = _compile_command(
        harness=harness,
        source=source,
        filters_header=filters_header,
        binary=binary,
        sanitizers="address,undefined",
    )
    asan_compile_command = _compile_command(
        harness=harness,
        source=source,
        filters_header=filters_header,
        binary=asan_binary,
        sanitizers="address",
    )
    repaired_compile_command = _compile_command(
        harness=harness,
        source=repaired_source,
        filters_header=repaired_filters,
        binary=repaired_binary,
        sanitizers="address,undefined",
    )
    compile_result = _run(compile_command, cwd=checkout)
    asan_compile_result = _run(asan_compile_command, cwd=checkout)
    if repaired_source.is_file() and repaired_template.is_file() and repaired_filters.is_file():
        repaired_compile_result = _run(repaired_compile_command, cwd=checkout)
    else:
        repaired_compile_result = _failed(
            repaired_compile_command, "repair source extraction failed"
        )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
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
    template_text = template.read_text(encoding="utf-8", errors="replace")
    repaired_filters_text = repaired_filters.read_text(encoding="utf-8", errors="replace")
    graph_text = graph_source.read_text(encoding="utf-8", errors="replace")
    image_text = image_source.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        [
            "git",
            "show",
            "--format=",
            REPAIR_COMMIT,
            "--",
            "libavfilter/colorchannelmixer_template.c",
        ],
        cwd=checkout,
    )
    repair_message = _run(["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout)
    geometry_product = (3 + 128 * 8) * (HEIGHT + 128)
    vulnerable_start = "const int slice_start = (out->height * jobnr) / nb_jobs;"
    vulnerable_end = "const int slice_end = (out->height * (jobnr+1)) / nb_jobs;"
    source_indicators = {
        "graph_threads_accept_int_max": (
            '"Maximum number of threads"' in graph_text and "0, INT_MAX" in graph_text
        ),
        "selected_geometry_passes_generic_bound": (
            "stride*(h + 128ULL) >= INT_MAX" in image_text and geometry_product < 2_147_483_647
        ),
        "generated_callbacks_use_unchecked_int_products": (
            template_text.count(vulnerable_start) == 2 and template_text.count(vulnerable_end) == 2
        ),
        "framework_can_supply_selected_job_count": (
            "FFMIN(outlink->h, ff_filter_get_nb_threads(ctx))" in source_text
        ),
        "slice_helper_uses_int64_product": (
            "return (int)((int64_t)total * jobnr / nb_jobs);" in repaired_filters_text
        ),
        "exact_repair_uses_slice_helper": (
            repair_diff.returncode == 0
            and "ff_slice_pos(out->height, jobnr, nb_jobs)" in repair_diff.stdout
            and "ff_slice_pos(out->height, jobnr + 1, nb_jobs)" in repair_diff.stdout
            and "per-slice boundary computation" in repair_message.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    asan_combined = asan_run_result.stdout + asan_run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "proof_inputs_match_public_domains": (
            "height=2080410 width=1 jobnr=2064 nb_jobs=2065" in combined
            and "start_product=4293966240" in combined
            and "end_product=4296046650" in combined
        ),
        "ubsan_reports_slice_product_overflow": (
            "signed integer overflow: 2080410 * 2064" in combined
            and "colorchannelmixer_template.c:175" in combined
            and "ffmpeg_colorchannelmixer_slice_overflow_reproducer.c:60" in combined
        ),
        "ubsan_process_aborted": run_result.returncode != 0,
        "asan_reports_pre_frame_read": (
            "AddressSanitizer: heap-buffer-overflow" in asan_combined
            and "READ of size 1" in asan_combined
            and "1452 bytes before 6241230-byte region" in asan_combined
            and "ffmpeg_colorchannelmixer_slice_overflow_reproducer.c:60" in asan_combined
        ),
        "asan_process_aborted": asan_run_result.returncode != 0,
        "repaired_last_slice_is_processed": (
            repaired_run_result.returncode == 0
            and "last_pixel=127" in repaired_combined
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
        "repair_commit": REPAIR_COMMIT,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": _sha256(source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "asan_binary": str(asan_binary),
        "asan_binary_sha256": (_sha256(asan_binary) if asan_binary.is_file() else None),
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_compile_command": asan_compile_command,
        "asan_compile_returncode": asan_compile_result.returncode,
        "asan_compile_stdout": asan_compile_result.stdout,
        "asan_compile_stderr": asan_compile_result.stderr,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile_result.returncode,
        "repaired_compile_stdout": repaired_compile_result.stdout,
        "repaired_compile_stderr": repaired_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "ColorChannelMixer's planar and packed callbacks compute slice "
            "boundaries with signed-int height*job products. A valid "
            "1x2,080,410 RGB24 frame and 2,065 explicitly configured threads "
            "supply job 2,064. UBSan aborts on the exact production expression; "
            "without integer instrumentation, ASan observes a read 1,452 bytes "
            "before the packed frame. Exact repair f7368f97b9 delegates all four "
            "callback products to the int64-based ff_slice_pos helper, and the "
            "same final slice completes cleanly. Automatic graph threading is "
            "capped at 16, making this an explicit-high-thread configuration issue."
        ),
        "vulnerable_ubsan_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "vulnerable_asan_run": {
            "command": [str(asan_binary)],
            "returncode": asan_run_result.returncode,
            "stdout": asan_run_result.stdout,
            "stderr": asan_run_result.stderr,
        },
        "repaired_run": {
            "command": [str(repaired_binary)],
            "returncode": repaired_run_result.returncode,
            "stdout": repaired_run_result.stdout,
            "stderr": repaired_run_result.stderr,
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
