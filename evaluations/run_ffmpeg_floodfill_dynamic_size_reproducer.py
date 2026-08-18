"""Build and record Floodfill's dynamic-frame point-stack overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.floodfill-dynamic-size-reproducer.v1"
REPAIR_COMMIT = "24c322fdb232d0a3f3790d544dcb64e5c2138e79"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_floodfill_dynamic_size_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
    return [
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
        f'-DFLOODFILL_SOURCE="{source}"',
        "-fsanitize=address,undefined",
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
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
        "-lz",
    ]


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/vf_floodfill.c"
    archive = checkout / "libavutil/libavutil.a"
    if any(not path.is_file() for path in (harness, source, archive)):
        raise ValueError("harness, pinned Floodfill source, and libavutil must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-vf_floodfill.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/vf_floodfill.c"],
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
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
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
    repair_diff = _run(
        ["git", "show", "--format=", REPAIR_COMMIT, "--", "libavfilter/vf_floodfill.c"],
        cwd=checkout,
    )
    repair_message = _run(
        ["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout
    )
    source_indicators = {
        "point_stack_sized_from_configured_link": (
            "s->points = av_calloc(inlink->w * inlink->h, 4 * sizeof(Points));"
            in source_text
        ),
        "fill_uses_current_frame_dimensions": (
            "const int w = frame->width;" in source_text
            and "const int h = frame->height;" in source_text
        ),
        "neighbor_pushes_lack_capacity_check": (
            source_text.count("s->points[s->front++].y") == 4
            and "points_size" not in source_text
        ),
        "exact_repair_resizes_for_current_frame": (
            repair_diff.returncode == 0
            and "av_size_mult(w, h, &nb_points)" in repair_diff.stdout
            and "av_fast_malloc(&s->points, &s->points_size, points_size)"
            in repair_diff.stdout
            and "s->front = s->back = 0;" in repair_diff.stdout
            and "w > UINT16_MAX + 1" in repair_diff.stdout
            and "size the point stack for the current frame" in repair_message.stdout
            and "Fixes: out of array access" in repair_message.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "configured_and_frame_sizes_differ": (
            "configured=1x1 configured_point_slots=4 frame=8x8 "
            "required_point_slots=256" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "two_byte_write_after_point_stack": (
            "WRITE of size 2" in combined
            and "0 bytes after 16-byte region" in combined
        ),
        "production_allocation_and_fill_in_trace": (
            "in config_input" in combined and "in filter_frame" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_current_frame_completes": (
            repaired_run_result.returncode == 0
            and "filter_result=0 final_pixel=1" in repaired_combined
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
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "repair_commit": REPAIR_COMMIT,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": _sha256(source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (
            _sha256(repaired_binary) if repaired_binary.is_file() else None
        ),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
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
            "Floodfill allocates its DFS point stack from dimensions negotiated "
            "during link configuration but traverses the dimensions of each current "
            "frame. A configured 1x1 link gives four point slots; an 8x8 dynamic "
            "frame pushes a fifth point and ASan reports a two-byte write immediately "
            "after the 16-byte allocation. The exact repair sizes the stack from the "
            "current frame, resets its indices, and completes the same fill cleanly."
        ),
        "vulnerable_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "repaired_run": {
            "command": [str(repaired_binary)],
            "returncode": repaired_run_result.returncode,
            "stdout": repaired_run_result.stdout,
            "stderr": repaired_run_result.stderr,
        },
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
