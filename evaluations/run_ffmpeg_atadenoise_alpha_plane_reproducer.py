"""Build and record atadenoise's missing alpha-plane queue state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.atadenoise-alpha-plane-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_atadenoise_alpha_plane_reproducer.c"),
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
        "-ffunction-sections",
        "-fdata-sections",
        "-o",
        str(binary),
        str(harness),
        "-Llibavfilter",
        "-Llibavutil",
        "-lavfilter",
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
    source_path = checkout / "libavfilter/vf_atadenoise.c"
    if not harness.is_file() or not source_path.is_file():
        raise ValueError("harness and atadenoise source must exist")

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
        environment["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=1"
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

    source = source_path.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "alpha_formats_are_supported": all(
            term in source for term in ("AV_PIX_FMT_YUVA444P", "AV_PIX_FMT_GBRAP")
        ),
        "four_plane_selection_is_public": ("OFFSET(planes)" in source and "0, 15" in source),
        "filter_iterates_all_components": (
            "s->nb_planes = desc->nb_components" in source and "p < s->nb_planes" in source
        ),
        "queue_population_omits_alpha": all(
            term in source
            for term in (
                "s->data[0][i] = frame->data[0]",
                "s->data[1][i] = frame->data[1]",
                "s->data[2][i] = frame->data[2]",
            )
        )
        and "s->data[3][i] = frame->data[3]" not in source,
        "selected_plane_dereferences_queue_entries": (
            "srcf[i] = data[i] + slice_start * linesize[i]" in source
            and "srcjx = srcf[j][x]" in source
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_alpha_selection_reached": (
            "filter=atadenoise format=yuva444p planes=8 nb_planes=4 "
            "queue_size=5 alpha_data_entries_initialized=0" in combined
        ),
        "null_plane_state_reported": "null pointer" in combined.lower(),
        "filter_slice_in_trace": "filter_slice" in combined,
        "production_filter_row_in_trace": "fweight_row8" in combined,
        "asan_zero_page_read": all(
            term in combined
            for term in (
                "AddressSanitizer: SEGV",
                "READ memory access",
                "address points to the zero page",
            )
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
        "source": str(source_path),
        "source_sha256": _sha256(source_path),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Atadenoise advertises four-plane alpha formats and accepts the "
            "public alpha-only planes mask, but its temporal queue population "
            "copies only planes zero through two. The production alpha filter "
            "row therefore dereferences a null queue entry. UBSan records the "
            "invalid pointer formation, execution continues into fweight_row8, "
            "and ASan aborts on its zero-page read."
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
