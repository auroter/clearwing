"""Build and record ASoftClip's overflowing oversample-count proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.asoftclip-oversample-overflow-reproducer.v1"
SOURCE_PATH = "libavfilter/af_asoftclip.c"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_asoftclip_oversample_overflow_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _compile_command(
    *, harness: Path, source: Path, binary: Path, sanitizers: str
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
        f'-DASOFTCLIP_SOURCE="{source}"',
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
    command.append(
        "-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections"
    )
    command.append("-pthread")
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
    source = checkout / SOURCE_PATH
    required = (
        harness,
        source,
        checkout / "libavfilter/libavfilter.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact filter source, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    asan_binary = binary.with_name(binary.name + "-asan")
    compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=binary,
        sanitizers="address,undefined",
    )
    asan_compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=asan_binary,
        sanitizers="address",
    )
    compile_result = _run(compile_command, cwd=checkout)
    asan_compile_result = _run(asan_compile_command, cwd=checkout)

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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    master_head_result = _run(["git", "rev-parse", "origin/master"], cwd=checkout)
    master_source_result = _run(
        ["git", "show", f"origin/master:{SOURCE_PATH}"], cwd=checkout
    )
    post_pin_log_result = _run(
        [
            "git",
            "log",
            "--format=%H %cs %s",
            f"{head_result.stdout.strip()}..origin/master",
            "--",
            SOURCE_PATH,
        ],
        cwd=checkout,
    )
    master_source_text = master_source_result.stdout
    allocation_expression = (
        "ff_get_audio_buffer(outlink, in->nb_samples * s->oversample)"
    )
    worker_product = "const int nb_osamples = nb_samples * oversample;"
    indexed_write = "dst[oversample * n] = src[n];"
    source_indicators = {
        "public_option_allows_oversample_64": (
            '"oversample", "set oversample factor"' in source_text
            and "1, MAX_OVERSAMPLE" in source_text
            and "#define MAX_OVERSAMPLE 64" in source_text
        ),
        "production_allocation_uses_unchecked_signed_product": (
            allocation_expression in source_text
        ),
        "worker_recomputes_unchecked_signed_product": worker_product in source_text,
        "worker_indexes_output_by_oversample_product": indexed_write in source_text,
        "current_master_retains_all_three_sink_expressions": (
            master_source_result.returncode == 0
            and allocation_expression in master_source_text
            and worker_product in master_source_text
            and indexed_write in master_source_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    asan_combined = asan_run_result.stdout + asan_run_result.stderr
    runtime_indicators = {
        "proof_inputs_cross_signed_boundary_by_64_samples": (
            "nb_samples=67108865 oversample=64 product=4294967360 "
            "wrapped_output_samples=64" in combined
        ),
        "public_input_buffer_size_is_accepted": (
            "input_bytes=268435460" in combined
            and "input_buffer_check=268435460" in combined
        ),
        "wrapped_output_allocation_is_256_bytes": (
            "output_bytes=256" in asan_combined
            and "output_buffer_check=256" in asan_combined
        ),
        "production_filter_frame_path_is_called": (
            "calling_production_filter_frame=1" in combined
            and "calling_production_filter_frame=1" in asan_combined
        ),
        "ubsan_reports_production_allocation_product_overflow": (
            "signed integer overflow: 67108865 * 64" in combined
            and f"{SOURCE_PATH}:434" in combined
            and "filter_frame" in combined
        ),
        "ubsan_process_aborted": run_result.returncode != 0,
        "asan_reports_four_byte_heap_write_at_allocation_end": (
            "AddressSanitizer: heap-buffer-overflow" in asan_combined
            and "WRITE of size 4" in asan_combined
            and "0 bytes after 256-byte region" in asan_combined
        ),
        "asan_stack_crosses_all_production_filter_stages": all(
            name in asan_combined
            for name in ("filter_frame", "filter_channels", "filter_flt")
        ),
        "asan_allocation_uses_wrapped_sample_count": (
            "proof_ff_get_audio_buffer" in asan_combined
        ),
        "asan_process_aborted": asan_run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and asan_compile_result.returncode == 0
        and master_head_result.returncode == 0
        and post_pin_log_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "current_master_commit": master_head_result.stdout.strip() or None,
        "current_master_source_sha256": (
            _text_sha256(master_source_text)
            if master_source_result.returncode == 0
            else None
        ),
        "post_pin_source_log": post_pin_log_result.stdout.splitlines(),
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "commands": {
            "compile": compile_command,
            "asan_compile": asan_compile_command,
        },
        "results": {
            "compile": _result_payload(compile_result),
            "asan_compile": _result_payload(asan_compile_result),
            "run": _result_payload(run_result),
            "asan_run": _result_payload(asan_run_result),
            "master_source": _result_payload(master_source_result),
            "post_pin_log": _result_payload(post_pin_log_result),
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
