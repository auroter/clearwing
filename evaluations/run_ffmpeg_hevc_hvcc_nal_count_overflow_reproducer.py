"""Build and record the hvcC repeated-array NAL-count overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.hevc-hvcc-nal-count-overflow-reproducer.v1"
REPAIR_COMMIT = "c7132ef8f63c383d11a00a9e3034748d8dd15fb3"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_hevc_hvcc_nal_count_overflow_reproducer.c"),
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
        "-I./libavformat",
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DHEVC_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "libavcodec/golomb.c",
        "-Llibavformat",
        "-Llibavcodec",
        "-Llibavutil",
        "-lavformat",
        "-lavcodec",
        "-lavutil",
        "-lm",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-Wl,-dead_strip",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "AudioToolbox",
                "-framework",
                "Security",
                "-liconv",
            ]
        )
    else:
        command.append("-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _make_repaired_source(source: Path, destination: Path) -> Path:
    source_text = source.read_text(encoding="utf-8")
    old = """    uint16_t numNalus = array->numNalus;

    ret = av_reallocp_array(&array->nal, numNalus + 1, sizeof(*array->nal));
"""
    new = """    uint16_t numNalus = array->numNalus;

    if (numNalus >= UINT16_MAX)
        return AVERROR_INVALIDDATA;

    ret = av_reallocp_array(&array->nal, numNalus + 1, sizeof(*array->nal));
"""
    if source_text.count(old) != 1:
        raise ValueError("pinned hevc.c does not match the exact repair context")
    destination.write_text(source_text.replace(old, new), encoding="utf-8")
    return destination


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/hevc.c"
    required = (
        harness,
        source,
        checkout / "libavcodec/golomb.c",
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, pinned HEVC source, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = _make_repaired_source(
        source, binary.with_name(binary.name + "-repaired-hevc.c")
    )

    compile_command = _compile_command(harness, source, binary)
    repaired_compile_command = _compile_command(harness, repaired_source, repaired_binary)
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = _run(repaired_compile_command, cwd=checkout)

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
    repair_result = _run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/hevc.c",
        ],
        cwd=checkout,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "repeated_hvcc_arrays_accumulate_by_nal_type": all(
            term in source_text
            for term in (
                "for (int i = 0; i < num_arrays; i++)",
                "for (int j = 0; j < num_nalus; j++)",
                "hvcc_parse_nal_unit(data + get_bits_count(&gbc) / 8",
            )
        ),
        "array_count_is_uint16_and_incremented_unchecked": all(
            term in source_text
            for term in (
                "uint16_t numNalus;",
                "uint16_t numNalus = array->numNalus;",
                "array->numNalus++;",
            )
        ),
        "wrapped_count_indexes_preceding_element": (
            "nal = &array->nal[array->numNalus-1];" in source_text
        ),
        "exact_repair_rejects_before_wrap": (
            repair_result.returncode == 0
            and "reject hvcC NAL arrays that overflow the 16-bit count" in repair_text
            and "if (numNalus >= UINT16_MAX)" in repair_text
            and "Fixes: out of array access" in repair_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "two_arrays_declare_65536_nalus_of_one_type": (
            "hvcc_arrays=2 repeated_type=39 declared_nalus=65536" in combined
        ),
        "asan_reports_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "overflow_occurs_in_hvcc_add_path": (
            "hvcc_add_nal_unit" in combined or "write_configuration_record" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "exact_repair_rejects_cleanly": (
            repaired_run_result.returncode == 0
            and "rejected_invalid=1" in repaired_combined
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
        "repair_commit_output": repair_text,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": _sha256(source),
        "repaired_source_sha256": _sha256(repaired_source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
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
            "An hvcC record may repeat one NAL type across multiple arrays. "
            "The parser merges those units into one array whose count is uint16_t. "
            "At the 65,536th unit the count wraps to zero, and the next metadata "
            "assignment addresses array->nal[-1]. The proof uses the production "
            "hvcC parser with two same-type arrays and ASan observes the heap "
            "overflow. Exact repair c7132ef8 rejects before the count can wrap."
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
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
