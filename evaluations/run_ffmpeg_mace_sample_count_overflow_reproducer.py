"""Build and record MACE's sample-count overflow and undersized output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.mace-sample-count-overflow-reproducer.v1"
REPAIR_COMMIT = "947c57d9e68800dd4d39f110140f8f6c34cedf80"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_mace_sample_count_overflow_reproducer.c"
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
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
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
    command.append("-pthread")
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/mace.c"
    components = checkout / "config_components.h"
    if (
        not harness.is_file()
        or not source.is_file()
        or not components.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
    ):
        raise ValueError(
            "harness, MACE source, configuration, and archives must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        environment["UBSAN_OPTIONS"] = (
            "halt_on_error=0:print_stacktrace=1"
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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    configured_components = components.read_text(
        encoding="utf-8", errors="replace"
    )
    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/mace.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "mace3_decoder_enabled": (
            "#define CONFIG_MACE3_DECODER 1" in configured_components
        ),
        "sample_count_uses_signed_int": (
            "frame->nb_samples = 3 * (buf_size << (1 - is_mace3)) / "
            "channels;" in source_text
        ),
        "decode_loop_uses_original_packet_size": (
            "j < buf_size / (channels << is_mace3)" in source_text
        ),
        "exact_repair_present": (
            repair_result.returncode == 0
            and "reject sample counts that overflow int" in repair_text
            and "Fixes: heap buffer overflow" in repair_text
            and "if (nb_samples > INT_MAX)" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_mace3_packet": (
            "codec=mace3 channels=1 packet_size=1431655766" in combined
        ),
        "valid_sparse_virtual_mapping": "virtual_mapping=valid" in combined,
        "signed_sample_count_overflow": (
            "runtime error: signed integer overflow" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "decoder_aborted": run_result.returncode != 0,
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
        "source_sha256": _sha256(source),
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
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_result.stdout,
        "expected_observed": expected_observed,
        "scope": (
            "A valid sparse virtual mapping backs a public one-channel MACE3 "
            "packet whose size makes 3*buf_size wrap to two samples. FFmpeg "
            "allocates that undersized output while the production decode "
            "loop retains the full packet count, yielding UBSan and ASan."
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
