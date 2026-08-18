"""Build and record libcodec2's overflowing decoded sample count."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.libcodec2-sample-count-reproducer.v1"
REPAIR_COMMIT = "705ff11c2b02d2925fca5c2c78c547ccbd901182"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_libcodec2_sample_count_reproducer.c"
        ),
    )
    parser.add_argument(
        "--stub-directory",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_libcodec2_stub"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(
    harness: Path,
    stub_directory: Path,
    source: Path,
    binary: Path,
) -> list[str]:
    command = [
        "clang",
        f"-I{stub_directory}",
        "-I.",
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DLIBCODEC2_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fsanitize-recover=undefined",
        "-fno-sanitize-recover=address",
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


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    stub_directory = args.stub_directory.expanduser().resolve()
    stub_header = stub_directory / "codec2/codec2.h"
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/libcodec2.c"
    required = (
        harness,
        stub_header,
        source,
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError(
            "harness, proof-only Codec2 header, configured FFmpeg archives, "
            "and source must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-libcodec2.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavcodec/libcodec2.c"], cwd=checkout
    )
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(
        harness, stub_directory, source, binary
    )
    repaired_compile_command = _compile_command(
        harness, stub_directory, repaired_source, repaired_binary
    )
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = (
        _run(repaired_compile_command, cwd=checkout)
        if repaired_source.is_file()
        else _failed(repaired_compile_command, "repair source extraction failed")
    )

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=1"
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
    harness_text = harness.read_text(encoding="utf-8", errors="replace")
    repair_result = _run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/libcodec2.c",
        ],
        cwd=checkout,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "frame_count_derived_from_packet_size": (
            "nframes           = pkt->size / avctx->block_align;" in source_text
        ),
        "sample_count_uses_unchecked_signed_product": (
            "frame->nb_samples = avctx->frame_size * nframes;" in source_text
        ),
        "decode_loop_retains_original_frame_count": (
            "for (i = 0; i < nframes; i++)" in source_text
        ),
        "proof_stub_preserves_codec2_output_contract": all(
            term in harness_text
            for term in (
                "#define CODEC2_FRAME_SAMPLES 320",
                "return CODEC2_FRAME_SAMPLES;",
                "for (int i = 0; i < CODEC2_FRAME_SAMPLES; i++)",
                "speech[i] = (int16_t)i;",
            )
        ),
        "exact_repair_rejects_overflowing_count": (
            repair_result.returncode == 0
            and "reject packet sample counts that overflow int" in repair_text
            and "Fixes: out of array access" in repair_text
            and "if (nframes > INT_MAX / avctx->frame_size)" in repair_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "public_codec2_packet_geometry": (
            "packet_size=107374184 block_align=8 nframes=13421773 "
            "frame_size=320 mathematical_samples=4294967360 "
            "wrapped_samples=64 virtual_mapping=valid" in combined
        ),
        "signed_sample_count_overflow": (
            "signed integer overflow: 320 * 13421773" in combined
            and "libavcodec/libcodec2.c:135" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "codec2_frame_overwrites_wrapped_allocation": (
            "WRITE of size 2" in combined
            and "0 bytes after 128-byte region" in combined
            and "in codec2_decode" in combined
            and "in libcodec2_decode" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_packet_is_rejected": (
            repaired_run_result.returncode == 0
            and "send_result=" in repaired_combined
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
        "stub_header": str(stub_header),
        "stub_header_sha256": _sha256(stub_header),
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
            "A valid sparse 107,374,184-byte Codec2 packet contains 13,421,773 "
            "complete eight-byte frames. The production decoder multiplies that "
            "count by the mode's 320 samples in signed int, wrapping 4,294,967,360 "
            "mathematical samples to 64. FFmpeg allocates 128 output bytes while "
            "the retained frame loop asks Codec2 to emit a full 320-sample frame. "
            "The proof-only Codec2 implementation supplies that documented output "
            "contract; UBSan reports the production multiplication and ASan reports "
            "the two-byte write immediately after FFmpeg's undersized allocation. "
            "The exact repair rejects the same packet before multiplication."
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
