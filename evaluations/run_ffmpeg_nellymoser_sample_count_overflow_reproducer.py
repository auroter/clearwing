"""Build and record Nellymoser's sample-count overflow and output overwrite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.nellymoser-sample-count-overflow-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
REPAIR_COMMIT = "2864ce5e28e5627aa03aad645e25deaa98c39889"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_nellymoser_sample_count_overflow_reproducer.c"),
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


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
    source = checkout / "libavcodec/nellymoserdec.c"
    components = checkout / "config_components.h"
    required = (
        harness,
        source,
        components,
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if _head(checkout) != VULNERABLE_COMMIT or not all(path.is_file() for path in required):
        raise ValueError(f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}")

    source_text = source.read_text(encoding="utf-8", errors="replace")
    component_text = components.read_text(encoding="utf-8", errors="replace")
    if "#define CONFIG_NELLYMOSER_DECODER 1" not in component_text:
        raise ValueError("configured build must enable the Nellymoser decoder")

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

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/nellymoserdec.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    source_indicators = {
        "nellymoser_decoder_enabled": ("#define CONFIG_NELLYMOSER_DECODER 1" in component_text),
        "block_count_derived_from_packet_size": (
            "blocks     = buf_size / NELLY_BLOCK_LEN;" in source_text
        ),
        "sample_count_uses_unchecked_signed_product": (
            "frame->nb_samples = NELLY_SAMPLES * blocks;" in source_text
        ),
        "decode_loop_retains_original_block_count": ("for (i=0 ; i<blocks ; i++) {" in source_text),
        "exact_repair_present": (
            repair_result.returncode == 0
            and "Check block count to avoid integer overflow" in repair_text
            and "Fixes: out of array access" in repair_text
            and "blocks > INT_MAX / NELLY_SAMPLES" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_nellymoser_packet": (
            "codec=nellymoser packet_size=1073741888 blocks=16777217" in combined
        ),
        "valid_sparse_virtual_mapping": "virtual_mapping=valid" in combined,
        "sample_count_wrapped_to_256": "wrapped_nb_samples=256" in combined,
        "signed_sample_count_overflow": ("runtime error: signed integer overflow" in combined),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "overwrite_originates_in_nelly_decoder": "nellymoserdec.c" in combined,
        "decoder_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source": str(source),
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
            "A valid demand-zero virtual mapping backs a public Nellymoser "
            "packet containing 16,777,217 complete blocks. Multiplying the "
            "block count by 256 wraps frame->nb_samples to 256, so FFmpeg "
            "allocates one output block while the production loop decodes "
            "the full packet and writes beyond the allocation on block two."
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
