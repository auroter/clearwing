"""Build and record swresample's output-sample-bits negative-shift proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.swr-output-bits-negative-shift-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_swr_output_bits_negative_shift_reproducer.c"
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
        "-Llibswresample",
        "-Llibavutil",
        "-lswresample",
        "-lavutil",
        "-lm",
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
    dither_source = checkout / "libswresample/dither.c"
    options_source = checkout / "libswresample/options.c"
    sources = (dither_source, options_source)
    if (
        not harness.is_file()
        or any(not source.is_file() for source in sources)
        or not (checkout / "libswresample/libswresample.a").is_file()
    ):
        raise ValueError("harness, swresample sources, and configured archive must exist")

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
            "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
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

    dither_text = dither_source.read_text(encoding="utf-8", errors="replace")
    options_text = options_source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "public_option_accepts_thirty_three": (
            '"output_sample_bits"' in options_text
            and "OFFSET(dither.output_sample_bits)" in options_text
            and "0      , 64" in options_text
        ),
        "s32_path_uses_thirty_two_minus_option": (
            "out_fmt == AV_SAMPLE_FMT_S32" in dither_text
            and "1<<(32-s->dither.output_sample_bits)" in dither_text
        ),
        "dither_init_runs_during_public_swr_init": (
            "swri_dither_init" in dither_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_s32_resampler_configuration": (
            "api=swr_alloc_set_opts2 format=s32 output_sample_bits=33 "
            "declared_option_range=0..64 shift_exponent=-1" in combined
        ),
        "ubsan_negative_shift": (
            "runtime error: shift exponent -1 is negative" in combined
        ),
        "production_dither_init_in_trace": "in swri_dither_init" in combined,
        "public_swr_init_in_trace": "in swr_init" in combined,
        "initialization_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout) or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {str(path): _sha256(path) for path in sources},
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
            "The public output_sample_bits option accepts values through 64 "
            "for every output format. With S32 output and the accepted value "
            "33, swri_dither_init computes 1 << (32 - 33). A public mono "
            "S32-to-S32 swr_alloc_set_opts2 context reaches this during "
            "swr_init, and UBSan aborts because the shift exponent is -1."
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
