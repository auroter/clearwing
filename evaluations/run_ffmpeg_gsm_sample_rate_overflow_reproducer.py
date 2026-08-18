"""Build and record the GSM demuxer's sample-rate multiplication overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.gsm-sample-rate-overflow-reproducer.v1"
SOURCE_PATH = "libavformat/gsmdec.c"
VULNERABLE_EXPRESSION = (
    "GSM_BLOCK_SIZE * 8 * c->sample_rate / GSM_BLOCK_SAMPLES"
)
WIDENED_EXPRESSION = (
    "(int64_t)GSM_BLOCK_SIZE * 8 * c->sample_rate / GSM_BLOCK_SAMPLES"
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_gsm_sample_rate_overflow_reproducer.c"
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
    *, harness: Path, source: Path, binary: Path, sanitizers: str
) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavformat",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DGSMDEC_SOURCE="{source}"',
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
            "-Llibavformat",
            "-Llibavcodec",
            "-Llibavutil",
            "-lavformat",
            "-lavcodec",
            "-lavutil",
            "-lm",
            "-lz",
        ]
    )
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
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact GSM source, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    wrap_binary = binary.with_name(binary.name + "-wrap")
    widened_binary = binary.with_name(binary.name + "-widened")
    widened_source = binary.with_name(binary.name + "-widened-gsmdec.c")
    source_text = source.read_text(encoding="utf-8", errors="replace")
    if source_text.count(VULNERABLE_EXPRESSION) != 1:
        raise ValueError("expected exactly one GSM bit-rate multiplication expression")
    widened_source.write_text(
        source_text.replace(VULNERABLE_EXPRESSION, WIDENED_EXPRESSION),
        encoding="utf-8",
    )

    compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=binary,
        sanitizers="address,undefined",
    )
    wrap_compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=wrap_binary,
        sanitizers="address",
    )
    widened_compile_command = _compile_command(
        harness=harness,
        source=widened_source,
        binary=widened_binary,
        sanitizers="address,undefined",
    )
    compile_result = _run(compile_command, cwd=checkout)
    wrap_compile_result = _run(wrap_compile_command, cwd=checkout)
    widened_compile_result = _run(widened_compile_command, cwd=checkout)

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
    wrap_run_result = (
        _run([str(wrap_binary)], cwd=checkout, env=environment)
        if wrap_compile_result.returncode == 0
        else _failed([str(wrap_binary)], "wrap compile failed")
    )
    widened_run_result = (
        _run([str(widened_binary)], cwd=checkout, env=environment)
        if widened_compile_result.returncode == 0
        else _failed([str(widened_binary)], "widened compile failed")
    )

    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    master_head_result = _run(["git", "rev-parse", "origin/master"], cwd=checkout)
    master_source_result = _run(
        ["git", "show", f"origin/master:{SOURCE_PATH}"], cwd=checkout
    )
    source_indicators = {
        "public_option_accepts_selected_sample_rate": (
            '"sample_rate"' in source_text
            and "1, INT_MAX / GSM_BLOCK_SIZE" in source_text
        ),
        "bit_rate_uses_unchecked_signed_product": VULNERABLE_EXPRESSION in source_text,
        "current_master_retains_unchecked_product": (
            master_source_result.returncode == 0
            and VULNERABLE_EXPRESSION in master_source_result.stdout
        ),
        "widened_control_promotes_before_product": WIDENED_EXPRESSION
        in widened_source.read_text(encoding="utf-8", errors="replace"),
    }
    combined = run_result.stdout + run_result.stderr
    wrap_combined = wrap_run_result.stdout + wrap_run_result.stderr
    widened_combined = widened_run_result.stdout + widened_run_result.stderr
    runtime_indicators = {
        "proof_uses_exact_public_option_maximum": (
            "sample_rate=65075262 option_max=65075262 block_size=33" in combined
        ),
        "mathematical_bit_rate_is_107374182": (
            "mathematical_numerator=17179869168 "
            "mathematical_bit_rate=107374182" in combined
        ),
        "ubsan_reports_exact_signed_product_overflow": (
            "signed integer overflow: 264 * 65075262" in combined
            and f"{SOURCE_PATH}:85" in combined
            and "gsm_read_header" in combined
        ),
        "ubsan_process_aborted": run_result.returncode != 0,
        "ordinary_wrap_publishes_zero_bit_rate": (
            wrap_run_result.returncode == 0
            and "header_result=0 bit_rate=0" in wrap_combined
            and "Sanitizer" not in wrap_combined
            and "runtime error:" not in wrap_combined
        ),
        "widened_control_publishes_mathematical_bit_rate": (
            widened_run_result.returncode == 0
            and "header_result=0 bit_rate=107374182" in widened_combined
            and "Sanitizer" not in widened_combined
            and "runtime error:" not in widened_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and wrap_compile_result.returncode == 0
        and widened_compile_result.returncode == 0
        and master_head_result.returncode == 0
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
            hashlib.sha256(master_source_result.stdout.encode()).hexdigest()
            if master_source_result.returncode == 0
            else None
        ),
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "commands": {
            "compile": compile_command,
            "wrap_compile": wrap_compile_command,
            "widened_compile": widened_compile_command,
        },
        "results": {
            "compile": _result_payload(compile_result),
            "wrap_compile": _result_payload(wrap_compile_result),
            "widened_compile": _result_payload(widened_compile_result),
            "run": _result_payload(run_result),
            "wrap_run": _result_payload(wrap_run_result),
            "widened_run": _result_payload(widened_run_result),
            "master_source": _result_payload(master_source_result),
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
