"""Build and record Chromaprint's raw fingerprint size-overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.chromaprint-raw-size-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_chromaprint_raw_size_overflow_reproducer.c"),
    )
    parser.add_argument(
        "--stub-include",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_chromaprint_stub"),
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


def _compile_command(harness: Path, stub_include: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavformat",
        "-I./libavcodec",
        f"-I{stub_include}",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DCHROMAPRINT_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wno-unused-parameter",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
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


def _make_guarded_source(source: Path, destination: Path) -> Path:
    source_text = source.read_text(encoding="utf-8")
    old = """    case FINGERPRINT_RAW:
        avio_write(pb, fp, size * 4); //fp points to array of uint32_t
        break;
"""
    new = """    case FINGERPRINT_RAW:
        if (size > INT_MAX / 4)
            goto fail;
        avio_write(pb, fp, size * 4); //fp points to array of uint32_t
        break;
"""
    if source_text.count(old) != 1:
        raise ValueError("pinned chromaprint.c does not match the guard context")
    destination.write_text(source_text.replace(old, new), encoding="utf-8")
    return destination


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    stub_include = args.stub_include.expanduser().resolve()
    stub_header = stub_include / "chromaprint.h"
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/chromaprint.c"
    required = (
        harness,
        stub_header,
        source,
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, stub API, source, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    guarded_binary = binary.with_name(binary.name + "-guarded")
    guarded_source = _make_guarded_source(
        source, binary.with_name(binary.name + "-guarded-chromaprint.c")
    )

    compile_command = _compile_command(harness, stub_include, source, binary)
    guarded_compile_command = _compile_command(
        harness, stub_include, guarded_source, guarded_binary
    )
    compile_result = _run(compile_command, cwd=checkout)
    guarded_compile_result = _run(guarded_compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    guarded_run_result = (
        _run([str(guarded_binary)], cwd=checkout, env=environment)
        if guarded_compile_result.returncode == 0
        else _failed([str(guarded_binary)], "guarded compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "audio_packets_feed_unbounded_context_lifetime": (
            "chromaprint_feed(cpr->ctx" in source_text and "static int write_trailer" in source_text
        ),
        "library_returns_fingerprint_count_as_int": (
            "int size, enc_size" in source_text and "chromaprint_get_raw_fingerprint" in source_text
        ),
        "raw_output_multiplies_count_in_signed_int": (
            "avio_write(pb, fp, size * 4);" in source_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    guarded_combined = guarded_run_result.stdout + guarded_run_result.stderr
    runtime_indicators = {
        "api_permitted_count_exceeds_int_byte_domain": (
            "raw_fingerprint_entries=536870912 mathematical_bytes=2147483648" in combined
        ),
        "ubsan_reports_exact_signed_multiply_overflow": (
            "runtime error: signed integer overflow" in combined
            and "536870912 * 4" in combined
            and "chromaprint.c:137" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "guarded_control_rejects_cleanly": (
            guarded_run_result.returncode == 0
            and "write_trailer_result=" in guarded_combined
            and "rejected=1" in guarded_combined
            and "Sanitizer" not in guarded_combined
            and "runtime error:" not in guarded_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and guarded_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "stub_header": str(stub_header),
        "stub_header_sha256": _sha256(stub_header),
        "source_sha256": _sha256(source),
        "guarded_source_sha256": _sha256(guarded_source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "guarded_binary": str(guarded_binary),
        "guarded_binary_sha256": (_sha256(guarded_binary) if guarded_binary.is_file() else None),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "guarded_compile_command": guarded_compile_command,
        "guarded_compile_returncode": guarded_compile_result.returncode,
        "guarded_compile_stdout": guarded_compile_result.stdout,
        "guarded_compile_stderr": guarded_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Chromaprint returns the raw fingerprint element count as int after "
            "an unbounded sequence of feed calls. Raw output multiplies that count "
            "by four in signed int. A proof-only implementation of the documented "
            "external API returns the first count whose byte size exceeds INT_MAX; "
            "UBSan aborts at the exact production multiply. This requires retaining "
            "a roughly 2 GiB fingerprint and is low-severity."
        ),
        "vulnerable_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "guarded_run": {
            "command": [str(guarded_binary)],
            "returncode": guarded_run_result.returncode,
            "stdout": guarded_run_result.stdout,
            "stderr": guarded_run_result.stderr,
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
