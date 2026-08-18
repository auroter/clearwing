"""Build and record the RTMP AMF recursion-depth proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rtmp-amf-recursion-reproducer.v1"
REPAIR_COMMIT = "92804c9e25623f2d5c5c8d64d4b0a538d1861cd7"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rtmp_amf_recursion_reproducer.c"),
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
        f'-DRTMPPKT_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=undefined",
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
        "libavformat/libavformat.a",
        "libavcodec/libavcodec.a",
        "libavutil/libavutil.a",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/rtmppkt.c"
    protocol_source = checkout / "libavformat/rtmpproto.c"
    required = (
        harness,
        source,
        protocol_source,
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact RTMP sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-rtmppkt.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavformat/rtmppkt.c"], cwd=checkout
    )
    if repair_source_result.returncode == 0:
        repaired_source.write_text(repair_source_result.stdout, encoding="utf-8")

    compile_command = _compile_command(harness, source, binary)
    repaired_compile_command = _compile_command(harness, repaired_source, repaired_binary)
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
    protocol_text = protocol_source.read_text(encoding="utf-8", errors="replace")
    repaired_text = repaired_source.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        ["git", "show", "--format=", REPAIR_COMMIT, "--", "libavformat/rtmppkt.c"],
        cwd=checkout,
    )
    repair_message = _run(
        ["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout
    )
    source_indicators = {
        "amf_arrays_recurse_without_depth_limit": (
            "t = amf_tag_skip(gb);" in source_text
            and "static int amf_tag_skip(GetByteContext *gb)" in source_text
        ),
        "network_protocol_calls_recursive_size_parser": (
            "ff_amf_tag_size(ptr, data_end)" in protocol_text
            and "ff_amf_tag_size(gbc.buffer, gbc.buffer_end)" in protocol_text
        ),
        "encoded_proof_fits_rtmp_24_bit_packet_size": 5_000_002 <= 0xFFFFFF,
        "exact_repair_caps_both_recursive_walkers": (
            "#define MAX_DEPTH 16" in repaired_text
            and repaired_text.count("depth > MAX_DEPTH") == 2
            and "amf_tag_skip(gb, depth + 1)" in repaired_text
        ),
        "repair_identifies_out_of_array_access": (
            "Check recursion depth" in repair_message.stdout
            and "Fixes: out of array access" in repair_message.stdout
            and repair_diff.returncode == 0
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "proof_uses_one_million_nested_strict_arrays": (
            "nested_strict_arrays=1000000 encoded_size=5000002" in combined
        ),
        "asan_reports_stack_overflow_in_amf_tag_skip": (
            "AddressSanitizer: stack-overflow" in combined
            and combined.count("in amf_tag_skip") >= 10
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_parser_rejects_at_depth_limit": (
            repaired_run_result.returncode == 0
            and "tag_size_result=-1" in repaired_combined
            and "exceeded max depth" in repaired_combined
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
        "source_sha256": {
            "libavformat/rtmppkt.c": _sha256(source),
            "libavformat/rtmpproto.c": _sha256(protocol_source),
        },
        "repaired_source_sha256": _sha256(repaired_source),
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
            "RTMP AMF strict arrays can recursively contain one value, and the "
            "packet-size and field walkers recurse once per nested array without "
            "a depth limit. A 5,000,002-byte AMF value fits the protocol's "
            "24-bit packet-size field and makes ASan report stack overflow in "
            "amf_tag_skip. Exact repair 92804c9e25 caps both recursive walkers "
            "at depth 16, explicitly identifies out-of-array access, and cleanly "
            "rejects the same value."
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
