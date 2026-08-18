"""Build and record the COOK subpacket-channel overread proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.cook-subpacket-channel-overread-reproducer.v1"
REPAIR_COMMIT = "1152139b4898888f7ca3daa1caca715c87dc1e85"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_cook_subpacket_channel_overread_reproducer.c"
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


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DCOOK_SOURCE="{source}"',
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
        "libavcodec/audiodsp.c",
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
    source = checkout / "libavcodec/cook.c"
    required = (
        harness,
        source,
        checkout / "libavcodec/cookdata.h",
        checkout / "libavcodec/audiodsp.c",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact COOK sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_source = binary.with_name(binary.name + "-repaired-cook.c")
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavcodec/cook.c"], cwd=checkout
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
    repaired_text = repaired_source.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        ["git", "show", "--format=", REPAIR_COMMIT, "--", "libavcodec/cook.c"],
        cwd=checkout,
    )
    repair_message = _run(
        ["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout
    )
    source_indicators = {
        "subpacket_guard_mixes_count_with_channel_count": (
            "q->num_subpackets + q->subpacket[s].num_channels > channels"
            in source_text
        ),
        "stereo_subpackets_each_claim_two_channels": (
            "q->subpacket[s].num_channels = 2;" in source_text
        ),
        "decoder_accumulates_channel_index_per_subpacket": (
            "chidx += q->subpacket[i].num_channels;" in source_text
            and "q->subpacket[i].ch_idx = chidx;" in source_text
        ),
        "output_pointer_is_indexed_by_unbounded_channel_index": (
            "outbuffer ? outbuffer[p->ch_idx] : NULL" in source_text
            and "outbuffer ? outbuffer[p->ch_idx + 1] : NULL" in source_text
        ),
        "exact_repair_tracks_total_subpacket_channels": (
            "int total_channels = 0;" in repaired_text
            and "total_channels + q->subpacket[s].num_channels > channels"
            in repaired_text
            and "total_channels += q->subpacket[s].num_channels;" in repaired_text
        ),
        "repair_identifies_evil_rm_out_of_array_read": (
            "bound subpacket channel sum against channel count" in repair_message.stdout
            and "Fixes: out of array read" in repair_message.stdout
            and "Fixes: evil.rm" in repair_message.stdout
            and repair_diff.returncode == 0
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "vulnerable_init_accepts_eight_channels_for_six_channel_output": (
            "declared_channels=6 stereo_subpackets=4 "
            "total_subpacket_channels=8 init_result=0 accepted_subpackets=4"
            in combined
        ),
        "valid_subpacket_reaches_first_missing_output_pointer": (
            "channel_indices=6,7 output_pointer_count=6 valid_packet_fill=132"
            in combined
        ),
        "asan_reports_pointer_array_heap_overread": (
            "AddressSanitizer: heap-buffer-overflow" in combined
            and "READ of size 8" in combined
            and "0 bytes after 48-byte region" in combined
            and "decode_subpacket" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_init_rejects_fourth_stereo_subpacket": (
            repaired_run_result.returncode == 0
            and "init_result=" in repaired_combined
            and "accepted_subpackets=3" in repaired_combined
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
        "source_sha256": _sha256(source),
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
            "COOK initialization checks subpacket count plus each subpacket's "
            "channel count rather than the cumulative channel count. Four "
            "stereo subpackets therefore pass for a six-channel stream while "
            "claiming eight channels. The decoder advances ch_idx by two for "
            "each accepted subpacket; a valid coded subpacket makes ASan report "
            "an eight-byte read immediately after the six-pointer output array. "
            "Exact repair 1152139b48 tracks the cumulative channel count, "
            "explicitly identifies evil.rm and an out-of-array read, and rejects "
            "the fourth subpacket before decoder initialization completes."
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
