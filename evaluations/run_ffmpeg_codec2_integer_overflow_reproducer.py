"""Build and record Codec2 packet-size and duration overflow proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.codec2-integer-overflow-reproducer.v1"
REPAIR_COMMIT = "2b7e5012424a52998cd6a1fe3556272313cb7527"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_codec2_integer_overflow_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/codec2.c"
    if not harness.is_file() or not source.is_file():
        raise ValueError("harness and pinned Codec2 source must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=undefined",
        "-fno-sanitize-recover=undefined",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wl,-dead_strip",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
    ]
    compile_result = _run(compile_command, cwd=checkout)
    environment: dict[str, str] | None = None
    run_results: dict[str, subprocess.CompletedProcess[str]] = {}
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        for case in ("packet-size", "duration"):
            run_results[case] = _run([str(binary), case], cwd=checkout, env=environment)

    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_result = _run(
        ["git", "show", "--format=", REPAIR_COMMIT, "--", "libavformat/codec2.c"],
        cwd=checkout,
    )
    repair_subject = _run(["git", "show", "-s", "--format=%s", REPAIR_COMMIT], cwd=checkout)
    source_indicators = {
        "public_option_accepts_int_max": (
            '"frames_per_packet"' in source_text and "{.i64 = 1}, 1, INT_MAX" in source_text
        ),
        "packet_size_product_is_unchecked_int": (
            "size = c2->frames_per_packet * block_align;" in source_text
            and "c2->frames_per_packet > INT_MAX / block_align" not in source_text
        ),
        "duration_product_is_unchecked_int": (
            "pkt->duration = n * frame_size;" in source_text
            and "pkt->duration = (int64_t)n * frame_size;" not in source_text
        ),
        "exact_later_repair_guards_both_products": (
            repair_result.returncode == 0
            and "c2->frames_per_packet > INT_MAX / block_align" in repair_result.stdout
            and "pkt->duration = (int64_t)n * frame_size;" in repair_result.stdout
            and "avoid integer overflow in packet size and duration" in repair_subject.stdout
        ),
    }

    packet_result = run_results.get("packet-size")
    duration_result = run_results.get("duration")
    packet_output = packet_result.stdout + packet_result.stderr if packet_result else ""
    duration_output = duration_result.stdout + duration_result.stderr if duration_result else ""
    runtime_indicators = {
        "packet_size_uses_public_int_max": (
            "case=packet-size frames_per_packet=2147483647 block_align=8" in packet_output
        ),
        "packet_size_mathematical_product": (
            "mathematical_packet_size=17179869176" in packet_output
        ),
        "packet_size_ubsan_overflow": (
            "signed integer overflow: 2147483647 * 8" in packet_output
            and "libavformat/codec2.c:201" in packet_output
        ),
        "duration_uses_representable_packet_size": (
            "case=duration frames_per_packet=6710887 block_align=4 frame_size=320"
            in duration_output
            and "mathematical_packet_size=26843548" in duration_output
        ),
        "duration_mathematical_product": ("mathematical_duration=2147483840" in duration_output),
        "duration_ubsan_overflow": (
            "signed integer overflow: 6710887 * 320" in duration_output
            and "libavformat/codec2.c:210" in duration_output
        ),
        "both_processes_aborted": (
            packet_result is not None
            and duration_result is not None
            and packet_result.returncode != 0
            and duration_result.returncode != 0
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "repair_commit": REPAIR_COMMIT,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Codec2 advertises frames_per_packet through INT_MAX. The pinned "
            "production packet reader first multiplies that option by the "
            "mode-owned block alignment in signed int; INT_MAX and block "
            "alignment eight overflow before av_get_packet. Independently, "
            "a representable 26,843,548-byte mode-six request yields 6,710,887 "
            "complete frames, whose 320-sample duration overflows signed int. "
            "The harness executes the exact pinned codec2_read_packet function "
            "and UBSan aborts at both expressions. Exact later repair "
            "2b7e501242 guards the packet product and widens the duration "
            "product. This is one low-severity public-option availability root."
        ),
        "runs": {
            case: {
                "command": [str(binary), case],
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            for case, result in run_results.items()
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
