"""Build and record SBC's invalid-bitpool packet disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.sbc-invalid-bitpool-disclosure-reproducer.v1"
REPAIR_COMMIT = "3540a6a308256837da76ccebaa4987b33d2471eb"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_sbc_invalid_bitpool_disclosure_reproducer.c"),
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
        "-ffunction-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
    ]
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.extend(
        [
            "libavcodec/libavcodec.a",
            "libavutil/libavutil.a",
            "-lm",
            "-lz",
        ]
    )
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
                "-liconv",
                "-framework",
                "AudioToolbox",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
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
    sources = {
        "sbc": checkout / "libavcodec/sbc.c",
        "sbcenc": checkout / "libavcodec/sbcenc.c",
        "sbcdsp": checkout / "libavcodec/sbcdsp.c",
        "encode": checkout / "libavcodec/encode.c",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError("harness, SBC sources, and configured FFmpeg archives must exist")

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
            "libavcodec/sbcenc.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    sbcenc = sources["sbcenc"].read_text(encoding="utf-8", errors="replace")
    encode = sources["encode"].read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "packet_size_uses_invalid_bitpool": all(
            term in sbcenc
            for term in (
                "int frame_length = 4 +",
                "frame->blocks * frame->bitpool",
                "ff_get_encode_buffer(avctx, avpkt, frame_length, 0)",
            )
        ),
        "packer_rejects_after_three_writes": all(
            term in sbcenc
            for term in (
                "avpkt->data[0] = SBC_SYNCWORD;",
                "avpkt->data[2] = frame->bitpool;",
                "return -5;",
            )
        ),
        "packer_result_is_ignored": all(
            term in sbcenc
            for term in (
                "sbc_pack_frame(avpkt, frame, j, sbc->msbc);",
                "*got_packet_ptr = 1;",
            )
        ),
        "public_encoder_returns_callback_packet": all(
            term in encode
            for term in (
                "ret = ff_encode_encode_cb(avctx, avpkt, frame, &got_packet);",
                "return ret;",
            )
        ),
        "later_repair_moves_validation_to_init": (
            repair_result.returncode == 0
            and "Don't output uninitialized data" in repair_text
            and "Invalid parameter combination" in repair_text
            and "return AVERROR_PATCHWELCOME;" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "invalid_bitpool_reached": "bitpool=249 maximum=128" in combined,
        "packet_was_published": "got_packet=1" in combined,
        "only_three_header_bytes_initialized": (
            "initialized_header_bytes=3 marker_tail_bytes=130" in combined
        ),
        "process_succeeded": run_result.returncode == 0,
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
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {name: _sha256(path) for name, path in sources.items()},
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "sample_rate": 44100,
            "channels": 2,
            "bit_rate": 100000,
            "sbc_delay_microseconds": 1000,
            "bitpool": 249,
            "maximum_bitpool": 128,
            "packet_bytes": 133,
            "initialized_header_bytes": 3,
            "untouched_marker_bytes": 130,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public SBC encoder accepts a low-delay 100 kbit/s stereo "
            "configuration whose derived bitpool exceeds the SBC limit. The packer "
            "writes three header bytes, returns an error encoded in size_t, and its "
            "caller ignores that return before publishing the full allocated packet. "
            "A custom public allocation callback pre-fills the packet with a marker; "
            "the returned packet preserves every byte after the three-byte header. "
            "Later repair 3540a6a308 moves the exact bitpool check into init."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
