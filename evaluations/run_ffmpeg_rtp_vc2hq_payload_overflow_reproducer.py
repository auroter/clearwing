"""Build and record the VC-2 HQ RTP payload-buffer overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rtp-vc2hq-payload-overflow-reproducer.v1"
REPAIR_COMMIT = "1afd5c3ddafda4209e0881cd30684b919e99de7c"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rtp_vc2hq_payload_overflow_reproducer.c"),
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
        "-DZLIB_CONST",
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
            "libavformat/libavformat.a",
            "libavcodec/libavcodec.a",
            "libswresample/libswresample.a",
            "libswscale/libswscale.a",
            "libavutil/libavutil.a",
            "-lm",
            "-lbz2",
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
    source = checkout / "libavformat/rtpenc_vc2hq.c"
    golomb = checkout / "libavcodec/golomb.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not golomb.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError(
            "harness, VC-2 packetizer sources, and configured FFmpeg archives " "must exist"
        )

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
            "libavformat/rtpenc_vc2hq.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "unit_size_only_bounded_by_input_frame": all(
            term in source_text
            for term in (
                "unit_size = AV_RB32(&unit[5]);",
                "if (unit_size > end - unit)",
            )
        ),
        "sequence_unit_passes_full_payload": (
            "send_packet(ctx, parse_code, 0, unit + "
            "DIRAC_DATA_UNIT_HEADER_SIZE, unit_size - "
            "DIRAC_DATA_UNIT_HEADER_SIZE" in source_text
        ),
        "payload_copy_has_no_capacity_check": all(
            term in source_text
            for term in (
                "memcpy(&rtp_ctx->buf[4 + info_hdr_size], buf, size);",
                "RTP_VC2HQ_PL_HEADER_SIZE + info_hdr_size + size",
            )
        )
        and "size > rtp_ctx->max_payload_size" not in source_text,
        "proof_calls_full_packetizer_entry": all(
            term in harness_source
            for term in (
                '#include "libavformat/rtpenc_vc2hq.c"',
                "frame[4] = DIRAC_PCODE_SEQ_HEADER;",
                "AV_WB32(&frame[5], FRAME_SIZE);",
                "ff_rtp_send_vc2hq(&format, frame, FRAME_SIZE, 0);",
            )
        ),
        "later_repair_adds_exact_payload_bound": (
            repair_result.returncode == 0
            and "reject data units larger than the RTP payload buffer" in repair_text
            and "size > rtp_ctx->max_payload_size - "
            "RTP_VC2HQ_PL_HEADER_SIZE - info_hdr_size" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_oversized_data_unit_state": (
            "frame_size=200 unit_size=200 unit_payload_size=187 "
            "rtp_payload_size=64 destination_write_size=191 "
            "overflow_bytes=127" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "oversized_payload_write": "WRITE of size 187" in combined,
        "write_reaches_payload_end": ("0 bytes after 64-byte region" in combined),
        "packetizer_and_copy_in_trace": (
            "in send_packet" in combined and "in ff_rtp_send_vc2hq" in combined
        ),
        "process_aborted": run_result.returncode != 0,
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
        "source_sha256": {
            str(source.relative_to(checkout)): _sha256(source),
            str(golomb.relative_to(checkout)): _sha256(golomb),
        },
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "frame_bytes": 200,
            "unit_bytes": 200,
            "data_unit_header_bytes": 13,
            "unit_payload_bytes": 187,
            "rtp_payload_header_bytes": 4,
            "rtp_payload_buffer_bytes": 64,
            "destination_write_bytes": 191,
            "overflow_bytes": 127,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A packet-controlled VC-2 sequence unit can occupy the full input "
            "frame while exceeding the RTP muxer's fixed payload buffer. The "
            "packetizer validates the unit only against the source frame, then "
            "passes all bytes after the 13-byte data-unit header to send_packet. "
            "That function writes its four-byte RTP payload header and memcpy's "
            "the entire remaining unit without consulting max_payload_size. The "
            "harness invokes the full pinned ff_rtp_send_vc2hq entry and stubs "
            "only the downstream network emission reached after the copy. ASan "
            "reports a 187-byte write crossing the end of the 64-byte payload "
            "allocation. Later repair 1afd5c3dda adds the exact missing bound "
            "and explicitly identifies the fixed-buffer overflow."
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
