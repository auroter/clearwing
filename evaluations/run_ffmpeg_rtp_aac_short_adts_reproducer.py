"""Build and record the RTP/AAC undersized-ADTS-packet reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rtp-aac-short-adts-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_rtp_aac_short_adts_reproducer.c"),
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
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
        "-Llibavformat",
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibswscale",
        "-Llibavutil",
        "-lavformat",
        "-lavcodec",
        "-lswresample",
        "-lswscale",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
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
    source = checkout / "libavformat/rtpenc_aac.c"
    if (
        not harness.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or not source.is_file()
    ):
        raise ValueError("harness, configured FFmpeg static libraries, and source must exist")

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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "adts_header_subtracted_when_extradata_absent": (
            "if ((s1->streams[0]->codecpar->extradata_size) == 0) {" in source_text
            and "size -= 7;" in source_text
            and "buff += 7;" in source_text
        ),
        "negative_size_reaches_copy": ("memcpy(s->buf_ptr, buff, size);" in source_text),
        "missing_seven_byte_minimum": (
            "size < 7" not in source_text and "size <= 6" not in source_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "production_packetizer_reached": (
            "aac_packet_size=1 adts_header_size=7 derived_payload_size=-6" in combined
        ),
        "asan_negative_size_param": ("AddressSanitizer: negative-size-param" in combined),
        "negative_copy_size": "size=-6" in combined,
        "aac_packetizer_in_trace": "ff_rtp_send_aac" in combined,
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
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "codec": "aac",
            "extradata_size": 0,
            "packet_size": 1,
            "adts_header_size": 7,
            "derived_payload_size": -6,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "later_repair_commit": "c77a16487a37ae450fa8ea5a94fd6488e40277b7",
        "expected_observed": expected_observed,
        "scope": (
            "The RTP packetizer accepts a one-byte AAC packet when stream "
            "extradata is absent. ff_rtp_send_aac assumes a seven-byte ADTS "
            "header, advances the source pointer and makes the payload size "
            "negative without a minimum check, then passes that negative int "
            "to memcpy. ASan reports negative-size-param in the production "
            "packetizer. Later FFmpeg repair c77a16487a adds the exact missing "
            "seven-byte guard."
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
