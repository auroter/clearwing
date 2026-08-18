"""Build and record the Bink Audio short-read disclosure proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.binka-short-read-disclosure-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_binka_short_read_disclosure_reproducer.c"),
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
        f'-DBINKA_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
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
    old = """    avio_read(pb, pkt->data + 4, pkt_size - 4);
    AV_WL32(pkt->data, pkt_size);
"""
    new = """    ret = avio_read(pb, pkt->data + 4, pkt_size - 4);
    if (ret != pkt_size - 4)
        return ret < 0 ? ret : AVERROR_INVALIDDATA;
    AV_WL32(pkt->data, pkt_size);
"""
    if source_text.count(old) != 1:
        raise ValueError("pinned binka.c does not match the guarded control context")
    destination.write_text(source_text.replace(old, new), encoding="utf-8")
    return destination


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/binka.c"
    packet_source = checkout / "libavcodec/packet.c"
    aviobuf_source = checkout / "libavformat/aviobuf.c"
    required = (
        harness,
        source,
        packet_source,
        aviobuf_source,
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact demux sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    guarded_binary = binary.with_name(binary.name + "-guarded")
    guarded_source = _make_guarded_source(
        source, binary.with_name(binary.name + "-guarded-binka.c")
    )

    compile_command = _compile_command(harness, source, binary)
    guarded_compile_command = _compile_command(harness, guarded_source, guarded_binary)
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
    packet_text = packet_source.read_text(encoding="utf-8", errors="replace")
    aviobuf_text = aviobuf_source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "packet_size_comes_from_input": ("pkt_size = avio_rl16(pb) + 4;" in source_text),
        "packet_payload_is_not_initialized": (
            "ret = av_buffer_realloc(buf, size + AV_INPUT_BUFFER_PADDING_SIZE);" in packet_text
            and "memset((*buf)->data + size, 0, AV_INPUT_BUFFER_PADDING_SIZE);" in packet_text
        ),
        "avio_read_can_return_short_count": (
            "return size1 - size;" in aviobuf_text
            and "if (avio_feof(s))  return AVERROR_EOF;" in aviobuf_text
        ),
        "demuxer_ignores_short_read_and_publishes_full_packet": all(
            term in source_text
            for term in (
                "avio_read(pb, pkt->data + 4, pkt_size - 4);",
                "AV_WL32(pkt->data, pkt_size);",
                "return 0;",
            )
        ),
    }

    combined = run_result.stdout + run_result.stderr
    guarded_combined = guarded_run_result.stdout + guarded_run_result.stderr
    runtime_indicators = {
        "truncated_input_publishes_declared_packet": (
            "declared_payload=64 available_payload=1 read_result=0 published_size=68" in combined
        ),
        "published_tail_retains_63_prior_heap_bytes": ("stale_tail_bytes=63" in combined),
        "vulnerable_replay_completes_without_sanitizer_noise": (
            run_result.returncode == 0
            and "Sanitizer" not in combined
            and "runtime error:" not in combined
        ),
        "short_read_guard_refuses_to_publish": (
            guarded_run_result.returncode != 0
            and "published_size=0 stale_tail_bytes=0" in guarded_combined
            and "Sanitizer" not in guarded_combined
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
        "source_sha256": {
            "libavformat/binka.c": _sha256(source),
            "libavformat/aviobuf.c": _sha256(aviobuf_source),
            "libavcodec/packet.c": _sha256(packet_source),
        },
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
            "The Bink Audio demuxer allocates the input-declared packet size, "
            "ignores avio_read's short return, and publishes the full packet. "
            "The exact-source proof initializes the fresh packet with a visible "
            "prior-heap marker, supplies one of 64 declared payload bytes, and "
            "observes all 63 unwritten bytes in the published packet. A guarded "
            "control rejects the short read before publication."
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
