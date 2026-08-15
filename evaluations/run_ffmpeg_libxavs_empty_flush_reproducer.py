"""Build and record libxavs's empty-encoder flush overread."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.libxavs-empty-flush-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_libxavs_empty_flush_reproducer.c"),
    )
    parser.add_argument(
        "--stub-directory",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_libxavs_stub"),
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


def _compile_command(harness: Path, stub_directory: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        f"-I{stub_directory}",
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
            "-pthread",
            "-lz",
        ]
    )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    stub_directory = args.stub_directory.expanduser().resolve()
    stub_header = stub_directory / "xavs.h"
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "libxavs": checkout / "libavcodec/libxavs.c",
        "encode": checkout / "libavcodec/encode.c",
        "avcodec": checkout / "libavcodec/avcodec.c",
    }
    if (
        not harness.is_file()
        or not stub_header.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError(
            "harness, proof-only xavs header, configured FFmpeg archives, " "and sources must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, stub_directory, binary)
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

    libxavs = sources["libxavs"].read_text(encoding="utf-8", errors="replace")
    encode = sources["encode"].read_text(encoding="utf-8", errors="replace")
    avcodec = sources["avcodec"].read_text(encoding="utf-8", errors="replace")
    harness_source = harness.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "public_empty_flush_enters_encoder": all(
            term in encode
            for term in (
                "if (!frame) {",
                "avci->draining = 1;",
                "// Flushing is signaled with a NULL frame",
                "ret = ff_encode_encode_cb(avctx, avpkt, frame, &got_packet);",
            )
        ),
        "libxavs_declares_encoder_delay": (
            ".p.capabilities = AV_CODEC_CAP_DR1 | AV_CODEC_CAP_DELAY" in libxavs
        ),
        "private_state_is_zero_initialized": (
            "avctx->priv_data = av_mallocz(codec2->priv_data_size);" in avcodec
        ),
        "pts_buffer_has_only_bframe_ring_entries": (
            "FF_ALLOCZ_TYPED_ARRAY(x4->pts_buffer, avctx->max_b_frames + 1)" in libxavs
        ),
        "empty_no_output_path_emits_end_marker": all(
            term in libxavs
            for term in (
                "if (!ret) {",
                "if (!frame && !(x4->end_of_stream))",
                "pkt->data[3] = 0xb1;",
            )
        ),
        "dts_uses_negative_c_remainders": all(
            term in libxavs
            for term in (
                "(x4->out_frame_count-1)%(avctx->max_b_frames+1)",
                "(x4->out_frame_count-2)%(avctx->max_b_frames+1)",
            )
        ),
        "proof_stubs_only_external_no_output_result": all(
            term in harness_source
            for term in (
                '#include "libavcodec/libxavs.c"',
                "*nals = NULL;",
                "*nnal = 0;",
                "return XAVS_frame(&avctx, &packet, NULL, &got_packet);",
            )
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_empty_flush_state": (
            "empty_flush=1 out_frame_count=0 max_b_frames=2 "
            "first_index=-1 second_index=-2" in combined
        ),
        "asan_heap_buffer_overflow": ("AddressSanitizer: heap-buffer-overflow" in combined),
        "eight_byte_read": "READ of size 8" in combined,
        "read_precedes_three_entry_ring": (
            "24-byte region" in combined
            and ("8 bytes before" in combined or "8 bytes to the left" in combined)
        ),
        "production_function_in_trace": "in XAVS_frame" in combined,
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
        "stub_header": str(stub_header),
        "stub_header_sha256": _sha256(stub_header),
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
            "input_frames": 0,
            "out_frame_count": 0,
            "max_b_frames": 2,
            "ring_entries": 3,
            "ring_bytes": 24,
            "first_index": -1,
            "second_index": -2,
            "observed_read_bytes_before_ring": 8,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public delayed-encoder flush path can invoke libxavs with a "
            "NULL frame before any frame was submitted. A successful zero-NAL "
            "library result enters the end-marker path with out_frame_count "
            "still zero. For max_b_frames=2, C remainder yields ring indices "
            "-1 and -2. The proof-only xavs header and function stub provide "
            "only that unavailable third-party no-output result; the context, "
            "allocation, indexing, packet allocation, and faulting XAVS_frame "
            "logic execute directly from the pinned production source. ASan "
            "reports an eight-byte heap read immediately before the allocated "
            "three-entry PTS ring."
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
