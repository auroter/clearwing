"""Build and record ffmpeg's borrowed subtitle-header lifetime proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.subtitle-header-uaf-reproducer.v1"
REPAIR_COMMIT = "fa391e90fb00510e926e305d6f8067cadf0f4153"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_subtitle_header_uaf_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _compile_command(*, checkout: Path, harness: Path, binary: Path, repaired: bool) -> list[str]:
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
    ]
    if repaired:
        command.append("-DREPAIRED")
    command.extend(
        [
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-g",
            "-O1",
            "-std=c17",
            "-o",
            str(binary),
            str(harness),
            str(checkout / "libavcodec/libavcodec.a"),
            str(checkout / "libavutil/libavutil.a"),
            "-lm",
            "-pthread",
        ]
    )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    header = checkout / "fftools/ffmpeg.h"
    decoder_source = checkout / "fftools/ffmpeg_dec.c"
    encoder_source = checkout / "fftools/ffmpeg_enc.c"
    codec_archive = checkout / "libavcodec/libavcodec.a"
    util_archive = checkout / "libavutil/libavutil.a"
    required = (
        harness,
        header,
        decoder_source,
        encoder_source,
        codec_archive,
        util_archive,
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact ffmpeg sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")

    compile_command = _compile_command(
        checkout=checkout, harness=harness, binary=binary, repaired=False
    )
    repaired_compile_command = _compile_command(
        checkout=checkout, harness=harness, binary=repaired_binary, repaired=True
    )
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = _run(repaired_compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")
    )
    repaired_run_result = (
        _run([str(repaired_binary)], cwd=checkout, env=environment)
        if repaired_compile_result.returncode == 0
        else subprocess.CompletedProcess([str(repaired_binary)], 127, "", "repaired compile failed")
    )

    header_text = header.read_text(encoding="utf-8", errors="replace")
    decoder_text = decoder_source.read_text(encoding="utf-8", errors="replace")
    encoder_text = encoder_source.read_text(encoding="utf-8", errors="replace")
    repair_diff = _run(
        [
            "git",
            "show",
            "--format=",
            REPAIR_COMMIT,
            "--",
            "fftools/ffmpeg.h",
            "fftools/ffmpeg_dec.c",
        ],
        cwd=checkout,
    )
    repair_message = _run(["git", "show", "-s", "--format=%s%n%b", REPAIR_COMMIT], cwd=checkout)
    source_indicators = {
        "decoder_exposes_borrowed_header_pointer": (
            "const uint8_t   *subtitle_header;" in header_text
            and "dp->dec.subtitle_header      = dp->dec_ctx->subtitle_header;" in decoder_text
        ),
        "decoder_thread_frees_header_owner": (
            "finish:" in decoder_text and "avcodec_free_context(&dp->dec_ctx);" in decoder_text
        ),
        "subtitle_encoder_later_reads_borrowed_header": (
            "if (dec->subtitle_header)" in encoder_text
            and "memcpy(enc_ctx->subtitle_header, dec->subtitle_header," in encoder_text
        ),
        "exact_repair_deep_copies_and_owns_header": (
            repair_diff.returncode == 0
            and "dp->dec.subtitle_header = av_mallocz" in repair_diff.stdout
            and "memcpy(dp->dec.subtitle_header, dp->dec_ctx->subtitle_header,"
            in repair_diff.stdout
            and "av_freep(&dp->dec.subtitle_header);" in repair_diff.stdout
        ),
        "repair_explicitly_identifies_use_after_free": (
            "deep-copy subtitle_header to fix use-after-free" in repair_message.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "proof_reaches_owner_release_before_sink": (
            "header_size=46 published=1" in combined and "decoder_context_freed=1" in combined
        ),
        "asan_reports_heap_use_after_free_read": (
            "AddressSanitizer: heap-use-after-free" in combined
            and "READ of size 46" in combined
            and "consume_header" in combined
        ),
        "asan_attributes_free_to_avcodec_context": (
            "freed by thread T0 here:" in combined and "avcodec_free_context" in combined
        ),
        "vulnerable_process_aborted": run_result.returncode != 0,
        "repaired_deep_copy_survives_owner_release": (
            repaired_run_result.returncode == 0
            and "decoder_context_freed=1" in repaired_combined
            and "encoder_header_checksum=3804" in repaired_combined
            and "AddressSanitizer" not in repaired_combined
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
        "decoder_source_sha256": _sha256(decoder_source),
        "encoder_source_sha256": _sha256(encoder_source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile_result.returncode,
        "repaired_compile_stdout": repaired_compile_result.stdout,
        "repaired_compile_stderr": repaired_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "ffmpeg's decoder object borrows AVCodecContext.subtitle_header, but "
            "the decoder thread frees that context while the scheduler may open "
            "the subtitle encoder later. The proof executes the exact ownership "
            "sequence with the configured libavcodec allocator and free path; ASan "
            "reports the encoder-side copy reading 46 freed bytes. Exact repair "
            "fa391e90fb deep-copies the header into Decoder-owned storage and frees "
            "that copy during decoder teardown; the repaired replay is clean."
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
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
