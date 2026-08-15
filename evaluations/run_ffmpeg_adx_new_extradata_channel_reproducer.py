"""Build and record the ADX NEW_EXTRADATA stale-channel-state crash."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.adx-new-extradata-channel-reproducer.v1"
REPAIR_COMMIT = "c10e7f5dc12367d0dfcc52983d427c6766425fa8"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_adx_new_extradata_channel_reproducer.c"),
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
    source = checkout / "libavcodec/adxdec.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, ADX source, and configured archives must exist")

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
            "libavcodec/adxdec.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    replacement_branch = source_text.split("if (new_extradata && new_extradata_size > 0)", 1)[
        1
    ].split("if (c->eof)", 1)[0]
    source_indicators = {
        "initial_header_captures_private_channel_count": all(
            term in source_text
            for term in (
                "c->channels      = avctx->ch_layout.nb_channels;",
                "c->header_parsed = 1;",
            )
        ),
        "replacement_header_changes_public_layout": all(
            term in source_text
            for term in (
                "av_channel_layout_uninit(&avctx->ch_layout);",
                "avctx->ch_layout.nb_channels = channels;",
            )
        ),
        "replacement_branch_leaves_private_channels_stale": (
            "c->channels" not in replacement_branch and "c->eof = 0;" in replacement_branch
        ),
        "buffer_uses_public_layout_before_private_channel_loop": (
            source_text.index("ff_get_buffer(avctx, frame, 0)")
            < source_text.index("for (ch = 0; ch < c->channels; ch++)")
        ),
        "later_repair_syncs_exact_state": (
            repair_result.returncode == 0
            and "Fixes: out of array access" in repair_text
            and "c->channels      = avctx->ch_layout.nb_channels;" in repair_text
            and "c->header_parsed = 1;" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_two_to_one_channel_transition": (
            "codec=adpcm_adx initial_channels=2 replacement_channels=1 "
            "packet_bytes=36 stale_decode_channels=2 allocated_planes=1" in combined
        ),
        "sanitizer_detected_invalid_access": (
            "AddressSanitizer" in combined or "UndefinedBehaviorSanitizer" in combined
        ),
        "write_access": "WRITE memory access" in combined or "WRITE of size" in combined,
        "adx_decoder_in_trace": "adx_decode" in combined and "adxdec.c" in combined,
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
        "source_sha256": {str(source.relative_to(checkout)): _sha256(source)},
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "initial_channels": 2,
            "replacement_channels": 1,
            "packet_bytes": 36,
            "block_bytes": 18,
            "private_decode_channels": 2,
            "allocated_audio_planes": 1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A valid two-channel ADX extradata header initializes the decoder's private "
            "channel count. Packet-side NEW_EXTRADATA then changes the public layout to "
            "one channel without synchronizing that private count. ff_get_buffer allocates "
            "one planar output channel, but the production decode loop still invokes the "
            "second channel with a null output plane and crashes under ASan. Later repair "
            "c10e7f5dc1 synchronizes exactly this state and identifies the out-of-array access."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
