"""Build and record VC-1 test muxer's short-extradata heap overread."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.vc1test-short-extradata-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_vc1test_missing_extradata_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compile_command(harness: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavformat",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/vc1testenc.c"
    mux_source = checkout / "libavformat/mux.c"
    if any(
        not path.is_file()
        for path in (
            harness,
            source,
            mux_source,
            checkout / "libavformat/libavformat.a",
            checkout / "libavcodec/libavcodec.a",
            checkout / "libavutil/libavutil.a",
        )
    ):
        raise ValueError("harness, pinned VC-1 mux sources, and archives must exist")

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
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    run_result = (
        subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if compile_result.returncode == 0
        else subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    mux_text = mux_source.read_text(encoding="utf-8", errors="replace")
    master_result = subprocess.run(
        ["git", "show", "master:libavformat/vc1testenc.c"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    video_validation = mux_text[mux_text.index("case AVMEDIA_TYPE_VIDEO:") :]
    video_validation = video_validation[: video_validation.index("break;")]
    source_indicators = {
        "vc1test_declares_four_extradata_bytes": (
            "avio_wl32(pb, 4);" in source_text
        ),
        "vc1test_reads_four_bytes_unconditionally": (
            "avio_write(pb, par->extradata, 4);" in source_text
        ),
        "header_has_no_extradata_size_guard": (
            "extradata_size" not in source_text[
                source_text.index("static int vc1test_write_header") :
                source_text.index("static int vc1test_write_packet")
            ]
        ),
        "generic_video_validation_only_requires_dimensions": (
            "par->width <= 0 || par->height <= 0" in video_validation
            and "extradata_size" not in video_validation
        ),
        "current_master_remains_unrepaired": (
            master_result.returncode == 0
            and "avio_write(pb, par->extradata, 4);" in master_result.stdout
            and "extradata_size < 4" not in master_result.stdout
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "short_public_codec_parameters_replayed": (
            "codec=wmv3 extradata_allocation=1 extradata_size=1" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "four_byte_read_after_one_byte_allocation": (
            "READ of size 4" in combined
            and "0 bytes after 1-byte region" in combined
        ),
        "output_copy_in_trace": "in avio_write" in combined,
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
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": commit_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The VC-1 test muxer declares and writes four sequence-header bytes but "
            "never checks WMV3 extradata_size. Generic mux initialization validates "
            "the codec and dimensions, not this format-specific minimum. A public "
            "one-byte AVCodecParameters extradata allocation therefore makes the "
            "exact production header writer pass four bytes to avio_write. ASan "
            "reports a four-byte heap read beginning at the end of that one-byte "
            "allocation. In ordinary execution the three adjacent heap bytes are "
            "copied into the output header, making this a small information-disclosure "
            "and availability root. Current upstream master remains unchecked."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
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
