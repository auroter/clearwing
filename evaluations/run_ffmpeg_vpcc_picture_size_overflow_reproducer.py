"""Build and record the VP9 vpcC picture-size signed overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.vpcc-picture-size-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_vpcc_picture_size_overflow_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


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
        f'-DVPCC_SOURCE="{source}"',
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
        "libavformat/libavformat.a",
        "libavcodec/libavcodec.a",
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
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
            ]
        )
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/vpcc.c"
    mux_source = checkout / "libavformat/mux.c"
    mov_source = checkout / "libavformat/movenc.c"
    flv_source = checkout / "libavformat/flvenc.c"
    archives = [
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    ]
    required = [
        harness,
        source,
        mux_source,
        mov_source,
        flv_source,
        *archives,
    ]
    if any(not path.is_file() for path in required):
        raise ValueError("harness, vpcC sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, source, binary)
    compile_result = _run(compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if compile_result.returncode == 0:
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")

    master_result = _run(["git", "show", "master:libavformat/vpcc.c"], cwd=checkout)
    source_text = source.read_text(encoding="utf-8", errors="replace")
    mux_text = mux_source.read_text(encoding="utf-8", errors="replace")
    mov_text = mov_source.read_text(encoding="utf-8", errors="replace")
    flv_text = flv_source.read_text(encoding="utf-8", errors="replace")
    master_text = master_result.stdout
    source_indicators = {
        "picture_size_uses_signed_int_multiplication": (
            "int picture_size = par->width * par->height;" in source_text
        ),
        "unknown_level_reaches_picture_size_estimator": (
            "par->level == AV_LEVEL_UNKNOWN ?" in source_text
            and "get_vp9_level(par, frame_rate)" in source_text
        ),
        "generic_mux_check_accepts_positive_dimensions": (
            "if ((par->width <= 0 || par->height <= 0)" in mux_text
        ),
        "mov_and_flv_header_writers_reach_vpcc": (
            "ff_isom_write_vpcc(s, pb, track->extradata" in mov_text
            and "ff_isom_write_vpcc(s, pb, par->extradata" in flv_text
        ),
        "current_master_remains_unchecked": (
            master_result.returncode == 0
            and "int picture_size = par->width * par->height;" in master_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "positive_16bit_dimensions_exceed_int_max_product": (
            "width=65535 height=65535 mathematical_picture_size=4294836225 "
            "positive_mux_dimensions=1" in combined
        ),
        "ubsan_signed_integer_overflow": (
            "runtime error: signed integer overflow: 65535 * 65535 "
            "cannot be represented in type 'int'" in combined
        ),
        "production_get_vp9_level_in_trace": "in get_vp9_level" in combined,
        "vulnerable_process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "current_master_checked": master_result.returncode == 0,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": {
            "libavformat/vpcc.c": _sha256(source),
            "libavformat/mux.c": _sha256(mux_source),
            "libavformat/movenc.c": _sha256(mov_source),
            "libavformat/flvenc.c": _sha256(flv_source),
        },
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The vpcC level estimator multiplies positive AVCodecParameters "
            "width and height in signed int. Generic mux initialization only "
            "requires both dimensions to be positive, and the MOV and FLV VP9 "
            "header writers call this estimator when level is unknown. The "
            "exact-source proof uses 65535x65535; UBSan aborts on the production "
            "multiply because 4,294,836,225 exceeds INT_MAX."
        ),
        "run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
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
