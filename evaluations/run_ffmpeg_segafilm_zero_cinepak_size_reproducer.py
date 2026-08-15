"""Build and record Sega FILM's zero Cinepak-size division."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.segafilm-zero-cinepak-size-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_segafilm_zero_cinepak_size_reproducer.c"),
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
    sources = {
        "segafilm_muxer": checkout / "libavformat/segafilmenc.c",
        "mux_framework": checkout / "libavformat/mux.c",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError("harness, Sega FILM sources, and configured FFmpeg archives must exist")

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
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
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

    segafilm = sources["segafilm_muxer"].read_text(encoding="utf-8", errors="replace")
    mux = sources["mux_framework"].read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "public_cinepak_packet_path": ("if (codec_id == AV_CODEC_ID_CINEPAK)" in segafilm),
        "encoded_size_is_packet_controlled": (
            "encoded_buf_size = AV_RB24(&pkt->data[1]);" in segafilm
        ),
        "zero_divisor_reaches_modulo": (
            "encoded_buf_size != pkt->size && " "(pkt->size % encoded_buf_size) != 0" in segafilm
        )
        and "encoded_buf_size == 0" not in segafilm,
        "mux_framework_has_no_minimum_packet_size": (
            "ret = ffofmt(s->oformat)->write_packet(s, pkt);" in mux and "pkt->size < 4" not in mux
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_zero_size_state": (
            "packet_size=4 encoded_buf_size=0 modulo_divisor=0 cinepak=1" in combined
        ),
        "ubsan_division_by_zero": "runtime error: division by zero" in combined,
        "exact_source_line": "segafilmenc.c:61:57" in combined,
        "production_function_in_trace": "in film_write_packet" in combined,
        "ubsan_summary": "UndefinedBehaviorSanitizer: undefined-behavior" in combined,
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
        "source_sha256": {name: _sha256(path) for name, path in sources.items()},
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "packet_bytes": 4,
            "encoded_size_field_offset": 1,
            "encoded_size_field_bytes": 3,
            "encoded_buf_size": 0,
            "modulo_divisor": 0,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A four-byte Cinepak packet contains the complete three-byte size "
            "field at offsets one through three. Setting those bytes to zero "
            "makes encoded_buf_size zero while pkt->size remains four. The "
            "first half of the compound condition succeeds and the second "
            "evaluates pkt->size modulo zero. The generic mux framework does "
            "not impose a Cinepak-specific minimum or nonzero header field. "
            "The direct pinned production-function harness reaches the branch "
            "with a fully allocated packet, and UBSan aborts on division by "
            "zero at segafilmenc.c:61."
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
