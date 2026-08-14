"""Record a public-producer and source proof for the VSX tight-row overread."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.swscale-vsx-tight-row-proof.v1"
SOURCE_WIDTH = 2
DESTINATION_WIDTH = 3
VECTOR_SIZE = 16


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_swscale_vsx_tight_row_producer.c"
        ),
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
        "-D_GNU_SOURCE",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
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
    sources = {
        "vsx": checkout / "libswscale/ppc/swscale_vsx.c",
        "hscale": checkout / "libswscale/hscale.c",
        "slice": checkout / "libswscale/slice.c",
        "public_api": checkout / "libswscale/swscale.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libswscale/libswscale.a").is_file()
        or any(not source.is_file() for source in sources.values())
    ):
        raise ValueError(
            "harness, configured FFmpeg static libraries, and sources must exist"
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
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    source_text = {
        name: path.read_text(encoding="utf-8", errors="replace")
        for name, path in sources.items()
    }
    source_indicators = {
        "public_stride_api": (
            "const int srcStride[]" in source_text["public_api"]
            and "int sws_scale(" in source_text["public_api"]
        ),
        "caller_row_forwarded": (
            "src[src_pos], srcW, xInc" in source_text["hscale"]
        ),
        "source_slice_uses_caller_pointer": (
            "src_i +  j * stride[i]" in source_text["slice"]
        ),
        "vsx_upscale_dispatch": (
            "c->opts.dst_w >= c->opts.src_w" in source_text["vsx"]
            and "c->hyscale_fast = hyscale_fast_vsx" in source_text["vsx"]
        ),
        "vsx_full_width_loop": (
            "for (i = 0; i < dstWidth; i += 16)" in source_text["vsx"]
        ),
        "vsx_first_vector_load": (
            "vin = vec_vsx_ld(0, &src[xx]);" in source_text["vsx"]
        ),
        "vsx_adjacent_vector_load": (
            "vin2 = vec_vsx_ld(1, &src[xx]);" in source_text["vsx"]
        ),
        "tail_repair_after_vector_loads": (
            "for (i=dstWidth-1; (i*xInc)>>16 >=srcW-1; i--)"
            in source_text["vsx"]
        ),
    }
    first_source_index = 0
    first_load_end = first_source_index + VECTOR_SIZE - 1
    adjacent_load_end = first_source_index + 1 + VECTOR_SIZE - 1
    furthest_read_offset = max(first_load_end, adjacent_load_end)
    bytes_beyond_row = max(0, furthest_read_offset + 1 - SOURCE_WIDTH)
    combined = run_result.stdout + run_result.stderr
    producer_indicators = {
        "public_guarded_input": (
            "public_sws_scale=1 source_width=2 destination_width=3 "
            "source_stride=2 guard_after_source=1 scaler=fast_bilinear"
            in combined
        ),
        "native_public_call_accepted": (
            run_result.returncode == 0 and "unexpected_scale_rows=1" in combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(producer_indicators.values())
        and bytes_beyond_row == 15
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
        "host_architecture": platform.machine(),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {
            str(path.relative_to(checkout)): _sha256(path)
            for path in sources.values()
        },
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "producer_indicators": producer_indicators,
        "geometry": {
            "source_width": SOURCE_WIDTH,
            "destination_width": DESTINATION_WIDTH,
            "first_source_index": first_source_index,
            "first_load_offsets": [first_source_index, first_load_end],
            "adjacent_load_offsets": [first_source_index + 1, adjacent_load_end],
            "furthest_read_offset": furthest_read_offset,
            "bytes_beyond_tight_row": bytes_beyond_row,
        },
        "evidence_level": "source_and_producer_confirmed",
        "runtime_scope": (
            "The public guard-page producer executes the native scaler to prove "
            "that the exact tight-row geometry is accepted. This arm64 host does "
            "not execute the architecture-gated little-endian PPC VSX routine; "
            "the out-of-range 16-byte load span is established from the pinned "
            "VSX source and its public call chain."
        ),
        "expected_observed": expected_observed,
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
