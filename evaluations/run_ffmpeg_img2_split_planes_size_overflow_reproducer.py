"""Build and record image2 split-plane size-overflow reproduction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.img2-split-planes-size-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_img2_split_planes_size_overflow_reproducer.c"
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


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
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
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
        "-Llibavutil",
        "-lavformat",
        "-lavcodec",
        "-lavutil",
        "-lm",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "Security",
                "-liconv",
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
    source = checkout / "libavformat/img2enc.c"
    if (
        not harness.is_file()
        or not source.is_file()
        or not (checkout / "libavformat/libavformat.a").is_file()
    ):
        raise ValueError("harness, image2 source, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        environment["UBSAN_OPTIONS"] = (
            "halt_on_error=0:print_stacktrace=1"
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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "plane_sizes_use_signed_int_products": (
            "int ysize = par->width * par->height;" in source_text
            and "int usize = AV_CEIL_RSHIFT(par->width" in source_text
        ),
        "total_size_check_uses_signed_addition": (
            "if (ysize + 2*usize + (desc->nb_components > 3) * ysize"
            in source_text
        ),
        "wrapped_check_precedes_io_writes": all(
            value in source_text
            for value in (
                "write_and_close(s, &pb[0], pkt->data",
                "write_and_close(s, &pb[1], pkt->data + ysize",
                "write_and_close(s, &pb[2], pkt->data + ysize + usize",
            )
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_split_plane_muxer": (
            "muxer=image2 split_planes=1 width=46340 height=46340" in combined
        ),
        "true_size_exceeds_int_max": (
            "y_size=2147395600 uv_size=536848900 true_total=3221093400"
            in combined
        ),
        "valid_padded_one_byte_packet": (
            "packet_size=1 packet_padding=64 output_io_buffer=4096" in combined
        ),
        "ubsan_signed_addition_overflow": (
            "runtime error: signed integer overflow" in combined
            and "img2enc.c:220" in combined
        ),
        "production_avio_overread": (
            "READ of size 4096" in combined and "in avio_write+" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "packet_padding_boundary_crossed": (
            "0 bytes after 65-byte region" in combined
        ),
        "muxer_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout) or None,
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
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public image2 muxer is configured for planar raw video and a "
            ".y target, with dimensions whose individual Y/U/V sizes fit int "
            "but whose total does not. The signed total-size check wraps and "
            "passes a valid one-byte padded AVPacket to output I/O as a "
            "2,147,395,600-byte Y plane. A contract-valid custom io_open "
            "provides an ordinary 4,096-byte AVIO buffer; production avio_write "
            "immediately copies that amount beyond the packet plus mandatory "
            "padding, and ASan aborts."
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
