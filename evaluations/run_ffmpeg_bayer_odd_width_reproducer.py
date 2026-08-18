"""Build and record Bayer odd-width source and destination guard faults."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import signal
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.bayer-odd-width-reproducer.v1"
WIDTH = 3
HEIGHT = 2
SOURCE_SIZE = WIDTH * HEIGHT
DESTINATION_STRIDE = WIDTH * 3
DESTINATION_SIZE = DESTINATION_STRIDE * HEIGHT


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_bayer_odd_width_reproducer.c"),
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
    return [
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
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-o",
        str(binary),
        str(harness),
        "-Llibswscale",
        "-Llibavutil",
        "-lswscale",
        "-lavutil",
        "-lm",
        "-pthread",
    ]


def _signal_name(returncode: int) -> str | None:
    if returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"signal_{-returncode}"


def _guard_fault(result: subprocess.CompletedProcess[str], mode: str) -> bool:
    accepted = (
        f"public_sws_scale=1 width={WIDTH} height={HEIGHT} "
        f"source_stride={WIDTH} destination_stride={DESTINATION_STRIDE} "
        f"guarded={mode} exact_size=1"
    )
    fatal_signals = {signal.SIGBUS, signal.SIGSEGV}
    return (
        accepted in result.stderr
        and result.returncode < 0
        and -result.returncode in fatal_signals
        and "unexpected_scale_rows=" not in result.stderr
    )


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "template": checkout / "libswscale/bayer_template.c",
        "wrapper": checkout / "libswscale/swscale_unscaled.c",
        "scale": checkout / "libswscale/swscale.c",
        "public_api": checkout / "libswscale/swscale.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libswscale/libswscale.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
        or any(not source.is_file() for source in sources.values())
    ):
        raise ValueError(
            "harness, configured FFmpeg archives, and Bayer sources must exist"
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
    runs: dict[str, subprocess.CompletedProcess[str]] = {}
    if compile_result.returncode == 0:
        for mode in ("source", "destination"):
            runs[mode] = subprocess.run(
                [str(binary), mode],
                cwd=checkout,
                check=False,
                capture_output=True,
                text=True,
            )

    source_text = {
        name: path.read_text(encoding="utf-8", errors="replace")
        for name, path in sources.items()
    }
    source_indicators = {
        "public_caller_owned_planes_and_strides": (
            "const uint8_t *const srcSlice[]" in source_text["public_api"]
            and "const int srcStride[]" in source_text["public_api"]
            and "int sws_scale(" in source_text["public_api"]
        ),
        "bayer_copy_loop_rounds_width_up_to_two_pixels": (
            "for (i = 0 ; i < width; i+= 2)" in source_text["template"]
            and "BAYER_TO_RGB24_COPY" in source_text["template"]
        ),
        "copy_macro_reads_and_writes_two_by_two_block": (
            "R(0, 1) =" in source_text["template"]
            and "R(1, 1) =" in source_text["template"]
            and "S(1, 1)" in source_text["template"]
        ),
        "wrapper_forwards_odd_source_width": (
            "copy(srcPtr, srcStride[0], dstPtr, dstStride[0], c->opts.src_w);"
            in source_text["wrapper"]
        ),
        "bayer_validation_only_constrains_slice_height": (
            "isBayer(sws->src_format) && srcSliceH <= 1"
            in source_text["scale"]
        ),
    }
    runtime_indicators = {
        "exact_source_guard_fault": (
            "source" in runs and _guard_fault(runs["source"], "source")
        ),
        "exact_destination_guard_fault": (
            "destination" in runs
            and _guard_fault(runs["destination"], "destination")
        ),
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
        "runs": {
            mode: {
                "command": [str(binary), mode],
                "returncode": result.returncode,
                "signal": _signal_name(result.returncode),
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            for mode, result in runs.items()
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "geometry": {
            "width": WIDTH,
            "height": HEIGHT,
            "source_stride": WIDTH,
            "source_size": SOURCE_SIZE,
            "first_invalid_source_offset": SOURCE_SIZE,
            "destination_stride": DESTINATION_STRIDE,
            "destination_size": DESTINATION_SIZE,
            "first_invalid_destination_offset": DESTINATION_SIZE,
            "destination_bytes_written_past_end": 3,
        },
        "expected_observed": expected_observed,
        "scope": (
            "The public sws_scale path accepts a 3x2 BAYER_BGGR8 frame with "
            "exact width-derived source and RGB24 destination strides. The "
            "two-pixel copy loop's final block reads source offset 6 from a "
            "six-byte plane and writes destination offsets 18 through 20 "
            "after an 18-byte plane. Independent guard-page executions fault "
            "on the exact source and destination boundaries."
        ),
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
