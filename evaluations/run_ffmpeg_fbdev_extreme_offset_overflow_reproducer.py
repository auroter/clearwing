"""Record fbdev's public extreme-offset signed-overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.fbdev-extreme-offset-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_fbdev_extreme_offset_overflow_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavdevice/fbdev_enc.c"
    if not harness.is_file() or not source.is_file():
        raise ValueError("harness and pinned fbdev source must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = [
        "clang",
        "-fsanitize=undefined",
        "-fno-sanitize-recover=undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
    ]
    compile_result = subprocess.run(compile_command, check=False, capture_output=True, text=True)
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        run_result = subprocess.run(
            [str(binary)],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")

    source_text = source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "public_xoffset_accepts_full_int_domain": (
            '"xoffset"' in source_text
            and "OFFSET(xoffset)" in source_text
            and "INT_MIN, INT_MAX" in source_text
        ),
        "public_yoffset_accepts_full_int_domain": (
            '"yoffset"' in source_text
            and "OFFSET(yoffset)" in source_text
            and source_text.count("INT_MIN, INT_MAX") >= 2
        ),
        "x_clipping_adds_before_check": (
            "int diff = (video_width + fbdev->xoffset) - fbdev->varinfo.xres;" in source_text
        ),
        "negative_offsets_negated_in_int": (
            "if (-fbdev->xoffset >= video_width)" in source_text
            and "if (-fbdev->yoffset >= video_height)" in source_text
        ),
        "unchecked_offsets_feed_mapped_pointer": (
            "pout += bytes_per_pixel * fbdev->xoffset;" in source_text
            and "pout += fbdev->yoffset * fbdev->fixinfo.line_length;" in source_text
            and "memcpy(pout, pin, bytes_to_copy);" in source_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_extreme_geometry": (
            "video_width=640 framebuffer_width=640 bytes_per_pixel=4 "
            "xoffset=2147483647 int_max=2147483647" in combined
        ),
        "ubsan_signed_addition_overflow": ("signed integer overflow: 640 + 2147483647" in combined),
        "process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = subprocess.run(
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
        "checkout_commit": head_result.stdout.strip() or None,
        "repair_commit": None,
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
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The Linux fbdev output exposes xoffset and yoffset across the "
            "complete signed-int range. With a positive video width and "
            "xoffset=INT_MAX, its horizontal clipping guard evaluates "
            "video_width+xoffset in signed int before deciding the frame is "
            "offscreen. UBSan aborts on the exact arithmetic expression. "
            "INT_MIN independently overflows the unary-negation guards for "
            "both axes; wrapped values can then feed pointer adjustments and "
            "the framebuffer memcpy. Full muxer execution is Linux-device-"
            "gated, so this portable proof mirrors the exact production "
            "guard and is classified as a low-severity configuration DoS."
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
