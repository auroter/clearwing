"""Record the WinRT gfxcapture crop/canvas division-overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.gfxcapture-crop-division-overflow.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_gfxcapture_crop_division_overflow_reproducer.c"),
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "options": checkout / "libavfilter/vsrc_gfxcapture.c",
        "winrt": checkout / "libavfilter/vsrc_gfxcapture_winrt.cpp",
        "hwcontext": checkout / "libavutil/hwcontext.c",
    }
    if not harness.is_file() or any(not path.is_file() for path in sources.values()):
        raise ValueError("harness and pinned gfxcapture sources must exist")

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
    compile_result = subprocess.run(
        compile_command,
        check=False,
        capture_output=True,
        text=True,
    )
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

    source_text = {
        name: path.read_text(encoding="utf-8", errors="replace") for name, path in sources.items()
    }
    setup_start = source_text["winrt"].find(
        "static int setup_gfxcapture_capture(AVFilterContext *avctx)"
    )
    setup_end = source_text["winrt"].find("static int prepare_render_resources", setup_start)
    setup_text = source_text["winrt"][setup_start:setup_end]
    source_indicators = {
        "canvas_accepts_minus_one": all(
            term in source_text["options"]
            for term in (
                '"width"',
                "OFFSET(canvas_width)",
                "INT_MIN, INT_MAX",
            )
        ),
        "crops_accept_int_max": all(
            term in source_text["options"]
            for term in (
                '"crop_left"',
                '"crop_right"',
                "OFFSET(crop_left)",
                "OFFSET(crop_right)",
                "0, INT_MAX",
            )
        ),
        "capture_border_can_skip_offsets": (
            '"capture_border"' in source_text["options"]
            and "if (!cctx->capture_border)" in setup_text
        ),
        "unchecked_crop_subtraction": (
            "int cap_w = wgctx->cap_size.Width - cctx->crop_left - cctx->crop_right;" in setup_text
        ),
        "exact_division_expression": (
            "cctx->canvas_width = (cap_w / cctx->canvas_width) * cctx->canvas_width;" in setup_text
        ),
        "no_predivision_geometry_guard": all(
            term not in setup_text
            for term in (
                "cap_w <= 0",
                "cap_w < 0",
                "canvas_width == -1",
                "AVERROR(EINVAL)",
            )
        ),
        "generic_dimension_check_is_later": (
            source_text["winrt"].find("ret = setup_gfxcapture_capture(avctx);")
            < source_text["winrt"].find("ret = init_hwframes_ctx(avctx);")
            and "ret = av_image_check_size(ctx->width, ctx->height, 0, ctx);"
            in source_text["hwcontext"]
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "options_form_int_min_without_prior_overflow": (
            "captured_width=1920 crop_left=1921 crop_right=2147483647 "
            "cap_w=-2147483648 canvas_width=-1 capture_border=1" in combined
        ),
        "ubsan_division_overflow": (
            "division of -2147483648 by -1 cannot be represented in type 'int'" in combined
        ),
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
        "repair_commit": None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {
            str(path.relative_to(checkout)): _sha256(path) for path in sources.values()
        },
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "captured_width": 1920,
            "crop_left": 1921,
            "crop_right": 2_147_483_647,
            "cap_w": -2_147_483_648,
            "canvas_width": -1,
            "capture_border": True,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The Windows-only gfxcapture filter exposes crops through "
            "INT_MAX and exposes -1 as a documented canvas rounding value. "
            "For a 1,920-pixel capture with border capture enabled, "
            "crop_left=1921 and crop_right=INT_MAX produce INT_MIN using "
            "two representable subtractions. width=-1 then evaluates the "
            "production expression INT_MIN / -1 before the generic hardware "
            "frame dimension check. The portable arithmetic harness executes "
            "that exact expression and UBSan aborts. Full filter execution is "
            "platform-gated because this checkout runs on macOS, and no later "
            "repair is known."
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
