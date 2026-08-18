"""Build and record three JPEG2000 integer/state repair-oracle proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.jpeg2000-integer-state-reproducer.v1"
MASK_REPAIR = "59367afc3d4d86dbe2123c5ff750be7f54f6da7a"
ROI_REPAIR = "90a285ca782ebe633ba40ab123b6ff0cde9085a8"
CLEANUP_REPAIR = "6631bbc5d47082a6212e3c82fce0215fce2dbac6"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_jpeg2000_integer_state_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _compile_command(*, harness: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-w",
        "-I.",
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DJPEG2000_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=undefined",
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
        "libavcodec/jpeg2000dwt.c",
        "libavcodec/jpeg2000dsp.c",
        "libavcodec/jpeg2000htdec.c",
        "libavcodec/libavcodec.a",
        "libavutil/libavutil.a",
        "-lm",
    ]
    command.append("-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _replace_once(source: str, old: str, new: str, output: Path) -> None:
    if source.count(old) != 1:
        raise ValueError(f"expected one repair target, found {source.count(old)}")
    output.write_text(source.replace(old, new), encoding="utf-8")


def _result_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/jpeg2000dec.c"
    required = (
        harness,
        source,
        checkout / "libavcodec/jpeg2000.c",
        checkout / "libavcodec/mqc.c",
        checkout / "libavcodec/mqcdec.c",
        checkout / "libavcodec/jpeg2000dwt.c",
        checkout / "libavcodec/jpeg2000dsp.c",
        checkout / "libavcodec/jpeg2000htdec.c",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact JPEG2000 sources, and archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    mask_binary = binary.with_name(binary.name + "-mask-repaired")
    roi_binary = binary.with_name(binary.name + "-roi-repaired")
    cleanup_binary = binary.with_name(binary.name + "-cleanup-repaired")
    mask_source = binary.with_name(binary.name + "-mask-repaired-jpeg2000dec.c")
    roi_source = binary.with_name(binary.name + "-roi-repaired-jpeg2000dec.c")
    cleanup_source = binary.with_name(
        binary.name + "-cleanup-repaired-jpeg2000dec.c"
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    _replace_once(
        source_text,
        "int mask = 3 << (bpno - 1), y0, x, y, runlen, dec;",
        "int mask = (3u << bpno)>>1, y0, x, y, runlen, dec;",
        mask_source,
    )
    _replace_once(
        source_text,
        "val <<= roi_shift;",
        "val = (uint32_t)val << roi_shift;",
        roi_source,
    )
    cleanup_old = """    memset(&s->poc  , 0, sizeof(s->poc));
    s->numXtiles = s->numYtiles = 0;
    s->ncomponents = 0;
"""
    cleanup_new = """    memset(&s->poc  , 0, sizeof(s->poc));
    memset(s->roi_shift, 0, sizeof(s->roi_shift));
    s->numXtiles = s->numYtiles = 0;
    s->ncomponents = 0;
    s->has_ppm = 0;
    s->isHT = 0;
    s->precision = 0;
    s->colour_space = 0;
    s->pal8 = 0;
"""
    _replace_once(source_text, cleanup_old, cleanup_new, cleanup_source)

    compile_commands = {
        "vulnerable": _compile_command(harness=harness, source=source, binary=binary),
        "mask_repaired": _compile_command(
            harness=harness, source=mask_source, binary=mask_binary
        ),
        "roi_repaired": _compile_command(
            harness=harness, source=roi_source, binary=roi_binary
        ),
        "cleanup_repaired": _compile_command(
            harness=harness, source=cleanup_source, binary=cleanup_binary
        ),
    }
    compile_results = {
        name: _run(command, cwd=checkout)
        for name, command in compile_commands.items()
    }
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    )

    run_specs = {
        "mask_vulnerable": (binary, "cleanup-mask", "vulnerable"),
        "roi_vulnerable": (binary, "roi-shift", "vulnerable"),
        "cleanup_vulnerable": (binary, "cleanup-two-frame", "vulnerable"),
        "mask_repaired": (mask_binary, "cleanup-mask", "mask_repaired"),
        "roi_repaired": (roi_binary, "roi-shift", "roi_repaired"),
        "cleanup_repaired": (
            cleanup_binary,
            "cleanup-two-frame",
            "cleanup_repaired",
        ),
    }
    run_results: dict[str, subprocess.CompletedProcess[str]] = {}
    for name, (executable, mode, compile_name) in run_specs.items():
        if compile_results[compile_name].returncode == 0:
            run_results[name] = _run(
                [str(executable), mode], cwd=checkout, env=environment
            )
        else:
            run_results[name] = _failed(
                [str(executable), mode], f"{compile_name} compile failed"
            )

    repair_diffs = {
        "mask": _run(
            ["git", "show", "--format=", MASK_REPAIR, "--", source.relative_to(checkout)],
            cwd=checkout,
        ),
        "roi": _run(
            ["git", "show", "--format=", ROI_REPAIR, "--", source.relative_to(checkout)],
            cwd=checkout,
        ),
        "cleanup": _run(
            [
                "git",
                "show",
                "--format=",
                CLEANUP_REPAIR,
                "--",
                source.relative_to(checkout),
            ],
            cwd=checkout,
        ),
    }
    source_indicators = {
        "cleanup_pass_accepts_internal_minus_one_bitplane": (
            "if (bpno < -1 || bpno > 29)" in source_text
            and "decode_clnpass(s, t1, width, height, bpno + 1" in source_text
        ),
        "cleanup_mask_has_negative_shift_at_zero": (
            "int mask = 3 << (bpno - 1)" in source_text
        ),
        "roi_shift_uses_signed_reconstruction_value": (
            "if (roi_shift && (((uint32_t)val & ~mask) == 0))" in source_text
            and "val <<= roi_shift;" in source_text
        ),
        "ppm_state_outlives_freed_storage": (
            "s->has_ppm = 1;" in source_text
            and "av_freep(&s->packed_headers);" in source_text
            and "s->has_ppm = 0;" not in source_text
        ),
        "stale_ppm_initializes_null_second_frame_stream": (
            "if (s->has_ppm) {\n                    bytestream2_init("
            in source_text
        ),
        "exact_mask_repair_matches_commit": (
            "-    int mask = 3 << (bpno - 1)" in repair_diffs["mask"].stdout
            and "+    int mask = (3u << bpno)>>1" in repair_diffs["mask"].stdout
        ),
        "exact_roi_repair_matches_commit": (
            "-                val <<= roi_shift;" in repair_diffs["roi"].stdout
            and "+                val = (uint32_t)val << roi_shift;"
            in repair_diffs["roi"].stdout
        ),
        "exact_cleanup_repair_resets_header_state": all(
            value in repair_diffs["cleanup"].stdout
            for value in (
                "+    memset(s->roi_shift, 0, sizeof(s->roi_shift));",
                "+    s->has_ppm = 0;",
                "+    s->isHT = 0;",
                "+    s->precision = 0;",
                "+    s->colour_space = 0;",
                "+    s->pal8 = 0;",
            )
        ),
    }

    combined = {
        name: result.stdout + result.stderr for name, result in run_results.items()
    }
    runtime_indicators = {
        "mask_domain_reaches_internal_minus_one": (
            "source_internal_bpno=-1 cleanup_pass_bpno=0"
            in combined["mask_vulnerable"]
        ),
        "ubsan_reports_negative_cleanup_shift": (
            "runtime error: shift exponent -1 is negative"
            in combined["mask_vulnerable"]
            and "libavcodec/jpeg2000dec.c:1960" in combined["mask_vulnerable"]
            and run_results["mask_vulnerable"].returncode != 0
        ),
        "mask_exact_repair_is_clean": (
            run_results["mask_repaired"].returncode == 0
            and "mask_decode_result=1" in combined["mask_repaired"]
            and "runtime error:" not in combined["mask_repaired"]
            and "Sanitizer" not in combined["mask_repaired"]
        ),
        "roi_domain_reconstructs_high_magnitude_value": (
            "M_b=0 roi_shift=1 initial_bpno=29" in combined["roi_vulnerable"]
        ),
        "ubsan_reports_signed_roi_shift_overflow": (
            "left shift of 1610612736 by 1 places cannot be represented"
            in combined["roi_vulnerable"]
            and "libavcodec/jpeg2000dec.c:2111" in combined["roi_vulnerable"]
            and run_results["roi_vulnerable"].returncode != 0
        ),
        "roi_exact_repair_is_clean": (
            run_results["roi_repaired"].returncode == 0
            and "roi_decode_result=1 reconstructed=0xc0000000"
            in combined["roi_repaired"]
            and "runtime error:" not in combined["roi_repaired"]
            and "Sanitizer" not in combined["roi_repaired"]
        ),
        "first_frame_leaves_stale_ppm_with_null_storage": (
            "post_first_has_ppm=1 post_first_packed_headers_null=1"
            in combined["cleanup_vulnerable"]
        ),
        "ubsan_reports_second_frame_null_bytestream": (
            "runtime error: applying zero offset to null pointer"
            in combined["cleanup_vulnerable"]
            and "libavcodec/bytestream.h:144" in combined["cleanup_vulnerable"]
            and run_results["cleanup_vulnerable"].returncode != 0
        ),
        "cleanup_exact_repair_decodes_second_frame": (
            run_results["cleanup_repaired"].returncode == 0
            and "post_first_has_ppm=0 post_first_packed_headers_null=1"
            in combined["cleanup_repaired"]
            and "second_send=0 second_receive=0 width=1 height=1"
            in combined["cleanup_repaired"]
            and "runtime error:" not in combined["cleanup_repaired"]
            and "Sanitizer" not in combined["cleanup_repaired"]
        ),
    }
    expected_observed = (
        all(result.returncode == 0 for result in compile_results.values())
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "repair_commits": {
            "cleanup_mask": MASK_REPAIR,
            "roi_shift": ROI_REPAIR,
            "cross_frame_cleanup": CLEANUP_REPAIR,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "commands": compile_commands,
        "compile_results": {
            name: _result_payload(result)
            for name, result in compile_results.items()
        },
        "run_results": {
            name: _result_payload(result) for name, result in run_results.items()
        },
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
