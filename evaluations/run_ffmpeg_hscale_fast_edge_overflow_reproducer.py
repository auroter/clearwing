"""Build and record the fast-bilinear final-edge signed-overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.hscale-fast-edge-overflow-reproducer.v1"
REPAIR_COMMIT = "ec2a4105e2a5db5941e93326ee89897774a95462"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_hscale_fast_edge_overflow_reproducer.c"),
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
    source = checkout / "libswscale/hscale_fast_bilinear.c"
    x86_source = checkout / "libswscale/x86/hscale_fast_bilinear_simd.c"
    if not harness.is_file() or not source.is_file() or not x86_source.is_file():
        raise ValueError("harness and pinned fast-bilinear sources must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=undefined",
        "-fno-sanitize-recover=undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
        str(source),
    ]
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

    source_text = source.read_text(encoding="utf-8", errors="replace")
    x86_text = x86_source.read_text(encoding="utf-8", errors="replace")
    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=",
            REPAIR_COMMIT,
            "--",
            str(source.relative_to(checkout)),
            str(x86_source.relative_to(checkout)),
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_indicators = {
        "c_edge_clamp_multiplies_in_int": (
            "(i*xInc)>>16 >=srcW-1" in source_text and "(i*(int64_t)xInc)>>16" not in source_text
        ),
        "mmx_edge_clamp_has_same_expression": (
            x86_text.count("(i*xInc)>>16 >=srcW-1") == 2 and "(i*(int64_t)xInc)>>16" not in x86_text
        ),
        "later_repair_promotes_all_variants": (
            repair_result.returncode == 0
            and repair_result.stdout.count("(i*(int64_t)xInc)>>16") >= 4
            and "avoid overflow in fast bilinear edge handling"
            in subprocess.run(
                ["git", "show", "-s", "--format=%s", REPAIR_COMMIT],
                cwd=checkout,
                check=False,
                capture_output=True,
                text=True,
            ).stdout
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "wide_upscale_geometry": (
            "src_width=40000 dst_width=40032 last_i=40031 x_inc=65484" in combined
        ),
        "mathematical_product_exceeds_int_max": (
            "mathematical_product=2621390004 int_max=2147483647" in combined
        ),
        "ubsan_signed_multiplication_overflow": (
            "signed integer overflow: 40031 * 65484" in combined
        ),
        "production_helper_in_trace": "hscale_fast_bilinear.c" in combined,
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
        "repair_commit": REPAIR_COMMIT,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {
            str(source.relative_to(checkout)): _sha256(source),
            str(x86_source.relative_to(checkout)): _sha256(x86_source),
        },
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
            "Fast bilinear scaling performs the final source-edge test as "
            "signed int i*xInc in its C and MMXEXT paths. A public 40000-to-"
            "40032 wide upscale makes the last product 2,621,390,004. The "
            "harness compiles and executes the pinned production C helper; "
            "UBSan aborts at the multiplication. In ordinary builds the wrap "
            "can suppress the edge clamp and interpolate with the padding "
            "byte. Exact later repair ec2a4105e2 promotes the multiplication "
            "to int64_t in the C, MMXEXT, and VSX implementations."
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
