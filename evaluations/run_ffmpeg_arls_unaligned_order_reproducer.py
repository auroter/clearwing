"""Build, run, and record the ARLS unaligned-order coefficient overread."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.arls-unaligned-order-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_arls_unaligned_order_reproducer.c"
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
        "-Llibavfilter",
        "-Llibavutil",
        "-lavfilter",
        "-lavutil",
        "-lm",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreFoundation",
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
        "filter": checkout / "libavfilter/af_arls.c",
        "template": checkout / "libavfilter/arls_template.c",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavfilter/libavfilter.a").is_file()
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
        "public_order_accepts_17": (
            '"order",    "set the filter order"' in source_text["filter"]
            and "1, INT16_MAX" in source_text["filter"]
        ),
        "kernel_aligned_to_16": (
            "s->kernel_size = FFALIGN(s->order, 16);"
            in source_text["filter"]
        ),
        "offset_uses_aligned_kernel": (
            "dst[0] = s->kernel_size - 1;" in source_text["filter"]
        ),
        "copy_uses_unaligned_order": (
            "memcpy(tmp, coeffs + order - *offset, order * sizeof(ftype));"
            in source_text["template"]
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_arls_graph": (
            "public_arls_graph=1 order=17 kernel_size=32 initial_offset=31 "
            "first_coefficient_index=-14 nb_samples=1"
            in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "sixty_eight_byte_read": "READ of size 68" in combined,
        "read_before_allocation": (
            "56 bytes before 272-byte region" in combined
        ),
        "arls_filter_in_trace": "filter_channels_float" in combined,
        "filter_aborted": run_result.returncode != 0,
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
        "geometry": {
            "order": 17,
            "kernel_size": 32,
            "initial_offset": 31,
            "first_coefficient_index": -14,
            "copy_elements": 17,
            "copy_bytes": 68,
            "bytes_before_allocation": 56,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A public two-input abuffer->arls->abuffersink graph selects "
            "order 17. ARLS rounds the allocation kernel to 32 and initializes "
            "the offset to 31, but the coefficient-copy expression still uses "
            "the unaligned order. Its first 17-float memcpy therefore begins "
            "at coefficient index -14 and ASan observes the resulting read."
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
