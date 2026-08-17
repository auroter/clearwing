"""Prove the S/PDIF AAC probe's one-byte logical over-read and repair."""

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

SCHEMA_VERSION = "cw.ffmpeg.spdif-aac-probe-boundary-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
REPAIR_COMMIT = "15bbf3a21d11847de21aa429ec22acf9424953ec"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-build-dir", type=Path, required=True)
    parser.add_argument("--repaired-source-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_spdif_aac_probe_boundary_reproducer.c"
        ),
    )
    parser.add_argument("--vulnerable-binary-output", type=Path, required=True)
    parser.add_argument("--repaired-binary-output", type=Path, required=True)
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
    harness: Path,
    source: Path,
    binary: Path,
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
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wno-pointer-sign",
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
            str(source),
            "libavformat/libavformat.a",
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
    build: Path,
    harness: Path,
    source: Path,
    binary: Path,
) -> dict[str, Any]:
    command = _compile_command(harness, source, binary)
    compile_result = subprocess.run(
        command,
        cwd=build,
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
            cwd=build,
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
        "source": str(source),
        "source_sha256": _sha256(source),
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
    vulnerable_build = args.vulnerable_build_dir.expanduser().resolve()
    repaired_source_dir = args.repaired_source_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    vulnerable_binary = args.vulnerable_binary_output.expanduser().resolve()
    repaired_binary = args.repaired_binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    vulnerable_source = vulnerable_build / "libavformat/spdifdec.c"
    repaired_source = repaired_source_dir / "libavformat/spdifdec.c"
    components = vulnerable_build / "config_components.h"
    required = (
        harness,
        vulnerable_source,
        repaired_source,
        components,
        vulnerable_build / "libavformat/libavformat.a",
        vulnerable_build / "libavcodec/libavcodec.a",
        vulnerable_build / "libavutil/libavutil.a",
    )
    if _head(vulnerable_build) != VULNERABLE_COMMIT or not all(
        path.is_file() for path in required
    ):
        raise ValueError(
            f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}"
        )
    if _head(repaired_source_dir) != REPAIR_COMMIT:
        raise ValueError(f"repaired source tree must be at {REPAIR_COMMIT}")
    if "#define CONFIG_SPDIF_DEMUXER 1" not in components.read_text(
        encoding="utf-8", errors="replace"
    ):
        raise ValueError("configured build must enable the S/PDIF demuxer")

    vulnerable_binary.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    vulnerable = _compile_and_run(
        vulnerable_build,
        harness,
        vulnerable_source,
        vulnerable_binary,
    )
    repaired = _compile_and_run(
        vulnerable_build,
        harness,
        repaired_source,
        repaired_binary,
    )

    vulnerable_text = vulnerable_source.read_text(
        encoding="utf-8", errors="replace"
    )
    repaired_text = repaired_source.read_text(
        encoding="utf-8", errors="replace"
    )
    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/spdifdec.c",
        ],
        cwd=vulnerable_build,
        check=False,
        capture_output=True,
        text=True,
    )
    source_indicators = {
        "vulnerable_check_is_one_byte_short": (
            "buf + 4 + AV_AAC_ADTS_HEADER_SIZE > p_buf + buf_size"
            in vulnerable_text
        ),
        "aac_parser_starts_at_fifth_byte": (
            "&buf[5], &offset, codec" in vulnerable_text
        ),
        "repair_requires_the_missing_byte": (
            "buf + 5 + AV_AAC_ADTS_HEADER_SIZE > p_buf + buf_size"
            in repaired_text
        ),
        "repair_identifies_uninitialized_read": (
            repair_result.returncode == 0
            and "fix reading past the buffer" in repair_result.stdout
            and "read of uninitialized memory" in repair_result.stdout
        ),
    }
    common_output = (
        "logical=14 allocated=15 tail=fc adts=0 samples=1024 "
        "frames=1 score=12"
    )
    runtime_indicators = {
        "vulnerable_run_succeeded": vulnerable["returncode"] == 0,
        "repaired_run_succeeded": repaired["returncode"] == 0,
        "tail_completes_valid_adts_header": (
            common_output in vulnerable["stdout"]
            and common_output in repaired["stdout"]
        ),
        "vulnerable_probe_consumed_logical_tail": (
            f"{common_output} codec=86018" in vulnerable["stdout"]
        ),
        "repaired_probe_did_not_consume_tail": (
            f"{common_output} codec=0" in repaired["stdout"]
        ),
        "sanitizer_clean": "Sanitizer" not in (
            vulnerable["stdout"]
            + vulnerable["stderr"]
            + repaired["stdout"]
            + repaired["stderr"]
        ),
    }
    expected_observed = all(source_indicators.values()) and all(
        runtime_indicators.values()
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "vulnerable_build": str(vulnerable_build),
        "vulnerable_commit": _head(vulnerable_build),
        "repaired_source_dir": str(repaired_source_dir),
        "repair_commit": _head(repaired_source_dir),
        "repair_commit_output": repair_result.stdout,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "logical_buffer_size": 14,
        "allocated_buffer_size": 15,
        "out_of_bounds_tail_byte": "fc",
        "vulnerable_run": vulnerable,
        "repaired_run": repaired,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The IEC 61937 probe sees one complete sync and exactly six "
            "logically available bytes of an AAC ADTS header. The vulnerable "
            "bound admits it and av_adts_header_parse consumes a seventh byte "
            "outside the declared buffer, setting the codec to AAC. Exact "
            "repair adds the missing byte to the precondition and leaves the "
            "codec unset under the identical allocation."
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
