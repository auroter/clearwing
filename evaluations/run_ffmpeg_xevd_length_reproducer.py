"""Build, run, and record the libxevd oversized-NAL ASan reproducer."""

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

SCHEMA_VERSION = "cw.ffmpeg.xevd-length-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--xevd-library", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_xevd_length_reproducer.c"),
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


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _commit(path: Path) -> str | None:
    result = _run(["git", "rev-parse", "HEAD"], cwd=path)
    return result.stdout.strip() or None


def _compile_command(
    *,
    checkout: Path,
    xevd_library: Path,
    harness: Path,
    binary: Path,
) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-o",
        str(binary),
        str(harness),
        "-Llibavcodec",
        "-lavcodec",
        "-Llibavutil",
        "-lavutil",
        f"-L{xevd_library.parent}",
        "-lxevd",
        "-lm",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-liconv",
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
    else:
        command.extend(["-ldl", "-pthread"])
    return command


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    xevd_library = args.xevd_library.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    required = [
        checkout / "config.h",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
        xevd_library,
        harness,
    ]
    if any(not path.is_file() for path in required):
        raise ValueError(
            "checkout must contain configured ASan FFmpeg libraries and "
            "xevd-library must name the matching ASan libxevd build"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    command = _compile_command(
        checkout=checkout,
        xevd_library=xevd_library,
        harness=harness,
        binary=binary,
    )
    compile_result = _run(command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    library_path_name = (
        "DYLD_LIBRARY_PATH" if platform.system() == "Darwin" else "LD_LIBRARY_PATH"
    )
    existing_library_path = environment.get(library_path_name)
    environment[library_path_name] = os.pathsep.join(
        value
        for value in (str(xevd_library.parent), existing_library_path)
        if value
    )
    if compile_result.returncode == 0:
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    combined = run_result.stdout + run_result.stderr
    indicators = {
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "xevd_bsr_flush_sink": "xevd_bsr_flush" in combined,
        "xevd_sei_path": "xevd_eco_sei" in combined,
        "ffmpeg_receive_boundary": "libxevd_receive_frame" in combined,
        "packet_plus_padding_allocation": "72-byte region" in combined,
    }
    expected_observed = compile_result.returncode == 0 and all(indicators.values())
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _commit(checkout),
        "xevd_library": str(xevd_library),
        "xevd_library_sha256": _sha256(xevd_library),
        "xevd_commit": _commit(xevd_library.parent),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_command": command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public FFmpeg EVC decoder accepts a four-byte NAL length of "
            "256 in an eight-byte packet, forwards that unchecked size to "
            "xevd_decode, and lets XEVD's SEI reader cross the complete "
            "eight-byte packet plus 64-byte FFmpeg padding allocation."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    _write_json(output, payload)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
