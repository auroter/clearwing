"""Build and record the public RC4 zero-bit-key out-of-bounds read."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.rc4-zero-key-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).parent / "ffmpeg_rc4_zero_key_reproducer.c",
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
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
    source = checkout / "libavutil/rc4.c"
    header = checkout / "libavutil/rc4.h"
    required = (source, header, harness, checkout / "libavutil/libavutil.a")
    if any(not path.is_file() for path in required):
        raise ValueError("source, header, harness, and configured libavutil must exist")

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
        "libavutil/rc4.c",
        "libavutil/libavutil.a",
        "-lm",
        "-pthread",
    ]
    compile_command.append(
        "-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections"
    )
    compile_result = _run(compile_command, cwd=checkout)
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    )
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")
    )
    run_output = run_result.stdout + run_result.stderr
    source_text = source.read_text(encoding="utf-8", errors="replace")
    header_text = header.read_text(encoding="utf-8", errors="replace")
    master = _run(["git", "show", "origin/master:libavutil/rc4.c"], cwd=checkout)
    indicators = {
        "public_header_allows_every_multiple_of_eight": (
            "key_bits must be a multiple of 8" in header_text
        ),
        "implementation_accepts_zero_then_reads_key_zero": all(
            expression in source_text
            for expression in (
                "if (key_bits & 7)",
                "int keylen = key_bits >> 3;",
                "key[j]",
            )
        ),
        "asan_reports_zero_length_key_read": (
            run_result.returncode != 0
            and "AddressSanitizer: use-after-poison" in run_output
            and "READ of size 1" in run_output
            and "av_rc4_init" in run_output
        ),
        "current_master_remains_unchecked": (
            master.returncode == 0
            and "if (key_bits & 7)" in master.stdout
            and "key[j]" in master.stdout
        ),
    }
    expected_observed = compile_result.returncode == 0 and all(indicators.values())
    head = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    master_head = _run(["git", "rev-parse", "origin/master"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head.stdout.strip() or None,
        "master_commit": master_head.stdout.strip() or None,
        "harness": {
            "path": str(harness),
            "sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        },
        "source": {
            "path": str(source),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "compile_command": compile_command,
        "compile_result": _payload(compile_result),
        "run_result": _payload(run_result),
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public RC4 API documents key lengths that are multiples of eight, "
            "accepts a zero-bit key, and reads key[0] despite the resulting zero-byte "
            "key contract. The exact production source reports the poisoned byte read "
            "under ASan, and current upstream master remains unchecked."
        ),
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
