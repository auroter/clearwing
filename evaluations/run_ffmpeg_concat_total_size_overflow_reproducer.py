"""Build and record the concat protocol total-size signed overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.concat-total-size-overflow-reproducer.v1"
REPAIR_COMMIT = "702b0784b73d22da4004757a1f4f3b4cbae5f969"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_concat_total_size_overflow_reproducer.c"),
    )
    parser.add_argument("--fixture", type=Path, required=True)
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
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
        "libavformat/libavformat.a",
        "libavcodec/libavcodec.a",
        "libswresample/libswresample.a",
        "libswscale/libswscale.a",
        "libavutil/libavutil.a",
        "-lm",
        "-lbz2",
        "-lz",
    ]
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


def _head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    build_dir = args.build_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    fixture = args.fixture.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/concat.c"
    if (
        not harness.is_file()
        or not fixture.is_file()
        or not source.is_file()
        or not (build_dir / "libavformat/libavformat.a").is_file()
        or not (build_dir / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, fixture, concat source, and configured archives must exist")
    if _head(checkout) != _head(build_dir):
        raise ValueError("checkout and configured build must use the same commit")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command,
        cwd=build_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    environment: dict[str, str] | None = None
    if compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        run_result = subprocess.run(
            [str(binary), str(fixture)],
            cwd=build_dir,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary), str(fixture)], 127, "", "compile failed"
        )

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/concat.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "node_sizes_are_signed_64_bit": "int64_t     size;" in source_text,
        "total_is_accumulated_in_signed_64_bit": (
            "int64_t size, total_size = 0;" in source_text and "total_size += size;" in source_text
        ),
        "subfile_accepts_large_logical_end": all(
            term
            in (checkout / "libavformat/subfile.c").read_text(encoding="utf-8", errors="replace")
            for term in (
                "AV_OPT_TYPE_INT64, {.i64 = 0}, 0, INT64_MAX",
                "return end - c->start;",
            )
        ),
        "later_repair_guards_exact_addition": (
            repair_result.returncode == 0
            and "guard total_size overflow" in repair_text
            and "if (total_size > INT64_MAX - size)" in repair_text
            and "err = AVERROR_INVALIDDATA;" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_public_protocol_geometry": (
            "protocol=concat nodes=2 node_size=9000000000000000000 "
            "mathematical_total=18000000000000000000" in combined
        ),
        "ubsan_signed_integer_overflow": ("runtime error: signed integer overflow" in combined),
        "exact_addends_reported": ("9000000000000000000 + 9000000000000000000" in combined),
        "concat_open_in_trace": "concat_open" in combined,
        "public_avio_open_in_trace": "avio_open2" in combined,
        "process_aborted": run_result.returncode != 0,
    }
    expected_observed = (
        compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout) or None,
        "build_dir": str(build_dir),
        "build_commit": _head(build_dir) or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "fixture": str(fixture),
        "fixture_sha256": _sha256(fixture),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary), str(fixture)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "ubsan_options": environment["UBSAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "node_count": 2,
            "node_size": 9_000_000_000_000_000_000,
            "mathematical_total": 18_000_000_000_000_000_000,
            "int64_max": 2**63 - 1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Two public subfile URLs can advertise large logical ranges while "
            "both remain backed by one tiny seekable file. concat_open adds their "
            "individually valid signed sizes without an overflow guard. The public "
            "avio_open2 call therefore aborts under UBSan on the second addition; "
            "later repair 702b0784b7 guards that exact operation."
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
