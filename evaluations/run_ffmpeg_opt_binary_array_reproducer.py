"""Build and record the AVOption binary-array element overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.opt-binary-array-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_opt_binary_array_reproducer.c"),
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
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-ffunction-sections",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
    ]
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.extend(["libavutil/libavutil.a", "-lm", "-lz"])
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "implementation": checkout / "libavutil/opt.c",
        "public_header": checkout / "libavutil/opt.h",
    }
    if (
        not harness.is_file()
        or any(not source.is_file() for source in sources.values())
        or not (checkout / "libavutil/libavutil.a").is_file()
    ):
        raise ValueError("harness, AVOption sources, and configured libavutil must exist")

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
        environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
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

    implementation = sources["implementation"].read_text(encoding="utf-8", errors="replace")
    public_header = sources["public_header"].read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "array_flag_is_documented_for_regular_types": (
            "May be combined with another regular option type to declare an array" in public_header
        ),
        "binary_scalar_requires_pointer_and_trailing_length": all(
            term in public_header
            for term in (
                "Underlying C type is a uint8_t*",
                "immediately followed by an int containing the array length in bytes",
            )
        ),
        "binary_array_element_size_is_pointer_only": (
            "[AV_OPT_TYPE_BINARY]        = { sizeof(uint8_t *)" in implementation
        ),
        "array_allocates_descriptor_element_size": all(
            term in implementation
            for term in (
                "const size_t      elem_size = opt_type_desc[TYPE_BASE(o->type)].size;",
                "tmp = av_realloc_array(elems, nb_elems + 1, elem_size);",
            )
        ),
        "binary_setter_writes_length_after_pointer": all(
            term in implementation
            for term in (
                "int *lendst = (int *)(dst + 1);",
                "*lendst = 0;",
                "*lendst = len;",
            )
        ),
        "string_array_path_dispatches_to_binary_setter": all(
            term in implementation
            for term in (
                "ret = opt_set_elem(obj, target_obj, o, str, tmp);",
                "case AV_OPT_TYPE_BINARY:",
                "return set_string_binary(obj, o, val, dst);",
            )
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "exact_one_element_layout": (
            "api=av_opt_set option=binary_array element_size=8 "
            "length_offset=8 allocation_bytes=8 input_hex_bytes=1" in combined
        ),
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in combined,
        "four_byte_write": "WRITE of size 4" in combined,
        "write_starts_at_allocation_end": "0 bytes after 8-byte region" in combined,
        "avoption_implementation_in_trace": "opt.c" in combined,
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
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "source_sha256": {
            str(source.relative_to(checkout)): _sha256(source) for source in sources.values()
        },
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "array_elements": 1,
            "binary_element_allocation_bytes": 8,
            "binary_length_offset": 8,
            "length_write_bytes": 4,
            "decoded_binary_bytes": 1,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public AVOption API documents array flags as combinable with regular "
            "option types. A binary scalar occupies a pointer followed by an int length, "
            "but the generic array descriptor sizes every binary element as only the "
            "pointer. av_opt_set() allocates one pointer-sized slot for a one-element "
            "binary array and dispatches its hexadecimal string to set_string_binary, "
            "which writes the four-byte length immediately beyond that allocation."
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
