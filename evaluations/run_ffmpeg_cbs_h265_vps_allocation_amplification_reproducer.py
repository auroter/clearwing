"""Build and record the HEVC CBS VPS allocation-amplification proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.cbs-h265-vps-allocation-amplification.v1"
REPAIR_COMMIT = "d2dd0a0a8f3d5540ffff9353a3898914c97b2b6b"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_cbs_h265_vps_allocation_amplification_reproducer.c"
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
                "-Wl,-dead_strip",
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = {
        "cbs_allocator": checkout / "libavcodec/cbs.c",
        "h265_descriptor": checkout / "libavcodec/cbs_h265.c",
        "h265_structures": checkout / "libavcodec/cbs_h265.h",
        "refstruct_allocator": checkout / "libavutil/refstruct.c",
        "configuration": checkout / "config.h",
    }
    if (
        not harness.is_file()
        or not (checkout / "libavcodec/libavcodec.a").is_file()
        or not (checkout / "libavutil/libavutil.a").is_file()
        or any(not path.is_file() for path in sources.values())
    ):
        raise ValueError("harness, sources, and configured FFmpeg archives must exist")

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

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavcodec/cbs_h265.c",
            "libavcodec/cbs_h265.h",
            "libavcodec/cbs_h265_syntax_template.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    source_text = {
        name: path.read_text(encoding="utf-8", errors="replace") for name, path in sources.items()
    }
    repair_text = repair_result.stdout
    source_indicators = {
        "cbs_h265_enabled": "#define CONFIG_CBS_H265 1" in source_text["configuration"],
        "vps_embeds_all_hrd_entries": (
            "H265RawHRDParameters hrd_parameters[HEVC_MAX_LAYER_SETS];"
            in source_text["h265_structures"]
        ),
        "vps_descriptor_allocates_whole_structure": (
            "CBS_UNIT_TYPE_INTERNAL_REF(HEVC_NAL_VPS, H265RawVPS, extension_data.data)"
            in source_text["h265_descriptor"]
        ),
        "allocation_precedes_vps_parse": (
            source_text["h265_descriptor"].find("err = ff_cbs_alloc_unit_content(ctx, unit);")
            < source_text["h265_descriptor"].find("err = cbs_h265_read_vps")
        ),
        "content_allocator_uses_descriptor_size": (
            "av_refstruct_alloc_ext_c(desc->content_size, 0," in source_text["cbs_allocator"]
        ),
        "content_allocation_is_zero_filled": (
            "memset(obj, 0, size);" in source_text["refstruct_allocator"]
        ),
        "later_repair_makes_hrd_dynamic": (
            repair_result.returncode == 0
            and "allocate VPS hrd_parameters dynamically" in repair_text
            and "H265RawHRDParameters *hrd_parameters;" in repair_text
            and "clusterfuzz-testcase-minimized" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "sixteen_valid_vps_units_parsed": (
            "packet_bytes=432 parsed_units=16 content_units=16" in combined
        ),
        "vulnerable_vps_is_7924248_bytes": ("vps_content_size=7924248" in combined),
        "proof_allocates_126787968_content_bytes": (
            "allocated_content_bytes=126787968" in combined
        ),
        "small_packet_projects_to_8gb": (
            "projected_1024_packet_bytes=27648 "
            "projected_1024_content_bytes=8114429952" in combined
        ),
        "process_succeeded": run_result.returncode == 0,
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
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_present": repair_result.returncode == 0,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
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
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "geometry": {
            "single_vps_packet_bytes": 27,
            "vps_content_bytes": 7_924_248,
            "proof_units": 16,
            "proof_packet_bytes": 432,
            "proof_content_bytes": 126_787_968,
            "projected_units": 1024,
            "projected_packet_bytes": 27_648,
            "projected_content_bytes": 8_114_429_952,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A packet containing sixteen complete 27-byte VPS NAL units "
            "passes through the production HEVC CBS read entry. Before "
            "parsing each VPS, CBS allocates and zero-fills the complete "
            "7,924,248-byte H265RawVPS because the structure embeds 1,024 "
            "HRD parameter sets. The 432-byte proof packet therefore retains "
            "126,787,968 bytes of unit content. At 1,024 units, only 27,648 "
            "input bytes imply 8,114,429,952 content bytes. Later repair "
            "d2dd0a0a8f, tied to a ClusterFuzz OOM testcase, makes the HRD "
            "array dynamic and sizes it to the count actually parsed."
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
