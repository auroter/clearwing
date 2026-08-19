"""Build and record the three retained FFmpeg ranks 2341-2364 proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.wave-2341-2364-reproducers.v1"
REPAIR_COMMIT = "f7368f97b92a0afe8dc8368a4b6749704b740317"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness-dir",
        type=Path,
        default=Path(__file__).parent,
    )
    parser.add_argument("--binary-output-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _common_compile_prefix(sanitizers: str) -> list[str]:
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
        f"-fsanitize={sanitizers}",
    ]
    if "undefined" in sanitizers:
        command.append("-fno-sanitize-recover=undefined")
    command.extend(
        [
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-ffunction-sections",
            "-fdata-sections",
            "-g",
            "-O1",
            "-std=c17",
        ]
    )
    return command


def _filter_compile_command(
    *,
    harness: Path,
    binary: Path,
    sanitizers: str,
    guarded: bool,
    source: Path | None = None,
) -> list[str]:
    command = _common_compile_prefix(sanitizers)
    command.insert(2, "-I./libavfilter")
    if guarded:
        command.append("-DCRYSTALIZER_GUARDED_REPLAY=1")
    if source is not None:
        command.append(f'-DCRYSTALIZER_SOURCE="{source}"')
    command.extend(
        [
            "-o",
            str(binary),
            str(harness),
            "libavfilter/libavfilter.a",
            "libavutil/libavutil.a",
            "-lm",
        ]
    )
    command.append(
        "-Wl,-dead_strip" if platform.system() == "Darwin" else "-Wl,--gc-sections"
    )
    command.append("-pthread")
    return command


def _format_compile_command(
    *,
    harness: Path,
    binary: Path,
    sanitizers: str,
    defines: tuple[str, ...] = (),
) -> list[str]:
    command = _common_compile_prefix(sanitizers)
    command.insert(2, "-I./libavformat")
    command.extend(f"-D{define}" for define in defines)
    command.extend(
        [
            "-o",
            str(binary),
            str(harness),
            "-Llibavformat",
            "-Llibavcodec",
            "-Llibavutil",
            "-lavformat",
            "-lavcodec",
            "-lavutil",
            "-lm",
            "-lz",
        ]
    )
    if platform.system() == "Darwin":
        command.extend(
            [
                "-Wl,-dead_strip",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "VideoToolbox",
                "-framework",
                "AudioToolbox",
                "-framework",
                "Security",
                "-liconv",
            ]
        )
    else:
        command.append("-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _result_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness_dir = args.harness_dir.expanduser().resolve()
    binary_dir = args.binary_output_dir.expanduser().resolve()
    output = args.output.expanduser().resolve()
    harnesses = {
        "crystalizer": harness_dir / "ffmpeg_crystalizer_slice_overflow_reproducer.c",
        "ttml": harness_dir / "ffmpeg_ttml_timestamp_overflow_reproducer.c",
        "westwood": harness_dir / "ffmpeg_westwood_aud_counter_overflow_reproducer.c",
    }
    sources = {
        "crystalizer": checkout / "libavfilter/af_crystalizer.c",
        "ttml": checkout / "libavformat/ttmlenc.c",
        "westwood": checkout / "libavformat/westwood_audenc.c",
    }
    required = (
        *harnesses.values(),
        *sources.values(),
        checkout / "libavfilter/libavfilter.a",
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harnesses, exact FFmpeg sources, and configured archives must exist")

    binary_dir.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_source = binary_dir / "repaired-af_crystalizer.c"
    repaired_filters = binary_dir / "filters.h"
    repair_source_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/af_crystalizer.c"],
        cwd=checkout,
    )
    repair_filters_result = _run(
        ["git", "show", f"{REPAIR_COMMIT}:libavfilter/filters.h"],
        cwd=checkout,
    )
    if repair_filters_result.returncode == 0:
        repaired_filters.write_text(repair_filters_result.stdout, encoding="utf-8")
    if repair_source_result.returncode == 0 and repaired_filters.is_file():
        repaired_source.write_text(
            repair_source_result.stdout.replace(
                '#include "audio.h"',
                f'#include "{repaired_filters}"\n#include "audio.h"',
            ).replace('#include "filters.h"', ""),
            encoding="utf-8",
        )

    binaries = {
        "crystalizer_ubsan": binary_dir / "crystalizer-ubsan",
        "crystalizer_asan": binary_dir / "crystalizer-asan",
        "crystalizer_repaired": binary_dir / "crystalizer-repaired",
        "ttml_ubsan": binary_dir / "ttml-ubsan",
        "ttml_wrap": binary_dir / "ttml-wrap",
        "westwood_ubsan": binary_dir / "westwood-ubsan",
        "westwood_wrap": binary_dir / "westwood-wrap",
    }
    compile_commands = {
        "crystalizer_ubsan": _filter_compile_command(
            harness=harnesses["crystalizer"],
            binary=binaries["crystalizer_ubsan"],
            sanitizers="address,undefined",
            guarded=False,
        ),
        "crystalizer_asan": _filter_compile_command(
            harness=harnesses["crystalizer"],
            binary=binaries["crystalizer_asan"],
            sanitizers="address",
            guarded=True,
        ),
        "crystalizer_repaired": _filter_compile_command(
            harness=harnesses["crystalizer"],
            binary=binaries["crystalizer_repaired"],
            sanitizers="address,undefined",
            guarded=True,
            source=repaired_source,
        ),
        "ttml_ubsan": _format_compile_command(
            harness=harnesses["ttml"],
            binary=binaries["ttml_ubsan"],
            sanitizers="address,undefined",
        ),
        "ttml_wrap": _format_compile_command(
            harness=harnesses["ttml"],
            binary=binaries["ttml_wrap"],
            sanitizers="address",
            defines=("TTML_WRAP_REPLAY=1",),
        ),
        "westwood_ubsan": _format_compile_command(
            harness=harnesses["westwood"],
            binary=binaries["westwood_ubsan"],
            sanitizers="address,undefined",
        ),
        "westwood_wrap": _format_compile_command(
            harness=harnesses["westwood"],
            binary=binaries["westwood_wrap"],
            sanitizers="address",
        ),
    }
    compile_results: dict[str, subprocess.CompletedProcess[str]] = {}
    for name, command in compile_commands.items():
        if name == "crystalizer_repaired" and not (
            repaired_source.is_file() and repaired_filters.is_file()
        ):
            compile_results[name] = _failed(command, "repair source extraction failed")
        else:
            compile_results[name] = _run(command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    )
    run_results: dict[str, subprocess.CompletedProcess[str]] = {}
    for name, binary in binaries.items():
        if compile_results[name].returncode == 0:
            run_results[name] = _run([str(binary)], cwd=checkout, env=environment)
        else:
            run_results[name] = _failed([str(binary)], "compile failed")

    source_text = {
        name: path.read_text(encoding="utf-8", errors="replace")
        for name, path in sources.items()
    }
    master_results = {
        name: _run(["git", "show", f"origin/master:{path.relative_to(checkout)}"], cwd=checkout)
        for name, path in sources.items()
    }
    repaired_text = (
        repaired_source.read_text(encoding="utf-8", errors="replace")
        if repaired_source.is_file()
        else ""
    )
    crystalizer_ubsan = (
        run_results["crystalizer_ubsan"].stdout
        + run_results["crystalizer_ubsan"].stderr
    )
    crystalizer_asan = (
        run_results["crystalizer_asan"].stdout
        + run_results["crystalizer_asan"].stderr
    )
    crystalizer_repaired = (
        run_results["crystalizer_repaired"].stdout
        + run_results["crystalizer_repaired"].stderr
    )
    ttml_ubsan = run_results["ttml_ubsan"].stdout + run_results["ttml_ubsan"].stderr
    ttml_wrap = run_results["ttml_wrap"].stdout + run_results["ttml_wrap"].stderr
    westwood_ubsan = (
        run_results["westwood_ubsan"].stdout + run_results["westwood_ubsan"].stderr
    )
    westwood_wrap = (
        run_results["westwood_wrap"].stdout + run_results["westwood_wrap"].stderr
    )

    case_indicators = {
        "crystalizer": {
            "vulnerable_source_has_signed_slice_products": all(
                expression in source_text["crystalizer"]
                for expression in (
                    "(channels * jobnr) / nb_jobs",
                    "(channels * (jobnr+1)) / nb_jobs",
                )
            ),
            "ubsan_reports_exact_production_overflow": (
                "signed integer overflow: 65536 * 32768" in crystalizer_ubsan
                and "af_crystalizer.c:129" in crystalizer_ubsan
                and "filter_noinverse_fltp_clip" in crystalizer_ubsan
            ),
            "asan_reports_negative_channel_pointer_read": (
                "AddressSanitizer: use-after-poison" in crystalizer_asan
                and "READ of size 8" in crystalizer_asan
                and "filter_noinverse_fltp_clip" in crystalizer_asan
            ),
            "exact_repair_uses_int64_slice_helper": all(
                expression in repaired_text
                for expression in (
                    "ff_slice_pos(channels, jobnr, nb_jobs)",
                    "ff_slice_pos(channels, jobnr + 1, nb_jobs)",
                )
            ),
            "exact_repair_replay_is_clean": (
                run_results["crystalizer_repaired"].returncode == 0
                and "selected_channel_value=0.250000" in crystalizer_repaired
                and "runtime error:" not in crystalizer_repaired
                and "AddressSanitizer:" not in crystalizer_repaired
            ),
        },
        "ttml": {
            "production_uses_unchecked_end_addition": (
                'ttml_write_time(pb, "        end",   pkt->pts + pkt->duration);'
                in source_text["ttml"]
            ),
            "ubsan_reports_exact_production_overflow": (
                "signed integer overflow: 9223372036854775807 + 1" in ttml_ubsan
                and "libavformat/ttmlenc.c:172" in ttml_ubsan
                and "ttml_write_packet" in ttml_ubsan
            ),
            "ordinary_execution_emits_negative_end": (
                run_results["ttml_wrap"].returncode == 0
                and "wrapped_negative_end=1" in ttml_wrap
            ),
            "current_master_remains_unchecked": (
                master_results["ttml"].returncode == 0
                and "pkt->pts + pkt->duration" in master_results["ttml"].stdout
            ),
        },
        "westwood": {
            "public_packets_are_individually_valid": (
                "if (pkt->size > UINT16_MAX / 4)" in source_text["westwood"]
            ),
            "production_accumulates_signed_int": (
                "a->uncomp_size += pkt->size * 4;" in source_text["westwood"]
            ),
            "full_sequence_reaches_exact_boundary": (
                "prior_packets=32770 packet_size=16383" in westwood_ubsan
                and "prior_uncompressed=2147483640" in westwood_ubsan
                and "mathematical_uncompressed=2147549172" in westwood_ubsan
            ),
            "ubsan_reports_exact_production_overflow": (
                "signed integer overflow: 2147483640 + 65532" in westwood_ubsan
                and "libavformat/westwood_audenc.c:100" in westwood_ubsan
                and "wsaud_write_packet" in westwood_ubsan
            ),
            "ordinary_execution_publishes_negative_counter": (
                run_results["westwood_wrap"].returncode == 0
                and "uncompressed=-2147418124" in westwood_wrap
            ),
            "current_master_remains_unchecked": (
                master_results["westwood"].returncode == 0
                and "a->uncomp_size += pkt->size * 4;"
                in master_results["westwood"].stdout
            ),
        },
    }
    expected_observed = (
        all(result.returncode == 0 for result in compile_results.values())
        and run_results["crystalizer_ubsan"].returncode != 0
        and run_results["crystalizer_asan"].returncode != 0
        and run_results["ttml_ubsan"].returncode != 0
        and run_results["westwood_ubsan"].returncode != 0
        and all(all(indicators.values()) for indicators in case_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    master_head_result = _run(["git", "rev-parse", "origin/master"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "master_commit": master_head_result.stdout.strip() or None,
        "repair_commit": REPAIR_COMMIT,
        "harnesses": {
            name: {"path": str(path), "sha256": _sha256(path)}
            for name, path in harnesses.items()
        },
        "sources": {
            name: {"path": str(path), "sha256": _sha256(path)}
            for name, path in sources.items()
        },
        "compile_commands": compile_commands,
        "compile_results": {
            name: _result_payload(result) for name, result in compile_results.items()
        },
        "run_results": {
            name: _result_payload(result) for name, result in run_results.items()
        },
        "case_indicators": case_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The exact pinned Crystalizer callback overflows its signed channel-slice "
            "product and reads a negative channel pointer; repair f7368f97 uses "
            "ff_slice_pos and is clean. TTML adds individually valid signed packet PTS "
            "and duration without checking and emits a negative end timestamp after "
            "ordinary wrap. Westwood AUD accepts 32,771 individually valid maximum-size "
            "packets, overflows its signed uncompressed-size accumulator, and publishes "
            "a negative counter. Current upstream master retains both muxer expressions."
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
