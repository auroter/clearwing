"""Build and record the HEIF ICC profile copy-amplification proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.heif-icc-profile-amplification.v1"
REPAIR_COMMIT = "711cdae64f572ad2cb2ae879d33ac63f828e6e08"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_heif_icc_profile_amplification_reproducer.c"),
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


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _compile_command(harness: Path, source: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavformat",
        "-I./libavcodec",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DMOV_SOURCE="{source}"',
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-inline",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wno-pointer-sign",
        "-Wno-switch",
        "-Wno-parentheses",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
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
            ]
        )
    return command


def _make_repaired_source(source: Path, header: Path, destination: Path) -> tuple[Path, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    repaired_source = destination / "mov.c"
    repaired_header = destination / "isom.h"
    source_text = source.read_text(encoding="utf-8")
    header_text = header.read_text(encoding="utf-8")

    old_guard = """        } else {
            av_freep(&item->icc_profile);
            icc_profile = item->icc_profile = av_malloc(atom.size - 4);
"""
    new_guard = """        } else {
            if (c->heif_icc_profile_items >= c->fc->max_streams) {
                av_log(c->fc, AV_LOG_WARNING,
                       "HEIF ICC profile copies exceed cap %d; ignoring further items\\n",
                       c->fc->max_streams);
                return 0;
            }
            av_freep(&item->icc_profile);
            icc_profile = item->icc_profile = av_malloc(atom.size - 4);
"""
    old_increment = """            item->icc_profile_size = atom.size - 4;
        }
        ret = ffio_read_size(pb, icc_profile, atom.size - 4);
"""
    new_increment = """            item->icc_profile_size = atom.size - 4;
            c->heif_icc_profile_items++;
        }
        ret = ffio_read_size(pb, icc_profile, atom.size - 4);
"""
    old_field = """    AVDictionary* decryption_keys;
} MOVContext;
"""
    new_field = """    AVDictionary* decryption_keys;
    unsigned heif_icc_profile_items;
} MOVContext;
"""
    if source_text.count(old_guard) != 1 or source_text.count(old_increment) != 1:
        raise ValueError("pinned mov.c does not match the exact repair context")
    if header_text.count(old_field) != 1:
        raise ValueError("pinned isom.h does not match the exact repair context")

    repaired_source.write_text(
        source_text.replace(old_guard, new_guard).replace(old_increment, new_increment),
        encoding="utf-8",
    )
    repaired_header.write_text(header_text.replace(old_field, new_field), encoding="utf-8")
    return repaired_source, repaired_header


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/mov.c"
    header = checkout / "libavformat/isom.h"
    archives = [
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libavutil/libavutil.a",
    ]
    if any(not path.is_file() for path in [harness, source, header, *archives]):
        raise ValueError("harness, MOV sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary = binary.with_name(binary.name + "-repaired")
    repaired_directory = binary.with_name(binary.name + "-repaired-source")
    repaired_source, repaired_header = _make_repaired_source(source, header, repaired_directory)

    compile_command = _compile_command(harness, source, binary)
    repaired_compile_command = _compile_command(harness, repaired_source, repaired_binary)
    compile_result = _run(compile_command, cwd=checkout)
    repaired_compile_result = _run(repaired_compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    repaired_run_result = (
        _run([str(repaired_binary)], cwd=checkout, env=environment)
        if repaired_compile_result.returncode == 0
        else _failed([str(repaired_binary)], "repaired compile failed")
    )

    repair_result = _run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/mov.c",
            "libavformat/isom.h",
        ],
        cwd=checkout,
    )
    source_text = source.read_text(encoding="utf-8", errors="replace")
    repair_text = repair_result.stdout
    source_indicators = {
        "iinf_count_controls_heif_item_population": (
            "entry_count = version ? avio_rb32(pb) : avio_rb16(pb);" in source_text
            and "FFMAX(entry_count, c->nb_heif_item)" in source_text
        ),
        "ipma_count_and_ids_are_input_controlled": (
            "count   = avio_rb32(pb);" in source_text
            and "for (int i = 0; i < count; i++)" in source_text
            and "int item_id = version ? avio_rb32(pb) : avio_rb16(pb);" in source_text
        ),
        "shared_property_replayed_per_association": (
            "c->cur_item_id = item_id;" in source_text
            and "ffio_init_read_context(&ref->b, ref->data, ref->size);" in source_text
        ),
        "profile_copied_into_each_item_without_cap": (
            "icc_profile = item->icc_profile = av_malloc(atom.size - 4);" in source_text
            and "ret = ffio_read_size(pb, icc_profile, atom.size - 4);" in source_text
            and "heif_icc_profile_items" not in source_text
        ),
        "exact_repair_caps_copies_at_max_streams": (
            repair_result.returncode == 0
            and "cap HEIF ICC profile copies" in repair_text
            and "c->heif_icc_profile_items >= c->fc->max_streams" in repair_text
            and "c->heif_icc_profile_items++;" in repair_text
        ),
    }

    combined = run_result.stdout + run_result.stderr
    repaired_combined = repaired_run_result.stdout + repaired_run_result.stderr
    runtime_indicators = {
        "one_megabyte_property_has_32_associations": (
            "shared_profile_bytes=1048576 ipma_item_associations=32 " in combined
        ),
        "vulnerable_path_copies_all_32_profiles": (
            "copied_items=32 copied_bytes=33554432 result=0" in combined
        ),
        "exact_repair_limits_copies_to_eight": (
            "max_streams=8 copied_items=8 copied_bytes=8388608 result=0" in repaired_combined
        ),
        "both_replays_complete_cleanly": (
            run_result.returncode == 0
            and repaired_run_result.returncode == 0
            and "AddressSanitizer" not in combined
            and "AddressSanitizer" not in repaired_combined
            and "runtime error:" not in combined
            and "runtime error:" not in repaired_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and repaired_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": {
            "libavformat/mov.c": _sha256(source),
            "libavformat/isom.h": _sha256(header),
        },
        "repaired_source_sha256": _sha256(repaired_source),
        "repaired_header_sha256": _sha256(repaired_header),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile_result.returncode,
        "repaired_compile_stdout": repaired_compile_result.stdout,
        "repaired_compile_stderr": repaired_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "geometry": {
            "shared_profile_bytes": 1_048_576,
            "item_associations": 32,
            "configured_max_streams": 8,
            "vulnerable_copied_bytes": 33_554_432,
            "repaired_copied_bytes": 8_388_608,
        },
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "HEIF ipma can associate one stored colr/prof property with many "
            "attacker-created item IDs. The production mov_read_colr sink "
            "allocates and copies the complete shared profile separately for "
            "every association. The proof replays 32 associations to one "
            "1 MiB profile and observes 32 MiB copied. Applying exact repair "
            "711cdae64f to the pinned sources caps the same replay at the "
            "configured max_streams value of eight, retaining only 8 MiB."
        ),
        "vulnerable_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "repaired_run": {
            "command": [str(repaired_binary)],
            "returncode": repaired_run_result.returncode,
            "stdout": repaired_run_result.stdout,
            "stderr": repaired_run_result.stderr,
        },
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
