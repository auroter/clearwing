"""Build and record the sofa2wavs SourcePosition heap over-read."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.sofa2wavs-source-position-reproducer.v1"
FFMPEG_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
LIBMYSOFA_COMMIT = "90531bdb0b485dd36e8a14b3e37ce1c47c54d669"
LIBMYSOFA_SOURCES = (
    "src/hrtf/reader.c",
    "src/hdf/superblock.c",
    "src/hdf/dataobject.c",
    "src/hdf/btree.c",
    "src/hdf/fractalhead.c",
    "src/hdf/gunzip.c",
    "src/hdf/gcol.c",
    "src/hrtf/check.c",
    "src/hrtf/tools.c",
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg-checkout", type=Path, required=True)
    parser.add_argument("--libmysofa-checkout", type=Path, required=True)
    parser.add_argument(
        "--probe",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_sofa2wavs_shape_probe.c"),
    )
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _head(checkout: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or None


def _write_generated_headers(include_dir: Path) -> None:
    include_dir.mkdir(parents=True, exist_ok=True)
    (include_dir / "config.h").write_text(
        """#ifndef SOURCEHUNT_LIBMYSOFA_CONFIG_H
#define SOURCEHUNT_LIBMYSOFA_CONFIG_H
#define CMAKE_INSTALL_PREFIX \"/usr/local\"
#define CPACK_PACKAGE_VERSION_MAJOR 1
#define CPACK_PACKAGE_VERSION_MINOR 3
#define CPACK_PACKAGE_VERSION_PATCH 3
#endif
""",
        encoding="utf-8",
    )
    (include_dir / "mysofa_export.h").write_text(
        """#ifndef SOURCEHUNT_LIBMYSOFA_EXPORT_H
#define SOURCEHUNT_LIBMYSOFA_EXPORT_H
#define MYSOFA_EXPORT
#endif
""",
        encoding="utf-8",
    )


def _compile_command(
    *,
    source: Path,
    binary: Path,
    include_dir: Path,
    libmysofa: Path,
) -> list[str]:
    command = [
        "clang",
        "-std=c99",
        "-D_DARWIN_C_SOURCE" if platform.system() == "Darwin" else "-D_GNU_SOURCE",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-I",
        str(include_dir),
        "-I",
        str(libmysofa / "src/hrtf"),
        "-I",
        str(libmysofa / "src/hdf"),
    ]
    command.extend(str(libmysofa / item) for item in LIBMYSOFA_SOURCES)
    command.extend([str(source), "-lz", "-lm", "-o", str(binary)])
    return command


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> None:
    args = _arguments()
    ffmpeg = args.ffmpeg_checkout.expanduser().resolve()
    libmysofa = args.libmysofa_checkout.expanduser().resolve()
    probe = args.probe.expanduser().resolve()
    fixture = (
        args.fixture.expanduser().resolve()
        if args.fixture
        else libmysofa / "tests/testfile.sofa"
    )
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    tool_source = ffmpeg / "tools/sofa2wavs.c"
    libmysofa_sources = [libmysofa / item for item in LIBMYSOFA_SOURCES]
    required = [
        tool_source,
        probe,
        fixture,
        libmysofa / "src/hrtf/easy.c",
        *libmysofa_sources,
    ]
    if any(not path.is_file() for path in required):
        raise ValueError("FFmpeg tool, probe, fixture, and libmysofa sources must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    include_dir = binary.parent / f"{binary.stem}-include"
    _write_generated_headers(include_dir)
    probe_binary = binary.with_name(f"{binary.stem}-shape-probe")
    tool_compile_command = _compile_command(
        source=tool_source,
        binary=binary,
        include_dir=include_dir,
        libmysofa=libmysofa,
    )
    probe_compile_command = _compile_command(
        source=probe,
        binary=probe_binary,
        include_dir=include_dir,
        libmysofa=libmysofa,
    )
    tool_compile = subprocess.run(
        tool_compile_command,
        cwd=ffmpeg,
        check=False,
        capture_output=True,
        text=True,
    )
    probe_compile = subprocess.run(
        probe_compile_command,
        cwd=ffmpeg,
        check=False,
        capture_output=True,
        text=True,
    )

    probe_run = subprocess.CompletedProcess([], 127, "", "compile failed")
    tool_run = subprocess.CompletedProcess([], 127, "", "compile failed")
    tool_command: list[str] = []
    if probe_compile.returncode == 0:
        probe_run = _run([str(probe_binary), str(fixture)], ffmpeg)
    if tool_compile.returncode == 0:
        with tempfile.TemporaryDirectory(
            prefix="sofa2wavs-sourcehunt-", dir=binary.parent
        ) as temporary:
            wav_output = Path(temporary) / "wav-output"
            tool_command = [str(binary), str(fixture), str(wav_output)]
            tool_run = _run(tool_command, ffmpeg)

    ffmpeg_commit = _head(ffmpeg)
    libmysofa_commit = _head(libmysofa)
    tool_text = tool_source.read_text(encoding="utf-8", errors="replace")
    reader_text = (libmysofa / "src/hrtf/reader.c").read_text(
        encoding="utf-8", errors="replace"
    )
    easy_text = (libmysofa / "src/hrtf/easy.c").read_text(
        encoding="utf-8", errors="replace"
    )
    source_indicators = {
        "raw_loader_result_is_trusted": (
            "hrtf = mysofa_load(argv[1], &err);" in tool_text
            and "mysofa_check" not in tool_text
        ),
        "measurement_count_bounds_source_reads": (
            "for (i = 0; i < hrtf->M; i++)" in tool_text
            and "hrtf->SourcePosition.values[i * 3]" in tool_text
        ),
        "reader_returns_without_semantic_check": (
            "return hrtf;" in reader_text and "mysofa_check" not in reader_text
        ),
        "validated_api_calls_semantic_check": (
            "*err = mysofa_check(easy->hrtf);" in easy_text
            and "SourcePosition.elements != easy->hrtf->C * easy->hrtf->M"
            in easy_text
        ),
    }
    probe_combined = probe_run.stdout + probe_run.stderr
    tool_combined = tool_run.stdout + tool_run.stderr
    runtime_indicators = {
        "raw_load_succeeds": "load_ptr=nonnull load_err=0" in probe_combined,
        "semantic_check_rejects": "check_err=10004" in probe_combined,
        "three_measurements_but_one_position": (
            "C=3 R=2 E=2 N=256 M=3 source_elements=3" in probe_combined
        ),
        "shared_position_dimension": "source_dimension=I,C" in probe_combined,
        "first_oob_index_is_three": (
            "first_unchecked_source_index=3" in probe_combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in tool_combined
        ),
        "four_byte_oob_read": "READ of size 4" in tool_combined,
        "exact_twelve_byte_allocation_boundary": (
            "0 bytes after 12-byte region" in tool_combined
        ),
        "ffmpeg_source_line_in_trace": "sofa2wavs.c:68" in tool_combined,
        "tool_aborted": tool_run.returncode != 0,
    }
    commit_indicators = {
        "ffmpeg_pin_matches": ffmpeg_commit == FFMPEG_COMMIT,
        "libmysofa_pin_matches": libmysofa_commit == LIBMYSOFA_COMMIT,
    }
    expected_observed = (
        tool_compile.returncode == 0
        and probe_compile.returncode == 0
        and probe_run.returncode == 0
        and all(commit_indicators.values())
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "ffmpeg_checkout": str(ffmpeg),
        "ffmpeg_commit": ffmpeg_commit,
        "expected_ffmpeg_commit": FFMPEG_COMMIT,
        "libmysofa_checkout": str(libmysofa),
        "libmysofa_commit": libmysofa_commit,
        "expected_libmysofa_commit": LIBMYSOFA_COMMIT,
        "fixture": str(fixture),
        "fixture_sha256": _sha256(fixture),
        "fixture_size": fixture.stat().st_size,
        "tool_source": str(tool_source),
        "tool_source_sha256": _sha256(tool_source),
        "probe": str(probe),
        "probe_sha256": _sha256(probe),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "probe_binary": str(probe_binary),
        "probe_binary_sha256": (
            _sha256(probe_binary) if probe_binary.is_file() else None
        ),
        "libmysofa_source_sha256": {
            str(path.relative_to(libmysofa)): _sha256(path)
            for path in libmysofa_sources
        },
        "tool_compile_command": tool_compile_command,
        "tool_compile_returncode": tool_compile.returncode,
        "tool_compile_stdout": tool_compile.stdout,
        "tool_compile_stderr": tool_compile.stderr,
        "probe_compile_command": probe_compile_command,
        "probe_compile_returncode": probe_compile.returncode,
        "probe_compile_stdout": probe_compile.stdout,
        "probe_compile_stderr": probe_compile.stderr,
        "probe_run": {
            "command": [str(probe_binary), str(fixture)],
            "returncode": probe_run.returncode,
            "stdout": probe_run.stdout,
            "stderr": probe_run.stderr,
        },
        "tool_run": {
            "command": tool_command,
            "asan_options": "halt_on_error=1:abort_on_error=1:detect_leaks=0",
            "returncode": tool_run.returncode,
            "stdout": tool_run.stdout,
            "stderr": tool_run.stderr,
        },
        "commit_indicators": commit_indicators,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "geometry": {
            "measurements": 3,
            "coordinate_components": 3,
            "source_position_elements": 3,
            "source_position_allocation_bytes": 12,
            "first_oob_measurement": 1,
            "first_oob_element_index": 3,
            "read_size": 4,
        },
        "expected_observed": expected_observed,
        "scope": (
            "Pinned tools/sofa2wavs.c accepts libmysofa's GeneralFIR-E "
            "testfile.sofa through raw mysofa_load. The file has M=3 but a "
            "shared I,C SourcePosition containing only three floats. The tool "
            "assumes M,C and reads element 3 for measurement one, exactly "
            "past the 12-byte heap allocation. ASan aborts at the production "
            "sofa2wavs.c read."
        ),
    }
    temporary_output = output.with_suffix(output.suffix + ".tmp")
    temporary_output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_output.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
