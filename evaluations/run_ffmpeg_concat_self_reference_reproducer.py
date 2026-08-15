"""Record concat-demuxer self-reference descriptor exhaustion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.concat-self-reference-reproducer.v1"
REPAIR_COMMIT = "597036b692b8c39198fe572aad027eeb4c13da35"
DESCRIPTOR_LIMIT = 64


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _limit_descriptors() -> None:
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(DESCRIPTOR_LIMIT, hard), hard))


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    output = args.output.expanduser().resolve()
    ffprobe = checkout / "ffprobe"
    sources = {
        "concat_demuxer": checkout / "libavformat/concatdec.c",
        "format_helpers": checkout / "libavformat/avformat.c",
        "configuration": checkout / "config_components.h",
    }
    if not ffprobe.is_file() or any(not path.is_file() for path in sources.values()):
        raise ValueError("ffprobe, concat sources, and configured components must exist")

    output.parent.mkdir(parents=True, exist_ok=True)
    self_ref = output.parent / "self_ref.ffconcat"
    self_ref.write_text("ffconcat version 1.0\nfile 'self_ref.ffconcat'\n", encoding="utf-8")
    run_command = [str(ffprobe), "-v", "error", "-f", "concat", self_ref.name]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    started = time.monotonic()
    try:
        run_result = subprocess.run(
            run_command,
            cwd=self_ref.parent,
            env=environment,
            preexec_fn=_limit_descriptors,
            timeout=10,
            check=False,
            capture_output=True,
            text=True,
        )
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        run_result = subprocess.CompletedProcess(
            run_command,
            124,
            exc.stdout or "",
            exc.stderr or "",
        )
        timed_out = True
    elapsed_seconds = time.monotonic() - started

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/avformat.c",
            "libavformat/avformat.h",
            "libavformat/options_table.h",
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
        "concat_and_file_protocol_enabled": all(
            term in source_text["configuration"]
            for term in (
                "#define CONFIG_CONCAT_DEMUXER 1",
                "#define CONFIG_FILE_PROTOCOL 1",
            )
        ),
        "concat_allocates_nested_context": (
            "cat->avf = avformat_alloc_context();" in source_text["concat_demuxer"]
        ),
        "concat_recursively_opens_entry": all(
            term in source_text["concat_demuxer"]
            for term in (
                "ff_copy_whiteblacklists(cat->avf, avf)",
                "avformat_open_input(&cat->avf, file->url, NULL, &options)",
            )
        ),
        "vulnerable_source_has_no_recursion_state": (
            "recursion_limit" not in source_text["format_helpers"]
            and "Too deep recursion" not in source_text["format_helpers"]
        ),
        "later_repair_adds_limit": (
            repair_result.returncode == 0
            and "avformat: Add recursion limit" in repair_text
            and "Fixes: self_ref.ffconcat" in repair_text
            and "dst->recursion_limit = src->recursion_limit - 1;" in repair_text
        ),
    }
    combined = run_result.stdout + run_result.stderr
    recursion_errors = combined.count("Impossible to open 'self_ref.ffconcat'")
    runtime_indicators = {
        "self_reference_reaches_descriptor_limit": "Too many open files" in combined,
        "deep_recursive_unwind_observed": recursion_errors >= 32,
        "process_returns_error": run_result.returncode != 0,
        "proof_did_not_timeout": not timed_out,
    }
    expected_observed = all(source_indicators.values()) and all(runtime_indicators.values())
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
        "ffprobe": str(ffprobe),
        "ffprobe_sha256": _sha256(ffprobe),
        "self_reference": str(self_ref),
        "self_reference_sha256": _sha256(self_ref),
        "source_sha256": {
            str(path.relative_to(checkout)): _sha256(path) for path in sources.values()
        },
        "run_command": run_command,
        "asan_options": environment["ASAN_OPTIONS"],
        "descriptor_limit": DESCRIPTOR_LIMIT,
        "elapsed_seconds": elapsed_seconds,
        "timed_out": timed_out,
        "returncode": run_result.returncode,
        "recursion_errors": recursion_errors,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A two-line concat script can name itself as its first file. Each "
            "nested concat open allocates another AVFormatContext and opens "
            "the same script with no internal recursion state. The production "
            "ffprobe proof reaches the deliberately reduced 64-descriptor "
            "process limit and emits a deep recursive unwind. On systems with "
            "higher limits the same tiny input consumes correspondingly more "
            "descriptors, contexts, and stack. Later repair 597036b692 adds a "
            "default depth limit of ten and names self_ref.ffconcat."
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
