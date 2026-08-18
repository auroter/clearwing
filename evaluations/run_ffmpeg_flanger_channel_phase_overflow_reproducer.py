"""Build and record the flanger channel-phase overflow proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.flanger-channel-phase-overflow-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_flanger_channel_phase_overflow_reproducer.c"
        ),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _failed(command: list[str], message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 127, "", message)


def _compile_command(
    *,
    harness: Path,
    source: Path,
    binary: Path,
    sanitizers: str,
    guarded_replay: bool,
) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-I./libavfilter",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        f'-DFLANGER_SOURCE="{source}"',
        f"-fsanitize={sanitizers}",
    ]
    if guarded_replay:
        command.append("-DFLANGER_GUARDED_REPLAY=1")
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
            "-o",
            str(binary),
            str(harness),
            "libavfilter/generate_wave_table.c",
            "libavfilter/libavfilter.a",
            "libavutil/libavutil.a",
            "-lm",
        ]
    )
    if platform.system() == "Darwin":
        command.append("-Wl,-dead_strip")
    else:
        command.append("-Wl,--gc-sections")
    command.append("-pthread")
    return command


def _make_guarded_source(source: Path, destination: Path) -> Path:
    source_text = source.read_text(encoding="utf-8")
    old = (
        "            int channel_phase = chan * s->lfo_length * "
        "s->channel_phase + .5;\n"
    )
    new = (
        "            int channel_phase = fmod((double)chan * s->lfo_length *\n"
        "                                     s->channel_phase + .5, "
        "s->lfo_length);\n"
    )
    if source_text.count(old) != 1:
        raise ValueError("pinned af_flanger.c does not match the guarded context")
    destination.write_text(source_text.replace(old, new), encoding="utf-8")
    return destination


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/af_flanger.c"
    wave_source = checkout / "libavfilter/generate_wave_table.c"
    channel_layout_source = checkout / "libavutil/channel_layout.c"
    required = (
        harness,
        source,
        wave_source,
        channel_layout_source,
        checkout / "libavfilter/libavfilter.a",
        checkout / "libavutil/libavutil.a",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("harness, exact filter sources, and configured archives must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    asan_binary = binary.with_name(binary.name + "-asan")
    guarded_binary = binary.with_name(binary.name + "-guarded")
    guarded_source = _make_guarded_source(
        source, binary.with_name(binary.name + "-guarded-af_flanger.c")
    )

    compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=binary,
        sanitizers="address,undefined",
        guarded_replay=False,
    )
    asan_compile_command = _compile_command(
        harness=harness,
        source=source,
        binary=asan_binary,
        sanitizers="address",
        guarded_replay=True,
    )
    guarded_compile_command = _compile_command(
        harness=harness,
        source=guarded_source,
        binary=guarded_binary,
        sanitizers="address,undefined",
        guarded_replay=True,
    )
    compile_result = _run(compile_command, cwd=checkout)
    asan_compile_result = _run(asan_compile_command, cwd=checkout)
    guarded_compile_result = _run(guarded_compile_command, cwd=checkout)

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    run_result = (
        _run([str(binary)], cwd=checkout, env=environment)
        if compile_result.returncode == 0
        else _failed([str(binary)], "compile failed")
    )
    asan_run_result = (
        _run([str(asan_binary)], cwd=checkout, env=environment)
        if asan_compile_result.returncode == 0
        else _failed([str(asan_binary)], "ASan compile failed")
    )
    guarded_run_result = (
        _run([str(guarded_binary)], cwd=checkout, env=environment)
        if guarded_compile_result.returncode == 0
        else _failed([str(guarded_binary)], "guarded compile failed")
    )

    source_text = source.read_text(encoding="utf-8", errors="replace")
    channel_layout_text = channel_layout_source.read_text(
        encoding="utf-8", errors="replace"
    )
    master_result = _run(
        ["git", "show", "origin/master:libavfilter/af_flanger.c"], cwd=checkout
    )
    vulnerable_expression = (
        "int channel_phase = chan * s->lfo_length * s->channel_phase + .5;"
    )
    source_indicators = {
        "public_options_allow_selected_speed_and_phase": (
            'OFFSET(speed), AV_OPT_TYPE_DOUBLE, {.dbl=0.5}, 0.1, 10' in source_text
            and 'OFFSET(channel_phase), AV_OPT_TYPE_DOUBLE, {.dbl=25}, 0, 100'
            in source_text
        ),
        "unspecified_layout_accepts_selected_channel_count": (
            "if (channel_layout->nb_channels <= 0)" in channel_layout_text
            and "case AV_CHANNEL_ORDER_UNSPEC:\n        return 1;" in channel_layout_text
        ),
        "lfo_length_uses_sample_rate_over_speed": (
            "s->lfo_length  = inlink->sample_rate / s->speed;" in source_text
        ),
        "channel_phase_uses_unchecked_signed_int_product": (
            vulnerable_expression in source_text
        ),
        "negative_remainder_indexes_lfo_directly": (
            "s->lfo[(s->lfo_pos + channel_phase) % s->lfo_length]" in source_text
        ),
        "current_master_remains_unrepaired": (
            master_result.returncode == 0
            and vulnerable_expression in master_result.stdout
        ),
    }

    combined = run_result.stdout + run_result.stderr
    asan_combined = asan_run_result.stdout + asan_run_result.stderr
    guarded_combined = guarded_run_result.stdout + guarded_run_result.stderr
    runtime_indicators = {
        "proof_geometry_reaches_first_overflow_channel": (
            "channels=561 sample_rate=384000 speed=0.1 lfo_length=3840000 "
            "first_overflow_channel=560" in combined
        ),
        "ubsan_reports_exact_channel_phase_product": (
            "signed integer overflow: 560 * 3840000" in combined
            and "libavfilter/af_flanger.c:140" in combined
        ),
        "ubsan_process_aborted": run_result.returncode != 0,
        "wrapped_product_produces_negative_lfo_index": (
            "mathematical_product=2150400000 "
            "wrapped_product=-2144567296 wrapped_index=-1847296" in asan_combined
        ),
        "asan_reports_guarded_pre_lfo_read": (
            "AddressSanitizer: use-after-poison" in asan_combined
            and "READ of size 4" in asan_combined
            and "68 bytes inside of" in asan_combined
            and "filter_frame" in asan_combined
        ),
        "asan_process_aborted": asan_run_result.returncode != 0,
        "floating_point_modulo_guard_completes": (
            guarded_run_result.returncode == 0
            and "filter_result=0" in guarded_combined
            and "Sanitizer" not in guarded_combined
            and "runtime error:" not in guarded_combined
        ),
    }
    expected_observed = (
        compile_result.returncode == 0
        and asan_compile_result.returncode == 0
        and guarded_compile_result.returncode == 0
        and all(source_indicators.values())
        and all(runtime_indicators.values())
    )
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    master_commit_result = _run(["git", "rev-parse", "origin/master"], cwd=checkout)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": head_result.stdout.strip() or None,
        "current_master_commit": master_commit_result.stdout.strip() or None,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source_sha256": {
            "libavfilter/af_flanger.c": _sha256(source),
            "libavfilter/generate_wave_table.c": _sha256(wave_source),
            "libavutil/channel_layout.c": _sha256(channel_layout_source),
        },
        "guarded_source_sha256": _sha256(guarded_source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "asan_binary": str(asan_binary),
        "asan_binary_sha256": _sha256(asan_binary) if asan_binary.is_file() else None,
        "guarded_binary": str(guarded_binary),
        "guarded_binary_sha256": (
            _sha256(guarded_binary) if guarded_binary.is_file() else None
        ),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "asan_compile_command": asan_compile_command,
        "asan_compile_returncode": asan_compile_result.returncode,
        "asan_compile_stdout": asan_compile_result.stdout,
        "asan_compile_stderr": asan_compile_result.stderr,
        "guarded_compile_command": guarded_compile_command,
        "guarded_compile_returncode": guarded_compile_result.returncode,
        "guarded_compile_stdout": guarded_compile_result.stdout,
        "guarded_compile_stderr": guarded_compile_result.stderr,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The flanger filter accepts an unspecified 561-channel layout, "
            "384 kHz audio, speed 0.1, and phase 100. Those values create a "
            "3,840,000-entry LFO. At channel 560, the production signed-int "
            "channel-times-LFO product is 2,150,400,000 and overflows before "
            "conversion to double. UBSan aborts at the exact expression. Under "
            "ordinary two's-complement wrapping, the product becomes "
            "-2,144,567,296 and the remainder indexes 1,847,296 floats before "
            "the LFO; a poisoned-prefix replay makes ASan report the exact "
            "four-byte read. A floating-point multiply plus modulo guard "
            "completes the identical frame cleanly. Current master is unchanged."
        ),
        "vulnerable_ubsan_run": {
            "command": [str(binary)],
            "returncode": run_result.returncode,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
        },
        "vulnerable_asan_run": {
            "command": [str(asan_binary)],
            "returncode": asan_run_result.returncode,
            "stdout": asan_run_result.stdout,
            "stderr": asan_run_result.stderr,
        },
        "guarded_run": {
            "command": [str(guarded_binary)],
            "returncode": guarded_run_result.returncode,
            "stdout": guarded_run_result.stdout,
            "stderr": guarded_run_result.stderr,
        },
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
