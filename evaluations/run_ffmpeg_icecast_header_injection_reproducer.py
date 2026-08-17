"""Prove Icecast metadata HTTP-header injection and its exact repair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.icecast-header-injection-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
REPAIR_COMMIT = "99e1ecca36455689c0c417a02ca36cd5b6e2346d"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-build-dir", type=Path, required=True)
    parser.add_argument("--repaired-build-dir", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_icecast_header_injection_reproducer.c"),
    )
    parser.add_argument("--vulnerable-binary-output", type=Path, required=True)
    parser.add_argument("--repaired-binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
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


def _compile_command(harness: Path, binary: Path) -> list[str]:
    return [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address",
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
        "-pthread",
    ]


def _validate_build(path: Path, expected_commit: str) -> None:
    required = (
        path / "libavformat/libavformat.a",
        path / "libavcodec/libavcodec.a",
        path / "libswresample/libswresample.a",
        path / "libswscale/libswscale.a",
        path / "libavutil/libavutil.a",
        path / "libavformat/icecast.c",
        path / "libavformat/http.c",
        path / "config_components.h",
    )
    if _head(path) != expected_commit or not all(item.is_file() for item in required):
        raise ValueError(f"configured FFmpeg build must be at {expected_commit}")
    components = (path / "config_components.h").read_text(encoding="utf-8", errors="replace")
    for protocol in ("HTTP", "ICECAST", "TCP"):
        if f"#define CONFIG_{protocol}_PROTOCOL 1" not in components:
            raise ValueError(f"configured build must enable the {protocol} protocol")


def _capture_request(binary: Path, cwd: Path, timeout: float) -> dict[str, Any]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(timeout)
    port = listener.getsockname()[1]
    captured = bytearray()
    server_errors: list[str] = []

    def serve() -> None:
        try:
            connection, _address = listener.accept()
            with connection:
                connection.settimeout(timeout)
                while b"\r\n\r\n" not in captured and len(captured) < 1024 * 1024:
                    block = connection.recv(4096)
                    if not block:
                        break
                    captured.extend(block)
                connection.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
        except (OSError, TimeoutError) as error:
            server_errors.append(f"{type(error).__name__}: {error}")
        finally:
            listener.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    try:
        result = subprocess.run(
            [str(binary), str(port)],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        run = {
            "timed_out": False,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired as error:
        run = {
            "timed_out": True,
            "returncode": None,
            "stdout": (
                (error.stdout or b"").decode("utf-8", errors="replace")
                if isinstance(error.stdout, bytes)
                else error.stdout or ""
            ),
            "stderr": (
                (error.stderr or b"").decode("utf-8", errors="replace")
                if isinstance(error.stderr, bytes)
                else error.stderr or ""
            ),
        }
    server.join(timeout)
    return {
        **run,
        "port": port,
        "request": captured.decode("latin-1", errors="replace"),
        "request_size": len(captured),
        "server_alive": server.is_alive(),
        "server_errors": server_errors,
    }


def main() -> None:
    args = _arguments()
    vulnerable_build = args.vulnerable_build_dir.expanduser().resolve()
    repaired_build = args.repaired_build_dir.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    vulnerable_binary = args.vulnerable_binary_output.expanduser().resolve()
    repaired_binary = args.repaired_binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if args.timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if not harness.is_file():
        raise ValueError("harness must exist")
    _validate_build(vulnerable_build, VULNERABLE_COMMIT)
    _validate_build(repaired_build, REPAIR_COMMIT)

    vulnerable_binary.parent.mkdir(parents=True, exist_ok=True)
    repaired_binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    vulnerable_compile_command = _compile_command(harness, vulnerable_binary)
    vulnerable_compile = subprocess.run(
        vulnerable_compile_command,
        cwd=vulnerable_build,
        check=False,
        capture_output=True,
        text=True,
    )
    vulnerable_run = (
        _capture_request(vulnerable_binary, vulnerable_build, args.timeout_seconds)
        if vulnerable_compile.returncode == 0
        else {
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "compile failed",
            "port": None,
            "request": "",
            "request_size": 0,
            "server_alive": False,
            "server_errors": [],
        }
    )

    repaired_compile_command = _compile_command(harness, repaired_binary)
    repaired_compile = subprocess.run(
        repaired_compile_command,
        cwd=repaired_build,
        check=False,
        capture_output=True,
        text=True,
    )
    repaired_run = (
        _capture_request(repaired_binary, repaired_build, args.timeout_seconds)
        if repaired_compile.returncode == 0
        else {
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "compile failed",
            "port": None,
            "request": "",
            "request_size": 0,
            "server_alive": False,
            "server_errors": [],
        }
    )

    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/icecast.c",
        ],
        cwd=vulnerable_build,
        check=False,
        capture_output=True,
        text=True,
    )
    vulnerable_source = (vulnerable_build / "libavformat/icecast.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repaired_source = (repaired_build / "libavformat/icecast.c").read_text(
        encoding="utf-8", errors="replace"
    )
    http_source = (vulnerable_build / "libavformat/http.c").read_text(
        encoding="utf-8", errors="replace"
    )
    repair_text = repair_result.stdout
    source_indicators = {
        "vulnerable_metadata_is_concatenated_into_headers": all(
            term in vulnerable_source
            for term in (
                'cat_header(&bp, "Ice-Name", s->name);',
                'av_bprintf(bp, "%s: %s\\r\\n", key, value);',
                'av_dict_set(&opt_dict, "headers", headers, AV_DICT_DONT_STRDUP_VAL);',
            )
        ),
        "http_protocol_appends_custom_headers_verbatim": all(
            term in http_source
            for term in (
                "/* now add in custom headers */",
                'av_bprintf(&request, "%s", s->headers);',
            )
        ),
        "vulnerable_source_lacks_crlf_guard": ('strpbrk(value, "\\r\\n")' not in vulnerable_source),
        "repair_is_exact_metadata_crlf_rejection": (
            repair_result.returncode == 0
            and "reject CR/LF in metadata header values" in repair_text
            and 'strpbrk(value, "\\r\\n")' in repaired_source
            and "Refusing to send '%s' header" in repaired_source
        ),
    }

    vulnerable_request = vulnerable_run["request"]
    repaired_request = repaired_run["request"]
    runtime_indicators = {
        "vulnerable_harness_compiled": vulnerable_compile.returncode == 0,
        "vulnerable_public_open_succeeded": (
            vulnerable_run["returncode"] == 0
            and "entry=avio_open2 option=ice_name open_ret=0" in vulnerable_run["stdout"]
        ),
        "vulnerable_metadata_header_was_transmitted": (
            "\r\nIce-Name: safe-name\r\n" in vulnerable_request
        ),
        "vulnerable_injected_header_was_transmitted": (
            "\r\nX-Injected: yes\r\n" in vulnerable_request
        ),
        "repaired_harness_compiled": repaired_compile.returncode == 0,
        "repaired_public_open_succeeded": (
            repaired_run["returncode"] == 0
            and "entry=avio_open2 option=ice_name open_ret=0" in repaired_run["stdout"]
        ),
        "repaired_crlf_value_was_rejected": (
            "Refusing to send 'Ice-Name' header: value contains CR/LF" in repaired_run["stderr"]
        ),
        "repaired_request_omits_poisoned_and_injected_headers": (
            "Ice-Name:" not in repaired_request and "X-Injected:" not in repaired_request
        ),
        "loopback_servers_completed_cleanly": (
            not vulnerable_run["server_alive"]
            and not repaired_run["server_alive"]
            and not vulnerable_run["server_errors"]
            and not repaired_run["server_errors"]
        ),
    }
    expected_observed = all(source_indicators.values()) and all(runtime_indicators.values())

    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "vulnerable_build_dir": str(vulnerable_build),
        "vulnerable_commit": _head(vulnerable_build) or None,
        "repaired_build_dir": str(repaired_build),
        "repaired_commit": _head(repaired_build) or None,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_text,
        "repair_commit_stderr": repair_result.stderr,
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "timeout_seconds": args.timeout_seconds,
        "vulnerable_compile_command": vulnerable_compile_command,
        "vulnerable_compile_returncode": vulnerable_compile.returncode,
        "vulnerable_compile_stdout": vulnerable_compile.stdout,
        "vulnerable_compile_stderr": vulnerable_compile.stderr,
        "vulnerable_binary": str(vulnerable_binary),
        "vulnerable_binary_sha256": (
            _sha256(vulnerable_binary) if vulnerable_binary.is_file() else None
        ),
        "vulnerable_run": vulnerable_run,
        "repaired_compile_command": repaired_compile_command,
        "repaired_compile_returncode": repaired_compile.returncode,
        "repaired_compile_stdout": repaired_compile.stdout,
        "repaired_compile_stderr": repaired_compile.stderr,
        "repaired_binary": str(repaired_binary),
        "repaired_binary_sha256": (_sha256(repaired_binary) if repaired_binary.is_file() else None),
        "repaired_run": repaired_run,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(0 if expected_observed else 1)


if __name__ == "__main__":
    main()
