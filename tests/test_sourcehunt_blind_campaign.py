from __future__ import annotations

import json
from argparse import Namespace

from evaluations import run_sourcehunt_blind_campaign as blind_campaign
from evaluations.run_sourcehunt_blind_campaign import (
    _resolve_api_key,
    _source_action_files,
)


def _event(**values: object) -> str:
    return json.dumps(values)


def test_ranked_window_counts_as_source_bearing_action(tmp_path) -> None:
    transcript = tmp_path / "trajectories" / "work-1" / "transcript.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(
        "\n".join(
            [
                _event(event="start", file_path="src/target.c"),
                _event(
                    event="tool_result",
                    tool_call={"fn_name": "read_ranked_window"},
                    tool_output="W1 src/target.c:1-20",
                    repeated_skip=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert _source_action_files(tmp_path) == ["src/target.c"]


def test_failed_ranked_window_does_not_count_as_source_bearing_action(tmp_path) -> None:
    transcript = tmp_path / "trajectories" / "work-1" / "transcript.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(
        "\n".join(
            [
                _event(event="start", file_path="src/target.c"),
                _event(
                    event="tool_result",
                    tool_call={"fn_name": "read_ranked_window"},
                    tool_output="ERROR: read W1 first",
                    repeated_skip=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert _source_action_files(tmp_path) == []


def test_api_key_stdin_uses_hidden_prompt(monkeypatch) -> None:
    monkeypatch.setattr(
        blind_campaign.getpass,
        "getpass",
        lambda prompt: "memory-only-key",
    )

    assert (
        _resolve_api_key(Namespace(api_key="cli-key", api_key_stdin=True))
        == "memory-only-key"
    )
