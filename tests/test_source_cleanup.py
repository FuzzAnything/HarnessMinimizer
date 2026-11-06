from pathlib import Path

import pytest

from harnessminimizer import api
from harnessminimizer.source_cleanup import clean_reduced_source


def test_cleanup_removes_comment_only_lines_without_touching_raw_string(tmp_path: Path):
    source = tmp_path / "reduced.cpp"
    source.write_bytes(
        b'#include <vector>\n'
        b'// standalone comment\n'
        b'/* first */ /* second */\n'
        b'/* block begins\n * block body\n */\n'
        b'int first = 1; // attached comment\n'
        b'\n\n\n'
        b'const char *text = R"tag(\n'
        b'// this is data, not a comment\n'
        b'\n\n\n'
        b'/* this is also data */\n'
        b')tag";\n'
        b'\n\n\n'
        b'int second = 2;\n'
    )

    clean_reduced_source(str(source))

    assert source.read_bytes() == (
        b'#include <vector>\n'
        b'int first = 1; // attached comment\n'
        b'\n'
        b'const char *text = R"tag(\n'
        b'// this is data, not a comment\n'
        b'\n\n\n'
        b'/* this is also data */\n'
        b')tag";\n'
        b'\n'
        b'int second = 2;\n'
    )
    # A second pass should leave the exported source unchanged.
    before = source.read_bytes()
    clean_reduced_source(str(source))
    assert source.read_bytes() == before


def test_cleanup_keeps_mixed_block_comments_and_macro_continuations(tmp_path: Path):
    source = tmp_path / "reduced.cpp"
    content = (
        b'#define VALUE 1 \\\n'
        b'// a continued directive is not an ordinary source comment\n'
        b'int first = 1; /* block begins\n'
        b' * this line belongs to the mixed block\n'
        b' */ int second = 2;\n'
        b'// removable\n'
        b'\n\n'
        b'int third = 3;\n'
    )
    source.write_bytes(content)

    clean_reduced_source(str(source))

    cleaned = source.read_bytes()
    assert b'// a continued directive' in cleaned
    assert b'/* block begins\n * this line belongs to the mixed block\n */' in cleaned
    assert b'// removable' not in cleaned
    assert b'\n\n\n' not in cleaned


@pytest.mark.parametrize("budget", [None, 10.0])
def test_cleanup_runs_before_format_and_inline_for_finished_or_timed_reduction(
    tmp_path: Path, monkeypatch, budget,
):
    source = tmp_path / "reduced.cpp"
    source.write_text('#include <vector>\n// stale comment\n\n\nint value = 1;\n')
    order = []

    def reduced(*_args, **_kwargs):
        order.append("reduction")
        return str(source)

    def formatted(path):
        order.append("format")
        assert path == str(source)
        assert source.read_text() == '#include <vector>\n\nint value = 1;\n'

    def inlined(*_args, **_kwargs):
        order.append("inline")
        return api.PostReductionOutcome(str(source))

    monkeypatch.setattr(api, "run_treereducer", reduced)
    monkeypatch.setattr(api, "format_reduced_harness", formatted)
    monkeypatch.setattr(api, "inline_literals_in_reduced_harness", inlined)
    monkeypatch.setattr(api, "_finalize_budget_checkpoint", lambda _path: order.append("checkpoint"))
    config = api.ReductionConfig(
        harness_path=str(source), crash_input=str(tmp_path / "input"),
        reduction_timeout_seconds=budget,
    )

    result = api._reduction_attempt(config, str(source), None, "fast crash", "symbolized crash", None)

    assert result[0] == str(source)
    assert order == ["reduction", "format", "inline", *(["checkpoint"] if budget else [])]
