"""Post-reduction validation must not depend on whether anything can be inlined."""
from contextlib import ExitStack
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch

import pytest

from harnessminimizer import api
from harnessminimizer.process_supervisor import run_supervised


def harness(parameters: str, body: str = "return 0;") -> str:
    return (
        "// Non-ASCII prefix: café 中文\n"
        "#include <cstdint>\n#include <cstddef>\n"
        f'extern "C" int LLVMFuzzerTestOneInput({parameters}) {{ {body} }}\n'
    )


def validators(stack: ExitStack, symbolize: bool, outcomes):
    def validate(*args, **kwargs):
        result = next(outcomes)
        if not result:
            Path(kwargs["validation_log_path"]).write_text("Controlled validation failure\n")
        return result

    fast = stack.enter_context(patch.object(api, "validate_crash_pattern_and_stack_trace"))
    symbolized = stack.enter_context(patch.object(api, "validate_symbolized_crash_pattern_depth_location"))
    selected, other = (symbolized, fast) if symbolize else (fast, symbolized)
    selected.side_effect = validate
    # Do not run a target merely to collect extra diagnostics in unit tests.
    stack.enter_context(patch.object(api, "_append_inline_stack_diagnostics"))
    return selected, other


@pytest.mark.parametrize("symbolize", [False, True])
@pytest.mark.parametrize("preserved", [False, True])
def test_zero_fdp_calls_still_validate(tmp_path: Path, capsys, symbolize, preserved):
    source = harness("const uint8_t *, size_t")
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(source)
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("S 100001 42\n")
    with ExitStack() as stack:
        selected, other = validators(
            stack,
            symbolize,
            iter([preserved] if preserved else [False, False]),
        )
        out, headers = api.inline_literals_in_reduced_harness(
            str(reduced), str(trace), "Symbolized", "seed.bin", "-I/include", "-ltarget",
            crash_pattern_symbolize_0="Fast", symbolize=symbolize,
        )
    prepared = reduced.with_suffix(".inline.cpp")
    assert out == str(prepared if preserved else reduced)
    assert headers == ()
    assert selected.call_count == (1 if preserved else 2)
    other.assert_not_called()
    first_call = selected.call_args_list[0]
    assert first_call.args[0] == str(prepared)
    assert first_call.kwargs["fdp_trace_file"] is None
    assert first_call.kwargs["compilation_mode"] == "direct"
    assert first_call.kwargs["retry_oom_without_rss_limit"] is True
    assert first_call.kwargs["evidence_attempts"] == api.POST_REDUCTION_VALIDATION_ATTEMPTS
    assert source in prepared.read_text()
    output = capsys.readouterr().out
    assert "No FDP callsites remain after replacement" in output
    assert "Skipping inline validation" not in output
    assert "tree-reduced" not in output
    if preserved:
        assert reduced.read_text() == source
    else:
        assert "Cleaned fallback harness did not pass final validation" in output
        assert "Controlled validation failure" in Path(f"{prepared}.validation.log").read_text()


@pytest.mark.parametrize("parameters,assignments", [
    ("const uint8_t *data, size_t size", ("data = ::fuzz_values;", "size = ::fuzz_index;")),
    ("const uint8_t *f_data, size_t f_size", ("f_data = ::fuzz_values;", "f_size = ::fuzz_index;")),
    ("const uint8_t *, size_t", ()),
    ("", ()),
    ("void", ()),
    ("const uint8_t *data, size_t", ("data = ::fuzz_values;",)),
    ("const uint8_t *, size_t size", ("size = ::fuzz_index;",)),
    ("const uint8_t *, /* keep ordinal position */ size_t length", ("length = ::fuzz_index;",)),
    ("const uint8_t bytes[N], size_t count = limit", ("bytes = ::fuzz_values;", "count = ::fuzz_index;")),
    ("const uint8_t *bytes [[maybe_unused]], size_t count", ("bytes = ::fuzz_values;", "count = ::fuzz_index;")),
    ("int *data, int size", (
        "data = reinterpret_cast<decltype(data)>(::fuzz_values);",
        "size = static_cast<decltype(size)>(::fuzz_index);",
    )),
])
@pytest.mark.parametrize("symbolize", [False, True])
@pytest.mark.parametrize("preserved", [False, True])
def test_direct_input_shapes_validate(tmp_path: Path, capsys, parameters, assignments, symbolize, preserved):
    reduced = tmp_path / "reduced.cpp"
    source = harness(parameters)
    reduced.write_text(source)
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"abc")
    with ExitStack() as stack:
        selected, other = validators(
            stack,
            symbolize,
            iter([preserved] if preserved else [False, False]),
        )
        out, headers = api.inline_literals_in_reduced_harness(
            str(reduced), None, "Symbolized", str(seed), "-I/include", "-ltarget",
            crash_pattern_symbolize_0="Fast", symbolize=symbolize,
        )
    prepared = reduced.with_suffix(".inline.cpp")
    assert out == str(prepared if preserved else reduced)
    header = tmp_path / api.DIRECT_INPUT_HEADER_NAME
    assert headers == ((str(header),) if assignments and preserved else ())
    assert header.exists() == bool(assignments)
    text = prepared.read_text()
    for assignment in assignments:
        assert assignment in text
    assert f"LLVMFuzzerTestOneInput({parameters}) {{" in text
    assert "café 中文" in text
    assert "None =" not in text
    assert "N =" not in text and "limit =" not in text and "maybe_unused =" not in text
    if not assignments:
        assert source in text
        assert "fuzz_values" not in text and "harness_values.h" not in text
    if assignments:
        assert text.count(" = ::fuzz_") + text.count(" = reinterpret_cast") + text.count(" = static_cast") == len(assignments)
    assert selected.call_count == (1 if preserved else 2)
    other.assert_not_called()
    first_call = selected.call_args_list[0]
    assert first_call.kwargs["fdp_trace_file"] is None
    assert first_call.kwargs["compilation_mode"] == "direct"
    assert first_call.kwargs["retry_oom_without_rss_limit"] is True
    assert str(seed) in first_call.args
    output = capsys.readouterr().out
    assert "tree-reduced" not in output
    if not assignments:
        assert "No named input parameters remain" in output
        assert "Inlined direct crash input" not in output
    if not preserved:
        assert "Returning the non-inlined reduced harness" in output
        assert "Controlled validation failure" in Path(f"{prepared}.validation.log").read_text()


@pytest.mark.parametrize("source", [
    harness("const uint8_t *data"),
    harness("size_t size"),
    harness("const uint8_t *"),
    harness("const uint8_t *, size_t, int extra"),
    harness("const uint8_t *, size_t, ..."),
    harness("void (*callback)(int nested), size_t size"),
    harness("const uint8_t (&data)[8], size_t size"),
    harness("const uint8_t *const data, size_t size"),
    harness("const uint8_t *data, const size_t size"),
    'extern "C" int LLVMFuzzerTestOneInput(const unsigned char *, unsigned long);\n',
    'int unrelated(int LLVMFuzzerTestOneInput, int size) { return 0; }\n',
    'int unrelated(int data = LLVMFuzzerTestOneInput, int size = 1) { return 0; }\n',
    'DEFINE_FUZZER_ENTRY()\n',
    harness("") + harness("void"),
])
@pytest.mark.parametrize("symbolize", [False, True])
@pytest.mark.parametrize("preserved", [False, True])
def test_unsupported_direct_signature_validates_unchanged(tmp_path: Path, capsys, source, symbolize, preserved):
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(source)
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    # An old/user-owned header must not be overwritten or reported as newly generated.
    header = tmp_path / api.DIRECT_INPUT_HEADER_NAME
    header.write_text("// existing header\n")
    with ExitStack() as stack:
        selected, other = validators(
            stack,
            symbolize,
            iter([preserved] if preserved else [False, False]),
        )
        out, headers = api.inline_literals_in_reduced_harness(
            str(reduced), None, "Pattern", str(seed), None, None, symbolize=symbolize,
        )
    assert selected.call_count == (1 if preserved else 2)
    other.assert_not_called()
    assert out == str(reduced.with_suffix(".inline.cpp") if preserved else reduced)
    assert headers == ()
    assert source in Path(out).read_text()
    if preserved:
        assert reduced.read_text() == source
    assert header.read_text() == "// existing header\n"
    output = capsys.readouterr().out
    assert "Input parameters could not be mapped safely" in output
    assert "No named input parameters remain" not in output
    if not preserved:
        assert "Cleaned fallback harness did not pass final validation" in output


@pytest.mark.parametrize("fdp_trace", [False, True])
@pytest.mark.parametrize("symbolize", [False, True])
@pytest.mark.parametrize("snapshot_success", [False, True])
def test_zero_replacements_retry_snapshot(tmp_path: Path, capsys, fdp_trace, symbolize, snapshot_success):
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(harness("const uint8_t *, size_t", "return 0;"))
    snapshot = tmp_path / "last_interesting.cpp"
    snapshot.write_text(harness("", "return 1;"))
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    trace = tmp_path / "trace.log"
    trace.write_text("S 100001 42\n")
    with ExitStack() as stack:
        outcomes = [False, snapshot_success]
        if not snapshot_success:
            outcomes.append(False)
        selected, other = validators(stack, symbolize, iter(outcomes))
        stack.enter_context(patch.object(api, "get_last_interesting_file", return_value=str(snapshot)))
        outcome = api.inline_literals_in_reduced_harness(
            str(reduced), str(trace) if fdp_trace else None, "Pattern", str(seed), None, None,
            symbolize=symbolize, snapshot=True,
        )
    out, headers = outcome
    assert selected.call_count == (2 if snapshot_success else 3)
    other.assert_not_called()
    assert headers == ()
    assert out == str(snapshot.with_suffix(".inline.cpp") if snapshot_success else snapshot)
    output = capsys.readouterr().out
    assert "tree-reduced" not in output
    if not snapshot_success:
        assert "non-inlined last interesting snapshot harness" in output
        assert "Cleaned fallback harness did not pass final validation" in output


def test_empty_direct_input_still_embeds_zero_length(tmp_path: Path):
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(harness("const uint8_t *, size_t count"))
    seed = tmp_path / "empty.bin"
    seed.write_bytes(b"")
    with patch.object(api, "validate_crash_pattern_and_stack_trace", return_value=True):
        out, headers = api.inline_literals_in_reduced_harness(
            str(reduced), None, "Pattern", str(seed), None, None,
        )
    assert "count = ::fuzz_index;" in Path(out).read_text()
    assert "fuzz_index = 0;" in Path(headers[0]).read_text()


@pytest.mark.parametrize("fdp_trace", [False, True])
def test_no_snapshot_retry_without_flag(tmp_path: Path, fdp_trace):
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(harness(""))
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    trace = tmp_path / "trace.log"
    trace.write_text("")
    with ExitStack() as stack:
        selected, _ = validators(stack, False, iter([False, False]))
        snapshot = stack.enter_context(patch.object(api, "get_last_interesting_file"))
        out, headers = api.inline_literals_in_reduced_harness(
            str(reduced), str(trace) if fdp_trace else None, "Pattern", str(seed), None, None,
        )
    assert selected.call_count == 2
    snapshot.assert_not_called()
    assert out == str(reduced) and headers == ()


@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize("fdp_trace", [False, True])
def test_pipeline_validates_reduced_no_input_harness(tmp_path: Path, optimized, fdp_trace):
    """Use real post-processing, but no reducer invocation or library execution."""
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(harness("const uint8_t *, size_t" if optimized else ""))
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"x")
    trace = tmp_path / "trace.log"
    trace.write_text("S 100001 42\n")
    config = api.ReductionConfig(
        harness_path=str(reduced), crash_input=str(seed), work_dir=str(tmp_path),
        compilation_mode="pch" if optimized else "split", amortize_link=optimized,
        symbolize=not optimized, stable=True, jobs=1,
    )
    with ExitStack() as stack:
        for name in (
            "configure_work_dir", "reset_stack_trace_state", "reset_last_interesting_state",
            "reset_poc_runtime_args", "check_tree_reducer",
            "resolve_amortized_link_inputs", "check_harness_compilation", "check_reducer_crash_pattern",
            "check_reducer_symbolized_crash_pattern", "check_reducer_symbolized_reduction_oracle",
            "format_reduced_harness",
        ):
            stack.enter_context(patch.object(api, name))
        stack.enter_context(patch.object(api, "get_poc_runtime_args", return_value=()))
        stack.enter_context(patch.object(api, "has_static_target_libraries", return_value=False))
        stack.enter_context(patch.object(api, "extract_crash_pattern_from_output", return_value="Fast"))
        stack.enter_context(patch.object(api, "get_reference_crash_pattern_symbolize_1", return_value="Symbolized"))
        stack.enter_context(patch.object(api, "tag_harness_with_fdp_ids", return_value=api.TaggedHarness(str(reduced), int(fdp_trace))))
        stack.enter_context(patch.object(api, "compile_dump_mode_harness", return_value="unused.out"))
        stack.enter_context(patch.object(api, "dump_fdp_trace", return_value=str(trace)))
        reducer = stack.enter_context(patch.object(api, "run_treereducer", return_value=str(reduced)))
        selected, other = validators(stack, not optimized, iter([True]))
        result = api.reduce_with_config(config)
    assert result.success
    assert result.reduced_harness == str(reduced.with_suffix(".inline.cpp"))
    assert result.generated_headers == ()
    reducer.assert_called_once()
    assert reducer.call_args.kwargs["compilation_mode"] == config.compilation_mode
    assert reducer.call_args.kwargs["amortize_link"] is optimized
    assert reducer.call_args.kwargs["stable"] is True
    selected.assert_called_once()
    other.assert_not_called()
    assert selected.call_args.kwargs["compilation_mode"] == "direct"
    assert selected.call_args.kwargs["fdp_trace_file"] is None


@pytest.mark.skipif(not shutil.which("clang++"), reason="Clang required for generated-source checks")
@pytest.mark.parametrize("parameters,body,call", [
    ("const uint8_t *data, size_t size", "return data[0] == 97 && size == 3 ? 0 : 1;", "nullptr, 99"),
    ("const uint8_t *data, size_t", "return data[0] == 97 ? 0 : 1;", "nullptr, 99"),
    ("const uint8_t *, size_t size", "return size == 3 ? 0 : 1;", "nullptr, 99"),
    ("const uint8_t *, size_t", "return 0;", "nullptr, 99"),
    ("", "return 0;", ""),
    ("void", "return 0;", ""),
    ("const uint8_t data[N], size_t count = limit", "return data[0] == 97 && count == 3 ? 0 : 1;", "nullptr, 99"),
    ("const uint8_t *bytes [[maybe_unused]], size_t count", "return bytes[0] == 97 && count == 3 ? 0 : 1;", "nullptr, 99"),
    ("int *data, int size", "return reinterpret_cast<uint8_t *>(data)[0] == 97 && size == 3 ? 0 : 1;", "nullptr, 99"),
])
def test_generated_direct_source_compiles_and_uses_expected_values(tmp_path: Path, parameters, body, call):
    prefix = "constexpr unsigned N = 8, limit = 99;\n" if "data[N]" in parameters else ""
    source = prefix + harness(parameters, body)
    transformed = api._inline_direct_input_source(source, api.DIRECT_INPUT_HEADER_NAME)
    if transformed != source:
        (tmp_path / api.DIRECT_INPUT_HEADER_NAME).write_text(api._direct_input_header_source(b"abc"))
    program = tmp_path / "program.cpp"
    program.write_text(transformed + f"int main() {{ return LLVMFuzzerTestOneInput({call}); }}\n")
    binary = tmp_path / "program.out"
    compile_result = run_supervised(
        ["clang++", "-std=c++17", "-Wall", "-Werror", str(program), "-o", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    result = run_supervised([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    assert result.returncode == 0, result.stderr
