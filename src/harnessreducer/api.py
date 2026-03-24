from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harnessreducer.fdp_transform import inline_source, inject_ids, load_trace
from harnessreducer.reducer_runner import (
    get_crash_tester_path,
    run_command,
    check_reducer_crash_pattern,
    check_tree_reducer,
    extract_crash_pattern_from_output,
    check_harness_compilation,
    compile_dump_mode_harness,
    configure_work_dir,
    dump_fdp_trace,
    format_reduced_harness,
    get_work_dir,
    run_treereducer,
)

ADDITIONAL_HEADES = [
    "#include <vector>",
    "#include <deque>",
    "#include <fstream>",
    "#include <map>",
    "#include <mutex>",
    "#include <sstream>"
]

@dataclass(frozen=True)
class ReductionConfig:
    harness_path: str
    extra_flags: str | None = None
    crash_input: str | None = None
    work_dir: str | None = None
    start_id: int = 100000
    marker: str = "FDP_ID"
    use_llm: bool = False


@dataclass(frozen=True)
class ReductionResult:
    reduced_harness: str
    tagged_harness: str
    fdp_trace: str


def tag_harness_with_fdp_ids(harness_path: str, start_id: int, marker: str) -> str:
    source = Path(harness_path).read_text(encoding="utf-8")
    transformed, count = inject_ids(source, start_id, marker)

    tagged_harness_file = str(Path(get_work_dir()) / Path(harness_path).name)
    Path(tagged_harness_file).write_text(transformed, encoding="utf-8")
    print(f"Injected {count} FDP callsite IDs into {tagged_harness_file}")
    return tagged_harness_file


def _prepend_additional_headers(harness_path: str) -> None:
    content = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
    missing = [header for header in ADDITIONAL_HEADES if header not in content]
    if not missing:
        return
    headers_block = "\n".join(missing) + "\n"
    Path(harness_path).write_text(headers_block + content, encoding="utf-8")


def inline_literals_in_reduced_harness(
    reduced_harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    crash_input: str | None,
    extra_flags: str | None,
) -> str:
    source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    streams = load_trace(Path(fdp_trace_file))
    transformed, count = inline_source(source, streams)
    inline_harness_path = str(Path(reduced_harness_path).with_suffix(".inline.cpp"))
    Path(inline_harness_path).write_text(transformed, encoding="utf-8")
    _prepend_additional_headers(inline_harness_path)
    print(f"Inlined {count} FDP calls into {inline_harness_path}")

    print(f"Verifying crash preservation for inlined harness: {inline_harness_path}")
    cmd = [
        get_crash_tester_path(),
        inline_harness_path,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        "--extra-flags",
        extra_flags or "",
        "--fdp-trace",
        fdp_trace_file,
    ]
    proc = run_command(cmd, "Inline reduction validation failed.", ignore_errors=True)
    if proc.returncode == 77:
        print("[+] Inline reduction preserved crash behavior.")
        return inline_harness_path

    print("[-] Inline reduction failed to preserve crash behavior. Falling back to tree-reduced harness.")
    _prepend_additional_headers(reduced_harness_path)
    return reduced_harness_path


def reduce_with_config(config: ReductionConfig) -> ReductionResult:
    configure_work_dir(config.work_dir)
    check_tree_reducer()
    check_harness_compilation(config.harness_path, config.extra_flags)
    crash_pattern = extract_crash_pattern_from_output(config.crash_input)
    print(f"[+] Extracted crash pattern: {crash_pattern}")
    check_reducer_crash_pattern(config.harness_path, crash_pattern, config.crash_input, config.extra_flags)
    tagged_harness_file = tag_harness_with_fdp_ids(
        config.harness_path,
        start_id=config.start_id,
        marker=config.marker,
    )
    tagged_harness_bin = compile_dump_mode_harness(tagged_harness_file, config.extra_flags)
    fdp_trace_file = dump_fdp_trace(tagged_harness_bin, config.crash_input)
    reduced_harness = run_treereducer(
        tagged_harness_file,
        fdp_trace_file,
        crash_pattern,
        config.extra_flags,
        config.crash_input,
    )
    format_reduced_harness(reduced_harness)
    post_inline_harness = inline_literals_in_reduced_harness(
        reduced_harness,
        fdp_trace_file,
        crash_pattern,
        config.crash_input,
        config.extra_flags,
    )

    if config.use_llm:
        from harnessreducer.llm_reducer import apply_llm_reduction
        final_harness = apply_llm_reduction(
            post_inline_harness,
            crash_pattern,
            config.crash_input,
            config.extra_flags,
            fdp_trace_file,
        )
    else:
        final_harness = post_inline_harness

    return ReductionResult(
        reduced_harness=final_harness,
        tagged_harness=tagged_harness_file,
        fdp_trace=fdp_trace_file,
    )


def process(
    harness_path: str,
    extra_flags: str | None,
    crash_input: str | None,
    work_dir: str | None = None,
    use_llm: bool = False,
) -> str:
    config = ReductionConfig(
        harness_path=harness_path,
        extra_flags=extra_flags,
        crash_input=crash_input,
        work_dir=work_dir,
        use_llm=use_llm,
    )
    return reduce_with_config(config).reduced_harness

