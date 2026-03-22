from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harnessreducer.fdp_transform import inline_source, inject_ids, load_trace
from harnessreducer.reducer_runner import (
    check_tree_reducer,
    compile_dump_mode_harness,
    configure_work_dir,
    dump_fdp_trace,
    format_reduced_harness,
    get_work_dir,
    run_treereducer,
)


@dataclass(frozen=True)
class ReductionConfig:
    harness_path: str
    crash_pattern: str
    extra_flags: str | None = None
    crash_input: str | None = None
    work_dir: str | None = None
    start_id: int = 100000
    marker: str = "FDP_ID"


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
    print(f"Injected {count} FDP callsite IDs into {harness_path}")
    return tagged_harness_file


def inline_literals_in_reduced_harness(reduced_harness_path: str, fdp_trace_file: str) -> None:
    source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    streams = load_trace(Path(fdp_trace_file))
    transformed, count = inline_source(source, streams)
    Path(reduced_harness_path).write_text(transformed, encoding="utf-8")
    print(f"Inlined {count} FDP calls into {reduced_harness_path}")


def reduce_with_config(config: ReductionConfig) -> ReductionResult:
    configure_work_dir(config.work_dir)
    check_tree_reducer()
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
        config.crash_pattern,
        config.extra_flags,
        config.crash_input,
    )
    format_reduced_harness(reduced_harness)
    inline_literals_in_reduced_harness(reduced_harness, fdp_trace_file)
    return ReductionResult(
        reduced_harness=reduced_harness,
        tagged_harness=tagged_harness_file,
        fdp_trace=fdp_trace_file,
    )


def process(
    harness_path: str,
    extra_flags: str | None,
    crash_pattern: str,
    crash_input: str | None,
    work_dir: str | None = None,
) -> str:
    config = ReductionConfig(
        harness_path=harness_path,
        crash_pattern=crash_pattern,
        extra_flags=extra_flags,
        crash_input=crash_input,
        work_dir=work_dir,
    )
    return reduce_with_config(config).reduced_harness
