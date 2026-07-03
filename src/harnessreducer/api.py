from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from harnessreducer.check_mode import (
    emit_check_statistics_summary,
    record_check_reference,
    reset_check_state,
    run_treereducer_with_check,
)
from harnessreducer.fdp_transform import inline_source_with_report, inject_ids, load_trace, strip_injected_ids
from harnessreducer.reducer_runner import (
    PHASE3_DIRECT,
    apply_coverage_guided_slice,
    candidate_files_match,
    check_reducer_crash_pattern,
    check_tree_reducer,
    extract_crash_pattern_from_output,
    get_last_interesting_file,
    get_normal_reference_stack_depth,
    get_symbolized_reference_stack_depth,
    check_harness_compilation,
    compile_dump_mode_harness,
    configure_work_dir,
    dump_fdp_trace,
    format_reduced_harness,
    get_work_dir,
    reset_stack_trace_state,
    reset_last_interesting_state,
    run_treereducer,
    validate_phase3_mode,
    validate_stack_trace,
)

ADDITIONAL_HEADERS = [
    "#include <cstddef>",
    "#include <cstring>",
    "#include <string>",
    "#include <vector>",
    "#include <deque>",
    "#include <fstream>",
    "#include <map>",
    "#include <mutex>",
    "#include <sstream>",
    "#include <cmath>",
    "#include <iomanip>",
    "#include <limits>",
]

@dataclass(frozen=True)
class ReductionConfig:
    harness_path: str
    compile_flags: str | None = None
    link_flags: str | None = None
    crash_input: str | None = None
    work_dir: str | None = None
    start_id: int = 100000
    marker: str = "FDP_ID"
    use_llm: bool = False
    stable: bool = False
    phase3_mode: str = "direct"
    statistics: bool = False
    slice_enabled: bool = False
    check: bool = False


@dataclass(frozen=True)
class ReductionResult:
    reduced_harness: str
    tagged_harness: str
    fdp_trace: str
    generated_headers: tuple[str, ...] = ()
    success: bool = True


def tag_harness_with_fdp_ids(harness_path: str, start_id: int, marker: str) -> str:
    source = Path(harness_path).read_text(encoding="utf-8")
    transformed, count = inject_ids(source, start_id, marker)

    tagged_harness_file = str(Path(get_work_dir()) / Path(harness_path).name)
    Path(tagged_harness_file).write_text(transformed, encoding="utf-8")
    print(f"Injected {count} FDP callsite IDs into {tagged_harness_file}")
    return tagged_harness_file


def _prepend_additional_headers(harness_path: str) -> None:
    content = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
    missing = [header for header in ADDITIONAL_HEADERS if header not in content]
    if not missing:
        return
    headers_block = "\n".join(missing) + "\n"
    Path(harness_path).write_text(headers_block + content, encoding="utf-8")


def _finalize_fallback_harness(reduced_harness_path: str, start_id: int) -> str:
    fallback_source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    cleaned_source, removed = strip_injected_ids(fallback_source, start_id=start_id)
    if removed:
        Path(reduced_harness_path).write_text(cleaned_source, encoding="utf-8")
        print(f"Removed {removed} injected FDP IDs from fallback harness.")
    _prepend_additional_headers(reduced_harness_path)
    return reduced_harness_path


def inline_literals_in_reduced_harness(
    reduced_harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    start_id: int = 100000,
    phase3_mode: str = "direct",
) -> tuple[str, tuple[str, ...]]:
    streams = load_trace(Path(fdp_trace_file))

    def _attempt_inline(base_harness_path: str, *, attempt_label: str) -> tuple[str, tuple[str, ...]] | None:
        source = Path(base_harness_path).read_text(encoding="utf-8", errors="ignore")
        inline_result = inline_source_with_report(source, streams)
        transformed, count = inline_result.source, inline_result.replaced
        inline_harness_path = str(Path(base_harness_path).with_suffix(".inline.cpp"))
        Path(inline_harness_path).write_text(transformed, encoding="utf-8")

        generated_headers: list[str] = []
        if inline_result.header_source and inline_result.header_name:
            header_path = Path(inline_harness_path).with_name(inline_result.header_name)
            header_path.write_text(inline_result.header_source, encoding="utf-8")
            generated_headers.append(str(header_path))
            details = []
            if inline_result.loop_replaced:
                details.append(f"{inline_result.loop_replaced} repeated")
            if inline_result.large_buffer_replaced:
                details.append(f"{inline_result.large_buffer_replaced} large-buffer")
            detail_text = f" ({', '.join(details)})" if details else ""
            print(
                f"Moved {inline_result.header_replaced} FDP callsites{detail_text} into "
                f"header-backed values: {header_path}"
            )

        _prepend_additional_headers(inline_harness_path)
        print(f"Inlined/replayed {count} FDP calls into {inline_harness_path}")

        unsupported_skips = [
            skip for skip in inline_result.skipped if skip.reason == "unsupported-repeated-trace-id"
        ]
        if unsupported_skips:
            skipped_ids = ", ".join(
                f"{skip.key}({skip.method}, {skip.record_count} records)" for skip in unsupported_skips
            )
            print(
                "[!] Could not header-replay some repeated FDP callsites; "
                f"they remain as FDP calls for validation/replay: {skipped_ids}"
            )

        if count == 0:
            print(
                "[!] Skipping inline validation because no FDP callsites were inlined/replayed; "
                f"returning the {attempt_label} harness."
            )
            return _finalize_fallback_harness(base_harness_path, start_id), ()

        print(f"Verifying crash preservation for inlined harness: {inline_harness_path}")
        validation_log_path = f"{inline_harness_path}.validation.log"
        if validate_stack_trace(
            inline_harness_path,
            crash_pattern,
            crash_input,
            compile_flags,
            link_flags,
            fdp_trace_file=fdp_trace_file,
            phase3_mode=phase3_mode,
            validation_log_path=validation_log_path,
        ):
            print("[+] Inline reduction preserved crash behavior.")
            inline_source_text = Path(inline_harness_path).read_text(encoding="utf-8", errors="ignore")
            cleaned, removed = strip_injected_ids(inline_source_text, start_id=start_id)
            if removed:
                Path(inline_harness_path).write_text(cleaned, encoding="utf-8")
                print(f"Removed {removed} remaining injected FDP IDs from inline harness.")
            return inline_harness_path, tuple(generated_headers)

        print(
            f"[-] Inline reduction failed to preserve crash behavior for the {attempt_label} harness. "
            f"Validation log: {validation_log_path}"
        )
        return None

    inline_result = _attempt_inline(reduced_harness_path, attempt_label="tree-reduced")
    if inline_result is not None:
        return inline_result

    last_interesting_path = get_last_interesting_file()
    if (
        os.path.exists(last_interesting_path)
        and not candidate_files_match(reduced_harness_path, last_interesting_path)
    ):
        print(
            "[!] Retrying inline reduction from the last interesting snapshot: "
            f"{last_interesting_path}"
        )
        snapshot_inline_result = _attempt_inline(
            last_interesting_path,
            attempt_label="last interesting snapshot",
        )
        if snapshot_inline_result is not None:
            return snapshot_inline_result
        print(
            "[-] Snapshot inline reduction also failed. Falling back to the last interesting snapshot harness."
        )
        return _finalize_fallback_harness(last_interesting_path, start_id), ()

    print("[-] Falling back to the tree-reduced harness.")
    return _finalize_fallback_harness(reduced_harness_path, start_id), ()


def reduce_with_config(config: ReductionConfig) -> ReductionResult:
    configure_work_dir(config.work_dir)
    reset_stack_trace_state()
    reset_last_interesting_state()
    reset_check_state()
    if config.statistics:
        from harnessreducer.reducer_runner import reset_statistics_state
        reset_statistics_state()
    validate_phase3_mode(config.phase3_mode)
    validation_phase3_mode = PHASE3_DIRECT
    reduction_phase3_mode = config.phase3_mode
    check_tree_reducer()
    check_harness_compilation(config.harness_path, config.compile_flags, config.link_flags)
    crash_pattern = extract_crash_pattern_from_output(
        config.crash_input,
        harness_path=config.harness_path,
    )
    if not crash_pattern:
        return ReductionResult(
            reduced_harness="",
            tagged_harness="",
            fdp_trace="",
            success=False
        )

    print(f"[+] Extracted crash pattern: {crash_pattern}")
    if config.check:
        print(
            "[+] Stored reference depths: "
            f"fast(symbolize=0)={get_normal_reference_stack_depth()}, "
            f"symbolized(symbolize=1)={get_symbolized_reference_stack_depth()}"
        )
        reference = record_check_reference(config.crash_input, crash_pattern)
        print(
            "[+] Recorded check reference: "
            f"{reference.frame_count} frame(s) in the first entire stack trace."
        )
    check_reducer_crash_pattern(
        config.harness_path,
        crash_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        phase3_mode=validation_phase3_mode,
    )
    if config.slice_enabled:
        effective_harness_path = apply_coverage_guided_slice(
            config.harness_path,
            crash_pattern,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            phase3_mode=validation_phase3_mode,
        )
    else:
        effective_harness_path = config.harness_path
    tagged_harness_file = tag_harness_with_fdp_ids(
        effective_harness_path,
        start_id=config.start_id,
        marker=config.marker,
    )
    tagged_harness_bin = compile_dump_mode_harness(
        tagged_harness_file,
        config.compile_flags,
        config.link_flags,
    )
    fdp_trace_file = dump_fdp_trace(tagged_harness_bin, config.crash_input)
    if config.check:
        reduced_harness = run_treereducer_with_check(
            tagged_harness_file,
            fdp_trace_file,
            crash_pattern,
            config.compile_flags,
            config.link_flags,
            config.crash_input,
            stable=config.stable,
            phase3_mode=reduction_phase3_mode,
        )
        emit_check_statistics_summary()
    else:
        reduced_harness = run_treereducer(
            tagged_harness_file,
            fdp_trace_file,
            crash_pattern,
            config.compile_flags,
            config.link_flags,
            config.crash_input,
            stable=config.stable,
            phase3_mode=reduction_phase3_mode,
            statistics=config.statistics,
        )
    format_reduced_harness(reduced_harness)
    post_inline_harness, generated_headers = inline_literals_in_reduced_harness(
        reduced_harness,
        fdp_trace_file,
        crash_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        config.start_id,
        phase3_mode=validation_phase3_mode,
    )

    if config.use_llm:
        from harnessreducer.llm_reducer import apply_llm_reduction
        final_harness = apply_llm_reduction(
            post_inline_harness,
            crash_pattern,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            fdp_trace_file,
            phase3_mode=validation_phase3_mode,
        )
    else:
        final_harness = post_inline_harness

    return ReductionResult(
        reduced_harness=final_harness,
        tagged_harness=tagged_harness_file,
        fdp_trace=fdp_trace_file,
        generated_headers=generated_headers,
        success=True
    )


def process(
    harness_path: str,
    compile_flags: str | None = None,
    crash_input: str | None = None,
    link_flags: str | None = None,
    work_dir: str | None = None,
    use_llm: bool = False,
    phase3_mode: str = "direct",
    statistics: bool = False,
    slice_enabled: bool = False,
    check: bool = False,
) -> str | None:
    config = ReductionConfig(
        harness_path=harness_path,
        compile_flags=compile_flags,
        link_flags=link_flags,
        crash_input=crash_input,
        work_dir=work_dir,
        use_llm=use_llm,
        phase3_mode=phase3_mode,
        statistics=statistics,
        slice_enabled=slice_enabled,
        check=check,
    )
    result = reduce_with_config(config)
    return result.reduced_harness if result.success else None
