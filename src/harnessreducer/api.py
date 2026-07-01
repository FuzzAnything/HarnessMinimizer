from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from harnessreducer.fdp_transform import inline_source_with_report, inject_ids, load_trace, strip_injected_ids
from harnessreducer.reducer_runner import (
    get_crash_tester_path,
    apply_coverage_guided_slice,
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
    pch_tester_args,
    prepare_phase3_pch_harness,
    reset_statistics_state,
    reset_stack_trace_state,
    run_treereducer,
    validate_phase3_mode,
    validate_stack_trace,
    get_stack_trace_backup_file,
    stack_trace_tester_args,
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
    iteration: int | None = None
    statistics: bool = False


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


def _write_inline_validation_failure_artifact(
    inline_harness_path: str,
    proc_returncode: int,
    stdout: str,
    stderr: str,
) -> str:
    artifact_path = f"{inline_harness_path}.validation.log"
    artifact = (
        f"returncode: {proc_returncode}\n"
        "===== stdout =====\n"
        f"{stdout}"
        "\n===== stderr =====\n"
        f"{stderr}"
    )
    Path(artifact_path).write_text(artifact, encoding="utf-8")
    return artifact_path


def inline_literals_in_reduced_harness(
    reduced_harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    start_id: int = 100000,
    phase3_mode: str = "direct",
    iteration: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    streams = load_trace(Path(fdp_trace_file))
    inline_result = inline_source_with_report(source, streams)
    transformed, count = inline_result.source, inline_result.replaced
    inline_harness_path = str(Path(reduced_harness_path).with_suffix(".inline.cpp"))
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
            "returning the tree-reduced harness."
        )
        return _finalize_fallback_harness(reduced_harness_path, start_id), ()

    print(f"Verifying crash preservation for inlined harness: {inline_harness_path}")
    validate_phase3_mode(phase3_mode)
    pch_artifacts = None
    validation_source = inline_harness_path
    if phase3_mode == "pch":
        pch_artifacts = prepare_phase3_pch_harness(
            inline_harness_path,
            compile_flags,
            use_replay=True,
        )
        validation_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        validation_source,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--fdp-trace",
        fdp_trace_file,
    ]
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    cmd.extend(stack_trace_tester_args(iteration))
    proc = run_command(cmd, "Inline reduction validation failed.", ignore_errors=True)
    if proc.returncode == 77:
        print("[+] Inline reduction preserved crash behavior.")
        inline_source_text = Path(inline_harness_path).read_text(encoding="utf-8", errors="ignore")
        cleaned, removed = strip_injected_ids(inline_source_text, start_id=start_id)
        if removed:
            Path(inline_harness_path).write_text(cleaned, encoding="utf-8")
            print(f"Removed {removed} remaining injected FDP IDs from inline harness.")
        return inline_harness_path, tuple(generated_headers)

    artifact_path = _write_inline_validation_failure_artifact(
        inline_harness_path,
        proc.returncode,
        proc.stdout,
        proc.stderr,
    )
    print(
        "[-] Inline reduction failed to preserve crash behavior. Falling back to tree-reduced harness. "
        f"Validation log: {artifact_path}"
    )
    return _finalize_fallback_harness(reduced_harness_path, start_id), ()


def reduce_with_config(config: ReductionConfig) -> ReductionResult:
    configure_work_dir(config.work_dir)
    reset_stack_trace_state()
    if config.statistics:
        reset_statistics_state()
        if config.iteration is not None:
            print("[*] Statistics collection is disabled when --iteration is set.")
    validate_phase3_mode(config.phase3_mode)
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
    check_reducer_crash_pattern(
        config.harness_path,
        crash_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        phase3_mode=config.phase3_mode,
    )
    effective_harness_path = apply_coverage_guided_slice(
        config.harness_path,
        crash_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        phase3_mode=config.phase3_mode,
    )
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
    reduced_harness = run_treereducer(
        tagged_harness_file,
        fdp_trace_file,
        crash_pattern,
        config.compile_flags,
        config.link_flags,
        config.crash_input,
        stable=config.stable,
        phase3_mode=config.phase3_mode,
        iteration=config.iteration,
        statistics=config.statistics,
    )
    format_reduced_harness(reduced_harness)
    # Final stack trace validation after tree reduction.
    if config.iteration is not None:
        if not validate_stack_trace(
            reduced_harness,
            crash_pattern,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            fdp_trace_file=fdp_trace_file,
            phase3_mode=config.phase3_mode,
        ):
            backup_file = get_stack_trace_backup_file()
            if os.path.exists(backup_file):
                print(f"[!] Final stack trace check failed. Restoring last backup: {backup_file}")
                shutil.copy2(backup_file, reduced_harness)
            else:
                print("[!] Final stack trace check failed but no backup exists. Keeping current reduced harness.")
        else:
            # Save a backup at this point for potential later rollback.
            backup_file = get_stack_trace_backup_file()
            shutil.copy2(reduced_harness, backup_file)
    post_inline_harness, generated_headers = inline_literals_in_reduced_harness(
        reduced_harness,
        fdp_trace_file,
        crash_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        config.start_id,
        phase3_mode=config.phase3_mode,
        iteration=config.iteration,
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
            phase3_mode=config.phase3_mode,
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
    iteration: int | None = None,
    statistics: bool = False,
) -> str | None:
    config = ReductionConfig(
        harness_path=harness_path,
        compile_flags=compile_flags,
        link_flags=link_flags,
        crash_input=crash_input,
        work_dir=work_dir,
        use_llm=use_llm,
        phase3_mode=phase3_mode,
        iteration=iteration,
        statistics=statistics,
    )
    result = reduce_with_config(config)
    return result.reduced_harness if result.success else None
