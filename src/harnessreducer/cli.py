from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from harnessreducer.api import ReductionConfig, reduce_with_config
from harnessreducer.reduction_engines import RawOutputCapture, TOOL_CHOICES
from harnessreducer.reducer_runner import (
    DEFAULT_TREEREDUCE_JOBS,
    MAX_TREEREDUCE_JOBS,
    get_candidate_profile_events_file,
    get_debug_log_path,
    get_reduction_profile_json_file,
    get_reduction_profile_text_file,
)


def _stage_debug_log(output: str) -> None:
    debug_log = get_debug_log_path()
    if not debug_log or not Path(debug_log).is_file():
        return

    destination = Path(output).resolve().parent / Path(debug_log).name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if Path(debug_log).resolve() != destination:
        shutil.copy2(debug_log, destination)
    print(f"Debug log saved to: {destination}")


def _stage_profile(output: str) -> None:
    destination_dir = Path(output).resolve().parent
    for source_name in (
        get_candidate_profile_events_file(),
        get_reduction_profile_json_file(),
        get_reduction_profile_text_file(),
    ):
        source = Path(source_name)
        if not source.is_file():
            continue
        destination = destination_dir / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination:
            shutil.copy2(source, destination)
        print(f"Profile artifact saved to: {destination}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnessreducer",
        description="Reduce FDP-based harnesses while preserving crash behavior.",
    )
    parser.add_argument(
        "--capture-raw-output",
        action="store_true",
        help="Save raw reducer output for evaluation; disabled by default and independent of --profile.",
    )
    parser.add_argument(
        "harness",
        help="Path to the original harness source file (.c/.cc/.cpp).",
    )
    parser.add_argument(
        "--tool", choices=TOOL_CHOICES, default="treereduce",
        help="Reduction engine (default: treereduce; other choices use Perses).",
    )
    parser.add_argument(
        "--compile-flags",
        default=None,
        help=(
            "Flags used while compiling/preprocessing, e.g. "
            "'-std=c++17 -I/path/include -DMACRO'."
        ),
    )
    parser.add_argument(
        "--link-flags",
        default=None,
        help=(
            "Flags used only while linking, e.g. "
            "'-L/path/lib -lfoo /path/libfoo.a'."
        ),
    )
    parser.add_argument(
        "--crash-input",
        default=None,
        help="Optional path to crashing input file fed to the harness binary.",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Use a fixed working directory instead of creating a temporary directory.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        required=True,
        help="Optional output path. If omitted, keeps result in reducer temp dir.",
    )
    parser.add_argument(
        "--stable",
        action="store_true",
        help="Repeat the selected engine's reduction passes until their stopping conditions are reached.",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=DEFAULT_TREEREDUCE_JOBS,
        help=(
            "Requested number of concurrent interestingness checks "
            f"(default: {DEFAULT_TREEREDUCE_JOBS}; maximum: {MAX_TREEREDUCE_JOBS})."
        ),
    )
    parser.add_argument(
        "--statistics",
        action="store_true",
        help=(
            "Collect crash_tester return-code statistics during reduction and "
            "write them to statistics.txt in the work directory."
        ),
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help=(
            "Record low-overhead per-candidate timings and tree-reduction "
            "throughput in candidate_profile.jsonl and reduction_profile.*."
        ),
    )
    parser.add_argument(
        "--protect-initializers", action="store_true",
        help=(
            "After unsuccessful final validation, diagnose uninitialized uses and, "
            "if relevant, retry reduction once from the original tagged source with "
            "whole initialized declarations protected. Profiles include both attempts."
        ),
    )
    parser.add_argument(
        "--auto-var-init-pattern",
        action="store_true",
        help=(
            "Compile reducer candidates with Clang's "
            "-ftrivial-auto-var-init=pattern. Final validation still runs without "
            "the flag first, then retries with the flag only if needed."
        ),
    )
    parser.add_argument(
        "--slice",
        action="store_true",
        help=(
            "Enable coverage-guided dynamic slicing before tree reduction. "
            "When omitted, the original harness is passed directly into the "
            "rest of the pipeline."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Insight-only mode: record the first entire stack trace and its frame "
            "count, then run tree reduction with symbolize=1 for every candidate "
            "while tracking how often frame count and full stack trace stay the same."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Follow the normal reduction path while recording every candidate's "
            "compile and crash-oracle result in reduction_debug.log."
        ),
    )
    parser.add_argument(
        "--symbolize",
        action="store_true",
        help=(
            "Ablation mode: run reduction candidates with symbolize=1 and validate "
            "the symbolized crash pattern, stack depth, and crash location."
        ),
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help=(
            "Enable last-interesting snapshotting during tree reduction and allow "
            "post-reduction fallback/retry from that snapshot if inline validation fails."
        ),
    )
    parser.add_argument(
        "--amortize-link",
        action="store_true",
        help=(
            "Reuse a persistent runner and shared/static target libraries during Phase 3. "
            "Requires split or PCH mode; when used alone, the default split mode applies."
        ),
    )
    phase3_group = parser.add_mutually_exclusive_group()
    phase3_group.add_argument(
        "--direct",
        "--single-step",
        dest="phase3_mode",
        action="store_const",
        const="direct",
        default="split",
        help="Use the single-step Phase 3 compile/link path.",
    )
    phase3_group.add_argument(
        "--split",
        dest="phase3_mode",
        action="store_const",
        const="split",
        help="Use two-step Phase 3 mode: compile the full source to an object, then link it (default).",
    )
    phase3_group.add_argument(
        "--pch",
        dest="phase3_mode",
        action="store_const",
        const="pch",
        help="Use Phase 3 precompiled-header mode and separate compile/link steps.",
    )
    parser.add_argument("--no-fdp-replay", action="store_true", help="Disable FDP replay for the replay evaluation.")
    parser.add_argument("--oracle-evaluation", help="Record oracle observations in an evaluation run directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.amortize_link and args.phase3_mode == "direct":
        parser.error("--amortize-link cannot be combined with --direct/--single-step")
    if args.debug and args.check:
        parser.error("--debug and --check are separate diagnostic modes and cannot be combined")
    if args.profile and args.check:
        parser.error("--profile currently measures the normal oracle and cannot be combined with --check")
    if args.protect_initializers and args.slice:
        parser.error("--protect-initializers cannot currently be combined with --slice")
    if not 1 <= args.jobs <= MAX_TREEREDUCE_JOBS:
        parser.error(f"--jobs must be between 1 and {MAX_TREEREDUCE_JOBS}")

    config = ReductionConfig(
        harness_path=args.harness,
        compile_flags=args.compile_flags,
        link_flags=args.link_flags,
        crash_input=args.crash_input,
        work_dir=args.work_dir,
        stable=args.stable,
        phase3_mode=args.phase3_mode,
        amortize_link=args.amortize_link,
        statistics=args.statistics,
        slice_enabled=args.slice,
        check=args.check,
        debug=args.debug,
        snapshot=args.snapshot,
        symbolize=args.symbolize,
        jobs=args.jobs,
        profile=args.profile,
        tool=args.tool,
        protect_initializers=args.protect_initializers,
        auto_var_init_pattern=args.auto_var_init_pattern,
        capture_raw_output=args.capture_raw_output,
        replay_enabled=not args.no_fdp_replay,
        oracle_evaluation=args.oracle_evaluation,
    )
    try:
        result = reduce_with_config(config)
    finally:
        if args.debug:
            _stage_debug_log(args.output)
        if args.profile:
            _stage_profile(args.output)
    if args.capture_raw_output and args.output and result.raw_reduced_harness:
        RawOutputCapture().capture(result.raw_reduced_harness, args.output)
    if not result.success:
        print("[!] Warning: Reduction did not complete successfully. Please see the detailed logs above for more information.")
        return 1
    reduced_harness = result.reduced_harness

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(reduced_harness, output_path)
        for header in result.generated_headers:
            header_path = Path(header)
            copied_header = output_path.parent / header_path.name
            shutil.copy2(header_path, copied_header)
            print(f"Generated values header saved to: {copied_header}")
        print(f"Reduced harness saved to: {output_path}")
    else:
        print(f"Reduced harness generated at: {reduced_harness}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
