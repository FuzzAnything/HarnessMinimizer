#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from harnessreducer.dynamic_slicer import slice_source_by_coverage
from harnessreducer.reducer_runner import (
    check_harness_compilation,
    check_reducer_crash_pattern,
    collect_harness_coverage,
    compile_coverage_harness,
    configure_work_dir,
    extract_crash_pattern_from_output,
    generate_harness_coverage_reports,
    get_stack_trace_file,
    reset_stack_trace_state,
    validate_stack_trace,
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _project_root() -> Path:
    return _REPO_ROOT


def _resolve_case_dir(case_name_or_path: str, benchmark_root: Path) -> Path:
    candidate = Path(case_name_or_path).expanduser()
    if candidate.exists():
        return candidate.resolve()

    candidate = benchmark_root / case_name_or_path
    if candidate.exists():
        return candidate.resolve()

    raise FileNotFoundError(
        f"Could not find benchmark case '{case_name_or_path}' or '{candidate}'."
    )


def _find_harness(case_dir: Path, requested: str | None) -> Path:
    if requested:
        harness = Path(requested).expanduser()
        if not harness.is_absolute():
            harness = case_dir / harness
        if not harness.exists():
            raise FileNotFoundError(f"Requested harness does not exist: {harness}")
        return harness.resolve()

    candidates = sorted(case_dir.glob("*.cpp"))
    if not candidates:
        candidates = sorted(
            path
            for path in case_dir.rglob("*.cpp")
            if "build" not in path.relative_to(case_dir).parts
            and "fdp_test_work" not in path.relative_to(case_dir).parts
            and "pch_test_work" not in path.relative_to(case_dir).parts
            and "pattern_extraction_work" not in path.relative_to(case_dir).parts
            and "dynamic_slicing_work" not in path.relative_to(case_dir).parts
        )

    if len(candidates) != 1:
        pretty = "\n".join(f"  - {path}" for path in candidates) or "  <none>"
        raise RuntimeError(
            "Expected exactly one .cpp harness in the benchmark case. "
            "Pass --harness to disambiguate. Candidates:\n" + pretty
        )
    return candidates[0].resolve()


def _find_crash_input(case_dir: Path, requested: str | None) -> Path | None:
    if requested:
        crash_input = Path(requested).expanduser()
        if not crash_input.is_absolute():
            crash_input = case_dir / crash_input
        if not crash_input.exists():
            raise FileNotFoundError(f"Requested crash input does not exist: {crash_input}")
        return crash_input.resolve()

    for name in ("crash-input", "crash_input", "seed", "input", "poc"):
        candidate = case_dir / name
        if candidate.is_file():
            return candidate.resolve()

    candidates = sorted(
        path
        for path in case_dir.iterdir()
        if path.is_file() and path.suffix in {".bin", ".seed", ".input"}
    )
    if len(candidates) == 1:
        return candidates[0].resolve()
    return None


def _find_build_root(case_dir: Path, build_profile: str | None) -> Path:
    build_dir = case_dir / "build"
    if not build_dir.exists():
        raise FileNotFoundError(f"Missing build directory: {build_dir}")

    if build_profile:
        candidate = build_dir / build_profile
        if not candidate.exists():
            raise FileNotFoundError(f"Requested build profile does not exist: {candidate}")
        build_dir = candidate

    if (build_dir / "include").is_dir() and (build_dir / "lib").is_dir():
        return build_dir.resolve()

    candidates = sorted(
        child
        for child in build_dir.iterdir()
        if child.is_dir() and (child / "include").is_dir() and (child / "lib").is_dir()
    )
    if len(candidates) != 1:
        pretty = "\n".join(f"  - {path}" for path in candidates) or "  <none>"
        raise RuntimeError(
            "Expected exactly one build profile with include/ and lib/. "
            "Pass --build-profile to disambiguate. Candidates:\n" + pretty
        )
    return candidates[0].resolve()


def _library_args(lib_dir: Path) -> list[str]:
    static_libs = sorted(lib_dir.glob("*.a"))
    if static_libs:
        return [str(path) for path in static_libs]

    shared_libs = sorted(lib_dir.glob("*.so"))
    if shared_libs:
        return [str(path) for path in shared_libs] + [f"-Wl,-rpath,{lib_dir}"]

    raise FileNotFoundError(f"No .a or .so libraries found in {lib_dir}")


def _case_flags(
    build_root: Path,
    user_compile_flags: str | None,
    user_link_flags: str | None,
    use_case_libraries: bool,
) -> tuple[str, str]:
    root = _project_root()
    compile_flags = [
        "-std=c++17",
        f"-I{root / 'include'}",
        f"-I{build_root / 'include'}",
    ]
    if user_compile_flags:
        compile_flags.extend(user_compile_flags.split())

    link_flags: list[str] = []
    if user_link_flags:
        link_flags.extend(user_link_flags.split())
    if use_case_libraries:
        link_flags.extend(_library_args(build_root / "lib"))

    return " ".join(compile_flags), " ".join(link_flags)


def _write_coverage_artifacts(
    work_dir: Path,
    reports: dict[str, str],
    covered_lines: list[int],
    executable_lines: list[int],
) -> tuple[list[Path], Path]:
    report_paths: list[Path] = []
    for filename, report_text in reports.items():
        path = work_dir / filename
        path.write_text(report_text, encoding="utf-8")
        report_paths.append(path)

    summary_path = work_dir / "coverage_summary.json"
    uncovered_lines = [line for line in executable_lines if line not in set(covered_lines)]
    summary_path.write_text(
        json.dumps(
            {
                "covered_lines": covered_lines,
                "executable_lines": executable_lines,
                "all_point_lines": executable_lines,
                "uncovered_lines": uncovered_lines,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_paths, summary_path


def run_case(args: argparse.Namespace) -> int:
    root = _project_root()
    benchmark_root = (root / args.benchmark_root).resolve()
    case_dir = _resolve_case_dir(args.dir, benchmark_root)
    harness = _find_harness(case_dir, args.harness)
    crash_input = _find_crash_input(case_dir, args.crash_input)
    build_root = _find_build_root(case_dir, args.build_profile)

    work_dir = Path(args.out_dir).expanduser() if args.out_dir else case_dir / "dynamic_slicing_work"
    if not work_dir.is_absolute():
        work_dir = (root / work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    configure_work_dir(str(work_dir))
    reset_stack_trace_state()

    compile_flags, link_flags = _case_flags(
        build_root,
        args.compile_flags,
        args.link_flags,
        use_case_libraries=not args.no_case_libraries,
    )

    print(f"[+] Benchmark case: {case_dir}")
    print(f"[+] Harness:        {harness}")
    print(f"[+] Crash input:    {crash_input if crash_input else '<none>'}")
    print(f"[+] Build root:     {build_root}")
    print(f"[+] Work dir:       {work_dir}")
    print(f"[+] Compile flags:  {compile_flags}")
    print(f"[+] Link flags:     {link_flags}")

    print("[+] Phase 1: compiling original harness...")
    check_harness_compilation(str(harness), compile_flags, link_flags)
    print("[+] Phase 1: extracting crash pattern and recording stack trace...")
    crash_pattern = extract_crash_pattern_from_output(str(crash_input) if crash_input else None)
    if not crash_pattern:
        print("[-] Could not extract a crash pattern from the original harness.")
        return 1
    print(f"[+] Extracted crash pattern: {crash_pattern}")

    stack_trace_file = Path(get_stack_trace_file())
    if stack_trace_file.exists():
        print(f"[+] Stored stack trace pattern: {stack_trace_file}")
        print("===== stack_trace.pattern =====")
        print(stack_trace_file.read_text(encoding="utf-8"))
    else:
        print("[!] No stack_trace.pattern was recorded.")

    if not args.skip_validation:
        print("[+] Validating original harness against crash_tester.py...")
        check_reducer_crash_pattern(
            str(harness),
            crash_pattern,
            str(crash_input) if crash_input else None,
            compile_flags,
            link_flags,
            phase3_mode="direct",
        )

    print("[+] Compiling coverage-enabled harness...")
    coverage_bin = Path(compile_coverage_harness(str(harness), compile_flags, link_flags))
    print(f"[+] Coverage binary: {coverage_bin}")
    coverage = collect_harness_coverage(
        str(coverage_bin),
        str(harness),
        str(crash_input) if crash_input else None,
    )
    reports = generate_harness_coverage_reports(str(coverage_bin), str(harness))
    covered_lines = sorted(coverage.covered_lines)
    executable_lines = sorted(coverage.executable_lines)
    report_paths, summary_path = _write_coverage_artifacts(
        work_dir,
        reports,
        covered_lines,
        executable_lines,
    )

    print(f"[+] Executable lines:     {executable_lines}")
    print(f"[+] Covered lines:        {covered_lines}")
    print(f"[+] Uncovered lines:      {[line for line in executable_lines if line not in set(covered_lines)]}")
    for path in report_paths:
        print(f"[+] Coverage report:       {path}")
    print(f"[+] Coverage summary:           {summary_path}")

    source = harness.read_text(encoding="utf-8", errors="ignore")
    slice_result = slice_source_by_coverage(source, coverage)
    preview_path = work_dir / f"{harness.stem}.sliced.preview.cpp"
    preview_path.write_text(slice_result.source, encoding="utf-8")
    print(f"[+] Sliced harness preview: {preview_path}")
    print(f"[+] Removed nodes:          {slice_result.removed_nodes}")

    accepted_path = work_dir / f"{harness.stem}.sliced.cpp"
    if slice_result.removed_nodes == 0:
        print("[*] No uncovered nodes were removed.")
        return 0

    if args.skip_validation:
        accepted_path.write_text(slice_result.source, encoding="utf-8")
        print(f"[+] Validation skipped; saved sliced harness to: {accepted_path}")
        return 0

    print("[+] Validating sliced harness crash pattern...")
    try:
        check_reducer_crash_pattern(
            str(preview_path),
            crash_pattern,
            str(crash_input) if crash_input else None,
            compile_flags,
            link_flags,
            phase3_mode="direct",
        )
        print("[+] Validating sliced harness stack trace...")
        trace_ok = validate_stack_trace(
            str(preview_path),
            crash_pattern,
            str(crash_input) if crash_input else None,
            compile_flags,
            link_flags,
            phase3_mode="direct",
        )
    except Exception as exc:
        print(f"[!] Sliced harness validation failed: {exc}")
        print("[!] Keeping preview only; dynamic slicing would fall back to the original harness.")
        return 0

    if not trace_ok:
        print("[!] Sliced harness changed the stack trace.")
        print("[!] Keeping preview only; dynamic slicing would fall back to the original harness.")
        return 0

    accepted_path.write_text(slice_result.source, encoding="utf-8")
    print(f"[+] Sliced harness accepted: {accepted_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Exercise HarnessReducer's dynamic coverage-guided slicing on a "
            "benchmark harness, saving both coverage artifacts and the sliced harness."
        )
    )
    parser.add_argument(
        "--dir",
        required=True,
        help="Benchmark case name under benchmark/ or an explicit benchmark case path.",
    )
    parser.add_argument(
        "--benchmark-root",
        default="benchmark",
        help="Benchmark root relative to the repository root. Default: benchmark",
    )
    parser.add_argument(
        "--harness",
        default=None,
        help="Optional harness .cpp path/name if the case has more than one candidate.",
    )
    parser.add_argument(
        "--crash-input",
        default=None,
        help="Optional crash input path/name. Defaults to crash-input if present.",
    )
    parser.add_argument(
        "--build-profile",
        default=None,
        help="Optional subdirectory under build/, e.g. sanitizer.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output/work directory. Default: <case>/dynamic_slicing_work",
    )
    parser.add_argument(
        "--compile-flags",
        default=None,
        help="Additional compile/preprocessor flags, quoted as a single string.",
    )
    parser.add_argument(
        "--link-flags",
        default=None,
        help="Additional linker/library flags, quoted as a single string.",
    )
    parser.add_argument(
        "--no-case-libraries",
        action="store_true",
        help="Do not append libraries discovered under build/*/lib.",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip crash-pattern / stack-trace validation of the sliced preview.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_case(args)


if __name__ == "__main__":
    raise SystemExit(main())
