from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from harnessreducer.reducer_runner import (  # noqa: E402
    ABORT_ASSERT_LOCATION_PATTERN,
    ABSL_CHECK_PATTERN,
    ASAN_ERROR_PATTERN,
    ASAN_SUMMARY_PATTERN,
    LEAK_PATTERN,
    LIBFUZZER_SIGNAL_PATTERN,
    UBSAN_PATTERN,
    check_harness_compilation,
    check_reducer_crash_pattern,
    configure_work_dir,
    extract_crash_pattern_from_output,
    get_work_dir,
    run_command,
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


@dataclass(frozen=True)
class CrashPatternMatch:
    priority: int
    name: str
    regex: str
    extracted_value: str
    line: str


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
        # Keep this consistent with reducer_runner._split_flags(), which performs
        # simple whitespace splitting before invoking clang++.
        compile_flags.extend(user_compile_flags.split())

    link_flags: list[str] = []
    if user_link_flags:
        link_flags.extend(user_link_flags.split())
    if use_case_libraries:
        link_flags.extend(_library_args(build_root / "lib"))

    return " ".join(compile_flags), " ".join(link_flags)


def _line_containing_span(output: str, start: int, end: int) -> str:
    line_start = output.rfind("\n", 0, start) + 1
    line_end = output.find("\n", end)
    if line_end == -1:
        line_end = len(output)
    return output[line_start:line_end]


def _match_crash_pattern_details(output: str) -> CrashPatternMatch:
    """Mirror Phase 1.3 priority order, reusing reducer_runner's regex objects."""

    asan_summary_match = ASAN_SUMMARY_PATTERN.search(output)
    if asan_summary_match:
        return CrashPatternMatch(
            priority=1,
            name="ASan Summary",
            regex=ASAN_SUMMARY_PATTERN.pattern,
            extracted_value=asan_summary_match.group(1).strip(),
            line=_line_containing_span(
                output, asan_summary_match.start(), asan_summary_match.end()
            ),
        )

    asan_error_match = ASAN_ERROR_PATTERN.search(output)
    if asan_error_match:
        return CrashPatternMatch(
            priority=2,
            name="ASan Error",
            regex=ASAN_ERROR_PATTERN.pattern,
            extracted_value=asan_error_match.group(0),
            line=_line_containing_span(output, asan_error_match.start(), asan_error_match.end()),
        )

    leak_match = LEAK_PATTERN.search(output)
    if leak_match:
        return CrashPatternMatch(
            priority=3,
            name="Leak Summary",
            regex=LEAK_PATTERN.pattern,
            extracted_value=leak_match.group(0),
            line=_line_containing_span(output, leak_match.start(), leak_match.end()),
        )

    ubsan_match = UBSAN_PATTERN.search(output)
    if ubsan_match:
        return CrashPatternMatch(
            priority=4,
            name="UBSan Summary",
            regex=UBSAN_PATTERN.pattern,
            extracted_value=ubsan_match.group(1),
            line=_line_containing_span(output, ubsan_match.start(), ubsan_match.end()),
        )

    for line in output.splitlines():
        if "Assertion" in line and "failed." in line:
            abort_assert_match = ABORT_ASSERT_LOCATION_PATTERN.search(line)
            if abort_assert_match:
                return CrashPatternMatch(
                    priority=5,
                    name="Assert/Abort",
                    regex=ABORT_ASSERT_LOCATION_PATTERN.pattern,
                    extracted_value=abort_assert_match.group(1),
                    line=line,
                )

    absl_check_match = ABSL_CHECK_PATTERN.search(output)
    if absl_check_match:
        return CrashPatternMatch(
            priority=6,
            name="Abseil CHECK",
            regex=ABSL_CHECK_PATTERN.pattern,
            extracted_value=absl_check_match.group(1).strip(),
            line=_line_containing_span(output, absl_check_match.start(), absl_check_match.end()),
        )

    libfuzzer_signal_match = LIBFUZZER_SIGNAL_PATTERN.search(output)
    if libfuzzer_signal_match:
        return CrashPatternMatch(
            priority=7,
            name="libFuzzer Signal",
            regex=LIBFUZZER_SIGNAL_PATTERN.pattern,
            extracted_value=libfuzzer_signal_match.group(1).strip(),
            line=_line_containing_span(
                output, libfuzzer_signal_match.start(), libfuzzer_signal_match.end()
            ),
        )

    raise ValueError("Failed to match crash pattern details from harness output.")


def _extract_crash_pattern_details_from_poc(crash_input: Path | None) -> CrashPatternMatch | None:
    """Run the already-compiled poc.out once more and report match diagnostics."""

    output_bin = Path(get_work_dir()) / "poc.out"
    cmd = [str(output_bin)]
    if crash_input:
        cmd.append(str(crash_input))

    env = os.environ.copy()
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:symbolize=0"
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0"
    proc = run_command(
        cmd,
        env=env,
        error_prefix="Failed to execute harness for crash pattern detail extraction",
        ignore_errors=True,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        print(
            "[!] Warning: Could not collect crash pattern details because the "
            f"diagnostic rerun exited with {proc.returncode}, not 77."
        )
        return None
    return _match_crash_pattern_details(output)


def run_case(args: argparse.Namespace) -> int:
    root = _project_root()
    benchmark_root = (root / args.benchmark_root).resolve()
    case_dir = _resolve_case_dir(args.dir, benchmark_root)
    harness = _find_harness(case_dir, args.harness)
    crash_input = _find_crash_input(case_dir, args.crash_input)
    build_root = _find_build_root(case_dir, args.build_profile)

    work_dir = Path(args.out_dir).expanduser() if args.out_dir else case_dir / "pattern_extraction_work"
    if not work_dir.is_absolute():
        work_dir = (root / work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    configure_work_dir(str(work_dir))

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

    # Phase 1.1: compile the original harness to <work_dir>/poc.out using the
    # production reducer_runner implementation.
    check_harness_compilation(str(harness), compile_flags, link_flags)

    # Phase 1.2/1.3: run poc.out and extract the first matching crash pattern
    # using the production extractor. This script intentionally does not
    # duplicate the regex logic from reducer_runner.py.
    crash_pattern = extract_crash_pattern_from_output(
        str(crash_input) if crash_input else None
    )
    if not crash_pattern:
        print("[-] Could not extract a crash pattern from the original harness.")
        return 1

    print(f"[+] Extracted crash pattern: {crash_pattern}")
    print(f"[+] repr(pattern): {crash_pattern!r}")

    details = _extract_crash_pattern_details_from_poc(crash_input)
    if details:
        print(f"[+] Pattern source: {details.name} (priority {details.priority})")
        print(f"[+] Regex used: {details.regex}")
        print(f"[+] Value from matched regex: {details.extracted_value!r}")
        if details.extracted_value != crash_pattern:
            print(
                "[!] Warning: diagnostic rerun extracted a different value than "
                "extract_crash_pattern_from_output()."
            )
        print("[+] Entire matched line:")
        print(details.line)

    if not args.skip_validation:
        check_reducer_crash_pattern(
            str(harness),
            crash_pattern,
            str(crash_input) if crash_input else None,
            compile_flags,
            link_flags,
            phase3_mode="direct",
        )

    _assert(bool(crash_pattern), "Crash pattern is empty.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Exercise HarnessReducer Crash Pattern Extraction (Phase 1): "
            "compile the original harness, run it, and print the regex pattern "
            "returned by extract_crash_pattern_from_output()."
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
        help="Output/work directory. Default: <case>/pattern_extraction_work",
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
        help="Only extract and print the pattern; skip crash_tester validation.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_case(args)


if __name__ == "__main__":
    raise SystemExit(main())
