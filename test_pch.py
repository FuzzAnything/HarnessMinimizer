#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from harnessreducer.api import tag_harness_with_fdp_ids
from harnessreducer.reducer_runner import (
    check_harness_compilation,
    check_reducer_crash_pattern,
    compile_dump_mode_harness,
    configure_work_dir,
    dump_fdp_trace,
    extract_crash_pattern_from_output,
    get_crash_tester_path,
    pch_tester_args,
    prepare_phase3_pch_harness,
    run_command,
)


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


def _phase3_extra_flags(
    build_root: Path,
    user_extra_flags: str | None,
    use_case_libraries: bool,
) -> str:
    root = _project_root()
    flags = [
        "-std=c++17",
        f"-I{root / 'include'}",
        f"-I{build_root / 'include'}",
    ]
    if user_extra_flags:
        # Match the source implementation's simple whitespace splitting.
        flags.extend(user_extra_flags.split())
    if use_case_libraries:
        flags.extend(_library_args(build_root / "lib"))
    return " ".join(flags)


def _run_pch_replay_candidate(
    tagged_harness: Path,
    fdp_trace_file: Path,
    crash_pattern: str,
    crash_input: Path | None,
    extra_flags: str,
) -> int:
    artifacts = prepare_phase3_pch_harness(
        str(tagged_harness),
        extra_flags,
        use_replay=True,
    )
    cmd = [
        get_crash_tester_path(),
        artifacts.body_source,
        crash_pattern,
        "--crash-input",
        str(crash_input) if crash_input else "",
        "--extra-flags",
        extra_flags,
        "--fdp-trace",
        str(fdp_trace_file),
    ]
    cmd.extend(pch_tester_args(artifacts, "pch"))
    proc = run_command(
        cmd,
        "PCH replay Phase 3 validation failed",
        ignore_errors=True,
    )
    print(f"[+] PCH replay crash_tester exit code: {proc.returncode}")
    if proc.returncode != 77:
        if proc.stdout:
            print("===== stdout =====")
            print(proc.stdout)
        if proc.stderr:
            print("===== stderr =====")
            print(proc.stderr)
        return 1
    return 0


def run_case(args: argparse.Namespace) -> int:
    root = _project_root()
    benchmark_root = (root / args.benchmark_root).resolve()
    case_dir = _resolve_case_dir(args.dir, benchmark_root)
    harness = _find_harness(case_dir, args.harness)
    crash_input = _find_crash_input(case_dir, args.crash_input)
    build_root = _find_build_root(case_dir, args.build_profile)

    work_dir = Path(args.out_dir).expanduser() if args.out_dir else case_dir / "pch_test_work"
    if not work_dir.is_absolute():
        work_dir = (root / work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    configure_work_dir(str(work_dir))

    extra_flags = _phase3_extra_flags(
        build_root,
        args.extra_flags,
        use_case_libraries=not args.no_case_libraries,
    )

    print(f"[+] Benchmark case: {case_dir}")
    print(f"[+] Harness:        {harness}")
    print(f"[+] Crash input:    {crash_input if crash_input else '<none>'}")
    print(f"[+] Build root:     {build_root}")
    print(f"[+] Work dir:       {work_dir}")
    print(f"[+] Extra flags:    {extra_flags}")

    if args.crash_pattern:
        crash_pattern = args.crash_pattern
        print(f"[+] Using provided crash pattern: {crash_pattern}")
    else:
        check_harness_compilation(str(harness), extra_flags)
        crash_pattern = extract_crash_pattern_from_output(
            str(crash_input) if crash_input else None
        )
        if not crash_pattern:
            print("[-] Could not extract a crash pattern from the original harness.")
            return 1
        print(f"[+] Extracted crash pattern: {crash_pattern}")

    if not args.skip_no_trace_validation:
        print("[+] Validating no-trace Phase 3 PCH path on the original harness...")
        check_reducer_crash_pattern(
            str(harness),
            crash_pattern,
            str(crash_input) if crash_input else None,
            extra_flags,
            phase3_mode="pch",
        )

    print("[+] Tagging FDP callsites with current source-code transformer...")
    tagged_harness = Path(
        tag_harness_with_fdp_ids(
            str(harness),
            start_id=args.start_id,
            marker=args.marker,
        )
    )

    print("[+] Compiling tagged harness in dump mode with current source-code runner...")
    tagged_binary = Path(compile_dump_mode_harness(str(tagged_harness), extra_flags))

    print("[+] Dumping FDP trace with current source-code runner...")
    fdp_trace_file = Path(
        dump_fdp_trace(
            str(tagged_binary),
            str(crash_input) if crash_input else None,
        )
    )
    print(f"[+] FDP trace: {fdp_trace_file}")

    print("[+] Validating replay Phase 3 PCH path on the tagged harness...")
    return _run_pch_replay_candidate(
        tagged_harness=tagged_harness,
        fdp_trace_file=fdp_trace_file,
        crash_pattern=crash_pattern,
        crash_input=crash_input,
        extra_flags=extra_flags,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Exercise HarnessReducer's source-code Phase 3 --pch path on a "
            "benchmark harness without running treereduce-c."
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
        help="Output/work directory. Default: <case>/pch_test_work",
    )
    parser.add_argument(
        "--extra-flags",
        default=None,
        help="Additional clang++ flags, quoted as a single string.",
    )
    parser.add_argument(
        "--crash-pattern",
        default=None,
        help="Optional regex to use instead of extracting one from the original harness.",
    )
    parser.add_argument("--start-id", type=int, default=100000)
    parser.add_argument("--marker", default="FDP_ID")
    parser.add_argument(
        "--skip-no-trace-validation",
        action="store_true",
        help="Skip the pre-reduction no-trace PCH validation step.",
    )
    parser.add_argument(
        "--no-case-libraries",
        action="store_true",
        help="Do not append libraries discovered under build/*/lib.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_case(args)


if __name__ == "__main__":
    raise SystemExit(main())
