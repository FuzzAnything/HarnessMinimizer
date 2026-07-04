#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import shutil
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from harnessreducer.fdp_transform import (
    VALUES_HEADER_NAME,
    inject_ids,
    inline_source_with_report,
    load_trace,
    strip_injected_ids,
)
from harnessreducer.reducer_runner import run_command


COMMON_HEADER_RULES = (
    ("std::memcpy", "#include <cstring>"),
    ("std::string", "#include <string>"),
    ("std::vector", "#include <vector>"),
    ("std::numeric_limits", "#include <limits>"),
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


def _compile_harness(
    source: Path,
    output: Path,
    compile_flags: str | None,
    link_flags: str | None,
    dump_mode: bool,
) -> None:
    cmd = [
        "clang++",
        "-fsanitize=address,fuzzer,undefined",
        "-g",
        "-O1",
        "-Werror=uninitialized",
    ]
    if dump_mode:
        cmd.append("-DFDP_MIN_MODE_DUMP")
    if compile_flags:
        cmd.extend(shlex.split(compile_flags))
    cmd.extend([str(source), "-o", str(output)])
    if link_flags:
        cmd.extend(shlex.split(link_flags))

    run_command(
        cmd,
        f"Failed to compile {'dump-mode ' if dump_mode else ''}harness {source}",
    )


def _case_flags(
    build_root: Path,
    user_compile_flags: str | None,
    user_link_flags: str | None,
) -> tuple[str, str]:
    root = _project_root()
    compile_flags = [
        "-std=c++17",
        f"-I{root / 'include'}",
        f"-I{build_root / 'include'}",
    ]
    if user_compile_flags:
        compile_flags.extend(shlex.split(user_compile_flags))

    link_flags = _library_args(build_root / "lib")
    if user_link_flags:
        link_flags.extend(shlex.split(user_link_flags))

    return " ".join(compile_flags), " ".join(link_flags)


def _run_harness(binary: Path, crash_input: Path | None, trace_path: Path | None = None):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0"
    env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1"
    if trace_path is not None:
        try:
            trace_path.unlink()
        except FileNotFoundError:
            pass
        env["FDP_TRACE_PATH"] = str(trace_path)

    cmd = [str(binary)]
    if crash_input is not None:
        cmd.append(str(crash_input))
    return run_command(cmd, f"Failed to run harness {binary}", env=env, ignore_errors=True)


def _prepend_needed_headers(source: str) -> str:
    missing: list[str] = []
    for needle, header in COMMON_HEADER_RULES:
        if needle in source and header not in source:
            missing.append(header)
    if not missing:
        return source
    return "\n".join(missing) + "\n" + source


def run_case(args: argparse.Namespace) -> int:
    root = _project_root()
    benchmark_root = (root / args.benchmark_root).resolve()
    case_dir = _resolve_case_dir(args.dir, benchmark_root)
    harness = _find_harness(case_dir, args.harness)
    crash_input = _find_crash_input(case_dir, args.crash_input)
    build_root = _find_build_root(case_dir, args.build_profile)

    work_dir = Path(args.out_dir).expanduser() if args.out_dir else case_dir / "fdp_test_work"
    if not work_dir.is_absolute():
        work_dir = (root / work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    compile_flags, link_flags = _case_flags(
        build_root,
        args.compile_flags,
        args.link_flags,
    )

    print(f"[+] Benchmark case: {case_dir}")
    print(f"[+] Harness:        {harness}")
    print(f"[+] Crash input:    {crash_input if crash_input else '<none>'}")
    print(f"[+] Build root:     {build_root}")
    print(f"[+] Work dir:       {work_dir}")
    print(f"[+] Compile flags:  {compile_flags}")
    print(f"[+] Link flags:     {link_flags}")

    source = harness.read_text(encoding="utf-8", errors="ignore")
    tagged_source, injected = inject_ids(source, args.start_id, args.marker)
    _assert(injected > 0, "Expected inject_ids() to instrument at least one FDP callsite.")
    tagged_harness = work_dir / f"{harness.stem}.tagged.cpp"
    tagged_harness.write_text(tagged_source, encoding="utf-8")
    _assert(tagged_harness.exists(), f"Tagged harness was not written: {tagged_harness}")
    _assert(
        f"/*{args.marker}:" in tagged_source,
        f"Tagged source does not contain expected injected marker /*{args.marker}:",
    )
    print(f"[+] Injected {injected} FDP IDs: {tagged_harness}")

    tagged_binary = work_dir / "tagged_harness.out"
    _compile_harness(
        tagged_harness,
        tagged_binary,
        compile_flags,
        link_flags,
        dump_mode=True,
    )
    print(f"[+] Compiled dump-mode harness: {tagged_binary}")

    trace_path = work_dir / "fdp_trace.log"
    proc = _run_harness(tagged_binary, crash_input, trace_path=trace_path)
    print(f"[+] Dump-mode run exit code: {proc.returncode}")
    _assert(
        proc.returncode == args.expected_crash_exit_code,
        "Dump-mode harness did not exit with the expected crash code "
        f"{args.expected_crash_exit_code}; got {proc.returncode}.",
    )
    if not trace_path.exists():
        raise RuntimeError(f"FDP trace was not created: {trace_path}")
    _assert(trace_path.stat().st_size > 0, f"FDP trace is empty: {trace_path}")
    print(f"[+] FDP trace: {trace_path}")

    streams = load_trace(trace_path)
    _assert(bool(streams), "load_trace() returned no FDP trace streams.")
    inline_result = inline_source_with_report(
        tagged_source,
        streams,
        header_name=args.header_name,
    )
    transformed, removed = strip_injected_ids(inline_result.source, start_id=args.start_id)
    transformed = _prepend_needed_headers(transformed)
    _assert(
        inline_result.replaced > 0,
        "Expected inline_source_with_report() to replace at least one FDP callsite.",
    )
    _assert(
        f"/*{args.marker}:" not in transformed,
        f"Transformed source still contains injected marker /*{args.marker}:",
    )

    inline_harness = work_dir / f"{harness.stem}.fdp_inlined.cpp"
    inline_harness.write_text(transformed, encoding="utf-8")
    _assert(inline_harness.exists(), f"Transformed harness was not written: {inline_harness}")

    header_path: Path | None = None
    if inline_result.header_source and inline_result.header_name:
        header_path = work_dir / inline_result.header_name
        header_path.write_text(inline_result.header_source, encoding="utf-8")
        _assert(header_path.exists(), f"Generated values header was not written: {header_path}")
        _assert(header_path.stat().st_size > 0, f"Generated values header is empty: {header_path}")

    print(f"[+] Replaced FDP calls:       {inline_result.replaced}")
    print(f"[+] Header-backed callsites: {inline_result.header_replaced}")
    print(f"[+]   repeated/loop:         {inline_result.loop_replaced}")
    print(f"[+]   large buffers:         {inline_result.large_buffer_replaced}")
    print(f"[+] Removed leftover IDs:    {removed}")
    print(f"[+] Transformed harness:     {inline_harness}")
    if header_path:
        print(f"[+] Generated values header: {header_path}")
    if inline_result.skipped:
        print("[!] Skipped callsites:")
        for skip in inline_result.skipped:
            print(
                f"    FDP_ID {skip.key}: {skip.method}, "
                f"{skip.record_count} records, reason={skip.reason}"
            )

    if args.no_compile_result:
        return 0

    inline_binary = work_dir / "fdp_inlined_harness.out"
    _compile_harness(
        inline_harness,
        inline_binary,
        compile_flags,
        link_flags,
        dump_mode=False,
    )
    _assert(inline_binary.exists(), f"Transformed harness binary was not written: {inline_binary}")
    print(f"[+] Compiled transformed harness: {inline_binary}")

    if args.no_run_result:
        return 0

    result_proc = _run_harness(inline_binary, crash_input, trace_path=None)
    print(f"[+] Transformed harness run exit code: {result_proc.returncode}")
    if result_proc.stdout:
        print("===== stdout =====")
        print(result_proc.stdout)
    if result_proc.stderr:
        print("===== stderr =====")
        print(result_proc.stderr)

    _assert(
        result_proc.returncode == args.expected_crash_exit_code,
        "Transformed harness did not preserve the expected crash exit code "
        f"{args.expected_crash_exit_code}; got {result_proc.returncode}.",
    )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a benchmark harness, dump FDP values, and rewrite FDP calls "
            "without running tree-reducer."
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
        help="Output/work directory. Default: <case>/fdp_test_work",
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
    parser.add_argument("--start-id", type=int, default=100000)
    parser.add_argument("--marker", default="FDP_ID")
    parser.add_argument("--header-name", default=VALUES_HEADER_NAME)
    parser.add_argument(
        "--expected-crash-exit-code",
        type=int,
        default=77,
        help="Expected sanitizer/libFuzzer crash exit code. Default: 77",
    )
    parser.add_argument(
        "--no-compile-result",
        action="store_true",
        help="Only generate the transformed harness/header; do not compile them.",
    )
    parser.add_argument(
        "--no-run-result",
        action="store_true",
        help="Compile the transformed harness but do not run it.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_case(args)


if __name__ == "__main__":
    raise SystemExit(main())
