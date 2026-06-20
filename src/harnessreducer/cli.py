from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from harnessreducer.api import ReductionConfig, reduce_with_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnessreducer",
        description="Reduce FDP-based harnesses while preserving crash behavior.",
    )
    parser.add_argument(
        "harness",
        help="Path to the original harness source file (.c/.cc/.cpp).",
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
        "--llm",
        action="store_true",
        help="Use LLM to perform final semantic minimization of the harness.",
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
        help="Use stable reduction mode (no randomization, deterministic output).",
    )
    phase3_group = parser.add_mutually_exclusive_group()
    phase3_group.add_argument(
        "--direct",
        dest="phase3_mode",
        action="store_const",
        const="direct",
        default="direct",
        help="Use the original one-step Phase 3 compile/link path (default).",
    )
    phase3_group.add_argument(
        "--pch",
        dest="phase3_mode",
        action="store_const",
        const="pch",
        help="Use Phase 3 precompiled-header mode and separate compile/link steps.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ReductionConfig(
        harness_path=args.harness,
        compile_flags=args.compile_flags,
        link_flags=args.link_flags,
        crash_input=args.crash_input,
        work_dir=args.work_dir,
        use_llm=args.llm,
        stable=args.stable,
        phase3_mode=args.phase3_mode,
    )
    result = reduce_with_config(config)
    if not result.success:
        print("[!] Warning: Reduction did not complete successfully. Please see the detailed logs above for more information.")
        return 0
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
