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
        "--extra-flags",
        default=None,
        help="Extra compiler flags passed to clang++ during build steps.",
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ReductionConfig(
        harness_path=args.harness,
        extra_flags=args.extra_flags,
        crash_input=args.crash_input,
        work_dir=args.work_dir,
        use_llm=args.llm,
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
        print(f"Reduced harness saved to: {output_path}")
    else:
        print(f"Reduced harness generated at: {reduced_harness}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
