#!/usr/bin/env python3
"""Detailed LLM crash triage for original or reduced fuzzing harnesses.

This script is intentionally separate from crash_triage.py:

- crash_triage.py asks the LLM to return only "library-bug" or "harness-bug".
- detailed_crash_triage.py asks the LLM to return the verdict plus the reason.

The local preparation is the same idea: compile the selected harness, run the
crash input to collect a stack trace, then send the harness, optional generated
value header, stack trace, and triage rules to the LLM.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Any, Sequence
import urllib.error
import urllib.request

import crash_triage as base


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_REPORT_DIR = PROJECT_ROOT / "detailed_crash_triage_reports"


# ---------------------------------------------------------------------------
# LLM configuration.
#
# Change these by commenting/uncommenting the lines below.
# Environment variables with the same names still override OPENAI_BASE_URL and
# OPENAI_MODEL at runtime. API_KEY_ENV controls which key variable is read.
# ---------------------------------------------------------------------------

# BigModel / Zhipu China endpoint.
OPENAI_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"

# Z.ai global endpoint.
# OPENAI_BASE_URL = "https://api.z.ai/api/paas/v4"

# HKU gateway endpoint.
# OPENAI_BASE_URL = "https://llm.shtech.org/v1"


OPENAI_MODEL = "glm-5.3"
# OPENAI_MODEL = "glm-5.3-flash"
# OPENAI_MODEL = "GLM-5.3"


# API key environment variable.
API_KEY_ENV = "GLM_API_KEY"
# API_KEY_ENV = "ZAI_API_KEY"
# API_KEY_ENV = "HKU_API_KEY"


# Reasoning effort for providers that support it.
LLM_REASONING_EFFORT = "high"
# LLM_REASONING_EFFORT = "max"
# LLM_REASONING_EFFORT = "low"


# Some providers/gateways may not support these provider-specific thinking
# fields. If a gateway rejects the request because of unknown fields, set this
# to False.
SEND_THINKING_OPTIONS = True

# Z.ai documentation recommends clear_thinking=false for some GLM models.
# Leave as None to omit it. Uncomment False if you want to send it explicitly.
THINKING_CLEAR_THINKING: bool | None = None
# THINKING_CLEAR_THINKING = False


LLM_TIMEOUT_SECONDS = 300
LLM_TEMPERATURE = 1.0
LLM_TOP_P = 0.95
LLM_RETRIES = 5
TRIAGE_REPETITIONS = 3


class DetailedTriageError(RuntimeError):
    """Raised when detailed crash triage cannot continue."""


def select_latest_reduced_harness(benchmark_dir: Path, tool: str, variant: str) -> Path:
    pattern = f"harnessreducer-perf-comparison-{tool}-*/{variant}/jobs-*/reduced.cpp"
    candidates = [path for path in benchmark_dir.glob(pattern) if path.is_file()]
    if not candidates:
        raise DetailedTriageError(
            f"No reduced harness found for tool {tool!r} and variant {variant!r} "
            f"under {benchmark_dir}. Expected files matching {pattern!r}."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def chat_completions_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"


def llm_configuration() -> tuple[str, str, str]:
    base_url = os.environ.get("OPENAI_BASE_URL", OPENAI_BASE_URL).strip()
    model = os.environ.get("OPENAI_MODEL", OPENAI_MODEL).strip()
    api_key = os.environ.get(API_KEY_ENV, "").strip()
    if not base_url:
        raise DetailedTriageError("OPENAI_BASE_URL is empty.")
    if not model:
        raise DetailedTriageError("OPENAI_MODEL is empty.")
    if not api_key:
        raise DetailedTriageError(
            f"{API_KEY_ENV} is empty. Export {API_KEY_ENV} before running, "
            "or change API_KEY_ENV near the top of detailed_crash_triage.py."
        )
    return base_url, model, api_key


def post_chat_completion(messages: list[dict[str, str]]) -> str:
    base_url, model, api_key = llm_configuration()
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "stream": False,
    }
    if SEND_THINKING_OPTIONS:
        thinking: dict[str, Any] = {"type": "enabled"}
        if THINKING_CLEAR_THINKING is not None:
            thinking["clear_thinking"] = THINKING_CLEAR_THINKING
        payload["thinking"] = thinking
        payload["reasoning_effort"] = LLM_REASONING_EFFORT

    encoded_payload = json.dumps(payload).encode("utf-8")
    endpoint = chat_completions_endpoint(base_url)
    last_error: Exception | None = None

    for attempt in range(1, LLM_RETRIES + 1):
        request = urllib.request.Request(
            endpoint,
            data=encoded_payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=LLM_TIMEOUT_SECONDS) as response:
                parsed = json.loads(response.read().decode("utf-8"))
            content = parsed["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise DetailedTriageError(f"Unexpected LLM content: {content!r}")
            return content.strip()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"LLM HTTP {exc.code}: {detail}")
            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                break
        except (
            KeyError,
            IndexError,
            TypeError,
            json.JSONDecodeError,
            urllib.error.URLError,
            TimeoutError,
        ) as exc:
            last_error = exc
        if attempt < LLM_RETRIES:
            time.sleep(min(2**attempt, 10))
    raise DetailedTriageError(
        f"LLM request failed after {LLM_RETRIES} attempts: {last_error}"
    )


def build_detailed_prompt(
    harness_source: str,
    values_header_source: str | None,
    stack_trace: str,
) -> list[dict[str, str]]:
    system_prompt = (
        "You are a C/C++ fuzzing crash triage assistant. "
        "Use only the supplied harness source, optional generated fuzz value "
        "header, stack trace, and decision rules. "
        "Do not use outside knowledge except general C/C++ and fuzzing knowledge."
    )
    header_section = ""
    if values_header_source is not None:
        header_section = (
            "\n\n## Generated Fuzz Value Header\n"
            "```cpp\n"
            f"{values_header_source}\n"
            "```"
        )
    user_prompt = (
        "## Decision Rules\n"
        f"{base.TRIAGE_RULES}\n\n"
        "## Harness Source\n"
        "```cpp\n"
        f"{harness_source}\n"
        "```"
        f"{header_section}\n\n"
        "## Stack Trace\n"
        "```text\n"
        f"{stack_trace}\n"
        "```\n\n"
        "Apply the decision rules and return this exact format:\n\n"
        "VERDICT: library-bug OR harness-bug\n"
        "RULES USED: short list of rule numbers or names\n"
        "REASON: explain the concrete evidence from the harness and stack trace\n"
        "UNCERTAINTY: mention any missing information or assumptions\n\n"
        "The VERDICT line must contain exactly one of: library-bug, harness-bug."
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def extract_verdict(response: str) -> str:
    verdict_match = re.search(
        r"(?im)^\s*VERDICT\s*:\s*(library[- ]bug|harness[- ]bug)\b",
        response,
    )
    if verdict_match:
        return verdict_match.group(1).lower().replace(" ", "-")

    normalized = response.lower()
    has_library = "library-bug" in normalized or "library bug" in normalized
    has_harness = "harness-bug" in normalized or "harness bug" in normalized
    if has_library and not has_harness:
        return "library-bug"
    if has_harness and not has_library:
        return "harness-bug"
    raise DetailedTriageError(
        "Could not parse detailed LLM verdict. Expected a line like "
        "'VERDICT: library-bug' or 'VERDICT: harness-bug'. Response was:\n"
        f"{response}"
    )


def majority_vote(votes: list[str]) -> str:
    library_count = votes.count("library-bug")
    harness_count = votes.count("harness-bug")
    return "library-bug" if library_count > harness_count else "harness-bug"


def default_report_path(benchmark_name: str, tool: str, variant: str) -> Path:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    safe_variant = variant.replace("/", "-")
    filename = f"{benchmark_name}_{tool}_{safe_variant}_{timestamp}.md"
    return DEFAULT_REPORT_DIR / filename


def write_report(
    path: Path,
    benchmark_dir: Path,
    tool: str,
    variant: str,
    harness: Path,
    values_header: Path | None,
    votes: list[str],
    responses: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    majority = majority_vote(votes)
    header = [
        "# Detailed crash triage report",
        "",
        f"- Benchmark: `{benchmark_dir.name}`",
        f"- Tool: `{tool}`",
        f"- Reduced-harness variant: `{variant}`",
        f"- Harness sent to LLM: `{harness}`",
        f"- Generated value header sent: `{values_header if values_header else 'none'}`",
        f"- Majority verdict: `{majority}`",
        f"- Votes: `{', '.join(votes)}`",
        "",
    ]
    sections: list[str] = []
    for index, (vote, response) in enumerate(zip(votes, responses, strict=True), start=1):
        sections.extend(
            [
                f"## Vote {index}: `{vote}`",
                "",
                "```text",
                response,
                "```",
                "",
            ]
        )
    path.write_text("\n".join(header + sections), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run detailed LLM crash triage for a benchmark and save the "
            "per-vote explanations to a Markdown report."
        )
    )
    parser.add_argument(
        "--dir",
        required=True,
        help=(
            "Benchmark directory name under benchmark/library-bug, or an explicit "
            "path to a benchmark directory."
        ),
    )
    parser.add_argument("--compile-flags", default=None, help="Harness compilation flags")
    parser.add_argument("--link-flags", default=None, help="Target-library link flags")
    parser.add_argument(
        "--tool",
        default=None,
        help=(
            "Reduction tool name. Omit this, or use 'none', to triage the "
            "original harness.cpp. Otherwise, triage the latest reduced.cpp for "
            "that tool and selected variant."
        ),
    )
    parser.add_argument(
        "--variant",
        default="optimized",
        choices=["optimized", "split-symbolize"],
        help=(
            "Reduced-run variant used when --tool is not none. Default is "
            "'optimized' to match the current crash_triage.py selection."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Markdown report path. By default, a timestamped report is written "
            "under detailed_crash_triage_reports/."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds for the local crash run used to collect stack trace.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")

    try:
        benchmark_dir = base.resolve_benchmark_dir(args.dir)
        crash_input = benchmark_dir / "crash-input"
        if not crash_input.is_file():
            raise DetailedTriageError(f"Crash input does not exist: {crash_input}")
        compile_flags = base.expand_benchmark_flags(args.compile_flags, benchmark_dir)
        link_flags = base.expand_benchmark_flags(args.link_flags, benchmark_dir)

        if not base.is_original_tool(args.tool):
            tool = str(args.tool)
            harness = select_latest_reduced_harness(benchmark_dir, tool, args.variant)
            values_header = base.find_generated_values_header(harness)
            report_variant = args.variant
        else:
            tool = "none"
            harness = benchmark_dir / "harness.cpp"
            values_header = None
            report_variant = "original"

        if not harness.is_file():
            raise DetailedTriageError(f"Harness source does not exist: {harness}")

        print(f"[+] Benchmark: {benchmark_dir.name}")
        print(f"[+] Tool: {tool}")
        print(f"[+] Harness sent to LLM: {harness}")
        if values_header is not None:
            print(f"[+] Generated fuzz value header sent to LLM: {values_header}")

        with tempfile.TemporaryDirectory(prefix="detailed_crash_triage_") as tmp:
            binary = Path(tmp) / "fuzzer"
            compile_command = base.build_compile_command(
                harness,
                binary,
                compile_flags,
                link_flags,
                values_header,
            )
            print("[+] Compiling harness to collect stack trace")
            base.compile_harness(compile_command)

            print("[+] Running crash input to collect stack trace")
            stack_trace = base.run_harness_for_stack_trace(
                binary,
                crash_input,
                link_flags,
                args.timeout,
            )

        harness_source = base.read_text(harness)
        values_header_source = (
            base.read_text(values_header) if values_header is not None else None
        )
        prompt = build_detailed_prompt(harness_source, values_header_source, stack_trace)

        votes: list[str] = []
        responses: list[str] = []
        for index in range(1, TRIAGE_REPETITIONS + 1):
            response = post_chat_completion(prompt)
            vote = extract_verdict(response)
            votes.append(vote)
            responses.append(response)
            print(f"\n[+] Detailed triage vote {index}: {vote}")
            print(response)

        result = majority_vote(votes)
        if args.output is not None:
            report_path = Path(args.output).expanduser().resolve()
        else:
            report_path = default_report_path(benchmark_dir.name, tool, report_variant)
        write_report(
            report_path,
            benchmark_dir,
            tool,
            report_variant,
            harness,
            values_header,
            votes,
            responses,
        )
        print(f"\n[+] Majority detailed triage verdict: {result}")
        print(f"[+] Detailed report written to: {report_path.resolve()}")
        return 0
    except Exception as exc:
        print(f"[-] Detailed crash triage failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
