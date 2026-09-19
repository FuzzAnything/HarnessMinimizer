	#!/usr/bin/env python3
"""Direct LLM crash triage for original or reduced fuzzing harnesses."""
 
from __future__ import annotations
 
import argparse
import csv
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Sequence
import urllib.error
import urllib.request
 
 
PROJECT_ROOT = Path(__file__).resolve().parent
BENCHMARK_ROOT = PROJECT_ROOT / "benchmark" / "library-bug"
DEFAULT_CSV_PATH = PROJECT_ROOT / "crash_triage_results.csv"
 
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer import reducer_runner as rr  # noqa: E402
 
 
OPENAI_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
# OPENAI_BASE_URL = "https://llm.shtech.org/v1"
OPENAI_MODEL = "glm-5.3"
# OPENAI_MODEL = "GLM-5.3"
LLM_TIMEOUT_SECONDS = 240
LLM_TEMPERATURE = 1.0
LLM_TOP_P = 0.95
LLM_RETRIES = 5
LLM_REASONING_EFFORT = "high"
# LLM_REASONING_EFFORT = "max"
TRIAGE_REPETITIONS = 3
# Echo the collected stack trace to the screen before sending it to the LLM.
PRINT_STACK_TRACE = True
# PRINT_STACK_TRACE = False
 
 
TRIAGE_RULES = r"""
**Rule 1: The "Harness Fault" Check (Sanity Check)**
-   **Condition**: Is the top-most frame located directly in the fuzzer harness file (e.g., `fuzz_harness.cpp`)?
-   **Verdict**: **HARNESS BUG**. (The harness crashed itself before entering the library).
 
**Rule 2: The "Null Pointer" Check**
-   **Condition**: Is it a NULL Dereference inside the library?
-   **Action**: Trace the NULL value back. Did the Harness pass a NULL pointer to an API directly?
-   **Verdict**:
    -   If Harness passed NULL violating contract -> **HARNESS BUG**.
    -   If Library generated NULL internally -> **LIBRARY BUG**.
 
**Rule 3: The "Memory Ownership" Check (UAF/Double Free)**
-   **Condition**: Is it a Use-After-Free or Double-Free?
-   **Action**: Check who freed the memory.
-   **Verdict**:
    -   If Harness freed it and passed it back -> **HARNESS BUG**.
    -   If Library freed it and tried to use it again -> **LIBRARY BUG**.
 
**Rule 4: The "Assertion" Check**
-   **Condition**: Did an `assert()` fail?
-   **Verdict**:
    -   If assert is enforcing input requirements (e.g., `assert(input != NULL)`) -> **HARNESS BUG**.
    -   If assert is checking internal state (e.g., `assert(state == VALID)`) -> **LIBRARY BUG**.
 
**Rule 5: OOM and Timeout**
-   **Condition**: Did the OOM/Timout is controlled by the harness?
-   **Verdict**:
    -   If allocation size or loop count is passed by the harness -> **HARNESS BUG**.
    -   If casued by internal states -> **LIBRARY BUG**.
 
**Rule 6: API Documentation**
-   **Condition**: Do the harness inputs and API usageappear to follow the API documentation.
-   **Verdict**:
    -   If violating API documentation -> **HARNESS BUG**.
    -   If not violating API documentation -> **LIBRARY BUG**.
 
**Rule 7: Default Liability**
-   **Condition**: If the crash is inside the library, and the harness inputs appear to follow the API documentation.
-   **Verdict**: **LIBRARY BUG**.
""".strip()
 
 
class TriageError(RuntimeError):
    """Raised when the triage script cannot prepare or parse a run."""
 
 
def format_command(command: Sequence[str]) -> str:
    return shlex.join(str(part) for part in command)
 
 
def split_flags(flags: str | None) -> list[str]:
    return rr._split_flags(flags)
 
 
def resolve_benchmark_dir(value: str) -> Path:
    supplied = Path(value).expanduser()
    candidates = [supplied]
    if not supplied.is_absolute():
        candidates.append(BENCHMARK_ROOT / value)
        candidates.append(PROJECT_ROOT / value)
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_dir():
            return resolved
    raise TriageError(
        f"Could not find benchmark directory {value!r}. Tried: "
        + ", ".join(str(path) for path in candidates)
    )
 
 
def select_latest_reduced_harness(benchmark_dir: Path, tool: str) -> Path:
    pattern = f"harnessreducer-perf-comparison-{tool}-*/optimized/jobs-*/reduced.cpp"
    candidates = [path for path in benchmark_dir.glob(pattern) if path.is_file()]
    if not candidates:
        raise TriageError(
            f"No reduced harness found for tool {tool!r} under {benchmark_dir}. "
            f"Expected files matching {pattern!r}."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)
 
 
def is_original_tool(tool: str | None) -> bool:
    return tool is None or tool.strip().lower() in {"", "none", "original"}
 
 
def find_generated_values_header(harness: Path) -> Path | None:
    local_header = harness.parent / "harness_values.h"
    if local_header.is_file():
        return local_header
 
    work_header = harness.parent / "work" / "harness_values.h"
    if work_header.is_file():
        return work_header
 
    work_headers = sorted(
        harness.parent.glob("work/**/harness_values.h"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if work_headers:
        return work_headers[0]
    return None
 
 
def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")
 
 
def expand_benchmark_flags(flags: str | None, benchmark_dir: Path) -> str | None:
    if flags is None:
        return None
    return flags.replace("$(pwd)", str(benchmark_dir))
 
 
def build_compile_command(
    harness: Path,
    output_binary: Path,
    compile_flags: str | None,
    link_flags: str | None,
    values_header: Path | None,
) -> list[str]:
    include_dirs = [harness.parent]
    if values_header is not None and values_header.parent not in include_dirs:
        include_dirs.append(values_header.parent)
 
    return [
        "clang++",
        *rr.PHASE3_SANITIZER_FLAGS,
        *rr.PHASE3_DIRECT_OPT_FLAGS,
        *rr.PHASE3_WARNING_FLAGS,
        *(f"-I{path}" for path in include_dirs),
        *split_flags(compile_flags),
        str(harness),
        "-o",
        str(output_binary),
        *split_flags(link_flags),
    ]
 
 
def compile_harness(command: Sequence[str]) -> None:
    process = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )
    if process.returncode == 0:
        return
    output = process.stderr.strip() or process.stdout.strip() or "(no output)"
    raise TriageError(
        "Harness compilation failed.\n\n"
        f"Command:\n{format_command(command)}\n\n"
        f"Compiler output:\n{output}"
    )
 
 
def sanitizer_environment(link_flags: str | None) -> dict[str, str]:
    env = rr.runtime_library_env(link_flags)
    env["DEBUGINFOD_URLS"] = ""
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env.setdefault("ASAN_SYMBOLIZER_PATH", symbolizer)
        env.setdefault("UBSAN_SYMBOLIZER_PATH", symbolizer)
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1"
    return env
 
 
def run_harness_for_stack_trace(
    binary: Path,
    crash_input: Path,
    link_flags: str | None,
    timeout_seconds: int,
) -> str:
    command = [str(binary), str(crash_input)]
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=sanitizer_environment(link_flags),
            timeout=timeout_seconds,
            check=False,
        )
        return (
            f"Command: {format_command(command)}\n"
            f"Exit status: {process.returncode}\n\n"
            "--- stdout ---\n"
            f"{process.stdout or '(empty)'}\n\n"
            "--- stderr ---\n"
            f"{process.stderr or '(empty)'}"
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        return (
            f"Command: {format_command(command)}\n"
            f"Exit status: timeout after {timeout_seconds} seconds\n\n"
            "--- stdout ---\n"
            f"{stdout or '(empty)'}\n\n"
            "--- stderr ---\n"
            f"{stderr or '(empty)'}"
        )
 
 
def llm_configuration() -> tuple[str, str, str]:
    base_url = os.environ.get("OPENAI_BASE_URL", OPENAI_BASE_URL).strip()
    model = os.environ.get("OPENAI_MODEL", OPENAI_MODEL).strip()
    api_key = os.environ.get("GLM_API_KEY", "").strip()
    # api_key = os.environ.get("HKU_API_KEY", "").strip()
    if not base_url:
        raise TriageError("OPENAI_BASE_URL is empty.")
    if not model:
        raise TriageError("OPENAI_MODEL is empty.")
    if not api_key:
        raise TriageError("GLM_API_KEY is empty. Export GLM_API_KEY before running.")
    return base_url, model, api_key
 
 
def chat_completions_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"
 
 
def post_chat_completion(messages: list[dict[str, str]]) -> str:
    base_url, model, api_key = llm_configuration()
    payload = {
        "model": model,
        "messages": messages,
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "stream": False,
        "thinking": {"type": "enabled"},
        "reasoning_effort": LLM_REASONING_EFFORT,
    }
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
                raise TriageError(f"Unexpected LLM content: {content!r}")
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
    raise TriageError(f"LLM request failed after {LLM_RETRIES} attempts: {last_error}")
 
 
# Matches "library-bug", "harness bug", "LIBRARY_BUG", "harnessbug", ...
VERDICT_TOKEN_PATTERN = re.compile(r"\b(?:library|harness)[\s_-]*bug\b", re.IGNORECASE)
# Matches section labels such as "Verdict:", "Final answer:", "Conclusion -".
VERDICT_MARKER_PATTERN = re.compile(
    r"(?:final\s+)?(?:verdict|answer|conclusion|decision)\s*[:\-–—]*\s*",
    re.IGNORECASE,
)
# Negations that invalidate a verdict mention, e.g. "not a harness bug".
VERDICT_NEGATION_PATTERN = re.compile(r"\bnot\b|n['’]t\b", re.IGNORECASE)
# How many characters before a verdict token to search for a negation.
NEGATION_LOOKBEHIND = 24
 
 
def classify_verdict(token: str) -> str:
    return "library-bug" if token.lower().startswith("library") else "harness-bug"
 
 
def exact_verdict(response: str) -> str | None:
    """Return the verdict when the entire reply is nothing but the token."""
    cleaned = re.sub(r"[^a-z]", "", response.lower())
    if cleaned == "librarybug":
        return "library-bug"
    if cleaned == "harnessbug":
        return "harness-bug"
    return None
 
 
def normalize_verdict_line(line: str) -> str | None:
    """Return the verdict if *line* states nothing but a verdict, allowing
    decorations such as 'Verdict:', '**', backticks, or list markers."""
    matches = list(VERDICT_TOKEN_PATTERN.finditer(line))
    if len(matches) != 1:
        return None
    verdict = classify_verdict(matches[0].group(0))
    remainder = line[: matches[0].start()] + line[matches[0].end():]
    remainder = VERDICT_MARKER_PATTERN.sub(" ", remainder)
    remainder = re.sub(r"[^a-z]", "", remainder.lower())
    return verdict if remainder == "" else None
 
 
def last_verdict_token(text: str) -> str | None:
    """Return the last non-negated verdict token mentioned in *text*."""
    for match in reversed(list(VERDICT_TOKEN_PATTERN.finditer(text))):
        prefix = text[max(0, match.start() - NEGATION_LOOKBEHIND): match.start()]
        if not VERDICT_NEGATION_PATTERN.search(prefix):
            return classify_verdict(match.group(0))
    return None
 
 
def normalize_triage_result(response: str) -> str:
    text = response.strip()
 
    # 1. Ideal case: the whole reply is just the token.
    verdict = exact_verdict(text)
    if verdict:
        return verdict
 
    # 2. Explicit verdict section: use the text after the LAST marker such
    #    as "Verdict:", "Final answer:", or "Conclusion:".
    markers = list(VERDICT_MARKER_PATTERN.finditer(text))
    if markers:
        tail = text[markers[-1].end():]
        verdict = last_verdict_token(tail) or normalize_verdict_line(tail)
        if verdict:
            return verdict
 
    # 3. The last non-empty line contains the verdict.
    lines = [stripped for stripped in (raw.strip() for raw in text.splitlines()) if stripped]
    if lines:
        verdict = last_verdict_token(lines[-1])
        if verdict:
            return verdict
 
    # 4. Some line states only the verdict (possibly decorated); use the last.
    for line in reversed(lines):
        verdict = normalize_verdict_line(line)
        if verdict:
            return verdict
 
    # 5. Last resort: the last non-negated token mention anywhere.
    verdict = last_verdict_token(text)
    if verdict:
        return verdict
 
    raise TriageError(
        "Could not parse LLM triage result. Expected exactly "
        "'library-bug' or 'harness-bug'. Response was:\n"
        f"{response}"
    )
 
 
def build_prompt(
    harness_source: str,
    values_header_source: str | None,
    stack_trace: str,
) -> list[dict[str, str]]:
    system_prompt = (
        "You are a C/C++ fuzzing crash triage assistant. "
        "Use only the supplied harness source, optional generated fuzz value "
        "header, stack trace, and decision rules. "
        "Apply the rules, then state the verdict. "
        "OUTPUT FORMAT (mandatory): your reply must end with a final line "
        "containing exactly one of the two tokens 'library-bug' or "
        "'harness-bug' and nothing else on that line. Do not mention either "
        "token anywhere else in your reply."
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
        f"{TRIAGE_RULES}\n\n"
        "## Harness Source\n"
        "```cpp\n"
        f"{harness_source}\n"
        "```"
        f"{header_section}\n\n"
        "## Stack Trace\n"
        "```text\n"
        f"{stack_trace}\n"
        "```\n\n"
        "Apply the decision rules.\n\n"
        "## Required Output Format\n"
        "Reply with exactly one token, 'library-bug' or 'harness-bug', as the "
        "final line of your reply. The final line must contain nothing but "
        "that token: no punctuation, no markdown, no explanation. If you "
        "justify your decision, keep the tokens out of the justification text."
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
 
 
def majority_vote(votes: list[str]) -> str:
    library_count = votes.count("library-bug")
    harness_count = votes.count("harness-bug")
    return "library-bug" if library_count > harness_count else "harness-bug"
 
 
def print_stack_trace(stack_trace: str) -> None:
    """Echo the collected stack trace to the screen so the crash output that
    reaches the LLM can be verified manually."""
    print("[+] Stack trace sent to the LLM (verification echo):")
    print(f"[+] ({len(stack_trace)} characters)")
    print("--------------- stack trace (start) ---------------")
    print(stack_trace.rstrip())
    print("---------------- stack trace (end) ----------------")
 
 
def send_stack_trace_to_llm(
    harness_source: str,
    values_header_source: str | None,
    stack_trace: str,
) -> str:
    """Send the stack trace to the LLM as part of the triage prompt.
 
    The collected stack trace is first echoed to the screen (unless disabled
    via PRINT_STACK_TRACE) so the crash output can be verified before it
    reaches the LLM. The prompt is then sent TRIAGE_REPETITIONS times and the
    majority verdict is returned.
    """
    if PRINT_STACK_TRACE:
        print_stack_trace(stack_trace)
 
    prompt = build_prompt(harness_source, values_header_source, stack_trace)
    votes: list[str] = []
    for index in range(1, TRIAGE_REPETITIONS + 1):
        response = post_chat_completion(prompt)
        vote = normalize_triage_result(response)
        votes.append(vote)
        print(f"[+] Triage vote {index}: {vote}")
    return majority_vote(votes)
 
 
def append_csv_row(csv_path: Path, benchmark_name: str, tool: str, result: str) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(["dir", "tool", "triage result"])
        writer.writerow([benchmark_name, tool, result])
 
 
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Triage a benchmark crash with one direct LLM prompt, repeated three "
            "times, and append the majority result to a CSV file."
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
            "original harness.cpp. Otherwise, triage the latest split-symbolize "
            "reduced.cpp from harnessreducer-perf-comparison-<tool>-*."
        ),
    )
    parser.add_argument(
        "--csv",
        default=str(DEFAULT_CSV_PATH),
        help=f"CSV result path (default: {DEFAULT_CSV_PATH})",
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
        benchmark_dir = resolve_benchmark_dir(args.dir)
        crash_input = benchmark_dir / "crash-input"
        if not crash_input.is_file():
            raise TriageError(f"Crash input does not exist: {crash_input}")
        compile_flags = expand_benchmark_flags(args.compile_flags, benchmark_dir)
        link_flags = expand_benchmark_flags(args.link_flags, benchmark_dir)
 
        if not is_original_tool(args.tool):
            harness = select_latest_reduced_harness(benchmark_dir, args.tool)
            csv_tool = args.tool
            values_header = find_generated_values_header(harness)
        else:
            harness = benchmark_dir / "harness.cpp"
            csv_tool = "none"
            values_header = None
 
        if not harness.is_file():
            raise TriageError(f"Harness source does not exist: {harness}")
 
        print(f"[+] Benchmark: {benchmark_dir.name}")
        print(f"[+] Tool: {csv_tool}")
        print(f"[+] Harness sent to LLM: {harness}")
        if values_header is not None:
            print(f"[+] Generated fuzz value header sent to LLM: {values_header}")
 
        with tempfile.TemporaryDirectory(prefix="crash_triage_") as tmp:
            binary = Path(tmp) / "fuzzer"
            compile_command = build_compile_command(
                harness,
                binary,
                compile_flags,
                link_flags,
                values_header,
            )
            print("[+] Compiling harness to collect stack trace")
            compile_harness(compile_command)
 
            print("[+] Running crash input to collect stack trace")
            stack_trace = run_harness_for_stack_trace(
                binary,
                crash_input,
                link_flags,
                args.timeout,
            )
 
        harness_source = read_text(harness)
        values_header_source = read_text(values_header) if values_header is not None else None
        result = send_stack_trace_to_llm(harness_source, values_header_source, stack_trace)
 
        csv_path = Path(args.csv).expanduser().resolve()
        append_csv_row(csv_path, benchmark_dir.name, csv_tool, result)
        print(f"[+] Majority triage result: {result}")
        print(f"[+] Appended CSV row to: {csv_path}")
        return 0
    except Exception as exc:
        print(f"[-] Crash triage failed: {exc}", file=sys.stderr)
        return 1
 
 
if __name__ == "__main__":
    raise SystemExit(main())