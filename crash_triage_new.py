#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import fcntl
import http.client
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
from typing import Any, Iterable, Iterator, Sequence
import urllib.error
import urllib.request


PROJECT_ROOT = Path(__file__).resolve().parent
BENCHMARK_ROOT = PROJECT_ROOT / "benchmark" / "bug"
DEFAULT_CSV_PATH = PROJECT_ROOT / "crash_triage_results_new.csv"
# Fixed audit file for cases whose initial votes require a deciding vote.
FIFTH_VOTE_CSV_PATH = PROJECT_ROOT / "crash_triage_fifth_vote_cases.csv"

sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer import reducer_runner as rr  # noqa: E402


OPENAI_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
OPENAI_MODEL = "glm-5.3"
# OPENAI_MODEL = "GLM-5.3"
# Timeout for a blocking network operation, not the total generation time.
# Streaming requests can run longer while the provider keeps sending data.
LLM_TIMEOUT_SECONDS = 3_600  # One hour.
LLM_TEMPERATURE = 0.3
LLM_TOP_P = 0.95
LLM_RETRIES = 5
LLM_REASONING_EFFORT = "max"
# Initial vote limit; stop once a majority is secured, or add one vote if tied.
TRIAGE_REPETITIONS = 10
# Echo the collected stack trace to the screen before sending it to the LLM.
PRINT_STACK_TRACE = True
# PRINT_STACK_TRACE = False

# Remove very large brace initializers from harness_values.h before sending it
# to the LLM. This does NOT modify the actual header used for compilation.
TRIM_LARGE_VALUES_HEADER_INITIALIZERS = True
# TRIM_LARGE_VALUES_HEADER_INITIALIZERS = False

# Any {...} initializer larger than this many characters is replaced in the
# LLM prompt with a short placeholder.
MAX_LLM_VALUES_HEADER_INITIALIZER_CHARS = 500
# MAX_LLM_VALUES_HEADER_INITIALIZER_CHARS = 20_000


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


class IncompleteLLMResponse(TriageError):
    """A disconnected response that can be retried, never used as a verdict."""


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


def find_matching_initializer_brace(source: str, brace_start: int) -> int | None:
    """Find the closing brace matching source[brace_start].

    The parser understands ordinary C/C++ strings, character literals,
    // comments, and /* comments */ so braces inside those constructs do not
    affect nesting.

    This is intentionally a lightweight parser because harness_values.h is a
    generated header and we only need to identify large brace initializers for
    the LLM prompt.
    """
    if brace_start >= len(source) or source[brace_start] != "{":
        return None

    depth = 0
    index = brace_start
    state = "normal"

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "normal":
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue

            if char == "/" and next_char == "*":
                state = "block_comment"
                index += 2
                continue

            if char == '"':
                state = "string"
                index += 1
                continue

            if char == "'":
                state = "char"
                index += 1
                continue

            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index

            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "normal"
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                state = "normal"
                index += 2
            else:
                index += 1
            continue

        if state == "string":
            if char == "\\":
                index += 2
                continue
            if char == '"':
                state = "normal"
            index += 1
            continue

        if state == "char":
            if char == "\\":
                index += 2
                continue
            if char == "'":
                state = "normal"
            index += 1
            continue

    return None


def sanitize_values_header_for_llm(
    source: str,
    max_initializer_chars: int = MAX_LLM_VALUES_HEADER_INITIALIZER_CHARS,
) -> tuple[str, int, int]:
    """Remove very large brace initializers from the LLM-facing header.

    The actual harness_values.h file on disk is never modified. Compilation
    therefore still uses all original generated values.

    Only the string passed to the LLM is changed.

    For example:

        static const unsigned char buffer[] = {
            0x01, 0x02, 0x03, ... hundreds of thousands of values ...
        };

    becomes:

        static const unsigned char buffer[] = {
            /* LARGE INITIALIZER OMITTED FROM LLM PROMPT:
               123456 characters */
        };

    Returns:
        (
            sanitized_source,
            number_of_initializers_removed,
            number_of_characters_removed,
        )
    """
    if not TRIM_LARGE_VALUES_HEADER_INITIALIZERS:
        return source, 0, 0

    if max_initializer_chars <= 0:
        raise TriageError(
            "MAX_LLM_VALUES_HEADER_INITIALIZER_CHARS must be positive."
        )

    result: list[str] = []
    index = 0
    last_written = 0
    removed_initializers = 0
    removed_characters = 0
    source_length = len(source)

    while index < source_length:
        if source[index] != "=":
            index += 1
            continue

        search = index + 1

        # Skip whitespace between '=' and '{'.
        while search < source_length and source[search].isspace():
            search += 1

        # This is not a brace initializer.
        if search >= source_length or source[search] != "{":
            index += 1
            continue

        brace_start = search
        brace_end = find_matching_initializer_brace(source, brace_start)

        # If the initializer is malformed or cannot be parsed, leave it alone.
        if brace_end is None:
            index += 1
            continue

        initializer_length = brace_end - brace_start + 1

        if initializer_length <= max_initializer_chars:
            # Skip over the initializer. There is no reason to inspect nested
            # braces separately because the complete initializer is already
            # below the configured size limit.
            index = brace_end + 1
            continue

        result.append(source[last_written:brace_start])

        omitted_body_length = max(0, initializer_length - 2)

        replacement = (
            "{\n"
            "    /* LARGE INITIALIZER OMITTED FROM LLM PROMPT: "
            f"{initializer_length} characters total, "
            f"{omitted_body_length} characters inside braces */\n"
            "}"
        )

        result.append(replacement)

        removed_initializers += 1
        removed_characters += initializer_length - len(replacement)

        last_written = brace_end + 1
        index = brace_end + 1

    if removed_initializers == 0:
        return source, 0, 0

    result.append(source[last_written:])

    return "".join(result), removed_initializers, removed_characters


def prepare_values_header_for_llm(path: Path) -> str:
    """Read harness_values.h and prepare a smaller LLM-facing representation."""
    original_source = read_text(path)

    sanitized_source, removed_count, removed_characters = (
        sanitize_values_header_for_llm(original_source)
    )

    if removed_count > 0:
        print(
            "[+] Trimmed generated fuzz value header for LLM prompt: "
            f"{removed_count} large initializer(s) removed"
        )
        print(
            "[+] harness_values.h prompt size: "
            f"{len(original_source)} -> {len(sanitized_source)} characters "
            f"({removed_characters} characters removed)"
        )
    elif TRIM_LARGE_VALUES_HEADER_INITIALIZERS:
        print(
            "[+] No harness_values.h initializer exceeded "
            f"{MAX_LLM_VALUES_HEADER_INITIALIZER_CHARS} characters"
        )
    else:
        print("[+] Large harness_values.h initializer trimming is disabled")

    return sanitized_source


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


def compile_harness(command: Sequence[str], cwd: Path | None = None) -> None:
    process = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        cwd=str(cwd) if cwd is not None else None,
        check=False,
    )
    if process.returncode == 0:
        return
    output = process.stderr.strip() or process.stdout.strip() or "(no output)"
    cwd_text = f"\nWorking directory:\n{cwd}\n" if cwd is not None else ""
    raise TriageError(
        "Harness compilation failed.\n\n"
        f"Command:\n{format_command(command)}\n"
        f"{cwd_text}\n"
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
    cwd: Path | None = None,
) -> str:
    command = [str(binary), "-rss_limit_mb=0", str(crash_input)]
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=sanitizer_environment(link_flags),
            timeout=timeout_seconds,
            cwd=str(cwd) if cwd is not None else None,
            check=False,
        )
        cwd_text = f"Working directory: {cwd}\n" if cwd is not None else ""
        return (
            f"Command: {format_command(command)}\n"
            f"{cwd_text}"
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
        cwd_text = f"Working directory: {cwd}\n" if cwd is not None else ""
        return (
            f"Command: {format_command(command)}\n"
            f"{cwd_text}"
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


def iter_sse_data(lines: Iterable[bytes]) -> Iterator[str]:
    """Read SSE data events, including comments and multi-line JSON payloads."""
    data: list[str] = []
    for raw_line in lines:
        line = raw_line.decode("utf-8").rstrip("\r\n")
        if not line:
            if data:
                yield "\n".join(data)
                data.clear()
        elif line.startswith("data:"):
            value = line[5:]
            data.append(value[1:] if value.startswith(" ") else value)


def completed_llm_content(content: Any, finish_reason: Any) -> str:
    if finish_reason == "network_error":
        raise IncompleteLLMResponse("The provider ended generation with network_error.")
    if finish_reason not in {None, "stop"}:
        raise TriageError(
            f"LLM stopped with finish_reason={finish_reason!r}; "
            "refusing to classify a possibly incomplete answer."
        )
    if not isinstance(content, str) or not content.strip():
        raise TriageError("The LLM returned no final answer text.")
    return content.strip()


def read_streamed_chat_completion(
    response: Iterable[bytes],
    started_at: float,
) -> str:
    parts: list[str] = []
    reasoning_chars = 0
    answer_chars = 0
    last_progress: float | None = None
    finish_reason = None
    completed = False
    for data in iter_sse_data(response):
        if data.strip() == "[DONE]":
            completed = True
            break
        chunk = json.loads(data)
        if "error" in chunk:
            raise TriageError(f"LLM stream error: {chunk['error']}")
        choices = chunk.get("choices")
        if not choices:
            continue  # Usage-only events and heartbeats have no answer text.
        choice = choices[0]
        delta = choice.get("delta") or {}
        reasoning = delta.get("reasoning_content")
        if isinstance(reasoning, str):
            reasoning_chars += len(reasoning)
        content = delta.get("content")
        if isinstance(content, str):
            parts.append(content)
            answer_chars += len(content)

        now = time.monotonic()
        if (reasoning_chars or answer_chars) and (
            last_progress is None or now - last_progress >= 30
        ):
            print(
                f"[+] LLM streaming after {now - started_at:.0f}s: "
                f"{reasoning_chars} reasoning characters, "
                f"{answer_chars} answer characters received",
                flush=True,
            )
            last_progress = now

        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            completed = True
            break

    if not completed:
        raise IncompleteLLMResponse(
            "LLM stream disconnected before completion "
            f"({reasoning_chars} reasoning characters, {answer_chars} answer "
            "characters received); discarding the partial answer."
        )
    # Reasoning chunks keep the connection active but must not become verdicts.
    return completed_llm_content("".join(parts), finish_reason)


def post_chat_completion(
    messages: list[dict[str, str]],
    *,
    timeout_seconds: int = LLM_TIMEOUT_SECONDS,
    reasoning_effort: str = LLM_REASONING_EFFORT,
) -> str:
    base_url, model, api_key = llm_configuration()
    payload = {
        "model": model,
        "messages": messages,
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "stream": True,
        "thinking": {"type": "enabled"},
        "reasoning_effort": reasoning_effort,
    }
    encoded_payload = json.dumps(payload).encode("utf-8")
    endpoint = chat_completions_endpoint(base_url)
    last_error: Exception | None = None

    for attempt in range(1, LLM_RETRIES + 1):
        started_at = time.monotonic()
        print(
            f"[+] LLM attempt {attempt}/{LLM_RETRIES}: model={model}, "
            f"reasoning={reasoning_effort}, network timeout={timeout_seconds}s",
            flush=True,
        )
        request = urllib.request.Request(
            endpoint,
            data=encoded_payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout_seconds,
            ) as response:
                if response.headers.get_content_type() == "application/json":
                    # Some compatible gateways ignore the streaming request.
                    parsed = json.loads(response.read().decode("utf-8"))
                    if "error" in parsed:
                        raise TriageError(f"LLM response error: {parsed['error']}")
                    choice = parsed["choices"][0]
                    content = completed_llm_content(
                        choice["message"]["content"], choice.get("finish_reason")
                    )
                else:
                    content = read_streamed_chat_completion(response, started_at)
            print(
                f"[+] LLM answer completed in {time.monotonic() - started_at:.1f}s",
                flush=True,
            )
            return content
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
            UnicodeDecodeError,
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            http.client.HTTPException,
            IncompleteLLMResponse,
        ) as exc:
            last_error = exc
        print(
            f"[-] LLM attempt {attempt}/{LLM_RETRIES} failed after "
            f"{time.monotonic() - started_at:.1f}s: "
            f"{type(last_error).__name__}: {last_error}",
            file=sys.stderr,
            flush=True,
        )
        if attempt < LLM_RETRIES:
            time.sleep(min(2**attempt, 10))
    raise TriageError(
        f"LLM request failed after {attempt} attempt(s): "
        f"{type(last_error).__name__}: {last_error}"
    )


# Matches "library-bug", "harness bug", "LIBRARY_BUG", "harnessbug", ...
VERDICT_TOKEN_PATTERN = re.compile(
    r"\b(?:library|harness)[\s_-]*bug\b",
    re.IGNORECASE,
)
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
        prefix = text[
            max(0, match.start() - NEGATION_LOOKBEHIND): match.start()
        ]
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
    lines = [
        stripped
        for stripped in (raw.strip() for raw in text.splitlines())
        if stripped
    ]
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
        "You are a C/C++ fuzzing crash triage assistant. You are an expert in analyzing fuzzing harnesses, generated fuzz values, and stack traces and determining whether a crash is due to a bug in the harness or the target library. "
        "You are provided with the harness source code, optional generated fuzz value "
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
    if library_count == harness_count:
        raise TriageError("Triage votes are tied; an additional vote is required.")
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
    *,
    benchmark_name: str,
    tool: str,
    llm_timeout_seconds: int = LLM_TIMEOUT_SECONDS,
    reasoning_effort: str = LLM_REASONING_EFFORT,
) -> str:
    """Send the stack trace to the LLM as part of the triage prompt.

    The collected stack trace is first echoed to the screen (unless disabled
    via PRINT_STACK_TRACE) so the crash output can be verified before it
    reaches the LLM. Request up to TRIAGE_REPETITIONS votes, stopping as soon
    as one verdict secures a majority. If the votes are tied at the limit,
    one additional independent vote decides the majority.
    """
    if PRINT_STACK_TRACE:
        print_stack_trace(stack_trace)

    prompt = build_prompt(
        harness_source,
        values_header_source,
        stack_trace,
    )

    votes_needed = TRIAGE_REPETITIONS // 2 + 1
    votes: list[str] = []
    for index in range(1, TRIAGE_REPETITIONS + 1):
        print(f"[+] Requesting triage vote {index}/{TRIAGE_REPETITIONS}", flush=True)
        response = post_chat_completion(
            prompt,
            timeout_seconds=llm_timeout_seconds,
            reasoning_effort=reasoning_effort,
        )
        vote = normalize_triage_result(response)
        votes.append(vote)
        print(f"[+] Triage vote {index}: {vote}")
        if votes.count(vote) >= votes_needed:
            print(
                f"[+] Majority secured: {vote} received {votes_needed} votes "
                f"after {index} triages; stopping.",
                flush=True,
            )
            return vote

    library_count = votes.count("library-bug")
    harness_count = votes.count("harness-bug")
    if library_count == harness_count:
        # Record the need for an extra vote even if that request later fails.
        append_fifth_vote_case(benchmark_name, tool, library_count, harness_count)
        index = len(votes) + 1
        print(
            f"[+] Triage votes tied {library_count}-{harness_count}; "
            f"requesting deciding vote {index}",
            flush=True,
        )
        response = post_chat_completion(
            prompt,
            timeout_seconds=llm_timeout_seconds,
            reasoning_effort=reasoning_effort,
        )
        vote = normalize_triage_result(response)
        votes.append(vote)
        print(f"[+] Triage vote {index}: {vote}")
    return majority_vote(votes)


def append_locked_csv_row(
    csv_path: Path,
    header: Sequence[str],
    row: Sequence[object],
) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        # Hold the lock through close/flush so parallel jobs share one header
        # and append complete rows. Compilation and LLM requests stay parallel.
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        write_header = os.fstat(handle.fileno()).st_size == 0
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(header)
        writer.writerow(row)


def append_csv_row(
    csv_path: Path,
    benchmark_name: str,
    tool: str,
    result: str,
) -> None:
    append_locked_csv_row(
        csv_path,
        ["dir", "tool", "triage result"],
        [benchmark_name, tool, result],
    )


def append_fifth_vote_case(
    benchmark_name: str,
    tool: str,
    library_votes: int,
    harness_votes: int,
) -> None:
    append_locked_csv_row(
        FIFTH_VOTE_CSV_PATH,
        ["dir", "tool", "library_votes", "harness_votes"],
        [benchmark_name, tool, library_votes, harness_votes],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Triage a benchmark crash with up to "
            f"{TRIAGE_REPETITIONS} votes, stopping once a verdict receives "
            f"{TRIAGE_REPETITIONS // 2 + 1} votes, with one extra vote if tied, "
            "and append the majority result to a CSV file."
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
    parser.add_argument(
        "--compile-flags",
        default=None,
        help="Harness compilation flags",
    )
    parser.add_argument(
        "--link-flags",
        default=None,
        help="Target-library link flags",
    )
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
    parser.add_argument(
        "--llm-timeout",
        type=int,
        default=LLM_TIMEOUT_SECONDS,
        help=(
            "LLM network I/O timeout in seconds, not total generation time "
            f"(default: {LLM_TIMEOUT_SECONDS}). Active streams may run longer."
        ),
    )
    parser.add_argument(
        "--llm-reasoning-effort",
        choices=("low", "high", "max"),
        default=LLM_REASONING_EFFORT,
        help=f"LLM reasoning effort (default: {LLM_REASONING_EFFORT}).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    if args.llm_timeout <= 0:
        raise SystemExit("--llm-timeout must be positive")

    try:
        benchmark_dir = resolve_benchmark_dir(args.dir)
        crash_input = benchmark_dir / "crash-input"
        if not crash_input.is_file():
            raise TriageError(f"Crash input does not exist: {crash_input}")

        compile_flags = expand_benchmark_flags(
            args.compile_flags,
            benchmark_dir,
        )
        link_flags = expand_benchmark_flags(
            args.link_flags,
            benchmark_dir,
        )

        if not is_original_tool(args.tool):
            harness = select_latest_reduced_harness(
                benchmark_dir,
                args.tool,
            )
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
            print(
                "[+] Generated fuzz value header used for compilation: "
                f"{values_header}"
            )
            print(
                "[+] Generated fuzz value header sanitized before LLM prompt: "
                f"{values_header}"
            )

        with tempfile.TemporaryDirectory(
            prefix="crash_triage_"
        ) as tmp:
            binary = Path(tmp) / "fuzzer"

            compile_command = build_compile_command(
                harness,
                binary,
                compile_flags,
                link_flags,
                values_header,
            )

            print("[+] Compiling harness to collect stack trace")
            compile_harness(compile_command, cwd=benchmark_dir)

            print("[+] Running crash input to collect stack trace")
            stack_trace = run_harness_for_stack_trace(
                binary,
                crash_input,
                link_flags,
                args.timeout,
                cwd=benchmark_dir,
            )

        harness_source = read_text(harness)

        # IMPORTANT:
        #
        # The real harness_values.h file was already used above for compilation.
        # We do NOT modify it.
        #
        # Only the copy passed to the LLM is filtered here.
        values_header_source = (
            prepare_values_header_for_llm(values_header)
            if values_header is not None
            else None
        )

        result = send_stack_trace_to_llm(
            harness_source,
            values_header_source,
            stack_trace,
            benchmark_name=benchmark_dir.name,
            tool=csv_tool,
            llm_timeout_seconds=args.llm_timeout,
            reasoning_effort=args.llm_reasoning_effort,
        )

        csv_path = Path(args.csv).expanduser().resolve()
        append_csv_row(
            csv_path,
            benchmark_dir.name,
            csv_tool,
            result,
        )

        print(f"[+] Majority triage result: {result}")
        print(f"[+] Appended CSV row to: {csv_path}")
        return 0

    except Exception as exc:
        print(f"[-] Crash triage failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
