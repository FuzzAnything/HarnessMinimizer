#!/usr/bin/env python3
"""Run resumable LLM crash triage for both evaluation datasets."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import csv
from datetime import datetime
import fcntl
import http.client
import json
import multiprocessing
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
DEFAULT_CSV_PATH = PROJECT_ROOT / "crash_triage_result.csv"

sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer import reducer_runner as rr  # noqa: E402
from harnessreducer.evaluation_metrics import EVALUATION_FORMAT, artifact_path, read_json
from harnessreducer.reduction_engines import TOOL_CHOICES
from run_harnessreducer_perf_sweep import load_cases, repository_path
from sort_triage_csv import csv_lock, read_csv_rows, sort_key, write_csv_rows_atomic


ENV_KEYS = ("OPENAI_BASE_URL", "LLM_API_KEY", "OPENAI_MODEL")
ALL_TOOLS = ("none", "treereduce", "perses", "wdd", "cdd")
RESULT_FIELDS = (
    "dataset", "dir", "tool", "status", "triage result", "library_votes",
    "harness_votes", "model", "reasoning_effort", "source_batch", "harness", "log", "error",
)
TIED_FIELDS = (
    "timestamp", "dataset", "dir", "tool", "library_votes", "harness_votes",
    "model", "reasoning_effort", "source_batch", "result_file",
)
# Timeout for a blocking network operation, not the total generation time.
# Streaming requests can run longer while the provider keeps sending data.
LLM_TIMEOUT_SECONDS = 3_600  # One hour.
LLM_TEMPERATURE = 0.3
LLM_TOP_P = 0.95
LLM_RETRIES = 5
LLM_REASONING_EFFORT = "high"
# Initial vote limit; stop once a majority is secured, or add one vote if tied.
TRIAGE_REPETITIONS = 20
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


def find_generated_values_header(harness: Path) -> Path | None:
    local_header = harness.parent / "harness_values.h"
    if local_header.is_file():
        return local_header
    if re.search(r'^\s*#\s*include\s*[<"]harness_values\.h[>"]', read_text(harness), re.MULTILINE):
        raise TriageError(f"Missing accompanying generated header: {local_header}")
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


def load_environment() -> None:
    """Load literal .env assignments; never execute or interpolate their values."""
    path = PROJECT_ROOT / ".env"
    if not path.is_file():
        return
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            raise TriageError(f"Invalid .env assignment at line {number}.")
        key = key.strip()
        if key not in ENV_KEYS:
            continue
        value = value.strip()
        try:
            if value.startswith(("'", '"')):
                values = shlex.split(value, comments=True)
                if len(values) != 1:
                    raise ValueError
                value = values[0]
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        except ValueError:
            raise TriageError(f"Invalid quoted .env value at line {number}.") from None
        os.environ.setdefault(key, value)


def redact(value: object) -> str:
    text = str(value)
    for secret in sorted(
        (os.environ.get(key, "").strip() for key in ("LLM_API_KEY", "OPENAI_BASE_URL")),
        key=len, reverse=True,
    ):
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def llm_configuration() -> tuple[str, str, str]:
    missing = [key for key in ENV_KEYS if not os.environ.get(key, "").strip()]
    if missing:
        raise TriageError("Set " + ", ".join(missing) + " in .env or the environment before running.")
    base_url = os.environ["OPENAI_BASE_URL"].strip()
    model = os.environ["OPENAI_MODEL"].strip()
    api_key = os.environ["LLM_API_KEY"].strip()
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


def print_stack_trace(stack_trace: str) -> None:
    """Echo the collected stack trace to the screen so the crash output that
    reaches the LLM can be verified manually."""
    print("[+] Stack trace sent to the LLM (verification echo):")
    print(f"[+] ({len(stack_trace)} characters)")
    print("--------------- stack trace (start) ---------------")
    print(stack_trace.rstrip())
    print("---------------- stack trace (end) ----------------")


def record_tied_case(csv_path: Path, row: dict) -> None:
    path = csv_path.with_name("crash_triage_tied_cases.csv")
    tied = {key: row[key] for key in TIED_FIELDS if key in row}
    tied.update(timestamp=datetime.now().astimezone().isoformat(), result_file=str(csv_path))
    with csv_lock(path):
        rows = []
        if path.exists():
            header, rows = read_csv_rows(path)
            if header != list(TIED_FIELDS):
                raise TriageError(f"Unexpected tied-case CSV header: {path}")
        rows.append(tied)
        write_csv_rows_atomic(path, TIED_FIELDS, rows)


def send_stack_trace_to_llm(
    harness_source: str,
    values_header_source: str | None,
    stack_trace: str,
    *,
    row: dict,
    csv_path: Path,
    llm_timeout_seconds: int,
) -> str:
    if PRINT_STACK_TRACE:
        print_stack_trace(stack_trace)
    prompt = build_prompt(harness_source, values_header_source, stack_trace)
    needed = TRIAGE_REPETITIONS // 2 + 1
    for index in range(1, TRIAGE_REPETITIONS + 2):
        if index > TRIAGE_REPETITIONS:
            # Persist the tie before a deciding request that might fail.
            record_tied_case(csv_path, row)
            print("[+] Votes tied 10–10; requesting the deciding vote", flush=True)
        print(f"[+] Requesting triage vote {index}", flush=True)
        response = post_chat_completion(
            prompt, timeout_seconds=llm_timeout_seconds,
            reasoning_effort=row["reasoning_effort"],
        )
        vote = normalize_triage_result(response)
        key = "library_votes" if vote == "library-bug" else "harness_votes"
        row[key] = str(int(row[key]) + 1)
        print(f"[+] Triage vote {index}: {vote}", flush=True)
        if int(row[key]) >= needed:
            print(f"[+] Majority secured after {index} votes: {vote}", flush=True)
            return vote
    raise TriageError("No majority after the deciding vote.")


def result_key(row: dict) -> tuple[str, str, str]:
    return row["dataset"], row["dir"], row["tool"]


def read_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    header, rows = read_csv_rows(path)
    if header != list(RESULT_FIELDS):
        raise TriageError(f"Unexpected triage result format: {path}")
    seen = set()
    for row in rows:
        key = result_key(row)
        if key in seen or any(not value for value in key):
            raise TriageError(f"Duplicate or empty triage identity in {path}.")
        seen.add(key)
        if row["status"] not in {"planned", "running", "success", "failed"}:
            raise TriageError(f"Invalid triage status in {path}.")
        successful = row["status"] == "success"
        if (successful and row["triage result"] not in {"library-bug", "harness-bug"}) or (
            not successful and row["triage result"]
        ):
            raise TriageError(f"Status and verdict disagree in {path}.")
        if any(not row[name].isdigit() for name in ("library_votes", "harness_votes")):
            raise TriageError(f"Invalid vote counts in {path}.")
    return rows


def update_result(csv_path: Path, row: dict) -> None:
    with csv_lock(csv_path):
        rows = {result_key(item): item for item in read_results(csv_path)}
        rows[result_key(row)] = row
        write_csv_rows_atomic(csv_path, RESULT_FIELDS, sorted(rows.values(), key=sort_key))


@contextmanager
def campaign_lock(csv_path: Path):
    """Prevent two invocations from independently scheduling the same CSV."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.with_name(csv_path.name + ".run.lock").open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TriageError(f"Another triage invocation is using {csv_path}.") from None
        yield


def select_batch(args: argparse.Namespace, previous: list[dict], needs_reduced: bool) -> Path | None:
    recorded = {row["source_batch"] for row in previous if row["source_batch"]}
    if len(recorded) > 1:
        raise TriageError("The result CSV contains more than one source batch.")
    batch = repository_path(next(iter(recorded))) if recorded else None
    if args.results_dir:
        requested = repository_path(args.results_dir)
        if batch is not None and requested != batch:
            raise TriageError("--results-dir conflicts with the batch recorded in the resume CSV.")
        batch = requested
    if batch is None and needs_reduced:
        batches = sorted(
            path.parent for path in (PROJECT_ROOT / "output/evaluation").glob("*/run_manifest.json")
            if re.fullmatch(r"\d{8}-\d{6}-\d{6}", path.parent.name)
        )
        if not batches:
            raise TriageError("No evaluation batch found. Run the performance evaluation first, or supply --results-dir.")
        batch = batches[-1].resolve()
    return batch


def load_optimized_runs(batch: Path | None) -> dict[tuple, dict]:
    if batch is None:
        return {}
    manifest = read_json(batch / "run_manifest.json")
    if manifest.get("format") != EVALUATION_FORMAT or not isinstance(manifest.get("runs"), list):
        raise TriageError("The selected batch has an invalid evaluation manifest.")
    runs = {}
    for run in manifest["runs"]:
        if not isinstance(run, dict):
            raise TriageError("Invalid run in the evaluation manifest.")
        if run.get("configuration") != "optimized":
            continue
        key = (run["dataset"], run["case"], run["tool"])
        if key in runs:
            raise TriageError(f"Duplicate optimized run in the manifest: {key}")
        runs[key] = run
    return runs


def prepare_items(args: argparse.Namespace, cases: list[dict], csv_path: Path) -> tuple[list[dict], list[dict]]:
    if csv_path.exists() and not args.resume:
        raise TriageError(f"Result file already exists: {csv_path}. Use --resume or a different --csv.")
    previous = read_results(csv_path) if args.resume else []
    model = os.environ.get("OPENAI_MODEL", "").strip()
    recorded_models = {row["model"] for row in previous}
    if len(recorded_models) > 1 or (model and recorded_models and recorded_models != {model}):
        raise TriageError("OPENAI_MODEL conflicts with the model recorded in the resume CSV.")
    if any(row["reasoning_effort"] != args.llm_reasoning_effort for row in previous):
        raise TriageError("Reasoning effort conflicts with the resume CSV.")
    if not model and args.dry_run and recorded_models:
        model = next(iter(recorded_models))
    tools = ALL_TOOLS if args.tool == "all" else (args.tool,)
    needs_reduced = any(tool != "none" for tool in tools)
    batch = select_batch(args, previous, needs_reduced)
    runs = load_optimized_runs(batch) if needs_reduced else {}
    previous_by_key = {result_key(row): row for row in previous}
    log_root = PROJECT_ROOT / "triage-logs" / datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    items = []
    retained = dict(previous_by_key)
    for case in cases:
        for tool in tools:
            key = (case["dataset"], case["case"], tool)
            if key in previous_by_key and previous_by_key[key]["status"] == "success":
                continue
            harness = Path(case["harness"])
            values_header = None
            error = ""
            try:
                if tool != "none":
                    run = runs.get(key)
                    if run is None:
                        raise TriageError("No optimized reduction for this case/tool in the selected batch.")
                    if run.get("status") != "success":
                        raise TriageError(f"Optimized reduction status is {run.get('status')!r}, expected success.")
                    harness = artifact_path(batch, run["output"])
                if not harness.is_file():
                    raise TriageError(f"Harness source does not exist: {harness}")
                values_header = find_generated_values_header(harness) if tool != "none" else None
                if batch is not None and tool != "none" and values_header is not None:
                    artifact_path(batch, str(values_header.relative_to(batch)))
            except (OSError, ValueError, KeyError, TypeError, TriageError) as exc:
                error = redact(exc)
                if tool != "none":
                    harness = None
            row = dict(zip(RESULT_FIELDS, ("",) * len(RESULT_FIELDS)))
            row.update(
                dataset=case["dataset"], dir=case["case"], tool=tool, status="planned",
                library_votes="0", harness_votes="0", model=model,
                reasoning_effort=args.llm_reasoning_effort, source_batch=str(batch) if batch else "",
                harness=str(harness) if harness is not None else "",
                log=str(log_root / case["dataset"] / case["case"] / f"{tool}.log"), error=error,
            )
            retained[key] = row
            items.append({"case": case, "row": row, "values_header": str(values_header) if values_header else None})
    print(f"{len(cases)} cases, {len(tools)} tools; {len(items)} pending, {len(cases) * len(tools) - len(items)} completed; --jobs {args.jobs}", flush=True)
    if batch is not None:
        print(f"Source evaluation batch: {batch}", flush=True)
    return items, sorted(retained.values(), key=sort_key)


class RedactedLog:
    def __init__(self, stream):
        self.stream = stream

    def write(self, value: str) -> int:
        self.stream.write(redact(value))
        return len(value)

    def flush(self) -> None:
        self.stream.flush()


def triage_item(item: dict, csv_path: Path, timeout: int, llm_timeout: int) -> bool:
    row, case = item["row"], item["case"]
    row["status"] = "running"
    update_result(csv_path, row)
    try:
        if row["error"]:
            raise TriageError(row["error"])
        harness = Path(row["harness"])
        values_header = Path(item["values_header"]) if item["values_header"] else None
        bench_dir = Path(case["benchmark_dir"])
        with tempfile.TemporaryDirectory(prefix="crash_triage_") as temporary:
            binary = Path(temporary) / "fuzzer"
            command = build_compile_command(
                harness, binary, case["compile_flags"], case["link_flags"], values_header,
            )
            print(f"[+] Compiling: {format_command(command)}", flush=True)
            compile_harness(command, cwd=bench_dir)
            stack = run_harness_for_stack_trace(
                binary, Path(case["crash_input"]), case["link_flags"], timeout, cwd=bench_dir,
            )
        row["triage result"] = send_stack_trace_to_llm(
            read_text(harness), prepare_values_header_for_llm(values_header) if values_header else None,
            stack, row=row, csv_path=csv_path, llm_timeout_seconds=llm_timeout,
        )
        row.update(status="success", error="")
    except Exception as exc:
        row.update(status="failed", error=redact(exc))
        row["triage result"] = ""
        print(f"[-] Crash triage failed: {row['error']}", file=sys.stderr, flush=True)
    update_result(csv_path, row)
    return row["status"] == "success"


def run_case(items: list[dict], csv_path: Path, timeout: int, llm_timeout: int) -> bool:
    failed = False
    for item in items:
        row = item["row"]
        path = Path(row["log"])
        label = "/".join(result_key(row))
        print(f"[START] {label}", flush=True)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as stream:
                log = RedactedLog(stream)
                with redirect_stdout(log), redirect_stderr(log):
                    succeeded = triage_item(item, csv_path, timeout, llm_timeout)
        except Exception as exc:
            succeeded = False
            row.update(status="failed", error=redact(exc))
            row["triage result"] = ""
            update_result(csv_path, row)
        failed |= not succeeded
        print(f"[{'DONE' if succeeded else 'FAIL'}] {label}; log: {path}", flush=True)
    return not failed


def run_batch(args: argparse.Namespace, cases: list[dict], csv_path: Path) -> int:
    items, rows = prepare_items(args, cases, csv_path)
    if args.dry_run:
        for item in items:
            row, case = item["row"], item["case"]
            print(f"[PLAN] {'/'.join(result_key(row))}: {row['harness'] or '(unavailable)'}")
            if row["error"]:
                print(f"  unavailable: {row['error']}")
                continue
            values_header = Path(item["values_header"]) if item["values_header"] else None
            command = build_compile_command(
                Path(row["harness"]), Path("<temporary-directory>/fuzzer"),
                case["compile_flags"], case["link_flags"], values_header,
            )
            print(f"  cwd={shlex.quote(case['benchmark_dir'])} {format_command(command)}")
            print(f"  run fuzzer -rss_limit_mb=0 {shlex.quote(case['crash_input'])}; LLM votes <= 21, effort={row['reasoning_effort']}")
        return int(any(item["row"]["error"] for item in items))
    # Persist all identities and settings before the first compile or LLM call.
    with csv_lock(csv_path):
        write_csv_rows_atomic(csv_path, RESULT_FIELDS, rows)
    groups = {}
    for item in items:
        key = (item["row"]["dataset"], item["row"]["dir"])
        groups.setdefault(key, []).append(item)
    failed = False
    if args.jobs == 1:
        for group in groups.values():
            failed |= not run_case(group, csv_path, args.timeout, args.llm_timeout)
    elif groups:
        # Separate processes isolate per-case log redirection and environment.
        with ProcessPoolExecutor(max_workers=args.jobs, mp_context=multiprocessing.get_context("spawn")) as pool:
            futures = {
                pool.submit(run_case, group, csv_path, args.timeout, args.llm_timeout): group
                for group in groups.values()
            }
            for future in as_completed(futures):
                try:
                    failed |= not future.result()
                except Exception as exc:
                    failed = True
                    current = {result_key(row): row for row in read_results(csv_path)}
                    for item in futures[future]:
                        row = current[result_key(item["row"])]
                        if row["status"] != "success":
                            row.update(status="failed", error=redact(exc))
                            row["triage result"] = ""
                            update_result(csv_path, row)
    print(f"Results: {csv_path}", flush=True)
    return int(failed)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, choices=("none", *TOOL_CHOICES, "all"),
                        help="all triages originals plus treereduce, perses, wdd, and cdd")
    parser.add_argument("--jobs", type=int, default=1, help="Concurrent benchmark cases (default: 1); tools within each case stay sequential")
    parser.add_argument("--results-dir", help="Evaluation batch override; default: newest batch, or the batch recorded for --resume")
    parser.add_argument("--csv", default=str(DEFAULT_CSV_PATH), help="Result CSV (default: crash_triage_result.csv in the repository)")
    parser.add_argument("--resume", action="store_true", help="Reuse recorded settings/batch and retry failed or unfinished cases")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print planned work without creating results or contacting the LLM")
    parser.add_argument("--timeout", type=int, default=60, help="Local harness timeout in seconds (default: 60)")
    parser.add_argument("--llm-timeout", type=int, default=LLM_TIMEOUT_SECONDS,
                        help="LLM network I/O timeout in seconds; active streams may run longer (default: 3600)")
    parser.add_argument("--llm-reasoning-effort", choices=("low", "high", "max"), default=LLM_REASONING_EFFORT,
                        help="Fixed effort for every vote and retry (default: high); never automatically downgraded")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for name in ("jobs", "timeout", "llm_timeout"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    try:
        load_environment()
        if not args.dry_run:
            llm_configuration()
        cases = load_cases()
        csv_path = repository_path(args.csv)
        if args.dry_run:
            return run_batch(args, cases, csv_path)
        with campaign_lock(csv_path):
            return run_batch(args, cases, csv_path)
    except (OSError, ValueError, KeyError, TypeError, csv.Error, TriageError) as exc:
        print(f"[-] Crash triage failed: {redact(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
