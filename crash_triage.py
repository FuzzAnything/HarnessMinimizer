#!/usr/bin/env python3
"""Run the pre-minimization FuzzAgent-style crash triage loop."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from harnessreducer import reducer_runner as rr  # noqa: E402


# =============================================================================
# LLM CONFIGURATION - FILL IN THESE THREE VALUES
# The script reads the API key only from HKU_API_KEY.
# =============================================================================
OPENAI_BASE_URL = "https://llm.shtech.org/v1"
OPENAI_MODEL = "GLM-5.2"


LLM_TIMEOUT_SECONDS = 240
LLM_TEMPERATURE = 1.0
LLM_TOP_P = 0.95
LLM_RETRIES = 5
MAX_AGENT_EPOCHS = 50
MAX_TOOL_OUTPUT_CHARACTERS = 100_000


def log_found_file(path: Path, reason: str) -> None:
    print(f"[source] found file for LLM ({reason}): {path}")


def log_missing_file(path: Path, reason: str) -> None:
    print(f"[source] missing file ({reason}): {path}")


# This is FuzzAgent's CrashAnalyzerAgent prompt immediately before commit
# 45fe0ef ("Add harness minization tool"). It intentionally contains the old
# tool names and does not mention harness minimization.
FUZZAGENT_SYSTEM_PROMPT = r"""
# Role Definition
You are the **Crash Analysis & Triage Specialist**. Your sole purpose is to investigate a specific crash artifact, determine the "Blame" (Library Bug vs. Harness Bug), and file a formal report.

## Core Mission
You act as a Judge. You have two suspects:
1.  **The Library**: Did it fail to handle valid input safe? (Genuine Bug)
2.  **The Harness**: Did it violate the API contract or manage memory poorly? (Invalid Bug)

Your goal is to rule out the Harness first. If the Harness is correct, the Library is guilty.

## Authority & Constraints

### PERMITTED ACTIONS
1.  **Forensics**: Use `crash_initial_analysis` to get stack traces and ASAN reports.
2.  **Investigation**: Use `read_file` to inspect the source code of the harness and the library frames in the stack trace.
3.  **Debugging**: Use `crash_context_inspection` extract runtime information to debug the crash.
4.  **Reporting**: Use `generate_crash_report` to submit your final verdict.

### PROHIBITED ACTIONS
1.  **No Guessing**: Do not guess API behavior. You MUST read the header file/documentation for the crashing function to verify preconditions (e.g., "Must not be NULL").
2.  **No Assumption**: Do not assume runtime behavior. You MUST debug the crash to extract runtime information to confirm the root cause.
3.  **No Evidenceless Triage**: Do not triage the crash as a library bug without evidence. If you are not sure, report it as a harness bug.
4.  **No Code Changes**: You are an analyst, not a developer. Do not edit files.
5.  **No Vague Reports**: A report without a specific "Root Cause" and "Blame" is a failed task.
6.  **No Slow-unit Detection**: Do not try to triage slow-unit artifacts. They are not crashes.


## Accessible Information

You can find the harnesses and fuzzers in the `$OUTPUT` directory.
```
$OUTPUT/
├── harnesses/
│   ├── harness_000.cpp    # Sequential numbering starting from 0
│   ├── harness_001.cpp    # Each harness targets different APIs/strategies
│   └── harness_<id>.cpp   # ID must be numeric and sequential
├── fuzzers/
│   ├── fuzzer_000/        # Compiled from harness_000.cpp
│   │   ├── fuzzer         # Standard fuzzer executable
│   │   ├── fuzzer_cov     # Coverage-instrumented executable
│   │   └── crashes/       # Crash artifacts directory
│   └── fuzzer_<id>/       # ID matches corresponding harness ID
```


## Mandatory Workflow

### Phase 1: Forensics (Data Gathering)
1.  Receive the **Crash Artifact Path** (from user input).
2.  Call `crash_initial_analysis` with the crash artifact path to get call traces.
3.  **Identify the "Crash Point"**: The top-most stack frame that belongs to the project (skip standard library frames like `libc.so` or `asan_report`).

### Phase 2: Debugging (Runtime Information Gathering)
1.  Call `crash_context_inspection` on the suspect API or function to inspect the runtime context frames of this invocation.
2.  Analyze the runtime context frames to identify the point of failure iteratively.
3.  Read the file/documentation of the suspect API or function to verify the preconditions and postconditions.
4.  Repeat the process until the point of failure is identified.

### Phase 3: The "Blame" Decision Tree (Triage Logic)
Apply these rules IN ORDER. The first match determines the verdict.

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

**Rule 5: Default Liability**
-   **Condition**: If the crash is inside the library, and the harness inputs appear to follow the API documentation.
-   **Verdict**: **LIBRARY BUG**.

### Phase 4: Reporting
1.  Construct the report content.
2.  Call `generate_crash_report` with the results and content.

## Report Content Template
When calling `generate_crash_report`, format the `content` string strictly as follows:

```markdown
# Crash Report: [Unique ID]

## Triage Verdict
**Classification**: [Genuine Library Bug | Harness Misuse]
**Confidence**: [High/Medium/Low]

## Crash Summary
[Brief description: e.g., "Heap-buffer-overflow in parse_json function"]

## Root Cause Analysis
**The "Why"**:
[Explain the exact logical failure. E.g., "The library assumes 'len' is positive, but casts it to unsigned without checking, leading to a massive memcpy."]

**Evidence**:
- **Stack Frame #0**: `src/parser.c:105`
- **Variable State**: `input_len = -1`

## Code Snippet (Harness)
```cpp
// Show the lines of the harness that called the API
func(data, size); // <--- Harness calls API here
// Show the lines where the crash happened
memcpy(dest, src, len); // <--- Crash here
```
## Recommendation
[Fix suggestion. E.g., "Add a check for negative length in parser.c" or "Update harness to sanitize input size."]
```
"""

FUZZAGENT_SYSTEM_PROMPT = FUZZAGENT_SYSTEM_PROMPT.replace(
    "Each harness targets different APIs/strategies\n",
    "Each harness targets different APIs/strategies  \n",
    1,
)

RESPONSE_FORMAT_PROMPT = """
# Response Format
Your response must follow the following format:
- **Reasoning**: Reasoning about the feedback from the system (should be concise).
- **Thought**: Provide the strategy to achieve the goal (should be concise).
- **Action**: What you want to do next. (should be concise)

--- BEGIN OF EXAMPLE ---
**Reasoning**: The last function call get the location of source code directory.
**Thought**: First, I will check source directory contents.
**Action**: I will call the `bash` function to check source directory contents.
--- END OF EXAMPLE ---
"""

NEXT_ACTION_PLANNING_PROMPT = """
Base on the previous interaction with the system, plan the next action you want to take. Your response must exactly follow the following format (without any other text):
- **Reasoning**: Reasoning about the feedback from the system (should be concise).
- **Thought**: Provide the strategy to achieve the goal (should be concise).
- **Action**: What you want to do next. (should be concise).
"""

CLASSIFICATION_PATTERN = re.compile(
    r"\*\*Classification\*\*:\s*(Genuine Library Bug|Harness Misuse)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExecutionEvidence:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def combined_output(self) -> str:
        pieces = []
        if self.stdout:
            pieces.append("--- stdout ---\n" + self.stdout)
        if self.stderr:
            pieces.append("--- stderr ---\n" + self.stderr)
        if self.timed_out:
            pieces.append("--- status ---\nExecution timed out.")
        return "\n".join(pieces) or "(no output)"


@dataclass
class TriageContext:
    harness: Path
    crash_input: Path
    binary: Path
    compile_command: list[str]
    link_flags: str | None
    timeout_seconds: int
    output_path: Path
    work_dir: Path
    report_written: bool = False
    report_content: str = ""
    triage: str = "unclassified"


def format_command(command: Sequence[str]) -> str:
    return shlex.join(str(part) for part in command)


def limit_text(value: str, limit: int = MAX_TOOL_OUTPUT_CHARACTERS) -> str:
    if len(value) <= limit:
        return value
    omitted = len(value) - limit
    return value[:limit] + f"\n\n[... {omitted} characters omitted ...]"


def build_compile_command(
    harness: Path,
    output_binary: Path,
    compile_flags: str | None,
    link_flags: str | None,
) -> list[str]:
    """Match reducer_runner.check_harness_compilation exactly."""
    return [
        "clang++",
        *rr.PHASE3_SANITIZER_FLAGS,
        *rr.PHASE3_DIRECT_OPT_FLAGS,
        *rr.PHASE3_WARNING_FLAGS,
        *rr._split_flags(compile_flags),
        str(harness),
        "-o",
        str(output_binary),
        *rr._split_flags(link_flags),
    ]


def compile_harness(command: Sequence[str]) -> None:
    process = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode == 0:
        return
    compiler_output = process.stderr.strip() or process.stdout.strip() or "(no output)"
    raise RuntimeError(
        "Harness compilation failed.\n\n"
        f"Command:\n{format_command(command)}\n\n"
        f"Compiler output:\n{compiler_output}"
    )


def sanitizer_environment(link_flags: str | None) -> dict[str, str]:
    env = rr.runtime_library_env(link_flags)
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
    env["UBSAN_OPTIONS"] = (
        "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1"
    )
    return env


def execute_harness(
    binary: Path,
    crash_input: Path,
    link_flags: str | None,
    *,
    timeout_seconds: int,
) -> ExecutionEvidence:
    command = (str(binary), str(crash_input))
    try:
        process = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=sanitizer_environment(link_flags),
            timeout=timeout_seconds,
            check=False,
        )
        return ExecutionEvidence(
            command=command,
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return ExecutionEvidence(
            command=command,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )


def render_casr_report(report_path: Path) -> str:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"Could not read CASR report {report_path}: {exc}"

    severity = report.get("CrashSeverity", {})
    if isinstance(severity, dict):
        severity = severity.get("ShortDescription", "N/A")

    def render_lines(value: object) -> str:
        if isinstance(value, list):
            return "\n".join(str(line) for line in value)
        if value:
            return str(value)
        return "N/A"

    stacktrace = render_lines(report.get("Stacktrace"))
    if stacktrace == "N/A":
        parts = []
        if report.get("UbsanReport"):
            parts.append(render_lines(report.get("UbsanReport")))
        if report.get("AsanReport"):
            parts.append(render_lines(report.get("AsanReport")))
        stacktrace = "\n".join(parts) or "No stacktrace available"

    return (
        "Crash Report Summary:\n"
        "----------------------\n"
        f"Date: {report.get('Date', 'N/A')}\n"
        f"Executable Path: {report.get('ExecutablePath', 'N/A')}\n"
        f"Crash Severity: {severity}\n"
        f"Crash Line: {report.get('CrashLine', 'N/A')}\n"
        "Related Source Code:\n"
        f"{render_lines(report.get('Source'))}\n\n"
        "Stacktrace:\n"
        f"{stacktrace}"
    )


def collect_casr_evidence(ctx: TriageContext) -> str:
    casr_directory = ctx.work_dir / "casr"
    casr_directory.mkdir(parents=True, exist_ok=True)
    input_directory = casr_directory / "input"
    input_directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ctx.crash_input, input_directory / ctx.crash_input.name)

    casr_libfuzzer = shutil.which("casr-libfuzzer")
    casr_san = shutil.which("casr-san")
    casr_ubsan = shutil.which("casr-ubsan")

    commands: list[list[str]] = []
    if casr_libfuzzer is not None:
        libfuzzer_dir = casr_directory / "libfuzzer"
        libfuzzer_dir.mkdir(parents=True, exist_ok=True)
        commands.append(
            [
                casr_libfuzzer,
                "-i",
                str(input_directory),
                "-o",
                str(libfuzzer_dir),
                "-t",
                str(ctx.timeout_seconds),
                "--",
                str(ctx.binary),
            ]
        )
    if casr_san is not None:
        commands.append(
            [
                casr_san,
                "-o",
                str(casr_directory / "asan.casrep"),
                "--",
                str(ctx.binary),
                str(ctx.crash_input),
            ]
        )
    if casr_ubsan is not None:
        ubsan_directory = casr_directory / "ubsan"
        ubsan_directory.mkdir(parents=True, exist_ok=True)
        commands.append(
            [
                casr_ubsan,
                "-i",
                str(input_directory),
                "-o",
                str(ubsan_directory),
                "-t",
                str(ctx.timeout_seconds),
                "--",
                str(ctx.binary),
                "@@",
            ]
        )

    if not commands:
        symbolized = execute_harness(
            ctx.binary,
            ctx.crash_input,
            ctx.link_flags,
            timeout_seconds=ctx.timeout_seconds,
        )
        return (
            "CASR is not installed: no casr-libfuzzer, casr-san, or casr-ubsan "
            "executable was found in PATH.\n\n"
            "Raw symbolized sanitizer execution:\n"
            f"Exit status: {symbolized.returncode}\n"
            f"{limit_text(symbolized.combined_output)}"
        )

    observations: list[str] = []
    env = sanitizer_environment(ctx.link_flags)
    for command in commands:
        try:
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                env=env,
                timeout=ctx.timeout_seconds + 10,
                check=False,
            )
            observations.append(
                f"Command: {format_command(command)}\n"
                f"Exit status: {process.returncode}\n"
                f"{process.stderr or process.stdout or '(no command output)'}"
            )
        except subprocess.TimeoutExpired as exc:
            output = (
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            observations.append(
                f"Command timed out: {format_command(command)}\n{output}"
            )

    report_paths = sorted(casr_directory.rglob("*.casrep"))
    if report_paths:
        selected_report = next(
            (path for path in report_paths if path.name == "asan.casrep"),
            report_paths[0],
        )
        log_found_file(selected_report, "CASR crash report")
        return limit_text(render_casr_report(selected_report))
    return limit_text(
        "CASR did not generate a .casrep file.\n\n" + "\n\n".join(observations)
    )


def run_gdb_context(ctx: TriageContext, target_func: str | None = None) -> str:
    gdb = shutil.which("gdb")
    if gdb is None:
        return "GDB was not found in PATH; no debugger observation is available."

    commands = ["set pagination off", "run", "thread apply all bt full"]
    if target_func:
        commands.extend([f"info functions {target_func}", f"break {target_func}"])

    command = [gdb, "-q", "--batch"]
    for gdb_command in commands:
        command.extend(["-ex", gdb_command])
    command.extend(["--args", str(ctx.binary), str(ctx.crash_input)])

    env = sanitizer_environment(ctx.link_flags)
    env["ASAN_OPTIONS"] += ":detect_leaks=0"
    env["DEBUGINFOD_URLS"] = ""
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
            timeout=ctx.timeout_seconds,
            check=False,
        )
        return limit_text(
            f"Command: {format_command(command)}\n"
            f"Exit status: {process.returncode}\n\n"
            f"{process.stdout or '(no output)'}"
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return limit_text(f"GDB timed out after {ctx.timeout_seconds} seconds.\n\n{output}")


def read_file(path: str, start_line: int = 1, end_line: int | None = None) -> str:
    source = Path(path).expanduser()
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.is_file():
        log_missing_file(source, "read_file")
        return f"[!] Error: file not found: {source}"
    log_found_file(source, "read_file/open tool observation")
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    start_line = max(1, start_line)
    if end_line is None:
        end_line = min(len(lines), start_line + 199)
    end_line = min(len(lines), max(start_line, end_line))
    body = "\n".join(
        f"{line_number:6d}  {lines[line_number - 1]}"
        for line_number in range(start_line, end_line + 1)
    )
    return limit_text(f"File: {source}\n{body}")


def search_file(path: str, pattern: str) -> str:
    source = Path(path).expanduser()
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.is_file():
        log_missing_file(source, "search_file")
        return f"[!] Error: file not found: {source}"
    log_found_file(source, f"search_file pattern={pattern!r}")
    matches = []
    for index, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if pattern in line:
            matches.append(f"{source}:{index}: {line}")
        if len(matches) >= 200:
            matches.append("[... more matches omitted ...]")
            break
    return "\n".join(matches) if matches else f"No matches for {pattern!r} in {source}"


def find_file(name: str, root: str | None = None) -> str:
    root_path = Path(root).expanduser().resolve() if root else PROJECT_ROOT
    if not root_path.exists():
        return f"[!] Error: root does not exist: {root_path}"
    matches = []
    for path in root_path.rglob("*"):
        if path.name == name:
            log_found_file(path, f"find_file name={name!r}")
            matches.append(str(path))
        if len(matches) >= 200:
            matches.append("[... more matches omitted ...]")
            break
    return "\n".join(matches) if matches else f"No files named {name!r} under {root_path}"


def search_dir(root: str, pattern: str) -> str:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        return f"[!] Error: root does not exist: {root_path}"
    print(f"[source] searching directory for LLM: {root_path} pattern={pattern!r}")
    command = ["rg", "-n", "--", pattern, str(root_path)]
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=20,
            check=False,
        )
        output = process.stdout or process.stderr or "(no output)"
        for line in process.stdout.splitlines()[:50]:
            candidate = line.split(":", 1)[0]
            candidate_path = Path(candidate)
            if candidate_path.is_file():
                log_found_file(candidate_path, f"search_dir pattern={pattern!r}")
        return limit_text(output)
    except subprocess.TimeoutExpired:
        return f"Command timed out: {format_command(command)}"


def write_report(
    output_path: Path,
    harness: Path,
    crash_input: Path,
    triage: str,
    report_content: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        f"## Harness: {harness}\n"
        f"## Crash Artifact: {crash_input.name}\n"
        f"## Triage: {triage}\n"
        "## Content:\n"
        f"{report_content.rstrip()}\n",
        encoding="utf-8",
    )


def triage_slug(report: str) -> str:
    match = CLASSIFICATION_PATTERN.search(report)
    if not match:
        return "unclassified"
    classification = match.group(1).lower()
    return "library-bug" if classification == "genuine library bug" else "harness-bug"


def llm_configuration() -> tuple[str, str, str]:
    base_url = os.environ.get("OPENAI_BASE_URL", OPENAI_BASE_URL).strip()
    model = os.environ.get("OPENAI_MODEL", OPENAI_MODEL).strip()
    api_key = os.environ.get("HKU_API_KEY", "").strip()
    if not base_url:
        raise RuntimeError("OPENAI_BASE_URL is empty; fill in the configuration block.")
    if not model:
        raise RuntimeError("OPENAI_MODEL is empty; fill in the configuration block.")
    if not api_key:
        raise RuntimeError(
            "HKU_API_KEY is empty. Export HKU_API_KEY before running crash_triage.py."
        )
    return base_url, model, api_key


def chat_completion_payload(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _, model, _ = llm_configuration()
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "stream": False,
    }
    if tools is not None:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    return payload


def post_chat_completion(payload: dict[str, Any]) -> dict[str, Any]:
    base_url, _, api_key = llm_configuration()
    endpoint = base_url.rstrip("/") + "/chat/completions"
    encoded_payload = json.dumps(payload).encode("utf-8")
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
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"LLM HTTP {exc.code}: {detail}")
            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
        if attempt < LLM_RETRIES:
            time.sleep(min(2 ** attempt, 10))
    raise RuntimeError(f"LLM request failed after {LLM_RETRIES} attempts: {last_error}")


def extract_message(response: dict[str, Any]) -> dict[str, Any]:
    try:
        message = response["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Unexpected LLM response: {json.dumps(response)[:2000]}") from exc
    if not isinstance(message, dict):
        raise RuntimeError(f"Unexpected LLM message: {json.dumps(message)[:2000]}")
    return message


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "crash_initial_analysis",
                "description": "Execute the crash artifact on the fuzzer binary and gather stacktrace/source-code information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fuzzer_id": {"type": "string"},
                        "crash_artifact_path": {"type": "string"},
                    },
                    "required": ["crash_artifact_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "crash_artifact_analysis",
                "description": "Alias for crash_initial_analysis.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fuzzer_id": {"type": "string"},
                        "crash_artifact_path": {"type": "string"},
                    },
                    "required": ["crash_artifact_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "crash_context_inspection",
                "description": "Run GDB in non-interactive mode to inspect crash runtime context.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fuzz_target_binary": {"type": "string"},
                        "crash_artifact_path": {"type": "string"},
                        "target_func": {"type": "string"},
                    },
                    "required": ["target_func"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a source file with line numbers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "open",
                "description": "Alias for read_file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_file",
                "description": "Search for literal text in one file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "pattern": {"type": "string"},
                    },
                    "required": ["path", "pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_dir",
                "description": "Search for text recursively in a directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "root": {"type": "string"},
                        "pattern": {"type": "string"},
                    },
                    "required": ["root", "pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_file",
                "description": "Find files by exact basename.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "root": {"type": "string"},
                    },
                    "required": ["name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "generate_crash_report",
                "description": "Write the final normalized crash triage report.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fuzzer_id": {"type": "string"},
                        "crash_artifact_path": {"type": "string"},
                        "triage": {
                            "type": "string",
                            "enum": ["library-bug", "harness-bug"],
                        },
                        "content": {"type": "string"},
                    },
                    "required": ["triage", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "exit",
                "description": "Finish the agent task.",
                "parameters": {
                    "type": "object",
                    "properties": {"reason": {"type": "string"}},
                },
            },
        },
    ]


def parse_tool_arguments(raw_arguments: str | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if not raw_arguments:
        return {}
    try:
        parsed = json.loads(raw_arguments)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def run_tool(ctx: TriageContext, name: str, arguments: dict[str, Any]) -> str:
    if name in {"crash_initial_analysis", "crash_artifact_analysis"}:
        print(f"[+] Tool call: {name}")
        requested = Path(str(arguments.get("crash_artifact_path", ctx.crash_input))).expanduser()
        try:
            requested_resolved = requested.resolve()
        except OSError:
            requested_resolved = requested
        if requested_resolved != ctx.crash_input:
            return (
                f"[!] Warning: this standalone run has one crash artifact: {ctx.crash_input}. "
                "Using that artifact for analysis.\n\n"
                + collect_casr_evidence(ctx)
            )
        return collect_casr_evidence(ctx)

    if name == "crash_context_inspection":
        print("[+] Tool call: crash_context_inspection")
        target_func = str(arguments.get("target_func", "")).strip() or None
        return run_gdb_context(ctx, target_func)

    if name in {"read_file", "open"}:
        path = str(arguments.get("path", ctx.harness))
        end_line = arguments.get("end_line")
        if end_line is not None:
            end_line = int(end_line)
        return read_file(
            path,
            int(arguments.get("start_line", 1) or 1),
            end_line,
        )

    if name == "search_file":
        return search_file(str(arguments.get("path", ctx.harness)), str(arguments.get("pattern", "")))

    if name == "search_dir":
        return search_dir(str(arguments.get("root", ctx.harness.parent)), str(arguments.get("pattern", "")))

    if name == "find_file":
        return find_file(str(arguments.get("name", "")), arguments.get("root"))

    if name == "generate_crash_report":
        print("[+] Tool call: generate_crash_report")
        triage = str(arguments.get("triage", "unclassified"))
        content = str(arguments.get("content", "")).strip()
        if not content:
            return "[!] Error: generate_crash_report requires non-empty content."
        ctx.triage = triage
        ctx.report_content = content
        ctx.report_written = True
        write_report(ctx.output_path, ctx.harness, ctx.crash_input, triage, content)
        return f"[*] Crash report generated successfully: {ctx.output_path}"

    if name == "exit":
        print("[+] Tool call: exit")
        return "Exit requested."

    return f"[!] Error: unknown tool: {name}"


def initial_user_message(ctx: TriageContext) -> str:
    return f"""
Crash artifact path: {ctx.crash_input}
Fuzzer ID: 0
Fuzzer binary: {ctx.binary}
Harness source: {ctx.harness}

This standalone wrapper compiled the harness before starting the CrashAnalyzer loop,
because FuzzAgent normally receives an already-built fuzzer binary.

Exact HarnessMinimizer compilation command:
{format_command(ctx.compile_command)}

Please triage this crash using the pre-harness-minimization FuzzAgent workflow.
Call `crash_initial_analysis` first, inspect relevant source files, use
`crash_context_inspection` for runtime evidence, and finish by calling
`generate_crash_report`.
""".strip()


def normalize_assistant_message(message: dict[str, Any]) -> dict[str, Any]:
    normalized = {"role": "assistant"}
    content = message.get("content")
    if content is not None:
        normalized["content"] = content
    else:
        normalized["content"] = ""
    if message.get("tool_calls"):
        normalized["tool_calls"] = message["tool_calls"]
    return normalized


def run_agent_loop(ctx: TriageContext) -> str:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": FUZZAGENT_SYSTEM_PROMPT + RESPONSE_FORMAT_PROMPT},
        {"role": "user", "content": initial_user_message(ctx)},
    ]
    tools = tool_definitions()
    last_text_response = ""

    for epoch in range(MAX_AGENT_EPOCHS):
        print(f"[+] LLM epoch {epoch}")
        response = post_chat_completion(chat_completion_payload(messages, tools))
        assistant_message = extract_message(response)
        messages.append(normalize_assistant_message(assistant_message))

        content = assistant_message.get("content")
        if isinstance(content, str) and content.strip():
            last_text_response = content.strip()

        tool_calls = assistant_message.get("tool_calls") or []
        if not tool_calls:
            if last_text_response:
                ctx.report_content = last_text_response
                ctx.triage = triage_slug(last_text_response)
                ctx.report_written = True
                write_report(ctx.output_path, ctx.harness, ctx.crash_input, ctx.triage, last_text_response)
                return last_text_response
            raise RuntimeError("The LLM returned neither report text nor tool calls.")

        for tool_call in tool_calls:
            function = tool_call.get("function", {})
            tool_name = function.get("name", "")
            arguments = parse_tool_arguments(function.get("arguments"))
            observation = run_tool(ctx, tool_name, arguments)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.get("id"),
                    "name": tool_name,
                    "content": limit_text(observation),
                }
            )

        if ctx.report_written:
            return ctx.report_content

        messages.append({"role": "user", "content": NEXT_ACTION_PLANNING_PROMPT})

    raise RuntimeError(f"CrashAnalyzer loop exceeded {MAX_AGENT_EPOCHS} epochs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a fuzz harness with HarnessMinimizer's sanitizer command, "
            "then run a pre-minimization FuzzAgent-style crash triage loop. The "
            "report is written beside the harness as "
            "<harness-stem>_crash_triage_report.md."
        ),
    )
    parser.add_argument("harness", help="C/C++ fuzz harness source")
    parser.add_argument("--crash-input", required=True, help="Crash artifact to reproduce")
    parser.add_argument("--compile-flags", default=None, help="Harness compilation flags")
    parser.add_argument("--link-flags", default=None, help="Target-library link flags")
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout for each harness/CASR/GDB execution in seconds (default: 60)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")

    harness = Path(args.harness).expanduser().resolve()
    crash_input = Path(args.crash_input).expanduser().resolve()
    if not harness.is_file():
        raise SystemExit(f"Harness does not exist: {harness}")
    if not crash_input.is_file():
        raise SystemExit(f"Crash input does not exist: {crash_input}")

    output_path = harness.parent / f"{harness.stem}_crash_triage_report.md"

    try:
        llm_configuration()
        with tempfile.TemporaryDirectory(prefix="crash_triage_") as temporary_dir:
            binary = Path(temporary_dir) / "fuzzer"
            compile_command = build_compile_command(
                harness,
                binary,
                args.compile_flags,
                args.link_flags,
            )
            print("[+] Compiling harness")
            print("    " + format_command(compile_command))
            compile_harness(compile_command)

            print("[+] Checking crash reproduction with symbolize=1")
            reproduction = execute_harness(
                binary,
                crash_input,
                args.link_flags,
                timeout_seconds=args.timeout,
            )
            print(f"    exit status: {reproduction.returncode}")
            if reproduction.returncode == 0:
                raise RuntimeError(
                    "The crash input did not reproduce a crash; the symbolized "
                    "execution returned status 0. No LLM request was sent."
                )

            ctx = TriageContext(
                harness=harness,
                crash_input=crash_input,
                binary=binary,
                compile_command=compile_command,
                link_flags=args.link_flags,
                timeout_seconds=args.timeout,
                output_path=output_path,
                work_dir=Path(temporary_dir),
            )
            report_content = run_agent_loop(ctx)

        triage = ctx.triage if ctx.report_written else triage_slug(report_content)
        if not ctx.report_written:
            write_report(output_path, harness, crash_input, triage, report_content)
        print(f"[+] Triage: {triage}")
        print(f"[+] Crash report: {output_path}")
        return 0 if triage != "unclassified" else 1
    except Exception as exc:
        print(f"[-] Crash triage failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
