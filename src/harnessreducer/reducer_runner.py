from __future__ import annotations

import atexit
from contextlib import contextmanager, nullcontext
import filecmp
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from harnessreducer.dynamic_slicer import CoverageMap, slice_source_by_coverage

TREEDUCER_DIR: str | None = None
_IS_USER_WORK_DIR = False
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
PHASE3_DIRECT = "direct"
PHASE3_DIRECT_ALIAS = "single-step"
PHASE3_SPLIT = "split"
PHASE3_PCH = "pch"
PHASE3_MODES = {PHASE3_DIRECT, PHASE3_SPLIT, PHASE3_PCH}
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]
PHASE3_PLUGIN_SANITIZER_FLAGS = ["-fsanitize=address,undefined"]
PHASE3_DIRECT_OPT_FLAGS = ["-gline-tables-only", "-O0"]
PHASE3_SPLIT_OPT_FLAGS = ["-O0", "-gline-tables-only"]
PHASE3_PCH_OPT_FLAGS = ["-O0", "-gline-tables-only"]
PHASE3_WARNING_FLAGS = ["-Werror=uninitialized"]
PCH_PREFIX_HEADER_NAME = "harness_prefix.h"
PCH_PREFIX_FILE_NAME = "harness_prefix.pch"
COVERAGE_BIN_FILE_NAME = "poc_cov.out"
COVERAGE_DRIVER_FILE_NAME = "coverage_driver.cpp"
SOURCE_COVERAGE_RAW_FILE_NAME = "coverage.profraw"
SOURCE_COVERAGE_DATA_FILE_NAME = "coverage.profdata"
SOURCE_COVERAGE_SHOW_FILE_NAME = "coverage_show.txt"
SOURCE_COVERAGE_EXPORT_FILE_NAME = "coverage_export.json"
STATISTICS_FILE_NAME = "statistics.txt"
SLICED_HARNESS_SUFFIX = ".sliced"

STACK_TRACE_FILE_NAME = "stack_trace.pattern"
LAST_INTERESTING_FILE_NAME = "last_interesting.cpp"
HARNESS_RUNNER_SOURCE_NAME = "harness_runner.cpp"
HARNESS_RUNNER_BINARY_NAME = "harness_runner"
NORMAL_REFERENCE_STACK_DEPTH: int | None = None
SYMBOLIZED_REFERENCE_STACK_DEPTH: int | None = None
# Matches symbolized stack frames like:
#   #0 0x5ea4dfe78fe6 in av1_func /root/src/file.c:444:18
#   #5 0x5ea4dfa2f68f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/path/fuzzer+0x46068f)
STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
STACK_FRAME_COUNT_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\b")
LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")
SOURCE_LOCATION_PATTERN = re.compile(r"(/[^:\s\)]+):(\d+)(?::(\d+))?")
LLVM_COV_SHOW_LINE_PATTERN = re.compile(r"^\s*(\d+)\|\s*([^|]*)\|")


@dataclass(frozen=True)
class PchArtifacts:
    body_source: str
    prefix_header: str
    pch_file: str
    restore_prefix: str


@dataclass(frozen=True)
class AmortizedRunner:
    socket_path: str
    process: subprocess.Popen[str]
    shared_libraries: tuple[str, ...]


def cleanup() -> None:
    global TREEDUCER_DIR

    if TREEDUCER_DIR is None or _IS_USER_WORK_DIR:
        return

    try:
        shutil.rmtree(TREEDUCER_DIR, ignore_errors=True)
    except OSError:
        pass


atexit.register(cleanup)

MEMORY_ADDRESS_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")
ASAN_SUMMARY_PATTERN = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*([\w-]+)")
ASAN_ERROR_PATTERN = re.compile(r"ERROR:\s*AddressSanitizer:\s*[\w-]+")
LEAK_PATTERN = re.compile(
    r"SUMMARY: AddressSanitizer: \d+ byte\(s\) leaked in \d+ allocation\(s\)\."
)
RUNTIME_ERROR_PATTERN = re.compile(
    r"(?:/[^\s:]+)+:\d+:\d+:\s*runtime error:.*"
)
UBSAN_PATTERN = re.compile(
    r"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\s+(\S+:\d+:\d+)"
)
# Captures source location as file:line from abort/assert lines.
# Example line:
# poc.out: /root/src/libaom/av1/encoder/intra_mode_search.c:358: ... Assertion `...` failed.
ABORT_ASSERT_LOCATION_PATTERN = re.compile(
    r"((?:/[^\s:]+)+:\d+:.*Assertion .* failed\.)"
)
# Captures the condition from absl CHECK failure lines.
# Example line:
# F0000 00:00:... Check failed: last_returned_size_ > 0 (0 vs. 0) BackUp() ...
ABSL_CHECK_PATTERN = re.compile(r"Check failed:\s*(.+?)\s*\(")
# Generic fallback for any libFuzzer-reported signal crash.
# Example line:
# SUMMARY: libFuzzer: deadly signal
LIBFUZZER_SIGNAL_PATTERN = re.compile(r"SUMMARY:\s*libFuzzer:\s*([\w][\w\s-]*)")

def get_project_root() -> Path:
    return PROJECT_ROOT


def get_fdp_header_dir() -> str:
    return str(get_project_root() / "include")


def get_crash_tester_path() -> str:
    return str(get_project_root() / "tests" / "crash_tester.py")


def validate_phase3_mode(mode: str) -> str:
    if mode == PHASE3_DIRECT_ALIAS:
        return PHASE3_DIRECT
    if mode not in PHASE3_MODES:
        raise ValueError(
            f"Unsupported phase 3 compilation mode {mode!r}; "
            f"expected one of: {', '.join(sorted(PHASE3_MODES | {PHASE3_DIRECT_ALIAS}))}"
        )
    return mode


def _split_flags(flags: str | None) -> list[str]:
    return flags.split() if flags else []


def runtime_library_directories(link_flags: str | None) -> tuple[str, ...]:
    """Return absolute runtime search directories implied by linker flags."""
    tokens = _split_flags(link_flags)
    directories: list[str] = []

    def add(path_text: str) -> None:
        directory = str(Path(path_text).expanduser().resolve())
        if directory not in directories:
            directories.append(directory)

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-L" and index + 1 < len(tokens):
            add(tokens[index + 1])
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            add(token[2:])
        elif _is_shared_library_path(Path(token)):
            add(str(Path(token).expanduser().resolve().parent))
        index += 1
    return tuple(directories)


def runtime_library_env(
    link_flags: str | None,
    base_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build an execution environment that can locate dynamically linked targets."""
    env = dict(base_env) if base_env is not None else os.environ.copy()
    directories = runtime_library_directories(link_flags)
    if not directories:
        return env
    existing = env.get("LD_LIBRARY_PATH", "")
    prefix = os.pathsep.join(directories)
    env["LD_LIBRARY_PATH"] = prefix + (os.pathsep + existing if existing else "")
    return env


def absolutize_link_flags(link_flags: str | None) -> str | None:
    """Make path-bearing link flags stable when treereduce changes cwd."""
    if not link_flags:
        return link_flags
    tokens = _split_flags(link_flags)
    normalized: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-L" and index + 1 < len(tokens):
            normalized.extend(
                ["-L", str(Path(tokens[index + 1]).expanduser().resolve())]
            )
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            normalized.append(
                "-L" + str(Path(token[2:]).expanduser().resolve())
            )
        elif token.endswith((".a", ".o", ".lo")) or _is_shared_library_path(
            Path(token)
        ):
            normalized.append(str(Path(token).expanduser().resolve()))
        else:
            normalized.append(token)
        index += 1
    return " ".join(normalized)


def _is_shared_library_path(path: Path) -> bool:
    return bool(re.search(r"\.so(?:\..+)?$", path.name))


def resolve_amortized_shared_libraries(link_flags: str | None) -> tuple[str, ...]:
    """Resolve shared-library inputs used by the amortized runner.

    This first implementation intentionally rejects static archives and object
    files. They cannot be made position independent at link time, and loading
    them into the persistent process would require a separate anchor/export
    strategy.
    """
    tokens = _split_flags(link_flags)
    library_dirs: list[Path] = []
    for index, token in enumerate(tokens):
        if token == "-L" and index + 1 < len(tokens):
            library_dirs.append(Path(tokens[index + 1]).expanduser().resolve())
        elif token.startswith("-L") and len(token) > 2:
            library_dirs.append(Path(token[2:]).expanduser().resolve())

    resolved: list[str] = []

    def add_library(path: Path) -> None:
        candidate = path.expanduser().resolve()
        if not candidate.exists():
            raise ValueError(f"Shared library does not exist: {candidate}")
        if not _is_shared_library_path(candidate):
            raise ValueError(
                "--amortize-link currently requires shared target libraries; "
                f"unsupported link input: {candidate}"
            )
        try:
            with candidate.open("rb") as handle:
                elf_magic = handle.read(4)
        except OSError as exc:
            raise ValueError(f"Could not inspect shared library {candidate}: {exc}") from exc
        if elf_magic != b"\x7fELF":
            raise ValueError(
                "--amortize-link requires a loadable ELF shared library, but "
                f"{candidate} appears to be a linker script or another file type."
            )
        value = str(candidate)
        if value not in resolved:
            resolved.append(value)

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-L":
            index += 2
            continue
        if token.startswith("-L"):
            index += 1
            continue
        if token == "-l" and index + 1 < len(tokens):
            library_name = tokens[index + 1]
            index += 2
        elif token.startswith("-l") and len(token) > 2:
            library_name = token[2:]
            index += 1
        else:
            path = Path(token)
            if token.endswith((".a", ".o", ".lo")):
                raise ValueError(
                    "--amortize-link does not yet support static archives or object files: "
                    f"{token}"
                )
            if _is_shared_library_path(path):
                add_library(path)
            index += 1
            continue

        if library_name.startswith(":"):
            file_name = library_name[1:]
        else:
            file_name = f"lib{library_name}.so"
        found = next((directory / file_name for directory in library_dirs if (directory / file_name).exists()), None)
        if found is None:
            # System libraries (for example -lm or -ldl) are already part of
            # the runner's normal dynamic-loader scope or are dependencies of
            # the target DSO. Only -l entries found in user-provided -L
            # directories are treated as target libraries to preload.
            continue
        add_library(found)

    if not resolved:
        raise ValueError(
            "--amortize-link requires at least one shared target library in --link-flags."
            " Pass a full .so path or use -L/path -ltarget."
        )
    return tuple(resolved)


def _compile_harness_runner() -> str:
    source = SCRIPT_DIR / HARNESS_RUNNER_SOURCE_NAME
    output = Path(get_work_dir()) / HARNESS_RUNNER_BINARY_NAME
    run_command(
        [
            "clang++",
            "-std=c++17",
            *PHASE3_PLUGIN_SANITIZER_FLAGS,
            "-O1",
            "-gline-tables-only",
            "-fno-omit-frame-pointer",
            str(source),
            "-ldl",
            "-o",
            str(output),
        ],
        "Failed to compile amortized-link runner",
    )
    return str(output)


@contextmanager
def start_amortized_runner(
    link_flags: str | None,
    crash_input: str | None,
    fdp_trace_file: str,
    *,
    symbolize: bool,
):
    shared_libraries = resolve_amortized_shared_libraries(link_flags)
    runner_binary = _compile_harness_runner()
    socket_path = f"/tmp/harness_runner_{os.getpid()}_{time.time_ns()}.sock"
    env = runtime_library_env(link_flags)
    symbolized = "1" if symbolize else "0"
    env["ASAN_OPTIONS"] = f"exitcode=77:symbolize={symbolized}:handle_abort=1"
    env["UBSAN_OPTIONS"] = (
        f"exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize={symbolized}"
    )
    env["FDP_TRACE_PATH"] = fdp_trace_file
    library_dirs = tuple(dict.fromkeys(str(Path(path).parent) for path in shared_libraries))
    if library_dirs:
        existing = env.get("LD_LIBRARY_PATH", "")
        prefix = os.pathsep.join(library_dirs)
        env["LD_LIBRARY_PATH"] = prefix + (os.pathsep + existing if existing else "")

    process = subprocess.Popen(
        [runner_binary, socket_path, crash_input or "", *shared_libraries],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    deadline = time.monotonic() + 15.0
    try:
        while not os.path.exists(socket_path):
            return_code = process.poll()
            if return_code is not None:
                stdout, stderr = process.communicate()
                raise RuntimeError(
                    "Amortized-link runner failed during startup:\n"
                    f"{stdout}{stderr}"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("Timed out waiting for amortized-link runner socket.")
            time.sleep(0.02)
        yield AmortizedRunner(
            socket_path=socket_path,
            process=process,
            shared_libraries=shared_libraries,
        )
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        try:
            os.remove(socket_path)
        except FileNotFoundError:
            pass


def run_amortized_reference_candidate(
    harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    phase3_mode: str,
    runner_socket: str,
    pch_artifacts: PchArtifacts | None,
    *,
    symbolize: bool,
) -> str:
    cmd = [
        get_crash_tester_path(),
        pch_artifacts.body_source if pch_artifacts is not None else harness_path,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--fdp-trace",
        fdp_trace_file,
        "--amortized-runner-socket",
        runner_socket,
    ]
    if symbolize:
        cmd.append("--symbolize")
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    proc = run_command(
        cmd,
        "Amortized-link reference candidate failed",
        ignore_errors=True,
    )
    output = proc.stdout + proc.stderr
    if proc.returncode != 77:
        raise RuntimeError(
            "The original harness did not preserve the crash in amortized-link mode.\n"
            f"{output}"
        )
    return output


def _phase3_replay_flags(use_replay: bool) -> list[str]:
    if not use_replay:
        return []
    return [f"-I{get_fdp_header_dir()}", "-DFDP_MIN_MODE_REPLAY"]


def _build_pch_compile_command(
    prefix_header: str,
    pch_file: str,
    compile_flags: str | None,
    use_replay: bool,
    amortize_link: bool = False,
) -> list[str]:
    sanitizer_flags = (
        PHASE3_PLUGIN_SANITIZER_FLAGS if amortize_link else PHASE3_SANITIZER_FLAGS
    )
    cmd = [
        "clang++",
        "-Qunused-arguments",
        *_phase3_replay_flags(use_replay),
        *sanitizer_flags,
        *PHASE3_PCH_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *(["-fPIC"] if amortize_link else []),
        "-x",
        "c++-header",
        *_split_flags(compile_flags),
        prefix_header,
        "-o",
        pch_file,
    ]
    return cmd


_INCLUDE_DIRECTIVE_PATTERN = re.compile(r"^\s*#\s*include\b")
_QUOTED_INCLUDE_PATTERN = re.compile(r'^(\s*#\s*include\s*)"([^"]+)"(.*)$')


def _rewrite_local_quoted_include_for_pch(line: str, source_dir: Path) -> str:
    """Preserve quote-include semantics after moving includes into the work dir.

    Direct compilation resolves #include "local.h" relative to the source file
    first. The generated harness_prefix.h lives in the reducer work directory, so a
    plain copy of that line could accidentally change the lookup root.  If the
    quoted header exists relative to the source being split, rewrite it to the
    resolved absolute path inside the PCH prefix.  The final restored harness
    still receives the original include spelling.
    """

    line_without_newline = line.rstrip("\r\n")
    newline = line[len(line_without_newline):]
    match = _QUOTED_INCLUDE_PATTERN.match(line_without_newline)
    if not match:
        return line

    include_name = match.group(2)
    if os.path.isabs(include_name):
        return line

    local_header = (source_dir / include_name).resolve()
    if not local_header.exists():
        return line

    escaped_header = str(local_header).replace("\\", "\\\\").replace('"', '\\"')
    return f'{match.group(1)}"{escaped_header}"{match.group(3)}{newline}'


def _split_source_for_pch(source: str, source_dir: Path) -> tuple[str, str, str]:
    """Return (pch_prefix, restore_prefix, include-stripped_body)."""

    standard_include_keys = {"#include <stdint.h>", "#include <stddef.h>"}
    pch_prefix_lines = [
        "// Generated by HarnessReducer for Phase 3 PCH compilation.\n",
        "#include <stdint.h>\n",
        "#include <stddef.h>\n",
    ]
    restore_prefix_lines = [
        "#include <stdint.h>\n",
        "#include <stddef.h>\n",
    ]
    body_lines: list[str] = []

    for line in source.splitlines(keepends=True):
        if _INCLUDE_DIRECTIVE_PATTERN.match(line):
            if line.strip() in standard_include_keys:
                continue
            pch_prefix_lines.append(_rewrite_local_quoted_include_for_pch(line, source_dir))
            restore_prefix_lines.append(line)
        else:
            body_lines.append(line)

    return (
        "".join(pch_prefix_lines),
        "".join(restore_prefix_lines),
        "".join(body_lines),
    )


def prepare_phase3_pch_harness(
    harness_path: str,
    compile_flags: str | None,
    use_replay: bool,
    amortize_link: bool = False,
) -> PchArtifacts:
    """Create harness_prefix.h/.pch and an include-stripped harness body.

    The PCH is compiled with Phase 3's conditional replay flags when
    ``use_replay`` is true.  The candidate body is what should be passed to
    crash_tester.py with ``--pch --pch-path <pch>``.
    """

    source_path = Path(harness_path)
    source = source_path.read_text(encoding="utf-8", errors="ignore")
    pch_prefix, restore_prefix, body = _split_source_for_pch(source, source_path.parent)

    work_dir = Path(get_work_dir())
    prefix_header = work_dir / PCH_PREFIX_HEADER_NAME
    pch_file = work_dir / PCH_PREFIX_FILE_NAME
    suffix = source_path.suffix or ".cpp"
    body_source = work_dir / f"{source_path.stem}.harness_body{suffix}"

    prefix_header.write_text(pch_prefix, encoding="utf-8")
    body_source.write_text(body, encoding="utf-8")

    compile_cmd = _build_pch_compile_command(
        str(prefix_header),
        str(pch_file),
        compile_flags,
        use_replay=use_replay,
        amortize_link=amortize_link,
    )
    print(f"[+] Precompiling Phase 3 header: {prefix_header} -> {pch_file}")
    run_command(compile_cmd, "Failed to precompile Phase 3 PCH header")
    print(f"[+] Wrote include-stripped Phase 3 harness body: {body_source}")

    return PchArtifacts(
        body_source=str(body_source),
        prefix_header=str(prefix_header),
        pch_file=str(pch_file),
        restore_prefix=restore_prefix,
    )


def restore_pch_includes(harness_path: str, artifacts: PchArtifacts) -> None:
    """Prepend the moved include directives back to a reduced body harness."""

    if not artifacts.restore_prefix:
        return
    path = Path(harness_path)
    body = path.read_text(encoding="utf-8", errors="ignore")
    path.write_text(artifacts.restore_prefix + body, encoding="utf-8")


def pch_tester_args(artifacts: PchArtifacts | None, phase3_mode: str) -> list[str]:
    mode = validate_phase3_mode(phase3_mode)
    if mode == PHASE3_DIRECT:
        return ["--single-step"]
    if mode == PHASE3_SPLIT:
        return ["--split"]
    if artifacts is None:
        raise ValueError("PCH Phase 3 mode requires prepared PCH artifacts.")
    return ["--pch", "--pch-path", artifacts.pch_file]


def configure_work_dir(work_dir: str | None) -> str:
    global TREEDUCER_DIR, _IS_USER_WORK_DIR

    if work_dir:
        path = str(Path(work_dir).expanduser().resolve())
        Path(path).mkdir(parents=True, exist_ok=True)
        TREEDUCER_DIR = path
        _IS_USER_WORK_DIR = True
        return TREEDUCER_DIR

    if TREEDUCER_DIR is None:
        TREEDUCER_DIR = tempfile.mkdtemp(prefix="harness_reducer_")
        _IS_USER_WORK_DIR = False
    return TREEDUCER_DIR


def get_work_dir() -> str:
    return configure_work_dir(None)


def run_command(cmd: list[str], error_prefix: str, env: dict[str, str] | None = None, ignore_errors: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0 and not ignore_errors:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown error"
        raise RuntimeError(f"{error_prefix}: {err_msg}")
    return proc


def check_tree_reducer() -> None:
    print("[+] Checking for tree-reducer availability...")
    run_command(
        ["treereduce-c", "--help"],
        "tree-reducer is not available. Please ensure it is installed and in your PATH",
    )
    print("[+] tree-reducer is available.")

def check_harness_compilation(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> None:
    print("[+] Checking harness compilation...")
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    compile_cmd = [
        "clang++",
        "-fsanitize=address,fuzzer,undefined",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        output_bin,
        *_split_flags(link_flags),
    ]

    run_command(compile_cmd, "Failed to compile the original harness. Please fix compilation errors before reduction.")
    print("[+] Harness compiles successfully.")


def compile_coverage_harness(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> str:
    """Compile a source-coverage-instrumented harness binary for pre-slicing."""
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, COVERAGE_BIN_FILE_NAME)
    driver_source = Path(work_dir) / COVERAGE_DRIVER_FILE_NAME
    driver_source.write_text(
        """
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <sanitizer/common_interface_defs.h>
#include <string>
#include <vector>

extern "C" int __llvm_profile_write_file(void);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void coverageDeathCallback() {
    __llvm_profile_write_file();
}

int main(int argc, char **argv) {
    __sanitizer_set_death_callback(coverageDeathCallback);
    std::vector<uint8_t> data;
    if (argc > 1 && argv[1] != nullptr && argv[1][0] != '\\0') {
        std::ifstream input(argv[1], std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
    const int result = LLVMFuzzerTestOneInput(data.empty() ? nullptr : data.data(), data.size());
    __llvm_profile_write_file();
    return result;
}
""".lstrip(),
        encoding="utf-8",
    )
    compile_cmd = [
        "clang++",
        "-fsanitize=address,undefined,fuzzer-no-link",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        str(driver_source),
        "-o",
        output_bin,
        *_split_flags(link_flags),
    ]
    run_command(compile_cmd, "Failed to compile coverage-enabled harness")
    return output_bin

def normalize_crash_signature(signature: str, escape: bool = False) -> str:
    signature = signature.strip()
    if escape:
        placeholder = "__ADDR__"
        signature = MEMORY_ADDRESS_PATTERN.sub(placeholder, signature)
        signature = re.escape(signature)
        return signature.replace(re.escape(placeholder), r"0x[0-9a-fA-F]+")

    return MEMORY_ADDRESS_PATTERN.sub(r"0x[0-9a-fA-F]+", signature)

def _frame_matches_harness_source(frame_line: str, harness_path: str | None) -> bool:
    if not harness_path:
        return False

    harness_resolved = str(Path(harness_path).resolve())
    if harness_resolved in frame_line:
        return True

    match = SOURCE_LOCATION_PATTERN.search(frame_line)
    if not match:
        return Path(harness_path).name in frame_line

    frame_source = match.group(1)
    try:
        if Path(frame_source).resolve() == Path(harness_path).resolve():
            return True
    except OSError:
        pass
    return Path(frame_source).name == Path(harness_path).name


def extract_stack_trace(output: str, harness_path: str | None = None) -> str | None:
    """Extract the first stack trace from symbolized sanitizer output.

    Parses stack frames (lines matching ``#N 0xADDR in ...``) and returns the
    first stack trace, truncated before the harness frames. When ``harness_path``
    is provided, truncation happens at the first frame whose source location
    belongs to that harness file. Otherwise it falls back to truncating at
    ``LLVMFuzzerTestOneInput``.

    Only the *first* stack trace is kept (ASan may emit multiple — e.g., one
    for the overflow and one for the allocation site).
    Returns None if no stack frames are found.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_PATTERN.match(line):
            in_first_trace = True
            if _frame_matches_harness_source(line, harness_path):
                break
            # Backward-compatible / robustness fallback.
            if LLVMFuzzerTestOneInput_PATTERN.search(line):
                break
            frames.append(line)
        elif in_first_trace:
            # A non-frame line after we started collecting means the first
            # trace is over.  Do not continue into a second trace.
            break
    if not frames:
        return None
    return "\n".join(frames)


def extract_first_sanitizer_stack_trace(output: str) -> str | None:
    """Extract the first contiguous sanitizer-style stack trace block.

    This helper is used for frame-depth counting and does not truncate at
    harness frames. It recognizes the common sanitizer frame shape
    ``#N 0x...`` and therefore works for both symbolized and unsymbolized
    sanitizer output, including ASan and UBSan traces that use that format.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_COUNT_PATTERN.match(line):
            in_first_trace = True
            frames.append(line)
        elif in_first_trace:
            break
    if not frames:
        return None
    return "\n".join(frames)


def count_first_stack_trace_frames(output: str) -> int:
    trace = extract_first_sanitizer_stack_trace(output)
    if not trace:
        return 0
    return sum(1 for line in trace.splitlines() if STACK_FRAME_COUNT_PATTERN.match(line))


def set_normal_reference_stack_depth(depth: int | None) -> None:
    global NORMAL_REFERENCE_STACK_DEPTH
    NORMAL_REFERENCE_STACK_DEPTH = depth


def get_normal_reference_stack_depth() -> int | None:
    return NORMAL_REFERENCE_STACK_DEPTH


def set_symbolized_reference_stack_depth(depth: int | None) -> None:
    global SYMBOLIZED_REFERENCE_STACK_DEPTH
    SYMBOLIZED_REFERENCE_STACK_DEPTH = depth


def get_symbolized_reference_stack_depth() -> int | None:
    return SYMBOLIZED_REFERENCE_STACK_DEPTH


def get_stack_trace_file() -> str:
    return os.path.join(get_work_dir(), STACK_TRACE_FILE_NAME)

def get_last_interesting_file() -> str:
    return os.path.join(get_work_dir(), LAST_INTERESTING_FILE_NAME)

def get_statistics_file() -> str:
    return os.path.join(get_work_dir(), STATISTICS_FILE_NAME)


def reset_stack_trace_state() -> None:
    """Remove persisted stack-trace validation artifacts from the work dir."""
    set_normal_reference_stack_depth(None)
    set_symbolized_reference_stack_depth(None)
    for path in (get_stack_trace_file(),):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def reset_last_interesting_state() -> None:
    try:
        os.remove(get_last_interesting_file())
    except FileNotFoundError:
        pass


def candidate_files_match(path_a: str, path_b: str) -> bool:
    try:
        return filecmp.cmp(path_a, path_b, shallow=False)
    except FileNotFoundError:
        return False


def reset_statistics_state() -> None:
    try:
        os.remove(get_statistics_file())
    except FileNotFoundError:
        pass


def _format_statistics_text(
    count_77: int,
    count_1: int,
    count_neg1: int,
) -> str:
    total = count_77 + count_1 + count_neg1

    def probability(count: int) -> float:
        return 0.0 if total == 0 else count / total

    return (
        f"total: {total}\n"
        f"count_77: {count_77}\n"
        f"count_1: {count_1}\n"
        f"count_-1: {count_neg1}\n"
        f"probability_77: {probability(count_77):.6f}\n"
        f"probability_1: {probability(count_1):.6f}\n"
        f"probability_-1: {probability(count_neg1):.6f}\n"
    )


def initialize_statistics_file() -> str:
    path = get_statistics_file()
    Path(path).write_text(_format_statistics_text(0, 0, 0), encoding="utf-8")
    return path


def _source_coverage_raw_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_RAW_FILE_NAME


def _source_coverage_data_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_DATA_FILE_NAME


def _source_coverage_show_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_SHOW_FILE_NAME


def _source_coverage_export_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_EXPORT_FILE_NAME


def _clear_source_coverage_artifacts() -> None:
    for path in (
        _source_coverage_raw_path(),
        _source_coverage_data_path(),
        _source_coverage_show_path(),
        _source_coverage_export_path(),
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _coverage_count_is_nonzero(count_text: str) -> bool:
    text = count_text.strip()
    if not text or text in {"-", "#####"}:
        return False
    return not re.fullmatch(r"0+(?:\.0+)?[kMGTPE]?", text)


def _parse_llvm_cov_show_text(report_text: str) -> CoverageMap:
    executable_lines: set[int] = set()
    covered_lines: set[int] = set()

    for line in report_text.splitlines():
        match = LLVM_COV_SHOW_LINE_PATTERN.match(line)
        if not match:
            continue
        line_no = int(match.group(1))
        count_text = match.group(2).strip()
        if not count_text:
            continue
        executable_lines.add(line_no)
        if _coverage_count_is_nonzero(count_text):
            covered_lines.add(line_no)

    return CoverageMap(
        executable_lines=frozenset(executable_lines),
        covered_lines=frozenset(covered_lines),
    )


def _merge_source_coverage_profile(raw_path: Path, profdata_path: Path) -> None:
    run_command(
        [
            "llvm-profdata",
            "merge",
            "-sparse",
            str(raw_path),
            "-o",
            str(profdata_path),
        ],
        "Failed to merge source coverage profile",
    )


def generate_harness_coverage_reports(
    coverage_bin: str,
    harness_path: str,
) -> dict[str, str]:
    """Generate llvm-cov reports for a previously collected source-coverage run."""
    profdata_path = _source_coverage_data_path()
    if not profdata_path.exists():
        raise RuntimeError("Coverage profile data is missing; collect coverage first.")

    harness_realpath = str(Path(harness_path).resolve())
    show_proc = run_command(
        [
            "llvm-cov",
            "show",
            coverage_bin,
            f"-instr-profile={profdata_path}",
            harness_realpath,
        ],
        "Failed to generate line coverage report",
    )
    export_proc = run_command(
        [
            "llvm-cov",
            "export",
            coverage_bin,
            f"-instr-profile={profdata_path}",
            f"--sources={harness_realpath}",
        ],
        "Failed to export coverage report",
    )

    _source_coverage_show_path().write_text(show_proc.stdout, encoding="utf-8")
    _source_coverage_export_path().write_text(export_proc.stdout, encoding="utf-8")
    return {
        SOURCE_COVERAGE_SHOW_FILE_NAME: show_proc.stdout,
        SOURCE_COVERAGE_EXPORT_FILE_NAME: export_proc.stdout,
    }


def collect_harness_coverage(
    coverage_bin: str,
    harness_path: str,
    crash_input: str | None,
    link_flags: str | None = None,
) -> CoverageMap:
    """Run the crashing input under source-based coverage and return line sets."""
    _clear_source_coverage_artifacts()
    raw_path = _source_coverage_raw_path()
    profdata_path = _source_coverage_data_path()

    env = runtime_library_env(link_flags)
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0:handle_abort=1"
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=0"
    env["LLVM_PROFILE_FILE"] = str(raw_path)
    cmd = [coverage_bin]
    if crash_input:
        cmd.append(crash_input)
    run_command(
        cmd,
        "Failed to execute coverage-enabled harness",
        env=env,
        ignore_errors=True,
    )

    if not raw_path.exists() or raw_path.stat().st_size == 0:
        raise RuntimeError("No source coverage profile was produced.")

    _merge_source_coverage_profile(raw_path, profdata_path)
    reports = generate_harness_coverage_reports(coverage_bin, harness_path)
    return _parse_llvm_cov_show_text(reports[SOURCE_COVERAGE_SHOW_FILE_NAME])


def apply_coverage_guided_slice(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
) -> str:
    """Conservatively prune uncovered harness code before tree reduction.

    If coverage collection, slicing, or validation fails, the original harness
    path is returned unchanged.
    """
    try:
        coverage_bin = compile_coverage_harness(harness_path, compile_flags, link_flags)
        coverage = collect_harness_coverage(
            coverage_bin,
            harness_path,
            crash_input,
            link_flags,
        )
        if not coverage.executable_lines:
            print("[*] Coverage-guided slicing skipped: no executable harness lines were found.")
            return harness_path

        source = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
        slice_result = slice_source_by_coverage(source, coverage)
        if slice_result.removed_nodes == 0 or slice_result.source == source:
            print("[*] Coverage-guided slicing found no removable uncovered blocks.")
            return harness_path

        source_path = Path(harness_path)
        sliced_path = Path(get_work_dir()) / f"{source_path.stem}{SLICED_HARNESS_SUFFIX}{source_path.suffix or '.cpp'}"
        sliced_path.write_text(slice_result.source, encoding="utf-8")

        if not validate_stack_trace(
            str(sliced_path),
            crash_pattern,
            crash_input,
            compile_flags,
            link_flags,
            phase3_mode=phase3_mode,
        ):
            print("[!] Coverage-guided slicing failed crash-preservation validation. Falling back to the original harness.")
            return harness_path

        print(
            f"[+] Coverage-guided slicing removed {slice_result.removed_nodes} uncovered nodes: {sliced_path}"
        )
        return str(sliced_path)
    except Exception as exc:
        print(f"[!] Coverage-guided slicing skipped: {exc}")
        return harness_path


def _run_harness_for_crash_reference(
    output_bin: str,
    crash_input: str | None,
    *,
    symbolize: bool,
    link_flags: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)
    env = runtime_library_env(link_flags)
    symbolized = "1" if symbolize else "0"
    env["UBSAN_OPTIONS"] = f"exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize={symbolized}"
    env["ASAN_OPTIONS"] = f"exitcode=77:symbolize={symbolized}:handle_abort=1"
    return run_command(
        cmd,
        env=env,
        error_prefix="Failed to execute harness for crash pattern extraction",
        ignore_errors=True,
    )


def _extract_crash_signature_from_output(output: str) -> str | None:
    abort_assert_match = ABORT_ASSERT_LOCATION_PATTERN.search(output)
    if abort_assert_match:
        parts = abort_assert_match.group(0).split(":")
        signature = parts[0] + ":" + parts[1]
        return normalize_crash_signature(signature)

    asan_summary_match = ASAN_SUMMARY_PATTERN.search(output)
    if asan_summary_match:
        return normalize_crash_signature(asan_summary_match.group(0))

    asan_error_match = ASAN_ERROR_PATTERN.search(output)
    if asan_error_match:
        return normalize_crash_signature(asan_error_match.group(0))

    leak_match = LEAK_PATTERN.search(output)
    if leak_match:
        return normalize_crash_signature(leak_match.group(0))

    runtime_error_match = RUNTIME_ERROR_PATTERN.search(output)
    if runtime_error_match:
        return normalize_crash_signature(runtime_error_match.group(0), escape=True)

    ubsan_match = UBSAN_PATTERN.search(output)
    if ubsan_match:
        return normalize_crash_signature(ubsan_match.group(0))

    absl_check_match = ABSL_CHECK_PATTERN.search(output)
    if absl_check_match:
        return normalize_crash_signature(absl_check_match.group(1))

    libfuzzer_signal_match = LIBFUZZER_SIGNAL_PATTERN.search(output)
    if libfuzzer_signal_match:
        return normalize_crash_signature(libfuzzer_signal_match.group(1))

    return None


def extract_crash_pattern_from_output(
    crash_input: str | None,
    harness_path: str | None = None,
    link_flags: str | None = None,
) -> str | None:
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    proc = _run_harness_for_crash_reference(
        output_bin,
        crash_input,
        symbolize=False,
        link_flags=link_flags,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        print("[!] Warning: No crash detected when running the harness. Output:\n" + output)
        set_normal_reference_stack_depth(None)
        set_symbolized_reference_stack_depth(None)
        return None

    normal_reference_stack_depth = count_first_stack_trace_frames(output)
    set_normal_reference_stack_depth(normal_reference_stack_depth or None)
    if normal_reference_stack_depth:
        print(f"[+] Recorded fast-path stack trace depth: {normal_reference_stack_depth}")
    else:
        print("[!] No fast-path stack-trace frames found for reference depth extraction.")

    crash_pattern = _extract_crash_signature_from_output(output)
    if not crash_pattern:
        raise ValueError("Failed to extract a valid crash pattern from the harness output. Output:\n" + output)

    symbolized_proc = _run_harness_for_crash_reference(
        output_bin,
        crash_input,
        symbolize=True,
        link_flags=link_flags,
    )
    symbolized_output = symbolized_proc.stdout + "\n" + symbolized_proc.stderr
    if symbolized_proc.returncode != 77:
        set_symbolized_reference_stack_depth(None)
        try:
            os.remove(get_stack_trace_file())
        except FileNotFoundError:
            pass
        print(
            "[!] Warning: Symbolized reference execution did not reproduce the crash; "
            "skipping symbolized stack-trace reference capture."
        )
        return crash_pattern

    symbolized_reference_stack_depth = count_first_stack_trace_frames(symbolized_output)
    set_symbolized_reference_stack_depth(symbolized_reference_stack_depth or None)
    if symbolized_reference_stack_depth:
        print(f"[+] Recorded symbolized stack trace depth: {symbolized_reference_stack_depth}")
    else:
        print("[!] No symbolized stack-trace frames found for reference depth extraction.")

    # Extract and save the first stack trace (normalized) for deeper symbolized validation.
    raw_stack_trace = extract_stack_trace(symbolized_output, harness_path=harness_path)
    if raw_stack_trace:
        normalized_trace = normalize_crash_signature(raw_stack_trace, escape=True)
        trace_file = get_stack_trace_file()
        Path(trace_file).write_text(normalized_trace, encoding="utf-8")
        print(f"[+] Saved stack trace pattern to {trace_file}")
    else:
        try:
            os.remove(get_stack_trace_file())
        except FileNotFoundError:
            pass
        print("[!] No symbolized stack trace found in crash output.")
    return crash_pattern


def check_reducer_crash_pattern(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
) -> None:
    print("[+] Checking crash pattern validity...")
    if not crash_pattern:
        raise ValueError("Crash pattern cannot be empty.")
    validate_phase3_mode(phase3_mode)

    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=False,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    cmd.extend(stack_depth_tester_args(symbolized=False))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    proc = run_command(cmd, "Invalid crash pattern.", ignore_errors=True)
    if proc.returncode != 77:
        print("Tester command: " + " ".join(cmd))
        raise ValueError(f"Crash pattern did not match the crash behavior. Tester output:\n{proc.stdout}\n{proc.stderr}")
    print("[+] Crash pattern is valid.")

def compile_dump_mode_harness(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> str:
    tagged_harness_bin = os.path.join(get_work_dir(), "tagged_harness.out")
    compile_cmd = [
        "clang++",
        "-DFDP_MIN_MODE_DUMP",
        f"-I{get_fdp_header_dir()}",
        "-fsanitize=address,fuzzer,undefined",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        tagged_harness_bin,
        *_split_flags(link_flags),
    ]

    run_command(compile_cmd, "Failed to compile tagged harness with dump mode")
    return tagged_harness_bin


def dump_fdp_trace(
    harness_bin: str,
    crash_input: str | None,
    link_flags: str | None = None,
) -> str:
    fdp_trace_file = os.path.join(get_work_dir(), "fdp_trace.log")
    # The dump runtime appends trace records, so remove any trace left by an
    # earlier run when a fixed work directory is reused.
    try:
        os.remove(fdp_trace_file)
    except FileNotFoundError:
        pass

    env = runtime_library_env(link_flags)
    env["FDP_TRACE_PATH"] = fdp_trace_file

    exec_cmd = [harness_bin, crash_input] if crash_input else [harness_bin]
    run_command(exec_cmd, "Failed to execute tagged harness in dump mode", env=env, ignore_errors=True)

    if not os.path.exists(fdp_trace_file):
        raise RuntimeError("FDP trace file was not created as expected.")
    return fdp_trace_file


def run_treereducer(
    harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    stable: bool = False,
    phase3_mode: str = PHASE3_SPLIT,
    statistics: bool = False,
    snapshot: bool = False,
    amortize_link: bool = False,
) -> str:
    # treereduce changes cwd to a temp dir when invoking the tester, so relative
    # paths for crash_input would not be found.  Resolve to absolute here.
    if crash_input:
        crash_input = str(Path(crash_input).resolve())
    link_flags = absolutize_link_flags(link_flags)
    validate_phase3_mode(phase3_mode)
    if amortize_link and phase3_mode == PHASE3_DIRECT:
        raise ValueError("Amortized linking requires split or PCH mode.")
    pch_artifacts: PchArtifacts | None = None
    reducer_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=True,
            amortize_link=amortize_link,
        )
        reducer_source = pch_artifacts.body_source

    reduced_harness = os.path.join(get_work_dir(), "reduced_harness.cpp")
    cmd = [
        "treereduce-c",
        "-j",
        "60",
        "-s",
        reducer_source,
        "-o",
        reduced_harness,
    ]
    if stable:
        cmd.append("--stable")
        cmd.append("--min-reduction")
        cmd.append("1")
    else:
        cmd.append("--fast")
    cmd.extend([
        "--timeout",
        "300",
        "--interesting-exit-code",
        "77",
        "--",
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--fdp-trace", fdp_trace_file,
    ])
    if snapshot:
        cmd.extend(["--last-interesting-file", get_last_interesting_file()])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    if statistics:
        cmd.extend(["--statistics-file", initialize_statistics_file()])

    runner_context = (
        start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=False,
        )
        if amortize_link
        else nullcontext(None)
    )
    with runner_context as amortized_runner:
        if amortized_runner is not None:
            reference_output = run_amortized_reference_candidate(
                harness_path,
                fdp_trace_file,
                crash_pattern,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode,
                amortized_runner.socket_path,
                pch_artifacts,
                symbolize=False,
            )
            reference_depth = count_first_stack_trace_frames(reference_output)
            if reference_depth:
                cmd.extend(["--stack-depth", str(reference_depth)])
            cmd.extend(
                ["--amortized-runner-socket", amortized_runner.socket_path]
            )
        else:
            cmd.extend(stack_depth_tester_args(symbolized=False))

        proc = subprocess.run(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run tree-reducer:\n{proc.stdout} {proc.stderr}")
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    if pch_artifacts is not None:
        restore_pch_includes(reduced_harness, pch_artifacts)
        if snapshot:
            last_interesting_file = get_last_interesting_file()
            if os.path.exists(last_interesting_file):
                restore_pch_includes(last_interesting_file, pch_artifacts)

    return reduced_harness


def format_reduced_harness(reduced_harness_path: str) -> None:
    print(f"Formatting reduced harness with clang-format: {reduced_harness_path}")
    run_command(
        ["clang-format", "-i", "--style=LLVM", reduced_harness_path],
        "Failed to format reduced harness with clang-format",
    )


def stack_depth_tester_args(*, symbolized: bool = False) -> list[str]:
    depth = (
        get_symbolized_reference_stack_depth()
        if symbolized
        else get_normal_reference_stack_depth()
    )
    if depth is None:
        return []
    return ["--stack-depth", str(depth)]


def validate_stack_trace(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
    validation_log_path: str | None = None,
) -> bool:
    """Run a symbolize=1 crash-preservation check.

    This always validates crash pattern preservation and first-stack-trace
    depth. When a stored non-empty ``stack_trace.pattern`` exists, it also
    validates the pre-harness stack trace against that pattern.
    """
    stack_trace_file = get_stack_trace_file()
    stack_trace_arg: list[str] = []
    if not os.path.exists(stack_trace_file):
        print("[*] No stored stack trace pattern; running crash/depth validation only.")
    else:
        stored_pattern = Path(stack_trace_file).read_text(encoding="utf-8")
        if not stored_pattern.strip():
            print("[*] Stored stack trace pattern is empty; running crash/depth validation only.")
        else:
            stack_trace_arg = ["--stack-trace-file", stack_trace_file]

    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--symbolize",  # force symbolize=1 for this check
    ]
    cmd.extend(stack_trace_arg)
    cmd.extend(stack_depth_tester_args(symbolized=True))
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))

    proc = run_command(cmd, "Stack trace validation failed.", ignore_errors=True)
    if validation_log_path is not None and proc.returncode != 77:
        artifact = (
            f"returncode: {proc.returncode}\n"
            "===== stdout =====\n"
            f"{proc.stdout}"
            "\n===== stderr =====\n"
            f"{proc.stderr}"
        )
        Path(validation_log_path).write_text(artifact, encoding="utf-8")
    return proc.returncode == 77
