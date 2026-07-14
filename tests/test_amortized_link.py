import subprocess
import sys
from pathlib import Path

import pytest

from harnessreducer import reducer_runner


def _compile_static_archive(
    tmp_path: Path,
    name: str,
    source_text: str,
) -> Path:
    source = tmp_path / f"{name}.cpp"
    object_file = tmp_path / f"{name}.o"
    archive = tmp_path / f"lib{name}.a"
    source.write_text(source_text, encoding="utf-8")
    subprocess.run(
        [
            "clang++",
            "-c",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(source),
            "-o",
            str(object_file),
        ],
        check=True,
    )
    subprocess.run(["ar", "rcs", str(archive), str(object_file)], check=True)
    return archive


def test_amortized_link_resolves_multiple_dynamic_libraries(tmp_path: Path) -> None:
    libraries: list[Path] = []
    for name in ("first", "second"):
        source = tmp_path / f"{name}.cpp"
        library = tmp_path / f"lib{name}.so"
        source.write_text(
            f'extern "C" int {name}_value() {{ return 1; }}\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["clang++", "-shared", "-fPIC", str(source), "-o", str(library)],
            check=True,
        )
        libraries.append(library.resolve())

    inputs = reducer_runner.resolve_amortized_link_inputs(
        f"-L{tmp_path} -lfirst -lsecond -lpthread"
    )
    assert inputs.shared_libraries == tuple(str(path) for path in libraries)
    assert inputs.static_libraries == ()
    assert "-lpthread" in inputs.runner_link_flags


def test_amortized_link_resolves_multiple_static_libraries(tmp_path: Path) -> None:
    first = _compile_static_archive(
        tmp_path,
        "first",
        'extern "C" int first_value() { return 1; }\n',
    )
    second = _compile_static_archive(
        tmp_path,
        "second",
        'extern "C" int second_value() { return 2; }\n',
    )

    inputs = reducer_runner.resolve_amortized_link_inputs(
        f"-L{tmp_path} -Wl,-Bstatic -lfirst -lsecond -Wl,-Bdynamic -lm"
    )
    assert inputs.shared_libraries == ()
    assert inputs.static_libraries == (
        str(first.resolve()),
        str(second.resolve()),
    )
    assert "-lm" in inputs.runner_link_flags


def test_runtime_library_env_uses_link_search_directories(tmp_path: Path) -> None:
    target_source = tmp_path / "runtime_target.cpp"
    target_library = tmp_path / "libruntime_target.so"
    main_source = tmp_path / "runtime_main.cpp"
    executable = tmp_path / "runtime_main"
    target_source.write_text(
        'extern "C" int runtime_value() { return 42; }\n', encoding="utf-8"
    )
    main_source.write_text(
        'extern "C" int runtime_value();\n'
        "int main() { return runtime_value() == 42 ? 0 : 1; }\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            str(target_source),
            "-o",
            str(target_library),
        ],
        check=True,
    )
    subprocess.run(
        [
            "clang++",
            str(main_source),
            "-L",
            str(tmp_path),
            "-lruntime_target",
            "-o",
            str(executable),
        ],
        check=True,
    )

    run = subprocess.run(
        [str(executable)],
        env=reducer_runner.runtime_library_env(f"-L{tmp_path} -lruntime_target"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr


def test_absolutize_link_flags_preserves_libraries_and_resolves_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    normalized = reducer_runner.absolutize_link_flags(
        "-Lrelative/lib -laom relative/lib/libextra.so -lm"
    )
    assert normalized == (
        f"-L{tmp_path / 'relative/lib'} -laom "
        f"{tmp_path / 'relative/lib/libextra.so'} -lm"
    )


def test_amortized_runner_executes_candidate_against_shared_target(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work"))
    target_source = tmp_path / "target.cpp"
    target_library = tmp_path / "libtarget_asan.so"
    harness_source = tmp_path / "harness.cpp"
    trace_path = tmp_path / "fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")

    target_source.write_text(
        """
extern "C" __attribute__((noinline)) void target_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void target_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  target_crash();
  return 0;
}
""",
        encoding="utf-8",
    )

    compile_target = subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(target_source),
            "-o",
            str(target_library),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert compile_target.returncode == 0, compile_target.stderr
    assert reducer_runner.resolve_amortized_shared_libraries(
        f"{target_library} -lm"
    ) == (str(target_library.resolve()),)

    with reducer_runner.start_amortized_runner(
        str(target_library),
        None,
        str(trace_path),
        symbolize=False,
    ) as runner:
        split_tester = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                str(harness_source),
                "AddressSanitizer",
                "--split",
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        pch = reducer_runner.prepare_phase3_pch_harness(
            str(harness_source),
            compile_flags=None,
            use_replay=True,
            amortize_link=True,
        )
        pch_tester = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                pch.body_source,
                "AddressSanitizer",
                "--pch",
                "--pch-path",
                pch.pch_file,
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert split_tester.returncode == 77, split_tester.stdout + split_tester.stderr
    assert "AddressSanitizer" in split_tester.stdout + split_tester.stderr
    assert pch_tester.returncode == 77, pch_tester.stdout + pch_tester.stderr
    assert "AddressSanitizer" in pch_tester.stdout + pch_tester.stderr


def test_amortized_runner_executes_candidate_against_multiple_static_targets(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-static"))
    entry_archive = _compile_static_archive(
        tmp_path,
        "static_entry",
        """
extern "C" void static_crash_helper();
extern "C" void static_target_crash() { static_crash_helper(); }
""",
    )
    helper_archive = _compile_static_archive(
        tmp_path,
        "static_helper",
        """
extern "C" __attribute__((noinline)) void static_crash_helper() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
    )
    harness_source = tmp_path / "static_harness.cpp"
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void static_target_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  static_target_crash();
  return 0;
}
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "static_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")
    link_flags = f"{entry_archive} {helper_archive}"

    with reducer_runner.start_amortized_runner(
        link_flags,
        None,
        str(trace_path),
        symbolize=False,
    ) as runner:
        assert runner.shared_libraries == ()
        assert runner.static_libraries == (
            str(entry_archive.resolve()),
            str(helper_archive.resolve()),
        )
        result = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                str(harness_source),
                "AddressSanitizer",
                "--split",
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert result.returncode == 77, result.stdout + result.stderr
    assert "AddressSanitizer" in result.stdout + result.stderr


def test_amortized_runner_supports_mixed_static_and_dynamic_targets(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-mixed"))
    shared_source = tmp_path / "mixed_dynamic.cpp"
    shared_library = tmp_path / "libmixed_dynamic.so"
    shared_source.write_text(
        """
extern "C" __attribute__((noinline)) void mixed_dynamic_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(shared_source),
            "-o",
            str(shared_library),
        ],
        check=True,
    )
    static_archive = _compile_static_archive(
        tmp_path,
        "mixed_static",
        """
extern "C" void mixed_dynamic_crash();
extern "C" void mixed_static_entry() { mixed_dynamic_crash(); }
""",
    )
    harness_source = tmp_path / "mixed_harness.cpp"
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void mixed_static_entry();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  mixed_static_entry();
  return 0;
}
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "mixed_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")
    link_flags = (
        f"-L{tmp_path} -Wl,-Bstatic -lmixed_static "
        "-Wl,-Bdynamic -lmixed_dynamic"
    )

    inputs = reducer_runner.resolve_amortized_link_inputs(link_flags)
    assert inputs.static_libraries == (str(static_archive.resolve()),)
    assert inputs.shared_libraries == (str(shared_library.resolve()),)

    with reducer_runner.start_amortized_runner(
        link_flags,
        None,
        str(trace_path),
        symbolize=False,
    ) as runner:
        result = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                str(harness_source),
                "AddressSanitizer",
                "--split",
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert result.returncode == 77, result.stdout + result.stderr
    assert "AddressSanitizer" in result.stdout + result.stderr
