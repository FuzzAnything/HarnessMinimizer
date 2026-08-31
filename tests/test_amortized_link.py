import subprocess
import shutil
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


def _compile_static_archive_from_sources(
    tmp_path: Path,
    name: str,
    sources: dict[str, str],
) -> Path:
    object_files: list[Path] = []
    for source_name, source_text in sources.items():
        source = tmp_path / f"{name}_{source_name}.cpp"
        object_file = tmp_path / f"{name}_{source_name}.o"
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
        object_files.append(object_file)

    archive = tmp_path / f"lib{name}.a"
    subprocess.run(["ar", "rcs", str(archive), *map(str, object_files)], check=True)
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


def test_amortized_link_resolves_gnu_ld_script_to_loadable_elf(
    tmp_path: Path,
) -> None:
    source = tmp_path / "target.cpp"
    real_library = tmp_path / "libscripted_real.so.1"
    linker_script = tmp_path / "libscripted.so"
    source.write_text(
        'extern "C" int scripted_value() { return 7; }\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["clang++", "-shared", "-fPIC", str(source), "-o", str(real_library)],
        check=True,
    )
    linker_script.write_text(
        f"/* GNU ld script */\nGROUP ( {real_library} )\n",
        encoding="utf-8",
    )

    inputs = reducer_runner.resolve_amortized_link_inputs(
        f"-L{tmp_path} -lscripted -lpthread"
    )
    assert inputs.shared_libraries == (str(real_library.resolve()),)
    assert inputs.static_libraries == ()
    assert "-lpthread" in inputs.runner_link_flags


def test_amortized_link_demotes_unresolved_shared_link_flag_to_runner_flags(
    tmp_path: Path,
) -> None:
    source = tmp_path / "target.cpp"
    real_library = tmp_path / "libtarget.so"
    bad_linker_script = tmp_path / "libbroken.so"
    source.write_text(
        'extern "C" int target_value() { return 11; }\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["clang++", "-shared", "-fPIC", str(source), "-o", str(real_library)],
        check=True,
    )
    bad_linker_script.write_text(
        "/* GNU ld script */\nGROUP ( /does/not/exist/libbroken.so.1 )\n",
        encoding="utf-8",
    )

    inputs = reducer_runner.resolve_amortized_link_inputs(
        f"-L{tmp_path} -ltarget -lbroken -lpthread"
    )
    assert inputs.shared_libraries == (str(real_library.resolve()),)
    assert inputs.static_libraries == ()
    assert "-lbroken" in inputs.runner_link_flags
    assert "-lpthread" in inputs.runner_link_flags


def test_amortized_link_rejects_non_elf_shared_library_without_script_target(
    tmp_path: Path,
) -> None:
    fake_library = tmp_path / "libbroken.so"
    fake_library.write_text("not an elf and not a linker script\n", encoding="utf-8")

    with pytest.raises(ValueError, match="loadable ELF shared library"):
        reducer_runner.resolve_amortized_link_inputs(str(fake_library))


def test_runner_dynamic_dependency_flags_retain_dynamic_libraries() -> None:
    inputs = reducer_runner.AmortizedLinkInputs(
        shared_libraries=("/tmp/libtarget.so",),
        static_libraries=(),
        runner_link_flags=("-L/tmp/deps", "-ldep"),
    )

    assert reducer_runner.runner_dynamic_dependency_link_flags(inputs) == [
        "-Wl,--no-as-needed",
        "/tmp/libtarget.so",
        "-L/tmp/deps",
        "-ldep",
        "-Wl,--as-needed",
    ]


def test_runner_dependency_flags_do_not_wrap_static_only_dependencies() -> None:
    inputs = reducer_runner.AmortizedLinkInputs(
        shared_libraries=(),
        static_libraries=("/tmp/libtarget.a",),
        runner_link_flags=("-lm",),
    )

    assert reducer_runner.runner_dynamic_dependency_link_flags(inputs) == ["-lm"]


def test_amortized_runner_filters_unused_broken_dso_selected_by_as_needed(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-as-needed-filter"))
    broken_source = tmp_path / "broken.cpp"
    broken_library = tmp_path / "libbroken.so"
    used_source = tmp_path / "used.cpp"
    used_library = tmp_path / "libused.so"
    reference_source = tmp_path / "reference.cpp"
    reference_executable = tmp_path / "reference"

    broken_source.write_text(
        'extern "C" void missing_dependency();\n'
        'extern "C" void unused_entry() { missing_dependency(); }\n',
        encoding="utf-8",
    )
    used_source.write_text(
        'extern "C" int used_entry() { return 42; }\n',
        encoding="utf-8",
    )
    reference_source.write_text(
        'extern "C" int used_entry();\n'
        "int main() { return used_entry() == 42 ? 0 : 1; }\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            str(broken_source),
            "-Wl,--allow-shlib-undefined",
            "-o",
            str(broken_library),
        ],
        check=True,
    )
    subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            str(used_source),
            "-o",
            str(used_library),
        ],
        check=True,
    )
    link_flags = (
        f"-Wl,--as-needed {broken_library} {used_library} "
        "-Wl,--no-as-needed"
    )
    reference_link = subprocess.run(
        [
            "clang++",
            str(reference_source),
            "-Wl,--as-needed",
            str(broken_library),
            str(used_library),
            "-Wl,--no-as-needed",
            "-o",
            str(reference_executable),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert reference_link.returncode == 0, reference_link.stderr

    unfiltered = reducer_runner.resolve_amortized_link_inputs(link_flags)
    assert unfiltered.shared_libraries == (
        str(broken_library.resolve()),
        str(used_library.resolve()),
    )
    filtered = reducer_runner.filter_amortized_shared_libraries_for_reference(
        unfiltered,
        reference_executable,
    )
    assert filtered.shared_libraries == (str(used_library.resolve()),)

    with reducer_runner.start_amortized_runner(
        link_flags,
        None,
        None,
        symbolize=False,
        reference_executable=reference_executable,
    ) as runner:
        assert runner.shared_libraries == (str(used_library.resolve()),)


def test_reference_filter_does_not_change_static_archive_inputs() -> None:
    inputs = reducer_runner.AmortizedLinkInputs(
        shared_libraries=(),
        static_libraries=("/tmp/libtarget.a", "/tmp/libhelper.a"),
        runner_link_flags=("-Wl,--start-group", "-Wl,--end-group"),
        plugin_link_flags=("/tmp/libtarget.a", "/tmp/libhelper.a"),
    )

    assert (
        reducer_runner.filter_amortized_shared_libraries_for_reference(
            inputs,
            "/this/reference/does/not/need/to/exist",
        )
        is inputs
    )


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


def test_amortized_runner_replay_runtime_supports_fdp_candidates(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-fdp-replay"))
    target_source = tmp_path / "fdp_target.cpp"
    target_library = tmp_path / "libfdp_target_asan.so"
    harness_source = tmp_path / "fdp_harness.cpp"
    trace_path = tmp_path / "fdp_trace.log"
    trace_path.write_text("S 101 1\nS 202 7\n", encoding="utf-8")

    target_source.write_text(
        """
extern "C" __attribute__((noinline)) void replay_target_crash(int trigger) {
  if (!trigger) {
    return;
  }
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
#include "fuzzer/FuzzedDataProvider.h"
extern "C" void replay_target_crash(int);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  bool trigger = fdp.ConsumeBool(101);
  uint8_t selector = fdp.ConsumeIntegral<uint8_t>(202);
  if (trigger && selector == 7) {
    replay_target_crash(1);
  }
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


def test_amortized_runner_replay_runtime_supports_fdp_bytes_and_strings(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-fdp-bytes"))
    target_source = tmp_path / "fdp_bytes_target.cpp"
    target_library = tmp_path / "libfdp_bytes_target_asan.so"
    harness_source = tmp_path / "fdp_bytes_harness.cpp"
    trace_path = tmp_path / "fdp_trace.log"
    trace_path.write_text(
        "B 101 3 7 8 9\nB 202 2 111 107\nB 303 2 1 2\n",
        encoding="utf-8",
    )

    target_source.write_text(
        """
extern "C" __attribute__((noinline)) void replay_target_crash(int trigger) {
  if (!trigger) {
    return;
  }
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
#include <string>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"
extern "C" void replay_target_crash(int);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::vector<uint8_t> prefix = fdp.ConsumeBytes<uint8_t>(3, 101);
  std::string token = fdp.ConsumeRandomLengthString(16, 202);
  std::vector<uint8_t> suffix = fdp.ConsumeRemainingBytes<uint8_t>(303);
  bool matches = prefix.size() == 3 && prefix[0] == 7 && prefix[1] == 8 &&
                 prefix[2] == 9 && token == "ok" && suffix.size() == 2 &&
                 suffix[0] == 1 && suffix[1] == 2;
  if (matches) {
    replay_target_crash(1);
  }
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


def test_split_source_for_pch_moves_pre_include_directives_ahead_of_headers(
    tmp_path: Path,
) -> None:
    source = """/*
 * Top comment
 */
#define VPX_DISABLE_CTRL_TYPECHECKS 1
#include <stddef.h>
#include <stdint.h>
#include "demo.h"

#define MAX_WIDTH 1920
int value = MAX_WIDTH;
"""

    pch_prefix, restore_prefix, body = reducer_runner._split_source_for_pch(
        source,
        tmp_path,
    )

    assert "#define VPX_DISABLE_CTRL_TYPECHECKS 1" in pch_prefix
    assert pch_prefix.index("#define VPX_DISABLE_CTRL_TYPECHECKS 1") < pch_prefix.index(
        '#include "'
    )
    assert "#define VPX_DISABLE_CTRL_TYPECHECKS 1" not in body
    assert "#define MAX_WIDTH 1920" not in pch_prefix
    assert "#define MAX_WIDTH 1920" in body

    restored_path = tmp_path / "restored.cpp"
    restored_path.write_text(body, encoding="utf-8")
    reducer_runner.restore_pch_includes(
        str(restored_path),
        reducer_runner.PchArtifacts(
            body_source=str(restored_path),
            prefix_header="",
            pch_file="",
            restore_prefix=restore_prefix,
        ),
    )
    restored_source = restored_path.read_text(encoding="utf-8")
    assert restored_source.index("#define VPX_DISABLE_CTRL_TYPECHECKS 1") < restored_source.index(
        '#include "demo.h"'
    )


def test_split_source_for_pch_keeps_conditional_include_closers_with_prefix(
    tmp_path: Path,
) -> None:
    source = """#ifdef USE_DEMO
#include "demo.h"
#endif
#define AFTER_HEADERS 1
int value = AFTER_HEADERS;
"""

    pch_prefix, _, body = reducer_runner._split_source_for_pch(source, tmp_path)

    assert "#ifdef USE_DEMO" in pch_prefix
    assert '#include "' in pch_prefix
    assert "#endif" in pch_prefix
    assert "#define AFTER_HEADERS 1" not in pch_prefix
    assert "#define AFTER_HEADERS 1" in body


def test_amortized_static_runner_uses_rooted_archive_members(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-rooted-static"))
    target_archive = _compile_static_archive_from_sources(
        tmp_path,
        "rooted_static",
        {
            "entry": """
extern "C" void rooted_static_helper();
extern "C" void rooted_static_crash() { rooted_static_helper(); }
""",
            "helper": """
extern "C" __attribute__((noinline)) void rooted_static_helper() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
            "unused": """
extern "C" void missing_unrelated_dependency();
extern "C" void unused_static_feature() { missing_unrelated_dependency(); }
""",
        },
    )
    harness_source = tmp_path / "rooted_static_harness.cpp"
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void rooted_static_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  rooted_static_crash();
  return 0;
}
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "rooted_static_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")
    root_object = reducer_runner.compile_static_archive_root_object(
        reducer_runner.StaticArchiveRootConfig(source=str(harness_source))
    )
    plan = reducer_runner.plan_static_archive_runner_link(
        reducer_runner.resolve_amortized_link_inputs(str(target_archive)),
        root_object,
    )
    assert not plan.uses_whole_archive
    assert "-Wl,--whole-archive" not in plan.flags
    assert any(flag.endswith(",rooted_static_crash") for flag in plan.flags)

    with reducer_runner.start_amortized_runner(
        str(target_archive),
        None,
        str(trace_path),
        symbolize=False,
        static_root_config=reducer_runner.StaticArchiveRootConfig(
            source=str(harness_source),
        ),
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


def test_amortized_runner_links_hidden_static_symbols_in_candidate_plugin(
    tmp_path: Path,
) -> None:
    if shutil.which("llvm-objcopy") is None:
        pytest.skip("llvm-objcopy is required for static symbol visibility export")

    reducer_runner.configure_work_dir(str(tmp_path / "work-hidden-static"))
    target_source = tmp_path / "hidden_static.cpp"
    target_object = tmp_path / "hidden_static.o"
    target_archive = tmp_path / "libhidden_static.a"
    target_source.write_text(
        """
extern "C" __attribute__((visibility("hidden"), noinline))
void hidden_static_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "clang++",
            "-c",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(target_source),
            "-o",
            str(target_object),
        ],
        check=True,
    )
    subprocess.run(["ar", "rcs", str(target_archive), str(target_object)], check=True)

    harness_source = tmp_path / "hidden_harness.cpp"
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void hidden_static_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  hidden_static_crash();
  return 0;
}
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "hidden_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")
    link_flags = str(target_archive)

    inputs = reducer_runner.resolve_amortized_link_inputs(link_flags)
    assert inputs.static_libraries == (str(target_archive.resolve()),)
    assert inputs.plugin_link_flags == (str(target_archive),)
    root_object = reducer_runner.compile_static_archive_root_object(
        reducer_runner.StaticArchiveRootConfig(source=str(harness_source))
    )
    plan = reducer_runner.plan_static_archive_runner_link(
        inputs,
        root_object,
        export_dir=tmp_path / "hidden-static-exports",
    )
    assert not plan.uses_whole_archive
    assert plan.visibility_exported_symbol_count == 1
    assert len(plan.visibility_exported_libraries) == 1

    with reducer_runner.start_amortized_runner(
        link_flags,
        None,
        str(trace_path),
        symbolize=False,
        static_root_config=reducer_runner.StaticArchiveRootConfig(
            source=str(harness_source),
        ),
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
                "--amortized-plugin-fallback-link-flags=-lthis_fallback_must_not_be_used",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert result.returncode == 77, result.stdout + result.stderr
    assert "AddressSanitizer" in result.stdout + result.stderr


def test_amortized_runner_does_not_fallback_for_unused_hidden_static_symbols(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-unused-hidden-static"))
    target_source = tmp_path / "unused_hidden_static.cpp"
    target_object = tmp_path / "unused_hidden_static.o"
    target_archive = tmp_path / "libunused_hidden_static.a"
    target_source.write_text(
        """
extern "C" __attribute__((visibility("hidden")))
void unused_hidden_static_function() {}
extern "C" __attribute__((noinline))
void visible_static_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "clang++",
            "-c",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(target_source),
            "-o",
            str(target_object),
        ],
        check=True,
    )
    subprocess.run(["ar", "rcs", str(target_archive), str(target_object)], check=True)

    harness_source = tmp_path / "unused_hidden_harness.cpp"
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void visible_static_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  visible_static_crash();
  return 0;
}
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "unused_hidden_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")

    with reducer_runner.start_amortized_runner(
        str(target_archive),
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
                "--amortized-plugin-fallback-link-flags=-lthis_fallback_must_not_be_used",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert result.returncode == 77, result.stdout + result.stderr
    assert "AddressSanitizer" in result.stdout + result.stderr


def test_amortized_runner_retains_dynamic_dependency_for_unresolved_target_symbol(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work-dynamic-dependency"))
    dependency_source = tmp_path / "dynamic_dep.cpp"
    dependency_library = tmp_path / "libdynamic_dep.so"
    target_source = tmp_path / "dynamic_target.cpp"
    target_library = tmp_path / "libdynamic_target.so"
    harness_source = tmp_path / "dynamic_dependency_harness.cpp"
    reference_source = tmp_path / "dynamic_dependency_reference.cpp"
    reference_executable = tmp_path / "dynamic_dependency_reference"
    trace_path = tmp_path / "dynamic_dependency_fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")

    dependency_source.write_text(
        """
extern "C" __attribute__((noinline)) void dependency_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    target_source.write_text(
        """
extern "C" void dependency_crash();
extern "C" void dynamic_target_entry() { dependency_crash(); }
""",
        encoding="utf-8",
    )
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void dynamic_target_entry();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  dynamic_target_entry();
  return 0;
}
""",
        encoding="utf-8",
    )

    compile_dependency = subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(dependency_source),
            "-o",
            str(dependency_library),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert compile_dependency.returncode == 0, compile_dependency.stderr
    compile_target = subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(target_source),
            "-Wl,--allow-shlib-undefined",
            "-o",
            str(target_library),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert compile_target.returncode == 0, compile_target.stderr

    reference_source.write_text(
        'extern "C" void dynamic_target_entry();\n'
        "int main() { dynamic_target_entry(); return 0; }\n",
        encoding="utf-8",
    )
    compile_reference = subprocess.run(
        [
            "clang++",
            "-fsanitize=address,undefined",
            str(reference_source),
            "-Wl,--as-needed",
            str(target_library),
            str(dependency_library),
            "-Wl,--no-as-needed",
            "-o",
            str(reference_executable),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert compile_reference.returncode == 0, compile_reference.stderr

    link_flags = f"-L{tmp_path} -ldynamic_target -ldynamic_dep"
    inputs = reducer_runner.resolve_amortized_link_inputs(link_flags)
    assert inputs.shared_libraries == (
        str(target_library.resolve()),
        str(dependency_library.resolve()),
    )
    assert reducer_runner.runner_dynamic_dependency_link_flags(inputs) == [
        "-Wl,--no-as-needed",
        str(target_library.resolve()),
        str(dependency_library.resolve()),
        f"-L{tmp_path.resolve()}",
        "-Wl,--as-needed",
    ]

    with reducer_runner.start_amortized_runner(
        link_flags,
        None,
        str(trace_path),
        symbolize=False,
        reference_executable=reference_executable,
    ) as runner:
        assert runner.shared_libraries == (
            str(target_library.resolve()),
            str(dependency_library.resolve()),
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
