"""Native link checks for selective archives in mixed shared/static runners."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from harnessminimizer import reducer_runner as rr


@pytest.fixture(params=["default", "lld"])
def linker_flags(request: pytest.FixtureRequest) -> tuple[str, ...]:
    if request.param == "lld":
        for directory in os.get_exec_path():
            linker = shutil.which("ld.lld", path=directory)
            if linker and subprocess.run(
                [linker, "--version"], capture_output=True, timeout=10,
            ).returncode == 0:
                return (f"-fuse-ld={linker}",)
        pytest.skip("a runnable ld.lld is required for the LLD link checks")
    return ()


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, **kwargs)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def _compile(directory: Path, name: str, source: str, *flags: str) -> Path:
    source_path = directory / f"{name}.cpp"
    output = directory / name
    source_path.write_text(source, encoding="utf-8")
    _run(["clang++", str(source_path), *flags, "-o", str(output)])
    return output


def _archive(directory: Path, name: str, **sources: str) -> Path:
    objects = [
        _compile(directory, f"{name}_{member}.o", source, "-c", "-fPIC",
                 "-fsanitize=address,undefined", "-O1", "-gline-tables-only")
        for member, source in sources.items()
    ]
    archive = directory / f"lib{name}.a"
    _run(["ar", "rcs", str(archive), *map(str, objects)])
    return archive


@pytest.mark.parametrize("direct_dependency_call", [False, True])
@pytest.mark.parametrize("needs_static_helper", [False, True])
def test_mixed_runner_keeps_dso_crash_site_and_required_static_helpers(
    tmp_path: Path, direct_dependency_call: bool, needs_static_helper: bool,
    linker_flags: tuple[str, ...],
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    rr.reset_stack_trace_state()
    # The DSO already contains dependency_crash. The same archive is also
    # listed by the caller, just as libalembic.so and libhdf5.a are in Alembic.
    dependency = _archive(tmp_path, "dependency", crash='''
extern "C" __attribute__((noinline)) void dependency_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
''')
    target_code = 'extern "C" void dependency_crash();\n'
    if needs_static_helper:
        target_code += 'extern "C" int required_static_helper();\n'
    target_code += 'extern "C" void target_entry() {\n'
    if needs_static_helper:
        target_code += '  if (required_static_helper() != 42) return;\n'
    target_code += '  dependency_crash();\n}\n'
    target = _compile(
        tmp_path, "libtarget.so", target_code, "-shared", "-fPIC",
        "-fsanitize=address,undefined", "-O1", "-gline-tables-only",
        str(dependency),
    )
    # An unrelated member must never be selected. A real static helper, when
    # requested only by the DSO, must be kept despite the empty harness roots.
    extra = _archive(tmp_path, "extras", helper='''
extern "C" int required_static_helper() { return 42; }
''', unused='''
extern "C" void unavailable_unrelated_feature();
extern "C" void unused_feature() { unavailable_unrelated_feature(); }
''')
    harness = tmp_path / "harness.cpp"
    entrypoint = "dependency_crash" if direct_dependency_call else "target_entry"
    harness.write_text(f'''#include <cstddef>
#include <cstdint>
extern "C" void {entrypoint}();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {{
  {entrypoint}();
  return 0;
}}
''', encoding="utf-8")
    link_flags = " ".join((*linker_flags, "-Wl,--as-needed", str(target),
                           "-Wl,--no-as-needed", str(dependency), str(extra)))
    reference = tmp_path / "reference"
    _run(rr.reference_harness_compile_command(str(harness), None, link_flags, str(reference)))
    env = rr.runtime_library_env(link_flags, symbolize=False)
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0:detect_leaks=0"
    env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1:print_stacktrace=1"
    result = subprocess.run([str(reference), "-runs=1"], env=env, capture_output=True,
                            text=True, timeout=15, cwd=tmp_path)
    assert result.returncode == 77, result.stdout + result.stderr
    site = rr.extract_first_dynamic_library_crash_site(result.stdout + result.stderr, link_flags)
    assert site is not None
    assert Path(site.library_path) == target
    rr.set_dynamic_reference_crash_site(site)
    try:
        with rr.start_amortized_runner(
            link_flags, None, None, symbolize=False,
            static_root_config=rr.StaticArchiveRootConfig(source=str(harness)),
            reference_executable=reference,
        ) as runner:
            symbols = _run(["nm", "-D", "--defined-only", str(tmp_path / "work/harness_runner")]).stdout
            assert not any(line.split()[-1] == "dependency_crash" for line in symbols.splitlines())
            has_helper = any(line.split()[-1] == "required_static_helper" for line in symbols.splitlines())
            assert has_helper == needs_static_helper
            # Fail immediately if the candidate needs a full dependency relink.
            output = rr.run_amortized_reference_candidate(
                str(harness), None, "AddressSanitizer", None, link_flags, None,
                "split", runner.socket_path, None, ("-lthis_fallback_must_not_be_used",),
                symbolize=False,
            )
            actual = rr.extract_first_dynamic_library_crash_site(
                output, link_flags, expected_library=site.library_path,
            )
            assert actual is not None and actual.offset == site.offset
    finally:
        rr.reset_stack_trace_state()


@pytest.mark.parametrize("static_first", [False, True])
def test_rooted_mixed_link_keeps_reference_provider_order(
    tmp_path: Path, static_first: bool, linker_flags: tuple[str, ...],
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    shared = _compile(tmp_path, "libchoice.so", 'extern "C" int choice() { return 42; }',
                      "-shared", "-fPIC")
    archive = _archive(tmp_path, "choice", value='extern "C" int choice() { return 7; }')
    libraries = [archive, shared] if static_first else [shared, archive]
    flags = " ".join((*linker_flags, "-Wl,--as-needed", *map(str, libraries)))
    source = 'extern "C" int choice(); int main() { return choice(); }'
    root = _compile(tmp_path, "root.o", source, "-c")
    reference = _compile(tmp_path, "reference", source, *flags.split(),
                         "-fsanitize=address,undefined")
    inputs = rr.resolve_amortized_link_inputs(flags)
    inputs = rr.filter_amortized_shared_libraries_for_reference(inputs, reference)
    tail = rr.amortized_runner_link_tail(inputs, root)
    # The real persistent runner has no direct call to choice(). Its only root
    # comes from the harness-object analysis, and the plugin resolves via ELF.
    runner = _compile(tmp_path, "runner", '''#include <dlfcn.h>
int main() {
  auto choice = reinterpret_cast<int (*)()>(dlsym(RTLD_DEFAULT, "choice"));
  return choice ? choice() : 99;
}
''', *tail, "-ldl", "-fsanitize=address,undefined")
    expected = 7 if static_first else 42
    for binary in (reference, runner):
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
        assert result.returncode == expected, result.stdout + result.stderr


def test_rooted_static_link_preserves_circular_archive_group(
    tmp_path: Path, linker_flags: tuple[str, ...],
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    first = _archive(tmp_path, "first", entry='''
extern "C" int middle();
extern "C" int entry() { return middle(); }
''', last='extern "C" int last() { return 42; }')
    second = _archive(tmp_path, "second", middle='''
extern "C" int last();
extern "C" int middle() { return last(); }
''')
    flags = " ".join((*linker_flags, "-Wl,--start-group", str(first), str(second),
                       "-Wl,--end-group"))
    source = 'extern "C" int entry(); int main() { return entry() == 42 ? 0 : 1; }'
    root = _compile(tmp_path, "root.o", source, "-c")
    inputs = rr.resolve_amortized_link_inputs(flags)
    tail = rr.amortized_runner_link_tail(inputs, root)
    binary = _compile(tmp_path, "runner", '''#include <dlfcn.h>
int main() {
  auto entry = reinterpret_cast<int (*)()>(dlsym(RTLD_DEFAULT, "entry"));
  return entry && entry() == 42 ? 0 : 1;
}
''', *tail, "-ldl", "-fsanitize=address,undefined")
    _run([str(binary)])


@pytest.mark.parametrize("whole_archive", [False, True])
def test_explicit_whole_archive_keeps_registration_initializers(
    tmp_path: Path, whole_archive: bool, linker_flags: tuple[str, ...],
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    archive = _archive(tmp_path, "registration", registration='''
extern "C" int registered;
__attribute__((constructor)) static void register_feature() { registered = 42; }
''')
    scope = ("-Wl,--whole-archive", str(archive), "-Wl,--no-whole-archive") if whole_archive else (str(archive),)
    flags = " ".join((*linker_flags, *scope))
    source = 'extern "C" { int registered = 0; } int main() { return registered; }'
    root = _compile(tmp_path, "root.o", source, "-c")
    reference = _compile(tmp_path, "reference", source, *flags.split(),
                         "-fsanitize=address,undefined")
    inputs = rr.resolve_amortized_link_inputs(flags)
    tail = rr.amortized_runner_link_tail(inputs, root)
    runner = _compile(tmp_path, "runner", source, *tail, "-fsanitize=address,undefined")
    for binary in (reference, runner):
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
        assert result.returncode == (42 if whole_archive else 0), result.stdout + result.stderr
