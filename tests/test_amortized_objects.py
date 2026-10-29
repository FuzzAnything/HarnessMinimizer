"""Fixed object operands belong to the runner, never to candidate plugins."""
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from harnessminimizer import reducer_runner as rr


def compile_file(directory: Path, name: str, source: str, *flags: str) -> Path:
    cpp = directory / (name + ".cpp")
    output = directory / name
    cpp.write_text(source)
    subprocess.run(
        ["clang++", str(cpp), *flags, "-o", str(output)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return output


@pytest.mark.parametrize("spelling", ["relative", "absolute", "named", "separate"])
def test_object_paths_resolve_and_stay_out_of_plugin_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str,
) -> None:
    obj = compile_file(tmp_path, "helper.o", 'extern "C" int helper() { return 1; }', "-c")
    archive = tmp_path / "libtarget.a"
    subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True, timeout=30)
    monkeypatch.chdir(tmp_path)
    flags = {
        "relative": "helper.o",
        "absolute": str(obj),
        "named": f"-L{tmp_path} -l:helper.o",
        "separate": f"-L{tmp_path} -l :helper.o",
    }[spelling]
    inputs = rr.resolve_amortized_link_inputs(f"{flags} -Wl,--start-group {archive} -Wl,--end-group")
    assert inputs.object_files == (str(obj),)
    assert inputs.ordered_link_flags.count(str(obj)) == 1
    assert not any("helper.o" in flag for flag in inputs.plugin_link_flags)
    assert str(archive) in inputs.plugin_link_flags


@pytest.mark.parametrize("data", [b"", b"BC\xc0\xdebitcode", b"# libtool object file\n", b"\x7fELF" + bytes(32)])
def test_non_relocatable_objects_fail_with_actionable_diagnostic(tmp_path: Path, data: bytes) -> None:
    obj = tmp_path / "invalid.o"
    obj.write_bytes(data)
    with pytest.raises(ValueError, match="ELF relocatable object"):
        rr.resolve_amortized_link_inputs(str(obj))


def test_missing_object_reports_its_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Could not read object file.*missing.o"):
        rr.resolve_amortized_link_inputs(str(tmp_path / "missing.o"))


@pytest.mark.parametrize("kind", ["shared", "static", "object-only"])
@pytest.mark.parametrize("pic", [False, True])
def test_runner_reuses_fixed_objects_and_initializers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, pic: bool,
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    rr.reset_stack_trace_state()
    marker = tmp_path / "initializations"
    monkeypatch.setenv("HM_FIXED_OBJECT_TEST_MARKER", str(marker))
    obj = compile_file(tmp_path, "helper.o", r'''
#include <cstdio>
#include <cstdlib>
static int state;
__attribute__((constructor)) static void initialize() {
  state = 41;
  FILE *file = std::fopen(std::getenv("HM_FIXED_OBJECT_TEST_MARKER"), "a");
  if (file) { std::fputs("initialized\n", file); std::fclose(file); }
}
extern "C" int fixed_helper() { return ++state; }
''', "-c", *(["-fPIC"] if pic else ["-fno-pic", "-fno-pie"]))
    original_digest = hashlib.sha256(obj.read_bytes()).hexdigest()
    target_source = r'''
extern "C" int fixed_helper();
extern "C" __attribute__((noinline)) void target_crash() {
  if (fixed_helper() != 42) return;
  volatile int *p = new int[1];
  p[4] = 7;
}
'''
    if kind == "shared":
        library = compile_file(tmp_path, "libtarget.so", target_source,
                               "-shared", "-fPIC", "-fsanitize=address,undefined")
        link_flags = f"-Wl,--as-needed {library} -Wl,--no-as-needed {obj}"
    elif kind == "static":
        target = compile_file(tmp_path, "target.o", target_source,
                              "-c", "-fsanitize=address,undefined")
        library = tmp_path / "libtarget.a"
        subprocess.run(["ar", "rcs", str(library), str(target)], check=True, timeout=30)
        link_flags = f"-Wl,--start-group {library} {obj} -Wl,--end-group"
    else:
        # A fixed object can itself be the target; no artificial archive is needed.
        library = compile_file(tmp_path, "target.o", target_source,
                               "-c", "-fsanitize=address,undefined")
        link_flags = f"{library} {obj}"
    harness = tmp_path / "harness.cpp"
    harness.write_text('''#include <cstddef>
#include <cstdint>
extern "C" void target_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) { target_crash(); return 0; }
''')
    commands = []
    original_run = rr.run_command

    def record(command, *args, **kwargs):
        commands.append(command)
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(rr, "run_command", record)
    with rr.start_amortized_runner(
        link_flags, None, None, symbolize=False,
        static_root_config=rr.StaticArchiveRootConfig(source=str(harness)),
    ) as runner:
        for _ in range(3):
            rr.run_amortized_reference_candidate(
                str(harness), None, "AddressSanitizer", None, link_flags, None,
                "split", runner.socket_path, None, runner.plugin_link_flags,
                symbolize=False,
            )
        assert runner.process.poll() is None
    assert marker.read_text().splitlines() == ["initialized"]
    assert hashlib.sha256(obj.read_bytes()).hexdigest() == original_digest
    runner_links = [command for command in commands if "-ldl" in command]
    assert len(runner_links) == 1
    # Even a plugin fallback must resolve the fixed helper through the runner.
    assert not any("helper.o" in flag for flag in runner.plugin_link_flags)


def test_hidden_object_symbols_are_exported_from_copies(tmp_path: Path) -> None:
    if shutil.which("llvm-objcopy") is None:
        pytest.skip("llvm-objcopy is required for visibility export")
    rr.configure_work_dir(str(tmp_path / "work"))
    obj = compile_file(tmp_path, "hidden.o",
                       'extern "C" __attribute__((visibility("hidden"))) int fixed_helper() { return 42; }',
                       "-c", "-fPIC")
    original = obj.read_bytes()
    inputs = rr.resolve_amortized_link_inputs(str(obj))
    flags = rr.amortized_runner_link_tail(inputs)
    exported = next(Path(flag) for flag in flags if flag.endswith(".o"))
    assert exported != obj
    symbols = subprocess.run(["readelf", "-sW", str(exported)], check=True,
                             capture_output=True, text=True, timeout=30).stdout
    assert any("DEFAULT" in line and "fixed_helper" in line for line in symbols.splitlines())
    assert obj.read_bytes() == original


@pytest.mark.parametrize("needs_dependency", [False, True])
def test_object_dependencies_root_archives_without_duplicate_definitions(
    tmp_path: Path, needs_dependency: bool,
) -> None:
    rr.configure_work_dir(str(tmp_path / "work"))
    value = "dependency()" if needs_dependency else "42"
    obj = compile_file(tmp_path, "helper.o",
                       'extern "C" int dependency();\n'
                       f'extern "C" int fixed_helper() {{ return {value}; }}', "-c")
    dependency = compile_file(tmp_path, "dependency.o", 'extern "C" int dependency() { return 42; }', "-c")
    duplicate = compile_file(tmp_path, "unused.o", 'extern "C" int fixed_helper() { return -1; }', "-c")
    archive = tmp_path / "libtarget.a"
    subprocess.run(["ar", "rcs", str(archive), str(dependency), str(duplicate)], check=True, timeout=30)
    root = compile_file(tmp_path, "root.o", 'extern "C" int fixed_helper(); int test() { return fixed_helper(); }', "-c")
    inputs = rr.resolve_amortized_link_inputs(f"{obj} -Wl,--start-group {archive} -Wl,--end-group")
    plan = rr.plan_static_archive_runner_link(inputs, root)
    assert plan.root_symbols == (("dependency",) if needs_dependency else ())
    assert not plan.uses_whole_archive
    tail = rr.amortized_runner_link_tail(inputs, root)
    main = 'extern "C" int fixed_helper(); int main() { return fixed_helper() == 42 ? 0 : 1; }'
    binary = compile_file(tmp_path, "reference", main, *tail)
    subprocess.run([str(binary)], check=True, timeout=30)


def test_repeated_objects_are_not_silently_deduplicated(tmp_path: Path) -> None:
    obj = compile_file(tmp_path, "helper.o", 'extern "C" int helper() { return 1; }', "-c")
    inputs = rr.resolve_amortized_link_inputs(f"{obj} {obj}")
    assert inputs.object_files == (str(obj), str(obj))
    assert inputs.ordered_link_flags == (str(obj), str(obj))
