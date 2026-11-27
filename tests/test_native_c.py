"""Native C regressions: real compiler, PCH, plugins, export and recovery."""

from argparse import Namespace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from harnessminimizer import api, reducer_runner as runner
from harnessminimizer.api import PostReductionOutcome
from harnessminimizer.cli import main as cli_main
from harnessminimizer.initializer_analysis import analyze_uninitialized
from harnessminimizer.initializer_recovery import reduce_with_initializer_recovery
from harnessminimizer.initializer_protection import (
    prepare_initializer_protection, preparation_compile_flags, verify_preparation,
)
from harnessminimizer.process_supervisor import run_supervised, runner_request, treereduce_binary
from harnessminimizer.reduction_engines import (
    PersesRuntime, absolute_checker_paths, perses_flags, prepare_reducer_invocation,
    write_perses_test_script,
)
from harnessminimizer.source_language import C
from tests import crash_tester


HARNESS = '''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#ifdef __cplusplus
#error Must compile as C
#endif
void target(unsigned char);
static int initialized;
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    initialized = 1;
    fprintf(stderr, "C_INITIALIZED\\n");
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *restrict data, size_t size) {
    int unused = 0;
    if (initialized && size) target(_Generic(data[0], unsigned char: data[0]));
    return 0;
}
'''


def compile_command(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return result


@pytest.fixture
def c_case(tmp_path, monkeypatch):
    for name in ('clang', 'clang++', 'ar'):
        if not shutil.which(name):
            pytest.skip(f'{name} is required')
    monkeypatch.setenv('PATH', str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'])
    monkeypatch.setenv('DEBUGINFOD_URLS', '')
    monkeypatch.setattr(runner, 'TREEDUCER_DIR', None)
    monkeypatch.setattr(runner, '_IS_USER_WORK_DIR', False)
    runner.configure_work_dir(str(tmp_path / 'work'))
    runner.reset_stack_trace_state()
    source = tmp_path / 'target.c'
    source.write_text('void target(unsigned char value) { if (value == 120) { volatile int zero = 0; volatile int out = 7 / zero; (void)out; } }\n')
    library = tmp_path / 'libtarget.so'
    compile_command(['clang', '-shared', '-fPIC', '-g', '-O0', '-fsanitize=address,undefined', str(source), '-o', str(library)])
    obj = tmp_path / 'target.o'
    compile_command(['clang', '-fPIC', '-g', '-O0', '-fsanitize=address,undefined', '-c', str(source), '-o', str(obj)])
    archive = tmp_path / 'libtarget.a'
    compile_command(['ar', 'rcs', str(archive), str(obj)])
    harness = tmp_path / 'harness.c'
    harness.write_text(HARNESS)
    seed = tmp_path / 'seed'
    seed.write_bytes(b'xy')
    return Namespace(root=tmp_path, harness=harness, library=library, archive=archive, obj=obj, seed=seed)


@pytest.mark.parametrize('mode,amortize', [
    ('direct', False), ('split', False), ('pch', False), ('split', True), ('pch', True),
])
@pytest.mark.parametrize('target', ['library', 'archive', 'obj'])
def test_native_c_compile_modes(c_case, mode, amortize, target):
    case = c_case
    link_flags = str(getattr(case, target))
    runner.check_harness_compilation(str(case.harness), '-std=c11', link_flags)
    expected = runner._run_harness_for_crash_reference(str(case.root / 'work/poc.out'), str(case.seed), symbolize=False)
    assert expected.returncode == 77
    assert expected.stderr.count('C_INITIALIZED\n') == 1
    artifacts = None
    source = str(case.harness)
    if mode == 'pch':
        artifacts = runner.prepare_phase3_pch_harness(source, '-std=c11', False, amortize_link=amortize)
        source = artifacts.body_source
        assert source.endswith('.c')
    args = Namespace(
        source=source, compile_flags='-std=c11', link_flags=link_flags, fdp_trace=None,
        pch=mode == 'pch', pch_path=artifacts.pch_file if artifacts else None,
        pch_amortized_link=amortize, profile_file=None, auto_var_init_pattern=False,
        amortized_runner_socket=None,
    )
    output = str(case.root / 'candidate')
    if amortize:
        roots = runner.StaticArchiveRootConfig(source, '-std=c11', artifacts.pch_file if artifacts else None, False)
        with runner.start_amortized_runner(
            link_flags, str(case.seed), None, symbolize=False,
            static_root_config=roots, reference_executable=case.root / 'work/poc.out',
        ) as active:
            args.amortized_runner_socket = active.socket_path
            status, obj = crash_tester.compile_amortized_plugin(args, output)
            assert status == 0
            try:
                for _ in range(2):
                    header, log = runner_request(active.socket_path, output, timeout=10)
                    assert int(header[0]) == 77, log.decode(errors='replace')
                    assert b'division by zero' in log
                    assert log.count(b'C_INITIALIZED\n') == 1
            finally:
                Path(obj).unlink(missing_ok=True)
    else:
        build = {'direct': crash_tester.compile_direct, 'split': crash_tester.compile_split, 'pch': crash_tester.compile_with_pch}[mode]
        status, obj = build(args, output)
        try:
            assert status == 0
            actual = runner._run_harness_for_crash_reference(output, str(case.seed), symbolize=False)
            assert actual.returncode == 77
            assert 'division by zero' in actual.stderr
        finally:
            if obj:
                Path(obj).unlink(missing_ok=True)


def install_deterministic_reducer(case, monkeypatch, *, stall=False, damage=False):
    """Execute the real checker, then finish or stall to test budget recovery."""
    driver = case.root / 'test-reducer'
    driver.write_text(f'#!{sys.executable}\n' + f'''
import pathlib, subprocess, sys, time
args = sys.argv[1:]
if '--help' in args: raise SystemExit(0)
source = pathlib.Path(args[args.index('-s') + 1])
candidate = source.with_name('accepted.c')
candidate.write_text(source.read_text().replace('int unused = 0;', ''))
checker = [str(candidate) if a == '@@.c' else a for a in args[args.index('--') + 1:]]
result = subprocess.run(checker)
if result.returncode != 77: raise SystemExit(1)
if {stall!r}: time.sleep(60)
text = candidate.read_text()
if {damage!r}: text = text.replace('target(_Generic(data[0], unsigned char: data[0]))', '(void)0')
pathlib.Path(args[args.index('-o') + 1]).write_text(text)
''')
    driver.chmod(0o700)
    monkeypatch.setenv('HARNESSMINIMIZER_TREEREDUCE', str(driver))


def assert_portable_c_export(case, result):
    assert result.success
    assert result.reduced_harness.endswith('.c')
    assert result.fdp_trace is None
    assert result.generated_headers
    destination = case.root / 'published'
    destination.mkdir()
    source = destination / 'poc.c'
    shutil.copy2(result.reduced_harness, source)
    for header in result.generated_headers:
        shutil.copy2(header, destination / Path(header).name)
    text = source.read_text()
    assert 'int unused' not in text
    assert 'FDP_ID' not in text
    assert '<vector>' not in text
    exe = destination / 'poc'
    compile_command(['clang', '-std=c11', '-fsanitize=address,fuzzer,undefined', '-g', '-O0', str(source), str(case.library), '-o', str(exe)])
    # The generated header, not the supplied runtime bytes, drives this replay.
    different_input = destination / 'different-input'
    different_input.write_bytes(b'zz')
    replay = runner._run_harness_for_crash_reference(str(exe), str(different_input), symbolize=False)
    assert replay.returncode == 77
    assert 'division by zero' in replay.stderr


@pytest.mark.parametrize('mode,amortize,symbolize', [
    ('direct', False, False), ('split', False, True), ('pch', False, True),
    ('split', True, False), ('pch', True, True),
])
def test_native_c_full_pipeline(c_case, monkeypatch, mode, amortize, symbolize):
    install_deterministic_reducer(c_case, monkeypatch)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(c_case.harness), compile_flags='-std=c11',
        link_flags=str(c_case.library), crash_input=str(c_case.seed),
        work_dir=str(c_case.root / 'work'), compilation_mode=mode,
        amortize_link=amortize, symbolize=symbolize, profile=True, debug=True,
    ))
    assert_portable_c_export(c_case, result)
    assert (c_case.root / 'work/reduction_profile.json').is_file()
    if symbolize:
        assert runner.SYMBOLIZED_TRACE_REQUIRED
        assert runner.SYMBOLIZED_TRACE_REFERENCE is not None


@pytest.mark.parametrize('snapshot', [False, True])
def test_native_c_timeout_exports_portable_checkpoint(c_case, monkeypatch, snapshot):
    install_deterministic_reducer(c_case, monkeypatch, stall=True)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(c_case.harness), compile_flags='-std=c11',
        link_flags=str(c_case.library), crash_input=str(c_case.seed),
        work_dir=str(c_case.root / 'work'), compilation_mode='pch',
        amortize_link=True, snapshot=snapshot, reduction_timeout_seconds=5,
    ))
    assert_portable_c_export(c_case, result)
    assert (c_case.root / 'work/last_interesting.c').read_text() == Path(result.reduced_harness).read_text()
    assert not (c_case.root / 'work/last_interesting.cpp').exists()


@pytest.mark.parametrize('snapshot', [False, True])
def test_native_c_failed_final_validation_and_snapshot_retry(c_case, monkeypatch, snapshot):
    install_deterministic_reducer(c_case, monkeypatch, damage=True)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(c_case.harness), compile_flags='-std=c11',
        link_flags=str(c_case.library), crash_input=str(c_case.seed),
        work_dir=str(c_case.root / 'work'), compilation_mode='pch', snapshot=snapshot,
    ))
    assert result.success is snapshot
    if snapshot:
        assert_portable_c_export(c_case, result)


def test_c_coverage_calls_initializer_and_flushes_crash_profile(c_case):
    binary = runner.compile_coverage_harness(str(c_case.harness), '-std=c11', str(c_case.library))
    coverage = runner.collect_harness_coverage(binary, str(c_case.harness), str(c_case.seed), str(c_case.library))
    assert coverage.covered_lines
    assert 10 in coverage.covered_lines  # initializer executes before the callback
    assert (c_case.root / 'work/coverage.profdata').is_file()


def test_c_initializer_protection_preprocessing_and_diagnosis(c_case):
    original = c_case.root / 'initialized.c'
    original.write_text(
        'typedef struct { int x; } Point;\n'
        'int f(int *restrict pointer) {\n'
        '  int value = _Generic(*pointer, int: 3);\n'
        '  Point point = (Point){.x = 4};\n'
        '  _Atomic int count = 5;\n'
        '  return value + point.x + count;\n}\n'
    )
    protection = prepare_initializer_protection(original, c_case.root / 'protected')
    assert protection.source.suffix == '.c'
    assert protection.declarations
    with preparation_compile_flags('-std=c11', original, protection.source.parent) as flags:
        verify_preparation(protection, flags, replay=False, plugin=True)
    restored = protection.restore(protection.source.read_text())
    assert restored == original.read_text()
    invalid = c_case.root / 'uninitialized.c'
    invalid.write_text('int f(int *restrict p) { int value; return value + _Generic(*p, int: 0); }\n')
    diagnosis = analyze_uninitialized(str(invalid), c_case.root / 'diagnosis', '-std=c11')
    assert diagnosis.status == 'uninitialized-use'


@pytest.mark.parametrize('tool', ['perses', 'wdd', 'cdd'])
def test_c_perses_adapter_tests_each_candidate(tmp_path, monkeypatch, tool):
    source = tmp_path / 'harness.c'
    source.write_text('int original;\n')
    runtime = PersesRuntime(('java', '-jar', 'test.jar'), 'digest', 'test', 'java', None)
    monkeypatch.setattr('harnessminimizer.reduction_engines.check_perses', lambda: runtime)
    checker = tmp_path / 'check.py'
    checker.write_text('import pathlib,sys\nsys.exit(77 if pathlib.Path(sys.argv[1]).read_text() == "accepted" else 1)\n')
    invocation = prepare_reducer_invocation(
        source=str(source), output=str(tmp_path / 'reduced.c'),
        checker_command=[sys.executable, str(checker), '@@.c'], stable=False, jobs=1, tool=tool,
    )
    assert invocation.command[invocation.command.index('--lang') + 1] == 'c'
    assert invocation.result.name == 'candidate.c'
    script = invocation.cwd / 'interesting.sh'
    for text, status in [('accepted', 0), ('rejected', 1)]:
        (invocation.cwd / 'candidate.c').write_text(text)
        result = subprocess.run([str(script)], cwd=invocation.cwd, capture_output=True)
        assert result.returncode == status, result.stderr
    assert source.read_text() == 'int original;\n'


def test_native_c_optional_slice_pipeline(c_case, monkeypatch):
    install_deterministic_reducer(c_case, monkeypatch)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(c_case.harness), compile_flags='-std=c11',
        link_flags=str(c_case.library), crash_input=str(c_case.seed),
        work_dir=str(c_case.root / 'work'), compilation_mode='pch',
        amortize_link=True, slice_enabled=True, symbolize=False,
    ))
    assert_portable_c_export(c_case, result)
    assert (c_case.root / 'work/coverage.profdata').is_file()


def test_native_c_pattern_initialized_candidates(c_case, monkeypatch):
    install_deterministic_reducer(c_case, monkeypatch)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(c_case.harness), compile_flags='-std=c11',
        link_flags=str(c_case.library), crash_input=str(c_case.seed),
        work_dir=str(c_case.root / 'work'), compilation_mode='pch',
        amortize_link=True, auto_var_init_pattern=True, symbolize=False,
    ))
    assert_portable_c_export(c_case, result)


def test_native_c_initializer_recovery_retries_with_c_source(c_case):
    tagged = c_case.root / 'tagged.c'
    tagged.write_text(
        '#ifdef __cplusplus\n#error Must compile as C\n#endif\n'
        'int f(int *restrict p) { int value = 7; return value + _Generic(*p, int: 0); }\n'
    )
    calls = []

    def attempt(source, flags, protection=None):
        calls.append((source, protection))
        destination = Path(runner.get_work_dir()) / 'reduced.c'
        if protection is None:
            destination.write_text(tagged.read_text().replace('int value = 7;', 'int value;'))
            return PostReductionOutcome(str(destination), validated=False, stage='direct-input')
        assert source.endswith('.c')
        restored = protection.restore(Path(source).read_text())
        assert restored == tagged.read_text()
        compile_command(['clang', *runner._split_flags(flags), '-c', source,
                         '-o', str(destination.with_suffix('.o'))])
        destination.write_text(restored)
        return PostReductionOutcome(str(destination), validated=True)

    outcome = reduce_with_initializer_recovery(
        attempt, str(tagged), '-std=c11', replay=False, plugin=True,
        profile=False, jobs=2,
    )
    assert outcome.validated
    assert len(calls) == 2
    assert calls[1][1].source.suffix == '.c'
    metadata = json.loads((c_case.root / 'work/initializer_recovery.json').read_text())
    assert metadata['status'] == 'recovered' and metadata['attempt_count'] == 2


def test_native_c_cli_stages_portable_header(c_case, monkeypatch):
    install_deterministic_reducer(c_case, monkeypatch)
    destination = c_case.root / 'published' / 'reduced.c'
    assert cli_main([
        str(c_case.harness), '--compile-flags=-std=c11',
        '--link-flags=' + str(c_case.library), '--crash-input', str(c_case.seed),
        '--work-dir', str(c_case.root / 'work'), '--split', '--no-symbolize',
        '-o', str(destination),
    ]) == 0
    assert destination.is_file()
    assert (destination.parent / 'harness_values.h').is_file()
    compile_command([
        'clang', '-std=c11', '-fsanitize=address,fuzzer,undefined',
        str(destination), str(c_case.library), '-o', str(destination.parent / 'replay'),
    ])


def test_real_tree_reducer_parses_native_c(tmp_path):
    if not shutil.which(treereduce_binary()):
        pytest.skip('The pinned treereduce-c executable is unavailable')
    source = tmp_path / 'original.c'
    source.write_text(
        '#ifdef __cplusplus\n#error Must compile as C\n#endif\n'
        'int value(const int *restrict p) { return _Generic(*p, int: 7); }\n'
        'int main(void) { int number = 1; return value(&number); }\n'
    )
    checker = tmp_path / 'checker.py'
    checker.write_text(
        f'#!{sys.executable}\n'
        'import pathlib, subprocess, sys, tempfile\n'
        'with tempfile.TemporaryDirectory() as temporary:\n'
        '  binary = pathlib.Path(temporary) / "candidate"\n'
        '  build = subprocess.run(["clang", "-std=c11", sys.argv[1], "-o", str(binary)], '
        'capture_output=True)\n'
        '  if build.returncode: sys.exit(1)\n'
        '  result = subprocess.run([str(binary)])\n'
        '  sys.exit(77 if result.returncode == 7 else 1)\n'
    )
    checker.chmod(0o700)
    invocation = prepare_reducer_invocation(
        source=str(source), output=str(tmp_path / 'reduced.c'),
        checker_command=[str(checker), '@@.c'], stable=False, jobs=2,
    )
    completed = invocation.run(lambda cmd, **kwargs: run_supervised(
        cmd, **{**kwargs, 'timeout': 90},
    ))
    assert completed.returncode == 0, completed.stdout
    invocation.publish_result()
    reduced = tmp_path / 'reduced.c'
    assert reduced.is_file()
    assert checker.is_file()
    assert subprocess.run([str(checker), str(reduced)]).returncode == 77
