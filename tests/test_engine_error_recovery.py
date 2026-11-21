"""Only current, accepted checkpoints can recover a failed reducer invocation."""
import subprocess
from pathlib import Path

import pytest

from harnessminimizer import reducer_runner as runner, reduction_engines
from harnessminimizer.reduction_engines import ReducerInvocation


@pytest.mark.parametrize('checkpoint_kind,recovers', [
    ('accepted', True), ('missing', False), ('stale', False), ('empty', False), ('unchanged', False),
])
def test_failed_engine_ignores_unverified_output(tmp_path, monkeypatch, checkpoint_kind, recovers):
    runner.configure_work_dir(str(tmp_path / 'work'))
    runner.reset_stack_trace_state()
    runner.configure_debug_logging(False)
    source = tmp_path / 'source.cpp'
    source.write_text('int original; int redundant;\n')
    result = tmp_path / 'engine-result.cpp'
    exported = Path(runner.get_work_dir()) / 'reduced_harness.cpp'
    checkpoint = Path(runner.get_last_interesting_file())
    if checkpoint_kind == 'stale':
        checkpoint.write_text('int stale;\n')
    invocation = ReducerInvocation(['fake-engine'], result, exported, {'tool': 'perses'})
    monkeypatch.setattr(reduction_engines, 'prepare_reducer_invocation', lambda **kwargs: invocation)
    monkeypatch.setattr(runner, 'calibrate_exec_timeout_ms', lambda *a, **k: 1000)

    def fail(*a, **k):
        assert not checkpoint.exists(), 'previous attempt must be cleared'
        result.write_text('int unverified;\n')
        if checkpoint_kind in ('accepted', 'empty', 'unchanged'):
            checkpoint.write_text({'accepted': 'int original;\n', 'empty': '',
                                   'unchanged': source.read_text()}[checkpoint_kind])
        return subprocess.CompletedProcess(['fake-engine'], 23, 'engine failed', '')

    monkeypatch.setattr(runner, 'run_supervised', fail)
    kwargs = dict(harness_path=str(source), fdp_trace_file=None, crash_pattern='crash',
                  compile_flags=None, link_flags=None, crash_input=None,
                  compilation_mode='direct', symbolize=False, snapshot=True, tool="perses")
    if recovers:
        output = runner.run_reducer(**kwargs)
        assert Path(output).read_text() == 'int original;\n'
    else:
        with pytest.raises(RuntimeError, match='Failed to run'):
            runner.run_reducer(**kwargs)
        assert not exported.exists()
    runner.reset_stack_trace_state()
