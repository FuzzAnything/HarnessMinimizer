"""Daily-test's ID cleanup with main's optional FDP calls and replay runtime."""
import os
import re
import subprocess
from pathlib import Path

import pytest

from harnessminimizer.fdp_transform import inject_ids, strip_injected_ids


@pytest.mark.parametrize('call', [
    'ConsumeIntegralInRange<int>(0, 100001)', 'ConsumeBytesAsString(100001)',
    'ConsumeRandomLengthString(100001)', 'ConsumeBytesWithTerminator<char>(4, 100001)',
    'ConsumeBytesAsString(/*FDP_ID:100001*/ 100001)',
    'ConsumeRandomLengthString(/*OTHER:100001*/ 100001)',
])
def test_native_numeric_argument_survives_repeated_cleanup(call):
    source = f'void f() {{ fdp.{call}; }}'
    assert strip_injected_ids(source) == (source, 0)


@pytest.mark.parametrize('call, expected', [
    ('ConsumeBool(/*SITE:100001*/ 0)', 'ConsumeBool()'),
    ('ConsumeIntegralInRange<int>(0, 100001, 0)', 'ConsumeIntegralInRange<int>(0, 100001)'),
    ('ConsumeRandomLengthString(/*SITE:100001*/ 0)', 'ConsumeRandomLengthString()'),
])
def test_reduced_ids_are_removed_without_consuming_native_arguments(call, expected):
    source, count = strip_injected_ids(f'void f() {{ fdp.{call}; }}', marker='SITE')
    assert count == 1
    assert f'fdp.{expected}' in source
    assert strip_injected_ids(source, marker='SITE') == (source, 0)


def test_optional_defaults_survive_marker_removal_and_compile_with_public_fdp(tmp_path):
    source = '''#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdio>
int main() {
  const uint8_t data[] = {65, 66, 67, 68, 69, 70, 71, 72};
  FuzzedDataProvider fdp(data, sizeof(data));
  auto bytes = fdp.ConsumeBytesWithTerminator<uint8_t>(2);
  auto text = fdp.ConsumeRandomLengthString();
  for (auto byte : bytes) printf("%u,", byte);
  for (auto byte : text) printf("%u,", static_cast<unsigned char>(byte));
}
'''
    tagged, count = inject_ids(source, 100000, 'FDP_ID')
    assert count == 2
    assert 'ConsumeRandomLengthString(static_cast<size_t>(-1),' in tagged
    assert 'ConsumeBytesWithTerminator<uint8_t>(2, 0,' in tagged
    # Reducers may delete the marker comments; the explicit defaults still
    # make the trailing ID unambiguous, even when the number is reduced to 0.
    no_markers = re.sub(r'/\*FDP_ID:\d+\*/ \d+', '0', tagged)
    cleaned, removed = strip_injected_ids(no_markers)
    assert removed == 2
    assert strip_injected_ids(cleaned) == (cleaned, 0)
    outputs = []
    for name, program, flags in (
        ('original', source, []),
        ('cleaned', cleaned, []),
        ('recorded', tagged, ['-DDUMP_MODE', '-I' + str(Path(__file__).resolve().parents[1] / 'include')]),
    ):
        cpp, binary = tmp_path / f'{name}.cpp', tmp_path / name
        cpp.write_text(program)
        built = subprocess.run(['clang++', '-std=c++17', *flags, str(cpp), '-o', str(binary)],
                               capture_output=True, text=True, timeout=30)
        assert built.returncode == 0, built.stderr
        replay = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10,
                                env={**os.environ, 'FDP_TRACE_PATH': str(tmp_path / 'trace')})
        assert replay.returncode == 0, replay.stderr
        outputs.append(replay.stdout)
    assert outputs[0] == outputs[1] == outputs[2]
