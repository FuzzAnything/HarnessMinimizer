"""PCH extraction preserves preprocessing structure and real compilation."""

import shutil
import subprocess

import pytest

from harnessminimizer.reducer_runner import (
    PchArtifacts, _split_source_for_pch, restore_pch_includes,
)


@pytest.mark.parametrize("conditional", [
    '#ifdef CHOICE\n#include "one.h"\n#else\n#include "two.h"\n#endif',
    '#ifndef CHOICE\n#include "one.h"\n#elif OTHER\n#include "two.h"\n#endif',
    '#if defined(CHOICE) && (CHOICE > 1)\n'
    '#ifdef NESTED\n#include "one.h"\n#endif\n'
    '#elif OTHER\n#include "two.h"\n#else\n#include "three.h"\n#endif',
])
def test_complete_conditional_blocks_and_trailing_body_macros(tmp_path, conditional):
    moved = '#define CONFIG 1\n' + conditional + ' // closing comment\n'
    body = '#define BODY_VALUE 3\nint value = BODY_VALUE;\n'
    pch, restored, remaining = _split_source_for_pch(moved + body, tmp_path)
    assert moved[moved.index('#if'):] in pch
    assert moved[moved.index('#if'):] in restored
    assert remaining == body
    assert pch.index('#define CONFIG') < pch.index('#include <stdint.h>')
    assert pch.index('#include <stdint.h>') < pch.index('#if')


@pytest.mark.parametrize("block", [
    '#if ENABLED\n#include "local.h"\nint variable;\n#endif\n',
    '#ifdef ENABLED\n#include "local.h"\n#else\nvoid function() {}\n#endif\n',
    '#if ENABLED\n#include "local.h"\n#ifdef OTHER\nstruct Type {};\n#endif\n#endif\n',
    'extern "C" {\n#include "local.h"\nint function();\n}\n',
    'namespace demo {\n#include "local.h"\n}\n',
])
def test_code_containing_blocks_stay_whole_in_body(tmp_path, block):
    source = '#include <limits.h>\n' + block + '#include "later.h"\n'
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    assert '#include <limits.h>' in pch
    assert 'local.h' not in pch
    assert body == block + '#include "later.h"\n'
    assert restored.endswith('#include <limits.h>\n')


@pytest.mark.parametrize("leading", [
    '/*\n#include "fake.h"\n#if FAKE\n*/\n',
    '// continued comment \\\n#include "fake.h"\n',
])
def test_comment_directives_do_not_change_prefix_boundary(tmp_path, leading):
    (tmp_path / 'fake.h').write_text('')
    (tmp_path / 'real.h').write_text('')
    source = leading + '#include "real.h"\nint body;\n'
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    assert leading in pch
    assert leading in restored
    assert str(tmp_path / 'fake.h') not in pch
    assert str(tmp_path / 'real.h') in pch
    assert body == 'int body;\n'


def test_raw_string_and_mid_body_includes_are_not_moved(tmp_path):
    source = ('const char *text = R"tag(\n#include "fake.h"\n#if FAKE\n)tag";\n'
              '#include "later.h"\n')
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    assert body == source
    assert 'fake.h' not in pch
    assert 'later.h' not in pch
    assert restored == '#include <stdint.h>\n#include <stddef.h>\n'


def test_multiline_macro_and_include_keep_original_spelling(tmp_path):
    (tmp_path / 'local.h').write_text('')
    moved = ('/* 中文 */ #define WRAP(x) \\\n  ((x) + 1)\n'
             '#include /* path comment */ \\\n"local.h" /* comment after include\n continues */\n')
    pch, restored, body = _split_source_for_pch(moved + 'int value = WRAP(2);\n', tmp_path)
    assert '#define WRAP(x) \\\n  ((x) + 1)' in pch
    assert '#include /* path comment */ \\\n"' + str(tmp_path / 'local.h') + '"' in pch
    assert '#include /* path comment */ \\\n"local.h"' in restored
    assert '/* 中文 */' in pch
    assert '/* comment after include\n continues */' in pch
    assert body == 'int value = WRAP(2);\n'


def test_macro_include_and_preceding_undef_are_preserved(tmp_path):
    moved = '#undef SELECTED\n#define SELECTED <limits.h>\n#include SELECTED\n'
    pch, restored, body = _split_source_for_pch(moved + 'int value = CHAR_BIT;\n', tmp_path)
    for prefix in (pch, restored):
        assert prefix.index('#undef SELECTED') < prefix.index('#define SELECTED')
        assert prefix.index('#define SELECTED') < prefix.index('#include SELECTED')
    assert body == 'int value = CHAR_BIT;\n'


def test_endif_attached_multiline_comment_is_not_split(tmp_path):
    conditional = '#if ENABLED\n#include <limits.h>\n#endif /* attached\n comment */\n'
    pch, restored, body = _split_source_for_pch(conditional + 'int value;\n', tmp_path)
    assert conditional in pch
    assert conditional in restored
    assert body == 'int value;\n'


def test_unconditional_standard_headers_are_still_deduplicated(tmp_path):
    source = '#define CONFIG 1\n#include <stddef.h>\n#include <stdint.h>\nint value;\n'
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    for prefix in (pch, restored):
        assert prefix.count('#include <stdint.h>') == 1
        assert prefix.count('#include <stddef.h>') == 1
        assert prefix.index('#define CONFIG') < prefix.index('#include <stdint.h>')
    assert body == 'int value;\n'


@pytest.mark.parametrize("ending", ['\n', '\r\n', ''])
def test_directive_at_eof_and_crlf(tmp_path, ending):
    source = '#include <limits.h>' + ending
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    assert '#include <limits.h>' in pch
    assert '#include <limits.h>' in restored
    assert body == ''
    assert restored.endswith(ending or '\n')


@pytest.mark.parametrize("tail", [
    '#ifdef MISSING_END\n#include "bad.h"\n',
    '#if BROKEN(\n#include "bad.h"\n#endif\n',
    'int broken( {\n#include "bad.h"\n',
])
def test_parser_errors_do_not_split_uncertain_constructs(tmp_path, tail):
    pch, restored, body = _split_source_for_pch('#include <limits.h>\n' + tail, tmp_path)
    assert 'bad.h' not in pch
    assert '#include <limits.h>' in restored
    assert body == tail


def test_local_absolute_and_search_path_headers_keep_lookup_behavior(tmp_path):
    local = tmp_path / 'local.h'
    local.write_text('')
    source = f'#include "local.h"\n#include "{local}"\n#include "search.h"\nint body;\n'
    pch, restored, body = _split_source_for_pch(source, tmp_path)
    assert pch.count(f'#include "{local}"') == 2
    assert '#include "search.h"' in pch
    assert '#include "local.h"' in restored
    assert body == 'int body;\n'


def _run(command):
    proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


@pytest.mark.skipif(not shutil.which('clang++'), reason='clang++ required')
@pytest.mark.parametrize('fast', [False, True])
@pytest.mark.parametrize('plugin', [False, True])
def test_native_pch_and_restored_source_match_original(tmp_path, fast, plugin):
    root = tmp_path / 'source with spaces'
    root.mkdir()
    work = tmp_path / 'work'
    work.mkdir()
    (root / 'fast.h').write_text('inline int library_value() { return SCALE(7); }\n')
    (root / 'normal.h').write_text('inline int library_value() { return SCALE(5); }\n')
    (root / 'later.h').write_text('static_assert(BODY_VALUE == 4);\n')
    source = (
        '/* 前置\n#include "fake.h"\n*/\n'
        '#define SCALE(x) \\\n ((x) * 3)\n'
        '#define LIMITS_HEADER <limits.h>\n'
        '#ifdef USE_FAST\n#if USE_FAST == 1\n#include \\\n"fast.h"\n#endif\n'
        '#else\n/* lead */ #include /* gap */ "normal.h"\n#endif // selected\n'
        '#include LIMITS_HEADER\n'
        '#define BODY_VALUE 4\n'
        'constexpr int body_value = BODY_VALUE;\n'
        '#include "later.h"\n'
        'extern "C" int selected_value() { return library_value() + body_value; }\n'
        '#include <cstdio>\n'
        'int main() { std::printf("%d\\n", selected_value()); return 0; }\n'
    )
    original = root / 'original.cpp'
    original.write_text(source)
    flags = ['-std=c++17', '-O0', '-I' + str(root), *(['-DUSE_FAST=1'] if fast else [])]
    original_exe = work / 'original'
    _run(['clang++', *flags, str(original), '-o', str(original_exe)])
    expected = _run([str(original_exe)])

    prefix, restore, body = _split_source_for_pch(source, root)
    assert '#include "later.h"' in body
    assert '#define BODY_VALUE' in body
    header = work / 'prefix.h'
    header.write_text(prefix)
    pch = work / 'prefix.pch'
    body_source = work / 'body.cpp'
    body_source.write_text(body)
    pch_flags = [*flags, *(['-fPIC'] if plugin else [])]
    _run(['clang++', *pch_flags, '-x', 'c++-header', str(header), '-o', str(pch)])
    obj = work / 'candidate.o'
    _run(['clang++', *pch_flags, '-include-pch', str(pch), '-c', str(body_source), '-o', str(obj)])
    candidate = work / ('plugin.so' if plugin else 'candidate')
    _run(['clang++', *(['-shared'] if plugin else []), str(obj), '-o', str(candidate)])
    if plugin:
        loader = work / 'loader.cpp'
        loader.write_text(
            '#include <dlfcn.h>\n#include <cstdio>\nint main(int, char **argv) {\n'
            'void *h = dlopen(argv[1], RTLD_NOW); if (!h) return 2;\n'
            'auto f = (int(*)())dlsym(h, "selected_value"); if (!f) return 3;\n'
            'std::printf("%d\\n", f()); return 0; }\n'
        )
        executable = work / 'loader'
        _run(['clang++', str(loader), '-ldl', '-o', str(executable)])
        actual = _run([str(executable), str(candidate)])
    else:
        actual = _run([str(candidate)])
    assert actual == expected

    restored = root / 'restored.cpp'
    restored.write_text(body)
    restore_pch_includes(str(restored), PchArtifacts(str(body_source), str(header), str(pch), restore))
    header.unlink()
    pch.unlink()
    final = work / 'restored'
    _run(['clang++', *flags, str(restored), '-o', str(final)])
    assert _run([str(final)]) == expected


@pytest.mark.skipif(not shutil.which('clang++'), reason='clang++ required')
def test_driver_types_available_when_first_include_branch_is_disabled(tmp_path):
    source = '#ifdef DISABLED\n#include "nonexistent.h"\n#endif\nint main() { return 0; }\n'
    prefix, _, body = _split_source_for_pch(source, tmp_path)
    header = tmp_path / 'prefix.h'
    header.write_text(prefix)
    pch = tmp_path / 'prefix.pch'
    _run(['clang++', '-x', 'c++-header', str(header), '-o', str(pch)])
    candidate = tmp_path / 'candidate.cpp'
    candidate.write_text('uint8_t byte; size_t size;\n' + body)
    _run(['clang++', '-include-pch', str(pch), str(candidate), '-o', str(tmp_path / 'candidate')])
