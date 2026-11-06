"""Language selection and source transformations must preserve C semantics."""

import builtins
from pathlib import Path
import subprocess

import pytest

from harnessminimizer import api, reducer_runner as runner
from harnessminimizer.dynamic_slicer import CoverageMap, slice_source_by_coverage
from harnessminimizer.pch_prefix import split_source_for_pch
from harnessminimizer.source_cleanup import clean_reduced_source
from harnessminimizer.source_language import (
    C, CPP, _grammar, current_language, language_for_path, language_scope,
)


@pytest.mark.parametrize("suffix", [".cpp", ".cc", ".cxx", ".c++", ".C"])
def test_cpp_suffixes(suffix):
    assert language_for_path("does-not-exist" + suffix) == CPP


def test_selection_and_scope_do_not_leak():
    assert language_for_path("does-not-exist.c") == C
    for name in ("harness", "harness.txt", "harness.i", "harness.ii"):
        with pytest.raises(ValueError, match="Unsupported harness suffix"):
            language_for_path(name)
    assert current_language() == CPP
    with language_scope(C):
        assert current_language() == C
        with language_scope(CPP):
            assert current_language() == CPP
        assert current_language() == C
    assert current_language() == CPP


def test_cpp_import_does_not_require_c_grammar(monkeypatch):
    real_import = builtins.__import__

    def without_c(name, *args, **kwargs):
        if name == "tree_sitter_c":
            raise ImportError("C grammar deliberately unavailable")
        return real_import(name, *args, **kwargs)

    _grammar.cache_clear()
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "__import__", without_c)
        assert not CPP.parser().parse(b"int main() { return 0; }").root_node.has_error
        with pytest.raises(RuntimeError, match="requires tree-sitter-c"):
            C.parser()
    _grammar.cache_clear()


def test_c_prefix_preserves_conditionals_and_body(tmp_path):
    (tmp_path / "local.h").write_text("typedef int Number;\n")
    source = (
        '#define MODE 1\r\n#if MODE\r\n#include "local.h"\r\n'
        '#else\r\n#include <stdlib.h>\r\n#endif // end\r\n'
        '#define BODY 2\r\n'
        'int f(int *restrict p) { return _Generic(*p, int: 1); }\r\n'
        '#include <stdio.h>\r\n'
    )
    header, prefix, body = split_source_for_pch(source, tmp_path, language=C)
    assert str(tmp_path / "local.h") in header
    assert str(tmp_path) not in prefix
    assert '#endif // end\r\n' in prefix
    assert body == source[source.index('#define BODY'):]
    assert '#include <stdio.h>' not in prefix
    conditional_code = '#if MODE\n#include <stdint.h>\nint keep;\n#endif\n'
    assert split_source_for_pch(conditional_code, tmp_path, language=C)[2] == conditional_code


def test_c_preparation_skips_fdp_and_preserves_original(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "TREEDUCER_DIR", str(tmp_path / "work"))
    (tmp_path / "work").mkdir()
    harness = tmp_path / "harness.c"
    original = (
        '#include <stddef.h>\n#include <stdint.h>\n'
        'int ConsumeBytes(int value) { return value; }\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *restrict data, size_t size) {\n'
        '  (void)data; (void)size;\n}\n'
    )
    harness.write_text(original)

    def unexpected(*_args, **_kwargs):
        pytest.fail("C source reached FDP transformation")

    monkeypatch.setattr(api, "inject_ids", unexpected)
    monkeypatch.setattr(api, "strip_injected_ids", unexpected)
    prepared = api._prepare_fuzzer_entry_return(str(harness), "-std=c11", str(tmp_path / "work"))
    assert prepared.path.endswith('.c')
    assert 'return 0;' in Path(prepared.path).read_text()
    tagged = api.tag_harness_with_fdp_ids(prepared.path, 100000, "FDP_ID")
    assert tagged.fdp_callsite_count == 0
    assert tagged.path.endswith('.c')
    assert api._finalize_fallback_harness(tagged.path, 100000) == tagged.path
    assert '<vector>' not in Path(tagged.path).read_text()
    assert harness.read_text() == original


@pytest.mark.parametrize("parameters", [
    "const uint8_t *restrict data, size_t size",
    "const unsigned char data[static 1], size_t size",
    "BytePtr data, Length size",
])
@pytest.mark.parametrize("data", [b"", b"\x00\xff\x80", bytes(range(256)) * 16])
def test_c_input_embedding_is_portable_and_collision_free(tmp_path, parameters, data):
    source = (
        '#include <stddef.h>\n#include <stdint.h>\n'
        '#ifdef __cplusplus\n#error Must compile as C\n#endif\n'
        'typedef const uint8_t *BytePtr; typedef size_t Length;\n'
        '#define hm_input_bytes_0 bad_macro\n'
        f'int LLVMFuzzerTestOneInput({parameters}) {{\n'
        '  int hm_input_size_1 = 0;\n'
        '  return (int)size + hm_input_size_1 + (size ? data[size - 1] : 0);\n}\n'
    )
    names = api._c_input_names(source)
    assert names == ('hm_input_bytes_2', 'hm_input_size_2')
    transformed = api._inline_direct_input_source(source, 'values.h', language=C, input_names=names)
    header = api._direct_input_header_source(data, language=C, input_names=names)
    (tmp_path / 'values.h').write_text(header)
    expected = len(data) + (data[-1] if data else 0)
    path = tmp_path / 'export.c'
    path.write_text(transformed + f'\nint main(void) {{ return LLVMFuzzerTestOneInput(0, 0) != {expected}; }}\n')
    exe = tmp_path / 'export'
    built = subprocess.run(['clang', '-std=c11', '-pedantic-errors', str(path), '-o', str(exe)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    assert subprocess.run([str(exe)]).returncode == 0
    assert 'constexpr' not in header


def test_c_cleanup_and_slicing_preserve_used_declarations(tmp_path):
    source = (
        '// delete this\n\n'
        'const char *text = "/* keep */ // keep";\n'
        'int f(int value) {\n'
        '  int used = (int){3};\n'
        '  if (value == 9) { return used; }\n'
        '  return used;\n}\n'
    )
    path = tmp_path / 'harness.c'
    path.write_text(source)
    clean_reduced_source(str(path))
    assert path.read_text() == source.replace('// delete this\n', '')
    result = slice_source_by_coverage(source, CoverageMap({5, 6, 7}, {5, 7}), language=C)
    assert 'if (value == 9)' not in result.source
    assert 'int used = (int){3};' in result.source
    assert not C.parser().parse(result.source.encode()).root_node.has_error
