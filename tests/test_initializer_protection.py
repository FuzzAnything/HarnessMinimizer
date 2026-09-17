"""Harmless source/preprocessor/compiler tests; no library benchmark execution."""
import json
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from harnessreducer.initializer_protection import (
    prepare_initializer_protection, preparation_compile_flags, source_tokens, verify_preparation,
)
from harnessreducer.initializer_analysis import analyze_uninitialized
from harnessreducer.macro_headers import prepare_macro_headers
from harnessreducer.reducer_runner import _split_source_for_pch


@pytest.mark.parametrize("declaration", [
    "int a = 1;", "Point p{2, 3};", "Point p(2, 3);", "int xs[3] = {1, 2, 3};",
    "int a = 1, b;", "int a = next(), b = a + 1;",
    'const char *str = "HR_KEEP_INIT_fake";',
    "auto value = fdp.ConsumeIntegral<int>(/*FDP_ID:100001*/100001);",
    "Point p = make_point(\n  2, /* comment */\n  3);",
    "double value = 1.25e+3;",
    'auto value = "example"_tag;',
    'auto value = R"tag(example)tag"_tag;',
])
def test_round_trip_and_opaque_complete_statement(tmp_path, declaration):
    source = tmp_path / "original.cpp"
    original = "void test() {\n  " + declaration + "\n}\n"
    source.write_text(original)
    preparation = prepare_initializer_protection(source, tmp_path / "work")
    assert len(preparation.declarations) == 1
    prepared = preparation.source.read_text()
    assert declaration not in prepared
    assert preparation.restore(prepared) == original
    assert preparation.restore(original) == original
    assert source.read_text() == original
    header = preparation.header.read_text()
    assert "#define " + preparation.declarations[0].marker in header
    assert tuple(t[2] for t in source_tokens(declaration[:-1])) == tuple(
        t[2] for t in source_tokens(header.split(" ", 2)[2])
    )


def test_surviving_units_only_and_token_aware_restoration(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text("void f() { int a=1; { int a=2; } }\n")
    preparation = prepare_initializer_protection(source, tmp_path / "work")
    first, second = preparation.declarations
    candidate = f'void f() {{ {second.marker}; }}\n// {first.marker}\n'
    assert preparation.restore(candidate) == f"void f() {{ int a=2; }}\n// {first.marker}\n"
    assert preparation.restore(f'const char *s="{first.marker}";') == f'const char *s="{first.marker}";'
    with pytest.raises(ValueError, match="Unknown"):
        preparation.restore("void f(){ " + preparation.prefix + "999; }")
    with pytest.raises(ValueError, match="directive"):
        preparation.restore(f"#undef {first.marker}\n")


def test_unsupported_and_non_initialized_forms_are_not_guessed(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text('''
int global = 1;
void f() {
  Point p;
  initialize(&p);
  for (int i=0; i<3; ++i) {}
  if (auto p=find(); p) {}
  auto [x,y] = pair;
  auto fn = [](){ int z=1; return z; };
  int line = __LINE__;
  auto s = R"tag(first
second)tag";
}
''')
    preparation = prepare_initializer_protection(source, tmp_path / "work")
    assert not preparation.declarations
    assert len(preparation.skipped) >= 5
    assert preparation.restore(preparation.source.read_text()) == source.read_text()


def test_conditional_definitions_compose_with_existing_macro_preparation(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text(
        "#define VALUE 2\nvoid f() {\n#if 1\n int n=VALUE;\n#else\n int n=3;\n#endif\n}\n"
    )
    preparation = prepare_initializer_protection(source, tmp_path / "work")
    assert len(preparation.declarations) == 2
    macro = prepare_macro_headers(preparation.source, tmp_path / "work")
    exported = preparation.restore(macro.restore(macro.source.read_text()))
    assert exported == source.read_text()


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    return result


@pytest.mark.skipif(not shutil.which("clang++"), reason="Clang required")
@pytest.mark.parametrize("mode", ["direct", "split", "pch", "pch-plugin"])
def test_compile_paths_preserve_scope_side_effects_and_portable_export(tmp_path, mode):
    root = tmp_path / "quoted ' path"
    root.mkdir()
    source = root / "source.cpp"
    # The declaration depends on an existing local and initializes two variables
    # in order. No crashing code is used.
    original = (
        "#include <cstdint>\n"
        "int next(int &i) { return ++i; }\n"
        'extern "C" int value() {\n'
        "  int n=0;\n  int a=next(n), b=a+1;\n  return a+b+n;\n}\n"
    )
    if mode != "pch-plugin":
        original += "int main() { return value()==4 ? 0 : 1; }\n"
    source.write_text(original)
    preparation = prepare_initializer_protection(source, root / "prepared")
    verify_preparation(preparation, "-std=c++17", replay=False, plugin=mode == "pch-plugin")
    flags = ["-std=c++17", "-O0"]
    if mode == "pch-plugin":
        flags.append("-fPIC")
    compiler_source = preparation.source
    restore_prefix = ""
    if mode.startswith("pch"):
        prefix, restore_prefix, body = _split_source_for_pch(preparation.source.read_text(), root)
        header = root / "prefix.h"
        header.write_text(prefix)
        pch = root / "prefix.pch"
        run(["clang++", *flags, "-x", "c++-header", str(header), "-o", str(pch)])
        compiler_source = root / "body.cpp"
        compiler_source.write_text(body)
        flags += ["-include-pch", str(pch)]
    binary = root / ("plugin.so" if mode == "pch-plugin" else "program")
    if mode == "direct":
        run(["clang++", *flags, str(compiler_source), "-o", str(binary)])
    else:
        obj = root / "candidate.o"
        run(["clang++", *flags, "-c", str(compiler_source), "-o", str(obj)])
        run(["clang++", *(["-shared"] if mode == "pch-plugin" else []), str(obj), "-o", str(binary)])
    if mode == "pch-plugin":
        # Exercise a real executable loading a candidate plugin. No sanitizer
        # failure or library benchmark is needed for this ABI/restoration test.
        loader = root / "loader.cpp"
        loader.write_text(
            '#include <dlfcn.h>\nint main(int, char **v) {'
            'void *h=dlopen(v[1],RTLD_NOW); if(!h)return 2;'
            'auto f=(int(*)())dlsym(h,"value"); return f && f()==4 ? 0 : 1; }\n'
        )
        run(["clang++", str(loader), "-ldl", "-o", str(root / "loader")])
        run([str(root / "loader"), str(binary)])
    else:
        run([str(binary)])
    restored = preparation.restore(restore_prefix + compiler_source.read_text())
    assert "HR_KEEP_INIT_" not in restored
    assert "initializer_definitions.h" not in restored
    assert restored.count("int a=next(n), b=a+1;") == 1
    final = root / "final.cpp"
    if mode == "pch-plugin":
        restored += "int main(){return value()==4 ? 0 : 1;}\n"
    final.write_text(restored)
    # Verify the delivered source does not need the temporary definitions.
    preparation.header.rename(preparation.header.with_suffix(".saved"))
    run(["clang++", "-std=c++17", str(final), "-o", str(root / "final")])
    run([str(root / "final")])


def test_quoted_preparation_flags(tmp_path):
    with preparation_compile_flags('-DVALUE="quoted"', Path("/source with spaces/a.cpp"), tmp_path) as flags:
        assert len(flags.split()) == 1 and flags.startswith("@")
        assert shlex.split(Path(flags[1:]).read_text()) == [
            "-iquote", "/source with spaces", '-DVALUE="quoted"',
        ]
    assert (tmp_path / "compile_flags.rsp").exists()
    assert not Path(flags[1:]).exists()


@pytest.mark.skipif(not shutil.which("clang++"), reason="Clang required")
def test_preparation_keeps_local_includes_and_literal_suffixes(tmp_path):
    root = tmp_path / "source with spaces"
    root.mkdir()
    (root / "local.h").write_text(
        "constexpr unsigned long operator\"\"_tag(const char *, unsigned long n){return n;}\n"
    )
    source = root / "original.cpp"
    source.write_text(
        '#include "local.h"\nint main(){auto value="example"_tag;return value==7 ? 0 : 1;}\n'
    )
    prepared = prepare_initializer_protection(source, tmp_path / "separate work")
    with preparation_compile_flags('-std=c++17 -DVALUE="quoted"', source, prepared.source.parent) as flags:
        verify_preparation(prepared, flags, replay=False, plugin=False)
        output = tmp_path / "program"
        run(["clang++", flags, str(prepared.source), "-o", str(output)])
        run([str(output)])


@pytest.mark.skipif(not shutil.which("clang++"), reason="Clang required")
def test_actual_analyzer_finds_uninitialized_struct_without_execution(tmp_path):
    source = tmp_path / "failed.cpp"
    source.write_text("struct Point { int x,y; }; void consume(Point); void f(){Point p; consume(p);}\n")
    result = analyze_uninitialized(str(source), tmp_path / "diagnosis", "-std=c++17")
    assert result.status == "uninitialized-use", Path(result.log).read_text()
    assert result.relevant
    source.write_text("struct Point { int x,y; }; void consume(Point); void f(){Point p={1,2}; consume(p);}\n")
    clean = analyze_uninitialized(str(source), tmp_path / "clean", "-std=c++17")
    assert clean.status == "no-relevant-diagnostic", Path(clean.log).read_text()


@pytest.mark.skipif(not shutil.which("clang++"), reason="Clang required")
def test_preparation_rejects_changed_location_sensitive_macro_expansion(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text("#define HERE __LINE__\nint f(){int n=HERE; return n;}\n")
    preparation = prepare_initializer_protection(source, tmp_path / "work")
    with pytest.raises(ValueError, match="changes preprocessed tokens"):
        verify_preparation(preparation, "", replay=False, plugin=False)
    assert json.loads((preparation.source.parent / "preparation_check.json").read_text())["tokens_match"] is False
