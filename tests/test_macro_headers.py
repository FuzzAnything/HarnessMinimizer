"""Macro preparation/restoration uses only harmless synthetic source programs."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

import pytest

from harnessreducer.macro_headers import prepare_macro_headers
from harnessreducer.reduction_engines import (
    prepare_reducer_invocation,
)
from harnessreducer.reducer_runner import PchArtifacts, _split_source_for_pch, restore_pch_includes
from harnessreducer.process_supervisor import run_supervised


@pytest.mark.parametrize("source,count", [
    ("#include <cstddef>\n#define N 3\nint value = N;\n", 1),
    ("#define JOIN(a,b) a##b\n#define TEXT(x) #x\n", 2),
    ("#define F(x) \\\n ((x) + 1)\nint n=F(2);\n", 1),
    ("#define F(x) \\\r\n ((x) + 1)\r\nint n=F(2);\r\n", 1),
    ("#if 1\n#define N 1\n#else\n#define N 2\n#endif\n#undef N\n#define N 3\n", 3),
    ("int f() {\n #define N 1\n return N;\n}\n", 1),
    ("// #define FAKE 1\n/*\n#define FAKE 2\n*/\n#define REAL 3\n", 1),
    ('const char *s = R"text(\n#define FAKE 1\n)text";\n#define REAL 2\n', 1),
    ('const char *s = R"x(a)x\\\n"\n#define FAKE 1\n)x";\n#define REAL 2\n', 1),
    ('const char *s = "text\\\n#define FAKE 1";\n#define REAL 2\n', 1),
    ("// comment \\\n#define FAKE 1\n#define REAL 2\n", 1),
    ("int n = 1'000;\n#define REAL 2\n", 1),
    ("/*前置*/ # /*gap*/ define N 1\n", 1),
    ("#def\\\nine N 1\n", 1),
    ("%:define N 1\n", 1),
    ("#define TEXT R\"x(first\nsecond)x\"\n", 1),
    ("#define N 1 /*comment\n comment*/ + 2\n", 1),
    ("#define N 1", 1),
    ("\ufeff#define N 1\n", 1),
    ('#include "library.h"\nconst char *s = "#define FAKE 1";\n', 0),
])
def test_only_real_definitions_are_moved_and_exactly_restored(tmp_path, source, count):
    original = tmp_path / "source.cpp"
    original.write_bytes(source.encode())
    preparation = prepare_macro_headers(original, tmp_path)
    assert len(preparation.headers) == count
    transformed = preparation.source.read_bytes().decode()
    assert preparation.restore(transformed) == source
    assert original.read_bytes().decode() == source
    assert transformed.count("\n") == source.count("\n")
    if not count:
        assert preparation.source == original
        assert preparation.manifest is None
        assert sorted(tmp_path.iterdir()) == [original]
    else:
        manifest = json.loads(preparation.manifest.read_text())
        assert len(manifest["headers"]) == count
        for header in preparation.headers:
            assert header.path.read_bytes().decode() == header.definition.rstrip("\r\n") + (
                "\r\n" if header.definition.endswith("\r\n") else "\n"
            )


def test_restore_uses_include_identity_not_positions_and_preserves_user_includes(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text('#include "original.h"\n#define A 1\n#define B(x) x##x\nint value;\n')
    preparation = prepare_macro_headers(source, tmp_path)
    # Simulate a reducer deleting one definition and reformatting the other.
    surviving = preparation.headers[1]
    candidate = (
        '#include "original.h"\n'
        f' #  include "{surviving.path}"\n'
        'int changed;\n'
    )
    restored = preparation.restore(candidate)
    assert '#include "original.h"' in restored
    assert "#define A" not in restored
    assert surviving.definition in restored
    assert "int changed;" in restored
    assert "reducer-macros-" not in restored
    assert preparation.restore(restored) == restored
    # A string/comment mentioning the temporary header must not be rewritten.
    comment = f'// #include "{surviving.path}"\n'
    assert preparation.restore(comment) == comment


@pytest.mark.parametrize("mode", ["split", "pch"])
def test_treereduce_restores_output_and_snapshot(tmp_path, mode):
    original = tmp_path / "source.cpp"
    source = '#include <cstddef>\nint before;\n#define VALUE (7 + 8 + 9)\nint value = VALUE;\n'
    original.write_text(source)
    prefix = ""
    engine_input = original
    if mode == "pch":
        _, prefix, body = _split_source_for_pch(source, tmp_path)
        engine_input = tmp_path / "body.cpp"
        engine_input.write_text(body)
    destination = tmp_path / "reduced.cpp"
    snapshot = tmp_path / "snapshot.cpp"
    invocation = prepare_reducer_invocation(
        source=str(engine_input), output=str(destination),
        checker_command=["checker.py", "@@.cpp", "--last-interesting-file", str(snapshot)],
        stable=True, jobs=2,
    )
    key = "-s"
    engine_source = Path(invocation.command[invocation.command.index(key) + 1]).read_text()
    assert "#define" not in engine_source
    assert ("#include <cstddef>" in engine_source) == (mode == "split")
    assert invocation.metadata["macro_preparation"]["definition_count"] == 1
    invocation.result.parent.mkdir(exist_ok=True)
    invocation.result.write_text(engine_source)
    snapshot_source = engine_source + "int snapshot_only;\n"
    snapshot.write_text(snapshot_source)
    invocation.publish_result()
    assert "#define VALUE" in destination.read_text()
    assert "#define VALUE" in snapshot.read_text()
    if mode == "pch":
        artifacts = PchArtifacts(str(engine_input), "prefix.h", "prefix.pch", prefix)
        restore_pch_includes(str(destination), artifacts)
        restore_pch_includes(str(snapshot), artifacts)
    assert "#include <cstddef>" in destination.read_text()
    assert "int snapshot_only;" in snapshot.read_text()
    assert not destination.with_suffix(".raw.cpp").exists()
    assert not snapshot.with_suffix(".raw.cpp").exists()
    assert original.read_text() == source


NATIVE_SOURCE = r'''#define BEFORE_INCLUDE 1
#include <cstddef>
#define JOIN(a, b) a##b
#define TEXT(x) #x
#define PRODUCT(a, b) \
    ((a) * (b))
#if BEFORE_INCLUDE
#define VALUE 7
#else
#define VALUE 0
#endif
constexpr int JOIN(my_, value) = PRODUCT(VALUE, 1);
#undef VALUE
#define VALUE 9
static_assert(my_value == 7 && VALUE == 9);
static_assert(sizeof(TEXT(hello)) == 6);
constexpr int location = __LINE__;
int main() { return my_value; }
'''


@pytest.mark.skipif(not shutil.which("clang++"), reason="clang++ required")
@pytest.mark.parametrize("mode", ["direct", "split", "pch"])
def test_native_compilation_and_restoration_across_modes(tmp_path, mode):
    root = tmp_path / "quoted space ' work"
    root.mkdir()
    original = root / "source.cpp"
    original.write_text(NATIVE_SOURCE)
    prepared_source = original
    flags = ["-std=c++17", "-O0"]
    prefix = ""

    def compile_command(command):
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr

    if mode == "pch":
        pch_text, prefix, body = _split_source_for_pch(NATIVE_SOURCE, root)
        header = root / "prefix.h"
        header.write_text(pch_text)
        pch = root / "prefix.pch"
        compile_command(["clang++", *flags, "-x", "c++-header", str(header), "-o", str(pch)])
        prepared_source = root / "body.cpp"
        prepared_source.write_text(body)
        flags.extend(["-include-pch", str(pch)])
    preparation = prepare_macro_headers(prepared_source, root)
    binary = root / "program"
    if mode == "direct":
        compile_command(["clang++", *flags, str(preparation.source), "-o", str(binary)])
    else:
        obj = root / "candidate.o"
        compile_command(["clang++", *flags, "-c", str(preparation.source), "-o", str(obj)])
        compile_command(["clang++", str(obj), "-o", str(binary)])
    assert subprocess.run([str(binary)], timeout=10).returncode == 7

    # No generated header dependencies remain in the exported standalone source.
    restored = root / "restored.cpp"
    restored.write_text(prefix + preparation.restore(preparation.source.read_text()))
    assert "reducer-macros-" not in restored.read_text()
    for header in preparation.headers:
        header.path.unlink()
    compile_command(["clang++", "-std=c++17", str(restored), "-o", str(binary)])
    assert subprocess.run([str(binary)], timeout=10).returncode == 7


@pytest.mark.skipif(not shutil.which("clang++"), reason="clang++ required")
def test_repeated_inclusion_does_not_add_implicit_include_guards(tmp_path):
    source = tmp_path / "source.cpp"
    source.write_text("#define VALUE 7\n")
    preparation = prepare_macro_headers(source, tmp_path)
    include = preparation.source.read_text()
    probe = include + "#undef VALUE\n" + include + "static_assert(VALUE == 7);\n"
    proc = subprocess.run(
        ["clang++", "-std=c++17", "-x", "c++", "-fsyntax-only", "-"],
        input=probe, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(os.environ.get("HARNESSREDUCER_TEST_TREEREDUCE") != "1", reason="opt-in real reducer test")
@pytest.mark.parametrize("mode", ["split", "pch"])
def test_real_treereduce_reduces_macros_and_exports_compilable_source(tmp_path, mode):
    source = tmp_path / "original.cpp"
    original = (
        '#include <cstddef>\n'
        '#define JOIN(a,b) a##b\n'
        '#define SAVED_VALUE \\\n JOIN(,7)\n'
        'int unused_function(int x) { return x + 3; }\n'
        'int main() { int unused_local = 12; return SAVED_VALUE; }\n'
    )
    source.write_text(original)
    flags = ["-std=c++17", "-O0"]
    prefix = ""
    if mode == "pch":
        pch_source, prefix, body = _split_source_for_pch(original, tmp_path)
        header = tmp_path / "prefix.h"
        header.write_text(pch_source)
        pch = tmp_path / "prefix.pch"
        run_supervised(
            ["clang++", *flags, "-x", "c++-header", str(header), "-o", str(pch)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
        )
        source = tmp_path / "body.cpp"
        source.write_text(body)
        flags.extend(["-include-pch", str(pch)])
    checker = tmp_path / "checker.py"
    checker.write_text(
        f'#!{sys.executable}\n'
        'import subprocess,sys,tempfile\nfrom pathlib import Path\n'
        'from harnessreducer.process_supervisor import run_supervised\n'
        'with tempfile.TemporaryDirectory() as build:\n'
        '  obj = str(Path(build)/"candidate.o")\n'
        '  exe = str(Path(build)/"program")\n'
        f'  command = ["clang++", *{flags!r}, "-c", sys.argv[1], "-o", obj]\n'
        '  p = run_supervised(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)\n'
        '  if p.returncode: sys.exit(255)\n'
        '  p = run_supervised(["clang++",obj,"-o",exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)\n'
        '  if p.returncode: sys.exit(255)\n'
        '  p = run_supervised([exe], timeout=5)\n'
        '  sys.exit(77 if p.returncode == 7 else 1)\n'
    )
    checker.chmod(0o700)
    destination = tmp_path / "reduced.cpp"
    invocation = prepare_reducer_invocation(
        source=str(source), output=str(destination),
        checker_command=[str(checker), "@@.cpp"], stable=True, jobs=2,
    )

    def bounded_run(command, **kwargs):
        kwargs["timeout"] = 180
        return run_supervised(command, **kwargs)

    result = invocation.run(bounded_run)
    assert result.returncode == 0, result.stdout
    invocation.publish_result()
    exported = prefix + destination.read_text()
    assert "reducer-macros-" not in exported
    assert "unused_function" not in exported
    destination.write_text(exported)
    binary = tmp_path / "final-program"
    run_supervised(
        ["clang++", "-std=c++17", str(destination), "-o", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
    )
    assert run_supervised([str(binary)], timeout=5).returncode == 7
    assert (tmp_path / "original.cpp").read_text() == original
