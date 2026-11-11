"""Exercise deadline recovery with real compilation and a synthetic crash.

The reducer driver deliberately stalls after the real interestingness tester
accepts a smaller source, so this does not depend on reducer search timing.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from harnessminimizer.reduction_engines import PersesRuntime

from harnessminimizer.api import ReductionConfig, reduce_with_config


@unittest.skipUnless(shutil.which("clang++") and shutil.which("ar"), "C++ toolchain required")
class BudgetPipelineTests(unittest.TestCase):
    def test_timeout_snapshot_survives_pch_restoration_and_inline_validation(self):
        self._check_timeout_recovery(snapshot=True)

    def test_timeout_recovers_without_optional_snapshot_retries(self):
        self._check_timeout_recovery(snapshot=False)

    def test_timeout_inlines_fdp_values_without_snapshot_retries(self):
        self._check_timeout_recovery(snapshot=False, with_fdp=True)

    def test_perses_timeout_inlines_fdp_and_restores_macros_with_amortized_linking(self):
        self._check_timeout_recovery(snapshot=False, with_fdp=True, tool="perses")

    def test_perses_normal_completion_uses_its_output_with_the_same_validation(self):
        self._check_timeout_recovery(snapshot=False, with_fdp=True, tool="perses", finish=True)

    def _check_timeout_recovery(self, *, snapshot, with_fdp=False, tool="treereduce", finish=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "library.cpp"
            library.write_text('extern "C" void target() { volatile int zero = 0; volatile int value = 7 / zero; (void)value; }\n')
            subprocess.run(["clang++", "-fsanitize=address,undefined", "-g", "-O0", "-c", str(library), "-o", str(root / "library.o")], check=True)
            subprocess.run(["ar", "rcs", str(root / "libtarget.a"), str(root / "library.o")], check=True)
            harness = root / "harness.cpp"
            if with_fdp:
                harness.write_text(
                    '#include <cstddef>\n#include <cstdint>\n#include <fuzzer/FuzzedDataProvider.h>\n'
                    'extern "C" void target();\n#define CALL_TARGET() target()\n'
                    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {\n'
                    '  FuzzedDataProvider fdp(data, size);\n'
                    '  int consumed = fdp.ConsumeIntegral<int>();\n'
                    '  int unused = 0;\n'
                    '  // A comment in the saved candidate must be removed.\n'
                    '\n\n\n'
                    '  CALL_TARGET(); return consumed;\n}\n'
                )
            else:
                harness.write_text('#include <cstddef>\n#include <cstdint>\nextern "C" void target();\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { int unused = 0; target(); return 0; }\n')
            seed = root / "seed"
            seed.write_bytes(b"fixture")
            tools = root / "bin"
            tools.mkdir()
            driver = tools / "treereduce-c"
            driver.write_text(f"#!{sys.executable}\n" + '''import pathlib, subprocess, sys, time
args=sys.argv[1:]
if '--help' in args: raise SystemExit(0)
source=pathlib.Path(args[args.index('-s')+1])
candidate=source.with_name('budget-candidate.cpp')
candidate.write_text(source.read_text().replace('int unused = 0;', ''))
tester=args[args.index('--')+1:]
tester=[str(candidate) if a == '@@.cpp' else a for a in tester]
result=subprocess.run(tester, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
if result.returncode != 77: raise SystemExit(1)
time.sleep(60)
''')
            if tool == "perses":
                driver.write_text(f"#!{sys.executable}\n" + '''import pathlib, shutil, subprocess, sys, time
args=sys.argv[1:]
source=pathlib.Path(args[args.index('--input-file')+1])
script=pathlib.Path(args[args.index('--test-script')+1])
assert pathlib.Path.cwd() == source.parent
source.write_text(source.read_text().replace('int unused = 0;', ''))
result=subprocess.run(['/bin/sh', str(script)], cwd=source.parent)
if result.returncode != 0: raise SystemExit(1)
if '--finish-fixture' in args:
    output=pathlib.Path(args[args.index('--output-dir')+1])
    output.mkdir(parents=True)
    shutil.copyfile(source, output/source.name)
else:
    time.sleep(60)
''')
            driver.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": os.pathsep.join([str(tools), str(Path(sys.executable).parent), os.environ["PATH"]]),
                "DEBUGINFOD_URLS": "",
                "HARNESSMINIMIZER_TREEREDUCE": str(driver),
                "ASAN_OPTIONS": "detect_leaks=0",
            }
            # Formatting is cosmetic and clang-format isn't needed by the
            # oracle; all compile/replay/inline checks below remain real.
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, environment))
                stack.enter_context(patch("harnessminimizer.api.format_reduced_harness"))
                if tool == "perses":
                    command = (sys.executable, str(driver)) + (("--finish-fixture",) if finish else ())
                    runtime = PersesRuntime(command, "fixture", "fixture", "fixture", None)
                    stack.enter_context(patch("harnessminimizer.api.check_perses", return_value=runtime))
                    stack.enter_context(patch("harnessminimizer.reduction_engines.check_perses", return_value=runtime))
                result = reduce_with_config(ReductionConfig(
                    harness_path=str(harness),
                    compile_flags=f"-I{Path(__file__).resolve().parents[1] / 'include'}" if with_fdp else None,
                    link_flags=str(root / "libtarget.a"),
                    crash_input=str(seed), work_dir=str(root / "work"),
                    tool=tool, jobs=8, amortize_link=tool == "perses",
                    compilation_mode="pch", stable=True, snapshot=snapshot,
                    reduction_timeout_seconds=10,
                ))
            self.assertTrue(result.success)
            self.assertTrue(Path(result.reduced_harness).is_file())
            self.assertNotIn("int unused = 0;", Path(result.reduced_harness).read_text())
            if with_fdp:
                exported = Path(result.reduced_harness).read_text()
                self.assertNotIn("A comment in the saved candidate", exported)
                checkpoint = root / "work" / "last_interesting.cpp"
                self.assertEqual(checkpoint.read_text(), exported)
                self.assertNotIn("FDP_ID:", exported)
                self.assertNotIn("fdp.ConsumeIntegral", exported)
                self.assertIn("#define CALL_TARGET()", exported)
                # The reduced source must compile against Clang's public FDP
                # header, without HarnessMinimizer's private include directory.
                public_binary = root / "public-poc"
                public_compile = subprocess.run(
                    ["clang++", "-fsanitize=address,fuzzer,undefined", "-g", "-O0",
                     result.reduced_harness, str(root / "libtarget.a"),
                     "-o", str(public_binary)],
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(public_compile.returncode, 0, public_compile.stderr)
                public_replay = subprocess.run(
                    [str(public_binary), str(seed)],
                    capture_output=True, text=True, timeout=30,
                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"},
                )
                self.assertNotEqual(public_replay.returncode, 0)
                self.assertIn("division by zero", public_replay.stderr)
