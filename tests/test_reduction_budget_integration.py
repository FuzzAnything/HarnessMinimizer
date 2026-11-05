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

from harnessreducer.api import ReductionConfig, reduce_with_config


@unittest.skipUnless(shutil.which("clang++") and shutil.which("ar"), "C++ toolchain required")
class BudgetPipelineTests(unittest.TestCase):
    def test_timeout_snapshot_survives_pch_restoration_and_inline_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "library.cpp"
            library.write_text('extern "C" void target() { volatile int zero = 0; volatile int value = 7 / zero; (void)value; }\n')
            subprocess.run(["clang++", "-fsanitize=address,undefined", "-g", "-O0", "-c", str(library), "-o", str(root / "library.o")], check=True)
            subprocess.run(["ar", "rcs", str(root / "libtarget.a"), str(root / "library.o")], check=True)
            harness = root / "harness.cpp"
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
            driver.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": os.pathsep.join([str(tools), str(Path(sys.executable).parent), os.environ["PATH"]]),
                "DEBUGINFOD_URLS": "",
                "ASAN_OPTIONS": "detect_leaks=0",
            }
            # Formatting is cosmetic and clang-format isn't needed by the
            # oracle; all compile/replay/inline checks below remain real.
            with patch.dict(os.environ, environment), patch("harnessreducer.api.format_reduced_harness"):
                result = reduce_with_config(ReductionConfig(
                    harness_path=str(harness), link_flags=str(root / "libtarget.a"),
                    crash_input=str(seed), work_dir=str(root / "work"),
                    phase3_mode="pch", stable=True, snapshot=True,
                    reduction_timeout_seconds=10,
                ))
            self.assertTrue(result.success)
            self.assertTrue(Path(result.reduced_harness).is_file())
            self.assertNotIn("int unused = 0;", Path(result.reduced_harness).read_text())
