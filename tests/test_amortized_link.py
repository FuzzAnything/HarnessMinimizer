import subprocess
import sys
from pathlib import Path

import pytest

from harnessreducer import reducer_runner


def test_amortized_link_rejects_static_archives() -> None:
    with pytest.raises(ValueError, match="does not yet support static archives"):
        reducer_runner.resolve_amortized_shared_libraries("/tmp/libtarget.a")


def test_amortized_runner_executes_candidate_against_shared_target(
    tmp_path: Path,
) -> None:
    reducer_runner.configure_work_dir(str(tmp_path / "work"))
    target_source = tmp_path / "target.cpp"
    target_library = tmp_path / "libtarget_asan.so"
    harness_source = tmp_path / "harness.cpp"
    trace_path = tmp_path / "fdp_trace.log"
    trace_path.write_text("", encoding="utf-8")

    target_source.write_text(
        """
extern "C" __attribute__((noinline)) void target_crash() {
  volatile int *values = new int[1];
  values[4] = 7;
}
""",
        encoding="utf-8",
    )
    harness_source.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" void target_crash();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  target_crash();
  return 0;
}
""",
        encoding="utf-8",
    )

    compile_target = subprocess.run(
        [
            "clang++",
            "-shared",
            "-fPIC",
            "-fsanitize=address,undefined",
            "-O1",
            "-gline-tables-only",
            str(target_source),
            "-o",
            str(target_library),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert compile_target.returncode == 0, compile_target.stderr
    assert reducer_runner.resolve_amortized_shared_libraries(
        f"{target_library} -lm"
    ) == (str(target_library.resolve()),)

    with reducer_runner.start_amortized_runner(
        str(target_library),
        None,
        str(trace_path),
        symbolize=False,
    ) as runner:
        split_tester = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                str(harness_source),
                "AddressSanitizer",
                "--split",
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        pch = reducer_runner.prepare_phase3_pch_harness(
            str(harness_source),
            compile_flags=None,
            use_replay=True,
            amortize_link=True,
        )
        pch_tester = subprocess.run(
            [
                sys.executable,
                reducer_runner.get_crash_tester_path(),
                pch.body_source,
                "AddressSanitizer",
                "--pch",
                "--pch-path",
                pch.pch_file,
                "--fdp-trace",
                str(trace_path),
                "--amortized-runner-socket",
                runner.socket_path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert split_tester.returncode == 77, split_tester.stdout + split_tester.stderr
    assert "AddressSanitizer" in split_tester.stdout + split_tester.stderr
    assert pch_tester.returncode == 77, pch_tester.stdout + pch_tester.stderr
    assert "AddressSanitizer" in pch_tester.stdout + pch_tester.stderr
