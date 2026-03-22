import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestFdpComplexExample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.example = cls.repo_root / "examples" / "fdp_complex_crash_harness.cpp"
        cls.include_dir = cls.repo_root / "include"
        cls.clang = shutil.which("clang++")

    def setUp(self):
        if not self.clang:
            self.skipTest("clang++ is not available in PATH")

    def _compile(self) -> Path:
        out_dir = Path(tempfile.mkdtemp(prefix="fdp_example_test_"))
        out_bin = out_dir / "fdp_complex_demo.out"
        cmd = [
            self.clang,
            "-std=c++17",
            f"-I{self.include_dir}",
            "-O0",
            "-g",
            str(self.example),
            "-o",
            str(out_bin),
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"compile failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        return out_bin

    def test_example_crashes_with_trigger_input(self):
        bin_path = self._compile()
        crashing_input = b"FDPDEMO!" + bytes([0x42, 0x99, 0x00, 0x01, 0x01]) + b"A" * 16

        with tempfile.NamedTemporaryFile(prefix="fdp_crash_", suffix=".bin", delete=False) as f:
            f.write(crashing_input)
            input_path = Path(f.name)

        proc = subprocess.run([str(bin_path), str(input_path)], text=True, capture_output=True, check=False)

        self.assertNotEqual(
            proc.returncode,
            0,
            msg="expected a crash (non-zero exit) for trigger input",
        )

    def test_example_does_not_crash_for_non_trigger(self):
        bin_path = self._compile()
        safe_input = b"FDPDEMO!" + bytes([0x41, 0x99, 0x00, 0x01, 0x01]) + b"B" * 16

        with tempfile.NamedTemporaryFile(prefix="fdp_safe_", suffix=".bin", delete=False) as f:
            f.write(safe_input)
            input_path = Path(f.name)

        proc = subprocess.run([str(bin_path), str(input_path)], text=True, capture_output=True, check=False)

        self.assertEqual(
            proc.returncode,
            0,
            msg=f"expected no crash for non-trigger input, got rc={proc.returncode}",
        )


if __name__ == "__main__":
    unittest.main()
