"""Unit and mocked-integration tests for native Rust support in HarnessMinimizer.

Designed to run under both ``pytest`` and ``PYTHONPATH=src python3 -m unittest``
without requiring ``rustc``, ``cargo``, ``perses``, or ``tree_sitter`` on the host.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# On minimal test hosts without C++ tree-sitter wheels installed, provide
# lightweight stubs strictly for importing api.py (Rust mode never invokes
# tree_sitter). Inside the full container/venv, real packages are imported.
if importlib.util.find_spec("tree_sitter") is None and "tree_sitter" not in sys.modules:
    _ts = ModuleType("tree_sitter")
    _ts.Language = lambda *_a, **_k: object()  # type: ignore[attr-defined]
    _ts.Node = object  # type: ignore[attr-defined]
    _ts.Parser = lambda *_a, **_k: object()  # type: ignore[attr-defined]
    sys.modules["tree_sitter"] = _ts

if importlib.util.find_spec("tree_sitter_cpp") is None and "tree_sitter_cpp" not in sys.modules:
    _ts_cpp = ModuleType("tree_sitter_cpp")
    _ts_cpp.language = lambda: object()  # type: ignore[attr-defined]
    sys.modules["tree_sitter_cpp"] = _ts_cpp

from harnessminimizer import (  # noqa: E402
    api,
    macro_headers,
    reducer_runner,
    reduction_engines,
    rust_support,
    source_cleanup,
    source_language,
    symbolized_trace,
)


def _make_rust_workspace(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\n'
        'members = ["crates/*"]\n'
        '\n'
        '[workspace.package]\n'
        'edition = "2021"\n'
        '\n'
        '[patch.crates-io]\n'
        'local-helper = { path = "vendor/local-helper" }\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text('version = 3\n', encoding="utf-8")
    (root / ".cargo").mkdir(parents=True, exist_ok=True)
    (root / ".cargo" / "config.toml").write_text(
        '[source.vendored-sources]\n'
        'directory = "vendor"\n',
        encoding="utf-8",
    )
    crate = root / "crates" / "demo-lib"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(
        '[package]\n'
        'name = "demo-lib"\n'
        'version = "0.1.0"\n'
        'edition.workspace = true\n'
        '\n'
        '[features]\n'
        'default = ["std"]\n'
        'std = []\n'
        'simd = []\n',
        encoding="utf-8",
    )
    (crate / "src" / "lib.rs").write_text(
        'pub fn parse(data: &[u8]) -> usize { data.len() }\n',
        encoding="utf-8",
    )
    return root


class TestRustSourceLanguageAndEngines(unittest.TestCase):
    def test_language_for_path_and_properties(self):
        lang = source_language.language_for_path("/tmp/harness_000.rs")
        self.assertEqual(lang, source_language.RUST)
        self.assertEqual(lang.name, "rust")
        self.assertEqual(lang.suffix, ".rs")
        self.assertEqual(lang.perses_language, "rust")
        self.assertFalse(lang.has_tree_sitter)
        self.assertTrue(source_language.CPP.has_tree_sitter)
        self.assertTrue(source_language.C.has_tree_sitter)
        self.assertEqual(reducer_runner.get_last_interesting_file(source_language.RUST), str(Path(reducer_runner.get_work_dir()) / "last_interesting.rs"))

    def test_perses_flags_and_script_use_rust_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "harness.rs"
            harness.write_text("pub fn fuzz_target(_: &[u8]) {}\n", encoding="utf-8")
            script = root / "test.sh"
            reduction_engines.write_perses_test_script(
                script,
                ["python3", "crash_tester.py", "--source-language=rust", "@@.rs"],
                language=source_language.RUST,
            )
            content = script.read_text(encoding="utf-8")
            self.assertIn("candidate.rs", content)
            self.assertIn("--source-language=rust", content)

            flags = reduction_engines.perses_flags(
                "wdd",
                stable=False,
                jobs=4,
                language=source_language.RUST,
            )
            self.assertIn("--lang", flags)
            self.assertEqual(flags[flags.index("--lang") + 1], "rust")

    def test_macro_headers_skips_rust(self):
        with tempfile.TemporaryDirectory() as tmp:
            rs = Path(tmp) / "harness.rs"
            rs.write_text("pub fn fuzz_target(_: &[u8]) {}\n", encoding="utf-8")
            prepared = macro_headers.prepare_macro_headers(rs, Path(tmp))
            self.assertEqual(prepared.source, rs)
            self.assertEqual(prepared.headers, ())


class TestRustCommentCleanupAndInlining(unittest.TestCase):
    def test_strip_rust_comment_lines_handles_nested_and_raw_strings(self):
        src = (
            "// standalone comment\n"
            "/* outer /* nested */ comment */\n"
            "pub fn fuzz_target(data: &[u8]) {\n"
            '    let s = r#"// not a comment\n'
            '/* also not a comment */"#;\n'
            "    let x = data.len(); // trailing comment stays\n"
            "    /* multi-line touching code\n"
            "       must stay */\n"
            "    let _ = (s, x);\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            rs = Path(tmp) / "reduced.rs"
            rs.write_text(src, encoding="utf-8")
            source_cleanup.clean_reduced_source(str(rs))
            cleaned = rs.read_text(encoding="utf-8")
        self.assertNotIn("// standalone comment", cleaned)
        self.assertNotIn("/* outer", cleaned)
        self.assertIn("// not a comment", cleaned)
        self.assertIn("/* also not a comment */", cleaned)
        self.assertIn("let x = data.len(); // trailing comment stays", cleaned)
        self.assertIn("let _ = (s, x);", cleaned)

    def test_inline_rust_direct_input_all_entry_styles(self):
        payload = b"\x00\x01AB"

        fn_src = "pub fn fuzz_target(data: &[u8]) {\n    let _ = data.len();\n}\n"
        inlined_fn = rust_support.inline_rust_direct_input(fn_src, payload)
        self.assertIn("const HM_INPUT_BYTES: &[u8] = &[", inlined_fn)
        self.assertIn("0x00, 0x01, 0x41, 0x42,", inlined_fn)
        self.assertIn("let data: &[u8] = HM_INPUT_BYTES;", inlined_fn)

        macro_src = "fuzz_target!(|buf: &[u8]| {\n    let _ = buf.len();\n});\n"
        inlined_macro = rust_support.inline_rust_direct_input(macro_src, payload)
        self.assertIn("let buf: &[u8] = HM_INPUT_BYTES;", inlined_macro)

        llvm_src = (
            '#[no_mangle]\n'
            'pub extern "C" fn LLVMFuzzerTestOneInput(ptr: *const u8, len: usize) -> i32 {\n'
            '    let _ = (ptr, len);\n'
            '    0\n'
            '}\n'
        )
        inlined_llvm = rust_support.inline_rust_direct_input(llvm_src, payload)
        self.assertIn("let ptr = HM_INPUT_BYTES.as_ptr();", inlined_llvm)
        self.assertIn("let len = HM_INPUT_BYTES.len();", inlined_llvm)

        # Typed arbitrary::Arbitrary macro entry
        typed_macro_src = "fuzz_target!(|mut inp: MyInput| {\n    let _ = inp;\n});\n"
        inlined_typed = rust_support.inline_rust_direct_input(typed_macro_src, payload)
        self.assertIn("const HM_INPUT_BYTES: &[u8] = &[", inlined_typed)
        self.assertIn("arbitrary::Unstructured::new(HM_INPUT_BYTES)", inlined_typed)
        self.assertIn("let Ok(mut inp) = <MyInput as arbitrary::Arbitrary>::arbitrary(&mut __hm_u)", inlined_typed)

        # Standalone fn main() returns source unchanged
        main_src = "fn main() {\n    let _ = 1 + 1;\n}\n"
        self.assertEqual(rust_support.inline_rust_direct_input(main_src, payload), main_src)

        # Ignored parameter returns source unchanged
        unused_src = "pub fn fuzz_target(_: &[u8]) {}\n"
        self.assertEqual(rust_support.inline_rust_direct_input(unused_src, payload), unused_src)

    def test_no_main_scaffold_preserves_harness_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _make_rust_workspace(root / "repo")
            target_dir = root / "target"
            harness = root / "harness_007.rs"
            harness.write_text(
                "#![no_main]\n"
                "fuzz_target!(|data: &[u8]| {\n"
                "    let _ = demo_lib::parse(data);\n"
                "});\n",
                encoding="utf-8",
            )
            cfg = rust_support.parse_rust_minimizer_flags(
                f"--rust-project-dir={ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
                "",
            )
            scaffold_dir = rust_support.scaffold_rust_candidate_crate(
                str(harness), root / "scaffold", cfg
            )
            copied = scaffold_dir / "harnesses" / "harness_007.rs"
            self.assertTrue(copied.is_file())
            self.assertFalse((scaffold_dir / "src" / "harness.rs").exists())
            lib_rs = (scaffold_dir / "src" / "lib.rs").read_text(encoding="utf-8")
            self.assertIn("harness_007.rs", lib_rs)
            # Preserving the blank line where #![no_main] was stripped keeps line numbers identical.
            self.assertEqual(
                len(copied.read_text(encoding="utf-8").splitlines()),
                len(harness.read_text(encoding="utf-8").splitlines()),
            )


class TestRustBuildScaffoldingAndCompilation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ws = _make_rust_workspace(self.root / "project")

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_flags_discover_crates_and_scaffold(self):
        target_dir = self.root / "target"
        cfg = rust_support.parse_rust_minimizer_flags(
            f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} "
            "--rust-target=x86_64-unknown-linux-gnu --rust-features=simd --rust-no-default-features "
            "--rust-asan --rust-sanitizer=address -C target-cpu=native",
            "-lz",
        )
        self.assertEqual(cfg.project_dir, str(self.ws.resolve()))
        self.assertEqual(cfg.target_dir, str(target_dir.resolve()))
        self.assertEqual(cfg.target_triple, "x86_64-unknown-linux-gnu")
        self.assertEqual(cfg.features, ("simd",))
        self.assertTrue(cfg.no_default_features)
        self.assertTrue(cfg.use_asan)
        self.assertEqual(cfg.sanitizer, "address")
        self.assertEqual(cfg.rustc_flags, ("-C", "target-cpu=native"))
        self.assertEqual(cfg.linker_args, ("-lz",))

        crates = rust_support.discover_rust_crates(str(self.ws))
        self.assertEqual([c.name for c in crates], ["demo-lib"])
        self.assertEqual(crates[0].lib_name, "demo_lib")

        harness = self.root / "harness_000.rs"
        harness.write_text(
            "use demo_lib::parse;\n"
            "pub fn fuzz_target(data: &[u8]) { let _ = parse(data); }\n",
            encoding="utf-8",
        )
        crate_dir = rust_support.scaffold_rust_candidate_crate(
            str(harness), self.root / "scaffold", cfg, crates=crates
        )
        manifest = tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["dependencies"]["demo-lib"]["features"], ["simd"])
        self.assertFalse(manifest["dependencies"]["demo-lib"]["default-features"])
        self.assertEqual(
            manifest["patch"]["crates-io"]["local-helper"]["path"],
            str((self.ws / "vendor" / "local-helper").resolve()),
        )
        self.assertTrue((crate_dir / "Cargo.lock").is_file())
        cargo_cfg = (crate_dir / ".cargo" / "config.toml").read_text(encoding="utf-8")
        self.assertIn(str((self.ws / "vendor").resolve()), cargo_cfg)
        driver_rs = (crate_dir / "src" / "bin" / "poc_driver.rs").read_text(encoding="utf-8")
        self.assertIn("std::process::exit(77)", driver_rs)
        self.assertIn("Backtrace::force_capture()", driver_rs)

        # Exported PoC mode (panic_exit_code=None) must NOT catch_unwind/exit(77)
        # and must set panic="abort" even without ASan so casr-gdb/GDB catch SIGABRT.
        cfg_no_asan = rust_support.parse_rust_minimizer_flags(
            f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
            "",
        )
        poc_crate = rust_support.scaffold_rust_candidate_crate(
            str(harness),
            self.root / "poc_export_scaffold",
            cfg_no_asan,
            crates=crates,
            panic_exit_code=None,
            bin_name="poc",
        )
        poc_manifest = tomllib.loads((poc_crate / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(poc_manifest["profile"]["dev"]["panic"], "abort")
        poc_driver = (poc_crate / "src" / "bin" / "poc.rs").read_text(encoding="utf-8")
        self.assertNotIn("catch_unwind", poc_driver)
        self.assertNotIn("exit(77)", poc_driver)
        self.assertIn("hm_rust_harness::__hm_run(&data);", poc_driver)
        export_env, export_flags = rust_support._rust_build_env(cfg_no_asan, force_panic_abort=True)
        self.assertIn("panic=abort", export_flags)
        self.assertIn("panic=abort", export_env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"])
        with mock.patch.dict(os.environ, {"CARGO_ENCODED_RUSTFLAGS": "-Copt-level=1"}):
            with self.assertRaisesRegex(RuntimeError, "CARGO_ENCODED_RUSTFLAGS"):
                rust_support._rust_build_env(cfg_no_asan)
        with (
            mock.patch.dict(os.environ, {"RUSTUP_TOOLCHAIN": "nightly-2026-11-01"}),
            mock.patch.object(rust_support.shutil, "which", return_value="/toolchain/rustup"),
        ):
            with self.assertRaisesRegex(RuntimeError, "RUSTUP_TOOLCHAIN"):
                rust_support._rust_build_env(cfg)

    def test_extract_direct_plan_and_compile_candidate_fast_path_and_fallback(self):
        target_dir = self.root / "target"
        deps_dir = target_dir / "x86_64-unknown-linux-gnu" / "debug" / "deps"
        deps_dir.mkdir(parents=True)
        rlib = deps_dir / "libdemo_lib-1234.rlib"
        rlib.write_bytes(b"rlib")

        cfg = rust_support.parse_rust_minimizer_flags(
            f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
            "",
        )
        crates = rust_support.discover_rust_crates(str(self.ws))
        cargo_json = "\n".join([
            json.dumps({
                "reason": "compiler-artifact",
                "target": {"name": "demo-lib", "kind": ["lib"]},
                "filenames": [str(rlib)],
            }),
            json.dumps({
                "reason": "build-script-executed",
                "linked_paths": ["native=/opt/native/lib"],
            }),
        ])
        plan = rust_support._extract_direct_plan_from_cargo_json(cargo_json, crates, cfg)
        self.assertEqual(plan["externs"], {"demo_lib": str(rlib)})
        self.assertEqual(plan["native_dirs"], ["native=/opt/native/lib"])
        self.assertEqual(plan["deps_dir"], str(deps_dir))

        plan_file = self.root / rust_support.RUST_DIRECT_PLAN_FILE
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        candidate = self.root / "cand.rs"
        candidate.write_text("pub fn fuzz_target(data: &[u8]) { let _ = data.len(); }\n", encoding="utf-8")
        out_bin = self.root / "cand.out"

        seen_cmds: list[list[str]] = []

        def fake_rustc(cmd, **_kwargs):
            if Path(cmd[0]).name == "rustc" and "-vV" in cmd:
                return SimpleNamespace(returncode=0, stdout="rustc 1.82.0\nhost: x86_64-unknown-linux-gnu\n", stderr="")
            seen_cmds.append(list(cmd))
            if Path(cmd[0]).name == "rustc":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"ELF-RUSTC")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            # Cargo fallback path uses unique per-candidate --bin names
            bin_name = cmd[cmd.index("--bin") + 1]
            built = target_dir / "x86_64-unknown-linux-gnu" / "debug" / bin_name
            built.parent.mkdir(parents=True, exist_ok=True)
            built.write_bytes(b"ELF-CARGO")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        # 1. Direct rustc fast path via plan file
        with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc):
            rc, cmd, err = rust_support.compile_rust_candidate(
                str(candidate),
                str(out_bin),
                f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-plan-file={plan_file}",
                "",
            )
        self.assertEqual(rc, 0, err)
        self.assertEqual(cmd[0], "rustc")
        self.assertIn(f"demo_lib={rlib}", cmd)
        self.assertEqual(out_bin.read_bytes(), b"ELF-RUSTC")

        # 1b. Direct rustc fast path discovered automatically next to candidate.rs (direct CLI usage)
        out_bin_auto = self.root / "cand_auto.out"
        with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc):
            rc_auto, cmd_auto, err_auto = rust_support.compile_rust_candidate(
                str(candidate),
                str(out_bin_auto),
                f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
                "",
            )
        self.assertEqual(rc_auto, 0, err_auto)
        self.assertEqual(cmd_auto[0], "rustc")
        self.assertEqual(out_bin_auto.read_bytes(), b"ELF-RUSTC")

        # 2. Fallback to cargo --offline when no plan file exists uses unique bin names per call
        plan_file.unlink()
        out_bin2 = self.root / "cand2.out"
        out_bin3 = self.root / "cand3.out"
        with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc):
            rc2, cmd2, err2 = rust_support.compile_rust_candidate(
                str(candidate),
                str(out_bin2),
                f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
                "",
            )
            rc3, cmd3, err3 = rust_support.compile_rust_candidate(
                str(candidate),
                str(out_bin3),
                f"--rust-project-dir={self.ws} --rust-target-dir={target_dir} --rust-target=x86_64-unknown-linux-gnu",
                "",
            )
        self.assertEqual(rc2, 0, err2)
        self.assertEqual(rc3, 0, err3)
        self.assertEqual(cmd2[0], "cargo")
        self.assertIn("--offline", cmd2)
        bin2 = cmd2[cmd2.index("--bin") + 1]
        bin3 = cmd3[cmd3.index("--bin") + 1]
        self.assertTrue(bin2.startswith("poc_driver_"))
        self.assertTrue(bin3.startswith("poc_driver_"))
        self.assertNotEqual(bin2, bin3)
        self.assertEqual(out_bin2.read_bytes(), b"ELF-CARGO")
        self.assertEqual(out_bin3.read_bytes(), b"ELF-CARGO")


class TestRustPanicAndBacktraceExtraction(unittest.TestCase):
    def test_panic_signature_matches_new_and_legacy_formats_without_dotall(self):
        new_out = (
            "thread 'main' panicked at crates/demo-lib/src/lib.rs:42:9:\n"
            "index out of bounds: the len is 2 but the index is 99\n"
            "stack backtrace:\n"
            "   0:     0x5555 - std::backtrace::Backtrace::force_capture\n"
            "             at /rustc/abc/library/std/src/backtrace.rs:330:18\n"
            "   1:     0x5556 - poc_driver::main::{{closure}}\n"
            "             at /tmp/work/src/bin/poc_driver.rs:12:5\n"
            "   2:     0x5557 - core::panicking::panic_bounds_check\n"
            "             at /rustc/abc/library/core/src/panicking.rs:101:5\n"
            "   3:     0x5558 - demo_lib::parse\n"
            "             at /src/crates/demo-lib/src/lib.rs:42:9\n"
            "   4:     0x5559 - hm_rust_harness::harness::fuzz_target\n"
            "             at /out/harnesses/harness_000.rs:10:5\n"
            "   5:     0x555a - hm_rust_harness::__hm_run\n"
            "             at /tmp/work/src/lib.rs:8:5\n"
        )
        sig = reducer_runner._extract_crash_signature_from_output(new_out)
        self.assertIsNotNone(sig)
        # Must match WITHOUT re.DOTALL (exact contract of crash_tester.py)
        self.assertIsNotNone(re.search(sig, new_out))
        # Must still match when numeric index changes slightly
        varied = new_out.replace("index is 99", "index is 17")
        self.assertIsNotNone(re.search(sig, varied))

        # Backtrace extraction must skip runtime frames and stop at harness
        trace = symbolized_trace.extract_stack_trace(new_out, harness_path="/out/harnesses/harness_000.rs")
        self.assertIsNotNone(trace)
        self.assertIn("demo_lib::parse", trace)
        self.assertNotIn("Backtrace::force_capture", trace)
        self.assertNotIn("poc_driver::main", trace)
        self.assertNotIn("harness_000.rs", trace)

        loc = reducer_runner.extract_symbolized_crash_location(
            new_out, harness_path="/out/harnesses/harness_000.rs"
        )
        self.assertEqual(loc, "/src/crates/demo-lib/src/lib.rs:42:9")
        self.assertIsNone(
            reducer_runner.extract_harness_crash_location(
                new_out, harness_path="/out/harnesses/harness_000.rs"
            )
        )

        # Legacy Rust <1.73 panic format
        old_out = (
            "thread 'main' panicked at 'attempt to subtract with overflow', "
            "crates/demo-lib/src/lib.rs:18:5\n"
        )
        old_sig = rust_support.extract_rust_panic_signature(old_out)
        self.assertIsNotNone(old_sig)
        self.assertIsNotNone(re.search(old_sig, old_out))

    def test_harness_panic_detected_as_harness_bug(self):
        harness_panic = (
            "thread 'main' panicked at /out/harnesses/harness_000.rs:7:13:\n"
            "index out of bounds: the len is 1 but the index is 10\n"
            "stack backtrace:\n"
            "   0:     0x5556 - core::panicking::panic_bounds_check\n"
            "             at /rustc/abc/library/core/src/panicking.rs:101:5\n"
            "   1:     0x5559 - hm_rust_harness::harness::fuzz_target\n"
            "             at /out/harnesses/harness_000.rs:7:13\n"
        )
        loc = reducer_runner.extract_harness_crash_location(
            harness_panic, harness_path="/out/harnesses/harness_000.rs"
        )
        self.assertEqual(loc, "/out/harnesses/harness_000.rs:7:13")


class TestRustApiPipelineMocked(unittest.TestCase):
    def test_rust_helpers_and_reduce_with_config_end_to_end_mocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir()
            harness = root / "harness_000.rs"
            harness.write_text(
                "// removable comment\n"
                "pub fn fuzz_target(data: &[u8]) {\n"
                "    let _ = data.len();\n"
                "}\n",
                encoding="utf-8",
            )
            crash_input = root / "crash-1"
            crash_input.write_bytes(b"\xde\xad\xbe\xef")

            # Verify safe no-op helpers for Rust
            prep = api._prepare_fuzzer_entry_return(str(harness), "", str(work))
            self.assertEqual(prep.path, str(harness))
            reducer_runner.configure_work_dir(str(work))
            tagged = api.tag_harness_with_fdp_ids(str(harness), start_id=100000, marker="FDP_ID")
            self.assertTrue(tagged.path.endswith(".tagged.rs"))
            self.assertEqual(Path(tagged.path).read_text(encoding="utf-8"), harness.read_text(encoding="utf-8"))
            self.assertEqual(tagged.fdp_callsite_count, 0)
            api._prepend_additional_headers(str(harness))
            self.assertNotIn("#include", harness.read_text(encoding="utf-8"))

            # End-to-end mocked reduce_with_config verifying Rust policy normalization
            plan_file = work / rust_support.RUST_DIRECT_PLAN_FILE
            captured_reducer_kwargs: dict[str, object] = {}

            def fake_check_compile(_h, _cf, _lf):
                plan_file.write_text(
                    json.dumps({"deps_dir": str(work), "externs": {"demo": str(work / "libdemo.rlib")}}),
                    encoding="utf-8",
                )

            def fake_run_reducer(src, _trace, _pat, cf, _lf, _inp, **kwargs):
                captured_reducer_kwargs["compile_flags"] = cf
                captured_reducer_kwargs.update(kwargs)
                reduced = work / "reduced_harness.rs"
                reduced.write_text(
                    "// comment to clean\npub fn fuzz_target(data: &[u8]) {\n    let _ = data[0];\n}\n",
                    encoding="utf-8",
                )
                return str(reduced)

            cfg = api.ReductionConfig(
                harness_path=str(harness),
                compile_flags=f"--rust-project-dir={root}",
                link_flags="",
                crash_input=str(crash_input),
                work_dir=str(work),
                compilation_mode="pch",  # must be normalized to direct for Rust
                amortize_link=True,      # must be normalized to False for Rust
                slice_enabled=True,      # must be normalized to False for Rust
                protect_initializers=True,  # must be normalized to False for Rust
                symbolize=True,
                jobs=2,
            )

            with (
                mock.patch.object(api, "check_perses", return_value=None),
                mock.patch.object(api, "check_harness_compilation", side_effect=fake_check_compile),
                mock.patch.object(api, "extract_crash_pattern_from_output", return_value=r"panicked at lib\.rs:1:1:\s*boom"),
                mock.patch.object(api, "get_reference_crash_pattern_symbolize_1", return_value=r"panicked at lib\.rs:1:1:\s*boom"),
                mock.patch.object(api, "check_reducer_symbolized_reduction_oracle", return_value=None),
                mock.patch.object(api, "run_treereducer", side_effect=fake_run_reducer),
                mock.patch.object(api, "format_reduced_harness", return_value=None),
                mock.patch.object(api, "_validate_post_reduction_harness", return_value=True),
            ):
                result = api.reduce_with_config(cfg)

            self.assertTrue(result.success, result.failure_reason)
            self.assertEqual(captured_reducer_kwargs["compilation_mode"], reducer_runner.PHASE3_DIRECT)
            self.assertEqual(captured_reducer_kwargs["tool"], "perses")
            self.assertFalse(captured_reducer_kwargs["amortize_link"])
            self.assertIn(f"--rust-plan-file={plan_file}", str(captured_reducer_kwargs["compile_flags"]))
            self.assertEqual(result.generated_headers, ())
            self.assertTrue(result.reduced_harness.endswith(".inline.rs"))
            inlined_text = Path(result.reduced_harness).read_text(encoding="utf-8")
            self.assertIn("const HM_INPUT_BYTES: &[u8] = &[", inlined_text)
            self.assertIn("0xde, 0xad, 0xbe, 0xef,", inlined_text)
            self.assertNotIn("// comment to clean", inlined_text)

    def test_format_reduced_harness_uses_rustfmt_not_clang_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            rs = Path(tmp) / "poc.rs"
            rs.write_text("pub fn fuzz_target(_: &[u8]) {}\n", encoding="utf-8")
            calls: list[list[str]] = []

            def fake_run(cmd, _msg, **_kwargs):
                calls.append(list(cmd))
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(reducer_runner.shutil, "which", side_effect=lambda name: "/usr/bin/rustfmt" if name == "rustfmt" else None),
                mock.patch.object(reducer_runner, "run_command", side_effect=fake_run),
            ):
                reducer_runner.format_reduced_harness(str(rs))
            self.assertEqual(calls, [["/usr/bin/rustfmt", str(rs)]])

    def test_round8_asan_abrt_prefers_rust_panic_and_real_asan_wins(self):
        # Safe Rust panic under ASan (handle_abort=1): prefer specific Rust panic signature over ABRT
        rust_panic_with_asan_abrt = (
            "thread 'main' panicked at crates/demo/src/lib.rs:42:9:\n"
            "index out of bounds: the len is 2 but the index is 99\n"
            "AddressSanitizer:DEADLYSIGNAL\n"
            "==123==ERROR: AddressSanitizer: ABRT on unknown address 0x00000001\n"
            "SUMMARY: AddressSanitizer: ABRT (/lib/libc.so.6+0x1234)\n"
        )
        sig = reducer_runner._extract_crash_signature_from_output(rust_panic_with_asan_abrt)
        self.assertIsNotNone(sig)
        self.assertNotIn("AddressSanitizer", sig)
        self.assertIn(r"crates/demo/src/lib\.rs:42:9", sig)
        self.assertIsNotNone(re.search(sig, rust_panic_with_asan_abrt))

        # Real ASan memory error must still take precedence over any panic text
        real_asan_hbo = (
            "thread 'main' panicked at crates/demo/src/lib.rs:10:1:\n"
            "prior message\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/lib.rs:55 in parse\n"
        )
        hbo_sig = reducer_runner._extract_crash_signature_from_output(real_asan_hbo)
        self.assertIsNotNone(hbo_sig)
        self.assertIn("heap\\-buffer\\-overflow", hbo_sig)

        # C/C++ ABRT without Rust panic still produces AddressSanitizer: ABRT
        cpp_abrt = "SUMMARY: AddressSanitizer: ABRT (/lib/libc.so.6+0x999)\n"
        cpp_sig = reducer_runner._extract_crash_signature_from_output(cpp_abrt)
        self.assertEqual(cpp_sig, r"(?:SUMMARY|ERROR):\s*AddressSanitizer:\s*ABRT(?![\w-])")

    def test_round8_symbolized_trace_stops_at_rust_wrapper_frames(self):
        asan_trace = (
            "    #0 0x55550001 in demo::parse /src/demo/src/lib.rs:42:9\n"
            "    #1 0x55550002 in demo::entry /src/demo/src/lib.rs:12:5\n"
            "    #2 0x55550003 in hm_rust_harness::harness::__hm_macro_entry /work/rust_ref_crate/src/lib.rs:14:9\n"
            "    #3 0x55550004 in hm_rust_harness::__hm_run /work/rust_ref_crate/src/lib.rs:16:1\n"
            "    #4 0x55550005 in poc_driver::main /work/rust_ref_crate/src/bin/poc_driver.rs:20:5\n"
        )
        extracted = symbolized_trace.extract_stack_trace(asan_trace, harness_path="/out/harnesses/harness_000.rs")
        self.assertIsNotNone(extracted)
        self.assertIn("demo::parse", extracted)
        self.assertIn("demo::entry", extracted)
        self.assertNotIn("__hm_macro_entry", extracted)
        self.assertNotIn("__hm_run", extracted)
        self.assertNotIn("poc_driver::main", extracted)

        rust_bt = (
            "stack backtrace:\n"
            "   0: demo::parse\n"
            "             at /src/demo/src/lib.rs:42:9\n"
            "   1: hm_rust_harness::harness::__hm_macro_entry\n"
            "             at /work/rust_ref_crate/src/lib.rs:14:9\n"
            "   2: poc_driver::main\n"
            "             at /work/rust_ref_crate/src/bin/poc_driver.rs:20:5\n"
        )
        bt_frames = rust_support.extract_rust_backtrace_frames(
            rust_bt, harness_path="/out/harnesses/harness_000.rs", stop_at_harness=True
        )
        self.assertEqual(len(bt_frames), 1)
        self.assertIn("demo::parse", bt_frames[0])

    def test_round8_compile_rust_reference_offline_first_and_locked_arbitrary_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "demo_crate"
            (proj / "src").mkdir(parents=True)
            (proj / "Cargo.toml").write_text(
                '[package]\nname = "demo_crate"\nversion = "0.1.0"\nedition = "2021"\n',
                encoding="utf-8",
            )
            (proj / "src" / "lib.rs").write_text("pub fn parse(_: &[u8]) {}\n", encoding="utf-8")
            (proj / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "arbitrary"\nversion = "1.4.2"\n',
                encoding="utf-8",
            )
            harness = root / "harness_000.rs"
            harness.write_text(
                "use arbitrary::Unstructured;\n"
                "pub fn fuzz_target(data: &[u8]) { let _ = Unstructured::new(data); }\n",
                encoding="utf-8",
            )
            work = root / "work"
            target_dir = root / "target"
            out_bin = work / "poc_driver"
            compile_flags = (
                f"--rust-project-dir={proj} --rust-target-dir={target_dir} "
                f"--rust-target=x86_64-unknown-linux-gnu"
            )

            # Case 1: --offline succeeds on first attempt and Cargo.toml pins arbitrary 1.4.2
            cmds: list[list[str]] = []

            def fake_run_offline_ok(cmd, **_kwargs):
                cmds.append(list(cmd))
                built = target_dir / "x86_64-unknown-linux-gnu" / "debug" / "poc_driver"
                built.parent.mkdir(parents=True, exist_ok=True)
                built.write_bytes(b"\x7fELF")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_run_offline_ok):
                rust_support.compile_rust_reference(
                    str(harness), compile_flags, "", str(out_bin), str(work)
                )
            self.assertEqual(len(cmds), 1)
            self.assertIn("--offline", cmds[0])
            cargo_toml = (work / "rust_ref_crate" / "Cargo.toml").read_text(encoding="utf-8")
            self.assertIn('arbitrary = { version = "1.4.2", features = ["derive"] }', cargo_toml)

            # Case 2: --offline cache miss triggers single online fallback
            cmds.clear()

            def fake_run_offline_miss_then_ok(cmd, **_kwargs):
                cmds.append(list(cmd))
                if "--offline" in cmd:
                    return SimpleNamespace(
                        returncode=101,
                        stdout="",
                        stderr="error: no matching package named `arbitrary` found (offline)",
                    )
                built = target_dir / "x86_64-unknown-linux-gnu" / "debug" / "poc_driver"
                built.parent.mkdir(parents=True, exist_ok=True)
                built.write_bytes(b"\x7fELF")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            clean_env = {k: v for k, v in os.environ.items() if k != "CARGO_NET_OFFLINE"}
            with (
                mock.patch.dict(os.environ, clean_env, clear=True),
                mock.patch.object(rust_support.subprocess, "run", side_effect=fake_run_offline_miss_then_ok),
            ):
                rust_support.compile_rust_reference(
                    str(harness), compile_flags, "", str(out_bin), str(work)
                )
            self.assertEqual(len(cmds), 2)
            self.assertIn("--offline", cmds[0])
            self.assertNotIn("--offline", cmds[1])

            # Case 3: Rust compile error under --offline does NOT retry online
            cmds.clear()

            def fake_run_compile_err(cmd, **_kwargs):
                cmds.append(list(cmd))
                return SimpleNamespace(
                    returncode=101,
                    stdout="",
                    stderr="error[E0308]: mismatched types",
                )

            with (
                mock.patch.dict(os.environ, clean_env, clear=True),
                mock.patch.object(rust_support.subprocess, "run", side_effect=fake_run_compile_err),
            ):
                with self.assertRaises(RuntimeError):
                    rust_support.compile_rust_reference(
                        str(harness), compile_flags, "", str(out_bin), str(work)
                    )
            self.assertEqual(len(cmds), 1)
            self.assertIn("--offline", cmds[0])

    def test_round9_direct_rustc_host_proc_macro_deps_arbitrary_and_cargo_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "demo_crate"
            (proj / "src").mkdir(parents=True)
            (proj / "Cargo.toml").write_text(
                '[package]\nname = "demo_crate"\nversion = "0.1.0"\nedition = "2021"\n',
                encoding="utf-8",
            )
            (proj / "src" / "lib.rs").write_text("pub fn parse(_: &[u8]) {}\n", encoding="utf-8")

            target_dir = root / "target"
            triple = "x86_64-unknown-linux-gnu"
            target_deps = target_dir / triple / "debug" / "deps"
            host_deps = target_dir / "debug" / "deps"
            target_deps.mkdir(parents=True)
            host_deps.mkdir(parents=True)
            demo_rlib = target_deps / "libdemo_crate-1111.rlib"
            arb_rlib = target_deps / "libarbitrary-2222.rlib"
            proc_so = host_deps / "libderive_arbitrary-3333.so"
            demo_rlib.write_bytes(b"rlib")
            arb_rlib.write_bytes(b"rlib")
            proc_so.write_bytes(b"so")

            cfg = rust_support.parse_rust_minimizer_flags(
                f"--rust-project-dir={proj} --rust-target-dir={target_dir} --rust-target={triple}",
                "",
            )
            crates = rust_support.discover_rust_crates(str(proj))

            # 1. Fresh-build fallback plan captures host_deps_dir, manifest_dir & arbitrary rlib
            plan = rust_support._extract_direct_plan_from_cargo_json(
                "", crates, cfg, harness_uses_arbitrary=True
            )
            self.assertEqual(plan["deps_dir"], str(target_deps))
            self.assertEqual(plan["host_deps_dir"], str(host_deps))
            self.assertEqual(plan["manifest_dir"], str(proj.resolve()))
            self.assertEqual(plan["externs"]["demo_crate"], str(demo_rlib))
            self.assertEqual(plan["externs"]["arbitrary"], str(arb_rlib))

            # 2. compile_rust_candidate passes both target & host -L dependency dirs and CARGO_MANIFEST_DIR
            work = root / "work"
            work.mkdir()
            plan_path = work / rust_support.RUST_DIRECT_PLAN_FILE
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            cand = root / "cand.rs"
            cand.write_text(
                "use arbitrary::Arbitrary;\n"
                "pub fn fuzz_target(data: &[u8]) { let _ = data; }\n",
                encoding="utf-8",
            )
            out_bin = root / "out_bin"
            seen_calls: list[tuple[list[str], dict | None]] = []

            def fake_rustc_ok(cmd, **kwargs):
                seen_calls.append((list(cmd), kwargs.get("env")))
                out_bin.write_bytes(b"\x7fELF")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            flags = f"--rust-project-dir={proj} --rust-target-dir={target_dir} --rust-target={triple} --rust-plan-file={plan_path}"
            with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc_ok):
                rc, cmd, err = rust_support.compile_rust_candidate(str(cand), str(out_bin), flags, "", work)
            self.assertEqual(rc, 0, err)
            self.assertIn(f"dependency={target_deps}", cmd)
            self.assertIn(f"dependency={host_deps}", cmd)
            self.assertEqual(seen_calls[0][1]["CARGO_MANIFEST_DIR"], str(proj.resolve()))

            # 3. Normal Rust syntax/type error fails fast without Cargo fallback or disabling direct mode
            seen_calls.clear()
            out_bin.unlink()

            def fake_rustc_type_err(cmd, **kwargs):
                seen_calls.append((list(cmd), kwargs.get("env")))
                return SimpleNamespace(returncode=1, stdout="", stderr="error[E0308]: mismatched types")

            with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc_type_err):
                rc, _cmd, err = rust_support.compile_rust_candidate(str(cand), str(out_bin), flags, "", work)
            self.assertNotEqual(rc, 0)
            self.assertEqual(len(seen_calls), 1)
            self.assertEqual(seen_calls[0][0][0], "rustc")
            self.assertFalse(json.loads(plan_path.read_text(encoding="utf-8")).get("direct_disabled", False))

            # 4. E0463 direct-rustc limitation falls back to isolated Cargo, succeeds, and disables direct mode
            seen_calls.clear()

            def fake_rustc_e0463_then_cargo_ok(cmd, **kwargs):
                seen_calls.append((list(cmd), kwargs.get("env")))
                if cmd[0] == "rustc":
                    return SimpleNamespace(
                        returncode=1,
                        stdout="",
                        stderr="error[E0463]: can't find crate for `derive_arbitrary`",
                    )
                bin_name = cmd[cmd.index("--bin") + 1]
                built = target_dir / triple / "debug" / bin_name
                built.parent.mkdir(parents=True, exist_ok=True)
                built.write_bytes(b"\x7fELF-CARGO")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc_e0463_then_cargo_ok):
                rc, _cmd, err = rust_support.compile_rust_candidate(str(cand), str(out_bin), flags, "", work)
            self.assertEqual(rc, 0, err)
            self.assertEqual(len(seen_calls), 2)
            self.assertEqual(seen_calls[0][0][0], "rustc")
            self.assertEqual(seen_calls[1][0][0], "cargo")
            self.assertTrue(json.loads(plan_path.read_text(encoding="utf-8")).get("direct_disabled"))

            # Subsequent candidate skips direct rustc and invokes Cargo directly
            seen_calls.clear()
            with mock.patch.object(rust_support.subprocess, "run", side_effect=fake_rustc_e0463_then_cargo_ok):
                rc, _cmd, err = rust_support.compile_rust_candidate(str(cand), str(out_bin), flags, "", work)
            self.assertEqual(rc, 0, err)
            self.assertEqual(len(seen_calls), 1)
            self.assertEqual(seen_calls[0][0][0], "cargo")

            # 5. Vendored .cargo/config.toml strips [source.crates-io] replace-with when injected arbitrary is absent
            (proj / ".cargo").mkdir()
            (proj / "vendor" / "serde-1.0.0").mkdir(parents=True)
            (proj / "vendor" / "serde-1.0.0" / "Cargo.toml").write_text('[package]\nname = "serde"\n', encoding="utf-8")
            (proj / ".cargo" / "config.toml").write_text(
                '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
                '[source.vendored-sources]\ndirectory = "vendor"\n\n'
                '[build]\njobs = 4\n',
                encoding="utf-8",
            )
            ws_no_extra = root / "ws_no_extra"
            rust_support._sync_cargo_config_and_lock(str(proj), ws_no_extra, extra_crates=())
            cfg_plain = (ws_no_extra / ".cargo" / "config.toml").read_text(encoding="utf-8")
            self.assertIn('replace-with = "vendored-sources"', cfg_plain)
            self.assertIn(str((proj / "vendor").resolve()), cfg_plain)

            ws_missing_arb = root / "ws_missing_arb"
            rust_support._sync_cargo_config_and_lock(str(proj), ws_missing_arb, extra_crates=("arbitrary",))
            cfg_stripped = (ws_missing_arb / ".cargo" / "config.toml").read_text(encoding="utf-8")
            self.assertNotIn("replace-with", cfg_stripped)
            self.assertIn("[build]", cfg_stripped)
            self.assertIn("jobs = 4", cfg_stripped)

            # 6. compile_rust_reference omits +nightly when rustup is absent even with --rust-asan
            asan_cmds: list[list[str]] = []

            def fake_asan_cargo(cmd, **_kwargs):
                asan_cmds.append(list(cmd))
                built = target_dir / triple / "debug" / "poc_driver"
                built.parent.mkdir(parents=True, exist_ok=True)
                built.write_bytes(b"\x7fELF")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            asan_flags = f"--rust-project-dir={proj} --rust-target-dir={target_dir} --rust-target={triple} --rust-asan"
            with (
                mock.patch.object(rust_support.shutil, "which", return_value=None),
                mock.patch.object(rust_support.subprocess, "run", side_effect=fake_asan_cargo),
            ):
                rust_support.compile_rust_reference(str(cand), asan_flags, "", str(out_bin), str(work / "no_rustup"))
            self.assertNotIn("+nightly", asan_cmds[0])

            asan_cmds.clear()
            with (
                mock.patch.object(rust_support.shutil, "which", side_effect=lambda name: "/usr/bin/rustup" if name == "rustup" else None),
                mock.patch.object(rust_support.subprocess, "run", side_effect=fake_asan_cargo),
            ):
                rust_support.compile_rust_reference(str(cand), asan_flags, "", str(out_bin), str(work / "with_rustup"))
            self.assertIn("+nightly", asan_cmds[0])

    def test_round10_runtime_only_frames_rejected_and_cfg_test_entry_detection(self):
        # 1. Runtime-only ASan/libc trace (raise + abort, with or without leading slash) must return None
        runtime_only_rel = (
            "==123==ERROR: AddressSanitizer: ABRT on unknown address 0x00000001\n"
            "    #0 0xaaa in raise raise.c:51:13\n"
            "    #1 0xbbb in abort abort.c:79:7\n"
            "SUMMARY: AddressSanitizer: ABRT (/lib/x86_64-linux-gnu/libc.so.6+0x42)\n"
        )
        self.assertIsNone(
            reducer_runner.extract_symbolized_crash_location(runtime_only_rel, harness_path="/out/harness_000.rs")
        )

        runtime_only_abs = (
            "==123==ERROR: AddressSanitizer: ABRT on unknown address 0x00000001\n"
            "    #0 0xaaa in __GI_raise /build/glibc/signal/../sysdeps/unix/sysv/linux/raise.c:51:1\n"
            "    #1 0xbbb in __GI_abort /build/glibc/stdlib/abort.c:79:7\n"
            "SUMMARY: AddressSanitizer: ABRT\n"
        )
        self.assertIsNone(
            reducer_runner.extract_symbolized_crash_location(runtime_only_abs, harness_path="/out/harness_000.rs")
        )

        rust_runtime_only = (
            "==123==ERROR: AddressSanitizer: ABRT\n"
            "    #0 0xaaa in core::panicking::panic /rustc/abc/library/core/src/panicking.rs:101:5\n"
            "    #1 0xbbb in std::panicking::rust_panic_with_hook /rustc/abc/library/std/src/panicking.rs:781:13\n"
            "SUMMARY: AddressSanitizer: ABRT\n"
        )
        self.assertIsNone(
            reducer_runner.extract_symbolized_crash_location(rust_runtime_only, harness_path="/out/harness_000.rs")
        )

        # 2. Runtime-only ASan stack PLUS Rust panic header falls through to the real Rust panic site
        panic_with_raise_abort = (
            "thread 'main' panicked at crates/demo/src/lib.rs:42:9:\n"
            "index out of bounds: the len is 1 but the index is 9\n"
            + runtime_only_abs
        )
        self.assertEqual(
            reducer_runner.extract_symbolized_crash_location(
                panic_with_raise_abort, harness_path="/out/harness_000.rs"
            ),
            "crates/demo/src/lib.rs:42:9",
        )

        # 3. detect_rust_entry_style ignores #[cfg(test)] items and nested module functions
        cfg_test_harness = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn main() {}\n"
            "    pub unsafe fn fuzz_target(_: &[u8]) {}\n"
            "}\n"
            "pub fn fuzz_target(data: &[u8]) { let _ = data; }\n"
        )
        self.assertEqual(rust_support.detect_rust_entry_style(cfg_test_harness), "fuzz_target_fn")

    def test_round11_audit_fixes_relative_paths_poc_driver_and_inner_attrs(self):
        # 1. Relative ./ and ../ Rust paths must not be truncated to /src/...
        rel_trace = (
            "==123==ERROR: AddressSanitizer: ABRT\n"
            "    #0 0xaaa in demo::parse ./src/lib.rs:42:9\n"
            "SUMMARY: AddressSanitizer: ABRT\n"
        )
        self.assertEqual(
            reducer_runner.extract_symbolized_crash_location(rel_trace, harness_path="/out/harness_000.rs"),
            "./src/lib.rs:42:9",
        )
        parent_rel_trace = (
            "==123==ERROR: AddressSanitizer: ABRT\n"
            "    #0 0xaaa in demo::parse ../crates/demo/src/lib.rs:42:9\n"
            "SUMMARY: AddressSanitizer: ABRT\n"
        )
        self.assertEqual(
            reducer_runner.extract_symbolized_crash_location(parent_rel_trace, harness_path="/out/harness_000.rs"),
            "../crates/demo/src/lib.rs:42:9",
        )
        abs_trace = (
            "==123==ERROR: AddressSanitizer: ABRT\n"
            "    #0 0xaaa in demo::parse /root/src/repo/src/lib.rs:42:9\n"
            "SUMMARY: AddressSanitizer: ABRT\n"
        )
        self.assertEqual(
            reducer_runner.extract_symbolized_crash_location(abs_trace, harness_path="/out/harness_000.rs"),
            "/root/src/repo/src/lib.rs:42:9",
        )

        # 2. poc_driver::harness::* is harness code (not runtime), while poc_driver::main is runtime
        self.assertFalse(rust_support.is_rust_runtime_frame("poc_driver::harness::fuzz_target", "harness_000.rs:12"))
        self.assertTrue(rust_support.is_rust_runtime_frame("poc_driver::main", "src/main.rs:88"))
        self.assertTrue(rust_support.is_rust_runtime_frame("poc_driver::main::{{closure}}", "src/main.rs:90"))

        harness_crash_trace = (
            "thread 'main' panicked at /out/harness_000.rs:12:5:\n"
            "explicit panic\n"
            "stack backtrace:\n"
            "   0: std::panicking::begin_panic_handler\n"
            "             at /rustc/abc/library/std/src/panicking.rs:645:5\n"
            "   1: poc_driver::harness::fuzz_target\n"
            "             at /out/harness_000.rs:12:5\n"
            "   2: poc_driver::main\n"
            "             at /tmp/work/src/main.rs:80:9\n"
        )
        self.assertEqual(
            reducer_runner.extract_harness_crash_location(harness_crash_trace, harness_path="/out/harness_000.rs"),
            "/out/harness_000.rs:12:5",
        )
        # stop_at_harness=True must stop at poc_driver::harness::fuzz_target (returning no frames after it)
        bt_with_harness_crash = (
            "stack backtrace:\n"
            "   0: demo::parse\n"
            "             at /repo/src/lib.rs:99:1\n"
            "   1: poc_driver::harness::fuzz_target\n"
            "             at /out/harness_000.rs:12:5\n"
            "   2: demo::should_not_appear\n"
            "             at /repo/src/after.rs:1:1\n"
        )
        frames = rust_support.extract_rust_backtrace_frames(
            bt_with_harness_crash, harness_path="/out/harness_000.rs", stop_at_harness=True
        )
        self.assertEqual(len(frames), 1)
        self.assertIn("demo::parse", frames[0])

        # 3. Rust 2024 inner attributes inside included fuzz_target! harness are not blocked by `use crate::fuzz_target;`
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "repo"
            (proj / "src").mkdir(parents=True)
            (proj / "Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2024"\n',
                encoding="utf-8",
            )
            (proj / "src" / "lib.rs").write_text("pub fn parse(_: &[u8]) {}\n", encoding="utf-8")
            cand = root / "harness_000.rs"
            cand.write_text(
                "#![allow(unused)]\n"
                "fuzz_target!(|data: &[u8]| {\n"
                "    demo::parse(data);\n"
                "});\n",
                encoding="utf-8",
            )
            ws = rust_support.scaffold_rust_candidate_crate(
                str(cand),
                root / "ws",
                rust_support.RustBuildConfig(
                    project_dir=str(proj),
                    target_dir=str(root / "target"),
                    target_triple="x86_64-unknown-linux-gnu",
                ),
            )
            lib_rs = (ws / "src" / "lib.rs").read_text(encoding="utf-8")
            self.assertIn("pub mod harness {", lib_rs)
            self.assertNotIn("use crate::fuzz_target;", lib_rs)
            direct_main = rust_support._rust_driver_main_source("fuzz_target_macro", include_path=str(cand))
            self.assertIn("pub mod harness {", direct_main)
            self.assertNotIn("use crate::fuzz_target;", direct_main)


if __name__ == "__main__":
    unittest.main()
