import json
import tempfile
import unittest
from pathlib import Path

from harnessreducer.reduction_profile import (
    build_profile_summary,
    read_profile_events,
    render_profile_text,
    write_profile_summary,
)


def _event(
    *,
    start: int,
    end: int,
    result: int,
    compile_ns: int,
    compile_link_ns: int = 0,
    compile_success: bool | None = True,
) -> dict[str, object]:
    event: dict[str, object] = {
        "start_wall_ns": start,
        "end_wall_ns": end,
        "result_code": result,
        "source_bytes": 100,
        "durations_ns": {
            "python_import_ns": 10,
            "argument_setup_ns": 20,
            "compile_ns": compile_ns,
            "compile_link_ns": compile_link_ns,
            "link_ns": 30,
            "execute_ns": 40,
            "oracle_ns": 50,
            "total_ns": end - start,
        },
        "cpu_ns": {
            "children_user_ns": 60,
            "children_system_ns": 70,
        },
    }
    if compile_success is not None:
        event["compile_success"] = compile_success
    return event


class TestReductionProfile(unittest.TestCase):
    def test_summary_reports_throughput_results_and_parallelism(self):
        events = [
            _event(
                start=100,
                end=300,
                result=77,
                compile_ns=80,
                compile_link_ns=55,
                compile_success=True,
            ),
            _event(
                start=200,
                end=400,
                result=1,
                compile_ns=100,
                compile_link_ns=65,
                compile_success=False,
            ),
        ]

        summary = build_profile_summary(
            events,
            wall_ns=1_000_000_000,
            jobs=4,
            returncode=0,
            configuration={"jobs": 4, "phase3_mode": "pch"},
        )

        reducer = summary["reducer"]
        self.assertEqual(reducer["profiled_checks"], 2)
        self.assertEqual(reducer["checks_per_second"], 2.0)
        self.assertEqual(reducer["result_counts"], {"1": 1, "77": 1})
        self.assertEqual(reducer["max_in_flight_checks"], 2)
        self.assertAlmostEqual(reducer["mean_in_flight_checks"], 400 / 1_000_000_000)

        compile_stats = summary["candidate_timing"]["compile_ns"]
        self.assertEqual(compile_stats["count"], 1)
        self.assertEqual(compile_stats["mean_ns"], 80.0)

        compile_link_stats = summary["candidate_timing"]["compile_link_ns"]
        self.assertEqual(compile_link_stats["count"], 1)
        self.assertEqual(compile_link_stats["mean_ns"], 55.0)

    def test_reader_skips_malformed_lines_and_writer_emits_both_reports(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "candidate_profile.jsonl"
            json_path = Path(tmpdir) / "reduction_profile.json"
            text_path = Path(tmpdir) / "reduction_profile.txt"
            event = _event(start=10, end=20, result=-1, compile_ns=5)
            events_path.write_text(
                json.dumps(event) + "\nnot-json\n",
                encoding="utf-8",
            )

            events, malformed = read_profile_events(events_path)
            self.assertEqual(len(events), 1)
            self.assertEqual(malformed, 1)

            summary = write_profile_summary(
                events_path,
                json_path,
                text_path,
                wall_ns=100,
                jobs=1,
                returncode=0,
                configuration={
                    "jobs": 1,
                    "phase3_mode": "split",
                    "amortize_link": False,
                    "symbolize": False,
                    "stable": False,
                },
            )

            self.assertTrue(json_path.is_file())
            self.assertTrue(text_path.is_file())
            self.assertEqual(summary["reducer"]["malformed_event_lines"], 1)
            self.assertIn("checks_per_second", render_profile_text(summary))
            self.assertIn(
                "Compile-related rows use only candidates with compile_success=yes",
                render_profile_text(summary),
            )


if __name__ == "__main__":
    unittest.main()
