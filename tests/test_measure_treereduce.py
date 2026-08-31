import json
import unittest

from measure_treereduce import (
    aggregate_runs,
    duration_ns,
    parse_jobs,
    parse_treereduce_log,
)


class TestMeasureTreereduce(unittest.TestCase):
    def test_duration_parser_supports_tracing_units(self):
        self.assertEqual(duration_ns("12ns"), 12)
        self.assertEqual(duration_ns("1.5µs"), 1_500)
        self.assertEqual(duration_ns("2.25ms"), 2_250_000)
        self.assertEqual(duration_ns("0.5s"), 500_000_000)

    def test_jobs_parser_deduplicates_and_validates(self):
        self.assertEqual(parse_jobs("1,4,4,16"), [1, 4, 16])
        with self.assertRaises(Exception):
            parse_jobs("64")

    def test_log_parser_counts_initial_and_candidate_checks(self):
        events = [
            {
                "fields": {
                    "message": "Interesting? true",
                    "is_interesting": True,
                }
            },
            {
                "fields": {
                    "message": "Interesting? false",
                    "is_interesting": False,
                }
            },
            {
                "fields": {
                    "message": "close",
                    "time.busy": "2.0µs",
                    "time.idle": "3.0ms",
                },
                "span": {"name": "Waiting for command"},
            },
        ]
        parsed = parse_treereduce_log(
            "\n".join(json.dumps(event) for event in events)
        )

        self.assertEqual(parsed["total_checks"], 2)
        self.assertEqual(parsed["candidate_checks"], 1)
        self.assertEqual(parsed["outcomes"], {"interesting": 1, "uninteresting": 1})
        self.assertEqual(
            parsed["candidate_check_timing"]["mean_ns"],
            3_002_000,
        )

    def test_aggregate_reports_per_run_wall_time_and_weighted_latency(self):
        runs = [
            {
                "checker": "compile",
                "jobs": 2,
                "wall_ns": 2_000_000_000,
                "total_checks": 10,
                "candidate_checks": 9,
                "outcomes": {"interesting": 8, "uninteresting": 2},
                "candidate_check_timing": {
                    "mean_ns": 100_000_000,
                    "p95_ns": 120_000_000,
                },
            },
            {
                "checker": "compile",
                "jobs": 2,
                "wall_ns": 4_000_000_000,
                "total_checks": 30,
                "candidate_checks": 29,
                "outcomes": {"interesting": 27, "uninteresting": 3},
                "candidate_check_timing": {
                    "mean_ns": 200_000_000,
                    "p95_ns": 240_000_000,
                },
            },
        ]

        row = aggregate_runs(runs)[0]
        self.assertEqual(row["runs"], 2)
        self.assertEqual(row["mean_checks_per_run"], 20)
        self.assertEqual(row["mean_wall_seconds"], 3.0)
        self.assertAlmostEqual(
            row["mean_check_ms"],
            (9 * 100 + 29 * 200) / 38,
        )
        self.assertEqual(row["mean_run_p95_check_ms"], 180.0)


if __name__ == "__main__":
    unittest.main()
