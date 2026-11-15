"""Unit tests for ci_time.py."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import ci_time
from ci_time import ReportError, report, required_jobs

START = "2026-11-14T10:00:00Z"


def job(name: str, created: str, started: str, completed: str, **extra: str) -> str:
    """Return one job as a line of `gh api ... --jq '.jobs[]'` output."""
    record = {
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "created_at": f"2026-11-14T10:{created}Z",
        "started_at": f"2026-11-14T10:{started}Z",
        "completed_at": f"2026-11-14T10:{completed}Z",
    }
    record.update(extra)
    return json.dumps(record)


class RequiredJobsTest(unittest.TestCase):
    """Which jobs count, and what is refused."""

    def test_keeps_only_the_required_jobs(self) -> None:
        """Jobs that are not required are left out."""
        lines = [
            job("check", "00:00", "00:10", "05:00"),
            job("coverage", "00:00", "00:10", "09:00"),
        ]
        self.assertEqual([j.name for j in required_jobs(lines, ["check"])], ["check"])

    def test_refuses_a_missing_job(self) -> None:
        """A required job that is not in the run is an error."""
        with self.assertRaisesRegex(ReportError, "no job named 'deny'"):
            required_jobs([job("check", "00:00", "00:10", "05:00")], ["check", "deny"])

    def test_refuses_a_job_that_did_not_succeed(self) -> None:
        """A run with a failed required job has no critical path."""
        lines = [job("check", "00:00", "00:10", "05:00", conclusion="failure")]
        with self.assertRaisesRegex(ReportError, "did not succeed"):
            required_jobs(lines, ["check"])

    def test_refuses_two_jobs_with_one_name(self) -> None:
        """Two jobs with one name cannot be told apart."""
        lines = [job("check", "00:00", "00:10", "05:00")] * 2
        with self.assertRaisesRegex(ReportError, "two jobs"):
            required_jobs(lines, ["check"])

    def test_refuses_a_timestamp_without_a_zone(self) -> None:
        """A timestamp without a time zone is ambiguous."""
        line = json.dumps(
            {
                "name": "check",
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-11-14T10:00:00",
                "started_at": "2026-11-14T10:00:00Z",
                "completed_at": "2026-11-14T10:01:00Z",
            }
        )
        with self.assertRaisesRegex(ReportError, "no time zone"):
            required_jobs([line], ["check"])

    def test_refuses_a_line_that_is_not_json(self) -> None:
        """A line that is not JSON is an error."""
        with self.assertRaisesRegex(ReportError, "not JSON"):
            required_jobs(["{"], ["check"])


class ReportTest(unittest.TestCase):
    """The critical path and the table."""

    def test_critical_path_counts_from_the_start_of_the_run(self) -> None:
        """The runner queue counts, and the slowest job comes first."""
        jobs = required_jobs(
            [job("check", "00:00", "00:30", "05:00"), job("image", "00:00", "03:00", "07:15")],
            ["check", "image"],
        )
        start = ci_time.timestamp({"run_started_at": START}, "run_started_at")
        text, critical = report(start, jobs, timedelta(minutes=10))
        self.assertEqual(critical, timedelta(minutes=7, seconds=15))
        self.assertIn("Within the budget of 10:00", text)
        # The slowest first, with its queue shown apart from its run.
        self.assertLess(text.index("| image | 3:00 | 4:15 | 7:15 |"), text.index("| check |"))


class MainTest(unittest.TestCase):
    """The exit code, the summary and the annotation."""

    def run_main(self, jobs: list[str], budget: int) -> tuple[int, str, str]:
        """Run main() on a run that started at START; return its code, output and summary."""
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory, "run.json")
            run.write_text(json.dumps({"run_started_at": START}), encoding="utf-8")
            listing = Path(directory, "jobs.jsonl")
            listing.write_text("\n".join(jobs) + "\n", encoding="utf-8")
            summary = Path(directory, "summary.md")
            argv = [
                "ci_time.py",
                *("--run", str(run), "--jobs", str(listing)),
                *("--budget-minutes", str(budget), "--require", "check"),
                *("--summary", str(summary)),
            ]
            out = io.StringIO()
            with mock.patch("sys.argv", argv), contextlib.redirect_stdout(out):
                code = ci_time.main()
            written = summary.read_text(encoding="utf-8") if summary.exists() else ""
            return code, out.getvalue(), written

    def test_passes_within_the_budget(self) -> None:
        """Within the budget: exit 0, a summary and no annotation."""
        code, out, summary = self.run_main([job("check", "00:00", "00:05", "04:00")], 10)
        self.assertEqual(code, 0)
        self.assertNotIn("::error::", out)
        self.assertIn("Critical path to the required checks: 4:00", summary)

    def test_fails_over_the_budget(self) -> None:
        """Over the budget: exit 1, with an error annotation."""
        code, out, summary = self.run_main([job("check", "00:00", "00:05", "11:00")], 10)
        self.assertEqual(code, 1)
        self.assertIn("::error::the required checks took 11:00", out)
        self.assertIn("Over the budget", summary)

    def test_a_broken_measurement_fails_without_a_report(self) -> None:
        """A missing required job fails with exit 2 and writes no summary."""
        code, out, summary = self.run_main([job("deny", "00:00", "00:05", "01:00")], 10)
        self.assertEqual(code, 2)
        self.assertIn("::error::cannot measure the critical path", out)
        self.assertEqual(summary, "")


if __name__ == "__main__":
    unittest.main()
