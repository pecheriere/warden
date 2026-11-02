"""Unit tests for coverage_summary.py."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import coverage_summary
from coverage_summary import ReportError, render

ROOT = "/work/warden"


def summary(covered: int, count: int) -> dict:
    """Return a summary with the same numbers for every metric."""
    metric = {"covered": covered, "count": count}
    return {"lines": metric, "regions": metric, "functions": metric}


def report(files: dict[str, tuple[int, int]], totals: tuple[int, int] = (3, 4)) -> dict:
    """Return a report shaped like `llvm-cov export -summary-only`."""
    return {
        "data": [
            {
                "files": [
                    {"filename": f"{ROOT}/{name}", "summary": summary(*numbers)}
                    for name, numbers in files.items()
                ],
                "totals": summary(*totals),
            },
        ],
    }


class RenderTest(unittest.TestCase):
    """What the report says, and what it refuses."""

    def test_adds_up_each_crate_and_keeps_the_reported_total(self) -> None:
        """Crates are sums of their files; the total is llvm-cov's own."""
        text = render(
            report(
                {
                    "crates/broker/src/a.rs": (1, 2),
                    "crates/broker/src/b.rs": (2, 2),
                    "crates/cli/src/main.rs": (0, 4),
                },
                totals=(3, 8),
            ),
            ROOT,
        )
        self.assertIn("| `total` | 37.50% | 3 / 8 |", text)
        self.assertIn("| `broker` | 75.00% | 3 / 4 |", text)
        self.assertIn("| `cli` | 0.00% | 0 / 4 |", text)

    def test_lists_files_worst_first(self) -> None:
        """The largest gap is the first thing a reader sees."""
        text = render(
            report({"crates/broker/src/good.rs": (2, 2), "crates/broker/src/bad.rs": (0, 2)}),
            ROOT,
        )
        self.assertLess(text.index("bad.rs"), text.index("good.rs"))

    def test_a_file_with_nothing_to_cover_is_not_reported_as_covered(self) -> None:
        """Zero of zero is not 100%."""
        text = render(report({"crates/broker/src/empty.rs": (0, 0)}), ROOT)
        self.assertIn("| `crates/broker/src/empty.rs` | n/a | 0 / 0 |", text)

    def test_refuses_a_report_that_measured_nothing(self) -> None:
        """An empty run must not print a table."""
        with self.assertRaises(ReportError):
            render(report({}), ROOT)

    def test_refuses_a_file_outside_the_workspace(self) -> None:
        """A dependency in the numbers would make them mean something else."""
        bad = report({"crates/broker/src/a.rs": (1, 1)})
        bad["data"][0]["files"][0]["filename"] = "/elsewhere/a.rs"
        with self.assertRaises(ReportError):
            render(bad, ROOT)

    def test_refuses_a_file_outside_the_crates(self) -> None:
        """Every measured file must belong to a crate."""
        with self.assertRaises(ReportError):
            render(report({"src/a.rs": (1, 1)}), ROOT)

    def test_refuses_malformed_reports(self) -> None:
        """Missing data and missing or non-numeric metrics are all errors."""
        no_metric = report({"crates/broker/src/a.rs": (1, 1)})
        del no_metric["data"][0]["files"][0]["summary"]["lines"]
        not_a_number = report({"crates/broker/src/a.rs": (1, 1)})
        not_a_number["data"][0]["totals"]["lines"]["count"] = "many"
        for bad in ({}, {"data": []}, {"data": [{}]}, no_metric, not_a_number):
            with self.subTest(bad=bad), self.assertRaises(ReportError):
                render(bad, ROOT)


class MainTest(unittest.TestCase):
    """The exit status CI depends on."""

    def run_main(self, content: str) -> tuple[int, str]:
        """Run main() on a file with this content."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_text(content, encoding="utf-8")
            output = io.StringIO()
            argv = ["coverage_summary.py", str(path), "--root", ROOT]
            with mock.patch("sys.argv", argv), contextlib.redirect_stdout(output):
                return coverage_summary.main(), output.getvalue()

    def test_prints_a_valid_report(self) -> None:
        """A readable report exits 0 and prints the table."""
        status, output = self.run_main(json.dumps(report({"crates/cli/src/main.rs": (3, 4)})))
        self.assertEqual(status, 0)
        self.assertIn("| `cli` | 75.00% | 3 / 4 |", output)

    def test_fails_on_invalid_json(self) -> None:
        """Unparseable output fails the step with an annotation."""
        status, output = self.run_main("not json")
        self.assertEqual(status, 1)
        self.assertIn("::error::", output)


if __name__ == "__main__":
    unittest.main()
