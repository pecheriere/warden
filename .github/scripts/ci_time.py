"""Measure how long a pull request waited for the required checks of one workflow run.

Usage: ci_time.py --run <run.json> --jobs <jobs.jsonl> --budget-minutes <n>
                  --require <job name> [--require ...] [--summary <file>]

<run.json> is the run attempt as `GET /repos/{repo}/actions/runs/{id}/attempts/{n}` returns
it, and <jobs.jsonl> holds one job per line, as `gh api --paginate .../jobs --jq '.jobs[]'`
writes them. The critical path is the time from the start of the run to the moment the last
required job finished: what a pull request waits for, runner queue included. The report
splits each job's time into waiting for a runner and running, so that a slow queue is not
mistaken for a slow job.

Exits 1 when the critical path is over the budget, and 2 when the data is not what GitHub
writes or a required job is missing or did not succeed: a broken measurement never passes
as a fast one.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


class ReportError(Exception):
    """The run or its jobs are not what the GitHub API returns."""


@dataclass(frozen=True)
class Job:
    """A finished job's times."""

    name: str
    created: datetime
    started: datetime
    completed: datetime


def timestamp(record: dict, field: str) -> datetime:
    """Parse one of GitHub's ISO 8601 UTC timestamps."""
    value = record.get(field)
    if not isinstance(value, str):
        message = f"{field} is missing or not a string"
        raise ReportError(message)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        message = f"{field} is not a timestamp: {value!r}"
        raise ReportError(message) from error
    if parsed.tzinfo is None:
        message = f"{field} has no time zone: {value!r}"
        raise ReportError(message)
    return parsed


def run_start(path: Path) -> datetime:
    """Return when the run attempt started."""
    run = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(run, dict):
        message = "the run is not a JSON object"
        raise ReportError(message)
    return timestamp(run, "run_started_at")


def required_jobs(lines: list[str], names: list[str]) -> list[Job]:
    """Return the required jobs, all of which must have finished successfully."""
    found: dict[str, dict] = {}
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            message = f"line {number} is not JSON: {error}"
            raise ReportError(message) from error
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            message = f"line {number} is not a job"
            raise ReportError(message)
        if record["name"] in names:
            if record["name"] in found:
                message = f"two jobs are named {record['name']!r}"
                raise ReportError(message)
            found[record["name"]] = record
    jobs = []
    for name in names:
        record = found.get(name)
        if record is None:
            message = f"no job named {name!r} in this run"
            raise ReportError(message)
        if record.get("status") != "completed" or record.get("conclusion") != "success":
            message = f"{name!r} did not succeed, so the run has no critical path"
            raise ReportError(message)
        jobs.append(
            Job(
                name=name,
                created=timestamp(record, "created_at"),
                started=timestamp(record, "started_at"),
                completed=timestamp(record, "completed_at"),
            )
        )
    return jobs


def minutes(duration: timedelta) -> str:
    """Format a duration as m:ss."""
    seconds = max(0, round(duration.total_seconds()))
    return f"{seconds // 60}:{seconds % 60:02d}"


def report(run_started: datetime, jobs: list[Job], budget: timedelta) -> tuple[str, timedelta]:
    """Return the Markdown report and the critical path."""
    critical = max(job.completed for job in jobs) - run_started
    verdict = "over" if critical > budget else "within"
    lines = [
        f"### Critical path to the required checks: {minutes(critical)}",
        "",
        f"{verdict.capitalize()} the budget of {minutes(budget)}, from the start of the run.",
        "",
        "| Job | Waited for a runner | Ran | Done after |",
        "|---|---:|---:|---:|",
    ]
    lines += [
        f"| {job.name} | {minutes(job.started - job.created)} "
        f"| {minutes(job.completed - job.started)} | {minutes(job.completed - run_started)} |"
        for job in sorted(jobs, key=lambda job: job.completed, reverse=True)
    ]
    return "\n".join(lines) + "\n", critical


def main() -> int:
    """Measure, write the report, and fail over the budget."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--jobs", type=Path, required=True)
    parser.add_argument("--budget-minutes", type=int, required=True)
    parser.add_argument("--require", action="append", required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    if args.budget_minutes <= 0:
        parser.error("--budget-minutes must be positive")

    try:
        run_started = run_start(args.run)
        jobs = required_jobs(args.jobs.read_text(encoding="utf-8").splitlines(), args.require)
    except (OSError, json.JSONDecodeError, ReportError) as error:
        print(f"::error::cannot measure the critical path: {error}")
        return 2

    budget = timedelta(minutes=args.budget_minutes)
    text, critical = report(run_started, jobs, budget)
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(text)
    print(text)
    if critical > budget:
        print(
            f"::error::the required checks took {minutes(critical)}, over the budget of "
            f"{minutes(budget)}: see the table for whether a job or the runner queue was slow"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
