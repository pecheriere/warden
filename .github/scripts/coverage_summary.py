"""Print a Markdown coverage report from the JSON summary `cargo llvm-cov report` writes.

Usage: coverage_summary.py <coverage.json> --root <workspace root>

The total comes from llvm-cov itself; this only adds the files up per crate and lists them.
Anything it cannot read is an error, so that a broken report never looks like a number.
"""

import argparse
import json
import sys
from pathlib import Path, PurePosixPath

METRICS = ("lines", "regions", "functions")

Counts = dict[str, tuple[int, int]]


class ReportError(Exception):
    """The coverage report is not what llvm-cov writes."""


def counts(summary: dict) -> Counts:
    """Return (covered, count) for each metric of a file's or the total's summary."""
    try:
        return {m: (int(summary[m]["covered"]), int(summary[m]["count"])) for m in METRICS}
    except (KeyError, TypeError, ValueError) as error:
        message = f"malformed summary: {error!r}"
        raise ReportError(message) from error


def percent(covered: int, count: int) -> str:
    """Format a ratio; nothing to cover is not the same as fully covered."""
    return f"{100 * covered / count:.2f}%" if count else "n/a"


def row(name: str, values: Counts) -> str:
    """Format one table row."""
    lines = values["lines"]
    cells = [
        f"`{name}`",
        percent(*lines),
        f"{lines[0]} / {lines[1]}",
        percent(*values["regions"]),
        percent(*values["functions"]),
    ]
    return "| " + " | ".join(cells) + " |"


def relative(filename: str, root: str) -> PurePosixPath:
    """Return a measured file's path within the workspace."""
    try:
        return PurePosixPath(filename).relative_to(root)
    except ValueError as error:
        message = f"{filename} is outside the workspace"
        raise ReportError(message) from error


def crate_of(path: PurePosixPath) -> str:
    """Return the crate a workspace file belongs to."""
    match path.parts:
        case ("crates", name, _, *_):
            return name
        case _:
            message = f"{path} is not in a crate"
            raise ReportError(message)


def add_up(files: list[tuple[PurePosixPath, Counts]]) -> dict[str, Counts]:
    """Sum the files of each crate."""
    crates: dict[str, Counts] = {}
    for path, values in files:
        crate = crates.setdefault(crate_of(path), dict.fromkeys(METRICS, (0, 0)))
        for metric in METRICS:
            covered, count = crate[metric]
            crate[metric] = (covered + values[metric][0], count + values[metric][1])
    return crates


def worst_first(item: tuple[PurePosixPath, Counts]) -> tuple[float, str]:
    """Sort key: lowest line coverage first, then by path."""
    covered, count = item[1]["lines"]
    return (covered / count if count else 1.0, str(item[0]))


def render(report: dict, root: str) -> str:
    """Render the report as Markdown: the total, each crate, then each file."""
    try:
        data = report["data"][0]
        totals = counts(data["totals"])
        files = [(relative(f["filename"], root), counts(f["summary"])) for f in data["files"]]
    except (KeyError, IndexError, TypeError) as error:
        message = f"malformed report: {error!r}"
        raise ReportError(message) from error
    if not files:
        message = "the report measured no files"
        raise ReportError(message)

    crates = add_up(files)
    header = [
        "| | Lines | Covered / total | Regions | Functions |",
        "|---|---:|---:|---:|---:|",
    ]
    return "\n".join(
        [
            "## Test coverage",
            "",
            *header,
            row("total", totals),
            *(row(name, crates[name]) for name in sorted(crates)),
            "",
            "<details><summary>Files, lowest line coverage first</summary>",
            "",
            *header,
            *(row(str(path), values) for path, values in sorted(files, key=worst_first)),
            "",
            "</details>",
            "",
        ],
    )


def main() -> int:
    """Print the report, or say why it could not be read."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        print(render(report, args.root))
    except (OSError, ValueError, ReportError) as error:
        print(f"::error::cannot read the coverage report: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
