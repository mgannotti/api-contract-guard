"""Shared command-line scaffold.

Every engine in this pack exposes the same contract:

    python scripts/<engine>.py --input <path> --outdir <dir> [--format json md html]

Exit codes are stable so the skills can be chained or gated in an automation:

    0  pass       no finding above the review threshold
    1  review     something a human should look at
    2  block      at least one blocking finding
    3  error      evidence missing or unusable (never a silent success)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
from pathlib import Path
from typing import Callable, Sequence

from .findings import Report
from .io import EvidenceError, write_json, write_text
from .render import render_html, render_markdown

EXIT_PASS, EXIT_REVIEW, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2, 3

_VERDICT_EXIT = {"pass": EXIT_PASS, "review": EXIT_REVIEW, "block": EXIT_BLOCK}

DEFAULT_FORMATS = ("json", "md", "html")


def bootstrap() -> None:
    """Put the pack's ``lib`` directory on ``sys.path``.

    Each engine lives at ``skills/<slug>/scripts/<engine>.py``, so the shared
    library sits three levels up. This keeps the skills runnable straight from a
    clone with no install step and no environment variables.
    """
    lib_dir = Path(__file__).resolve().parents[1]
    if str(lib_dir) not in sys.path:
        sys.path.insert(0, str(lib_dir))


def utc_now() -> str:
    """Current UTC timestamp, overridable for reproducible tests and fixtures."""
    override = os.environ.get("SCOUTKIT_NOW")
    if override:
        return override
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_parser(*, skill: str, description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=skill, description=description)
    parser.add_argument("--input", required=True, help="Evidence file or directory to analyze.")
    parser.add_argument("--outdir", default="out", help="Directory to write artifacts into (default: ./out).")
    parser.add_argument("--basename", default=skill, help="Artifact filename stem (default: the skill slug).")
    parser.add_argument(
        "--format",
        nargs="+",
        choices=("json", "md", "html"),
        default=list(DEFAULT_FORMATS),
        help="Artifact formats to emit (default: json md html).",
    )
    parser.add_argument(
        "--fail-on",
        choices=("never", "review", "block"),
        default="never",
        help="Return a non-zero exit code at this verdict or worse (default: never).",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the stdout summary line.")
    return parser


def emit(report: Report, outdir: str | os.PathLike[str], basename: str, formats: Sequence[str], *, title: str) -> list[Path]:
    """Write the report in each requested format and return the artifact paths."""
    out = Path(outdir)
    written: list[Path] = []
    if "json" in formats:
        written.append(write_json(out / f"{basename}.json", report.to_dict()))
    if "md" in formats:
        written.append(write_text(out / f"{basename}.md", render_markdown(report, title=title)))
    if "html" in formats:
        written.append(write_text(out / f"{basename}.html", render_html(report, title=title)))
    return written


def resolve_exit_code(verdict: str, fail_on: str) -> int:
    """Map a verdict to a process exit code under the chosen gating policy."""
    if fail_on == "never":
        return EXIT_PASS
    if fail_on == "review":
        return _VERDICT_EXIT.get(verdict, EXIT_PASS)
    return EXIT_BLOCK if verdict == "block" else EXIT_PASS


def run(
    argv: Sequence[str] | None,
    *,
    skill: str,
    title: str,
    description: str,
    analyze: Callable[[argparse.Namespace], Report],
    extend: Callable[[argparse.ArgumentParser], None] | None = None,
) -> int:
    """Parse arguments, run ``analyze``, emit artifacts, and return an exit code."""
    parser = build_parser(skill=skill, description=description)
    if extend is not None:
        extend(parser)
    args = parser.parse_args(argv)

    try:
        report = analyze(args)
    except EvidenceError as exc:
        print(f"{skill}: evidence error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not report.generated_at:
        report.generated_at = utc_now()

    written = emit(report, args.outdir, args.basename, args.format, title=title)

    if not args.quiet:
        counts = report.counts()
        tally = " ".join(f"{level}={counts[level]}" for level in ("critical", "high", "medium", "low", "info"))
        print(f"{skill}: verdict={report.verdict} {tally}")
        for path in written:
            print(f"  wrote {path}")

    return resolve_exit_code(report.verdict, args.fail_on)
