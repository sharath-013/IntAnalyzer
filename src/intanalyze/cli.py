"""Command-line interface (Typer)."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from intanalyze import __version__
from intanalyze.models import PackageSpec, Report, Verdict
from intanalyze.pipeline import CheckError, check_offline, check_online
from intanalyze.score import exit_code

app = typer.Typer(
    name="intanalyze",
    help="Does the published npm package match its source? IntAnalyze tells you the difference.",
    no_args_is_help=True,
    add_completion=False,
)
out = Console()
err = Console(stderr=True)

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class Format(StrEnum):
    terminal = "terminal"
    json = "json"


class FailOn(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"
    never = "never"


@app.command()
def version() -> None:
    """Print the IntAnalyze version."""
    typer.echo(f"intanalyze {__version__}")


def _render_terminal(report: Report, console: Console) -> None:
    console.print(
        f"[bold]IntAnalyze[/] {report.package}  source: {report.source.repo_url} "
        f"@ {report.source.ref}  status: [bold]{report.status}[/] score: {report.score}"
    )
    table = Table("path", "verdict", "severity", "rules", "reason")
    for f in report.findings:
        if f.verdict is Verdict.EXPECTED:
            continue
        table.add_row(f.path, f.verdict, f.severity, ", ".join(f.rule_ids), f.reason)
    console.print(table)
    console.print(f"expected: {report.expected_counts}")


@app.command()
def check(
    spec: str = typer.Argument(None, help="Package to check, e.g. ms@2.1.3"),
    repo: str = typer.Option(
        None, "--repo", help="Source repository URL (overrides the registry)."
    ),
    ref: str = typer.Option(None, "--ref", help="Git tag or full commit sha to compare against."),
    tarball: Path = typer.Option(None, "--tarball", help="Offline mode: local package .tgz."),
    source: Path = typer.Option(None, "--source", help="Offline mode: local source directory."),
    registry_json: Path = typer.Option(
        None, "--registry-json", help="Offline mode: registry metadata JSON for the tarball."
    ),
    fmt: Format = typer.Option(Format.terminal, "--format", help="Output format."),
    out_path: Path = typer.Option(None, "--out", help="Write the report to this file."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Use rule explanations only."),
    fail_on: FailOn = typer.Option(
        FailOn.high, "--fail-on", help="Exit 1 if any finding is at or above this severity."
    ),
    keep_workdir: bool = typer.Option(False, "--keep-workdir", help="Keep downloaded files."),
) -> None:
    """Compare a published npm package with its source repository."""
    try:
        if tarball or source:
            if not (tarball and source):
                raise CheckError("offline mode needs both --tarball and --source")
            report = check_offline(
                tarball, source, registry_json=registry_json, keep_workdir=keep_workdir
            )
        else:
            if not spec:
                raise CheckError("give a package as <name>@<version>, or --tarball and --source")
            try:
                parsed = PackageSpec.parse(spec)
            except ValueError as exc:
                raise CheckError(str(exc)) from exc
            with err.status(f"checking {parsed}..."):
                report = check_online(parsed, repo=repo, ref=ref, keep_workdir=keep_workdir)
    except CheckError as exc:
        err.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    if fmt is Format.json:
        text = report.model_dump_json(indent=2)
        if out_path:
            out_path.write_text(text + "\n", encoding="utf-8")
        else:
            typer.echo(text)
    else:
        _render_terminal(report, out)
        if out_path:
            out_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")

    raise typer.Exit(exit_code(report.findings, fail_on.value))


if __name__ == "__main__":  # pragma: no cover
    app()
