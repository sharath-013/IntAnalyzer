"""Command-line interface (Typer)."""

from __future__ import annotations

import platform
import subprocess
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table

from intanalyze import __version__
from intanalyze.llm import LLMError, LLMUnavailable, LMStudioClient, explain_report, llm_model
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

# Factory for the LLM client; tests swap in FakeLLM.
make_llm_client = LMStudioClient


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


def _explain(report: Report, *, no_llm: bool, model: str | None) -> None:
    """Ask the local model to explain CHANGED/SUSPICIOUS findings (rules already decided)."""
    if no_llm:
        explain_report(report, None)
        return
    client = make_llm_client(model=model)
    try:
        try:
            loaded = client.models()
        except LLMUnavailable as exc:
            err.print(f"[yellow]warning:[/] {exc}; using rule explanations only")
            explain_report(report, None)
            report.llm.server, report.llm.reason = client.server, str(exc)
            return
        except LLMError:
            loaded = []
        if client.model not in loaded:
            err.print(
                f"[yellow]note:[/] {client.model} is not listed as loaded on {client.server}; "
                "LM Studio may load it on first use"
            )
        todo = sum(1 for f in report.findings if f.verdict is not Verdict.EXPECTED)
        with Progress(
            TextColumn("explaining findings with {task.fields[model]}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=err,
            transient=True,
        ) as bar:
            task = bar.add_task("explain", total=min(todo, 25), model=client.model)
            explain_report(
                report,
                client,
                on_progress=lambda done, total: bar.update(task, completed=done),
                warn=lambda msg: err.print(f"[yellow]warning:[/] {msg}"),
            )
    finally:
        close = getattr(client, "close", None)
        if close:
            close()


@app.command()
def doctor() -> None:
    """Check the local LLM server, the configured model, git and Python."""
    client = make_llm_client()
    table = Table("check", "result", show_header=False)
    table.add_row("intanalyze", __version__)
    table.add_row("python", platform.python_version())
    try:
        git = subprocess.run(
            ["git", "--version"], capture_output=True, text=True, check=False, timeout=10
        ).stdout.strip()
    except OSError:
        git = ""
    table.add_row("git", git or "[red]not found[/] (needed to fetch sources)")
    table.add_row("LLM server", client.server)
    table.add_row("configured model", client.model)
    try:
        loaded = client.models()
    except LLMError as exc:
        table.add_row("reachable", f"[red]no[/] ({exc})")
        table.add_row("", "start it with: lms server start && lms load " + llm_model())
        table.add_row("", "IntAnalyze still works without it (rule explanations only)")
    else:
        table.add_row("reachable", "[green]yes[/]")
        table.add_row("loaded models", ", ".join(loaded) or "(none)")
        ok = client.model in loaded
        table.add_row(
            "model loaded",
            "[green]yes[/]" if ok else f"[yellow]no[/] (run: lms load {client.model})",
        )
    finally:
        close = getattr(client, "close", None)
        if close:
            close()
    out.print(table)


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
    model: str = typer.Option(
        None, "--model", help="Model id on the LM Studio server (default: qwen/qwen3.5-9b)."
    ),
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

    _explain(report, no_llm=no_llm, model=model)

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
