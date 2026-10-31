"""Command-line interface (Typer)."""

from __future__ import annotations

import typer
from rich.console import Console

from intanalyze import __version__

app = typer.Typer(
    name="intanalyze",
    help="Does the published npm package match its source? IntAnalyze tells you the difference.",
    no_args_is_help=True,
    add_completion=False,
)
err = Console(stderr=True)

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


@app.command()
def version() -> None:
    """Print the IntAnalyze version."""
    typer.echo(f"intanalyze {__version__}")


@app.command()
def check(spec: str = typer.Argument(None, help="Package to check, e.g. ms@2.1.3")) -> None:
    """Compare a published npm package with its source repository."""
    err.print("[red]error:[/] `check` is not implemented yet")
    raise typer.Exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    app()
