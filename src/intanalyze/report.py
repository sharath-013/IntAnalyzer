"""Render a Report as terminal output, Markdown, self-contained HTML or JSON."""

from __future__ import annotations

import io

from jinja2 import Environment, PackageLoader, StrictUndefined
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from intanalyze.models import Finding, Report, Severity, Status, Verdict
from intanalyze.rules import RULES

STATUS_STYLE = {Status.CLEAN: "bold green", Status.REVIEW: "bold yellow",
                Status.DANGEROUS: "bold red"}
SEVERITY_STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan",
                  Severity.INFO: "dim"}
VERDICT_STYLE = {Verdict.SUSPICIOUS: "red", Verdict.CHANGED: "yellow", Verdict.EXPECTED: "green"}
COUNT_LABELS = {
    "identical": "identical to the source",
    "build_output": "build output mapped to a source file",
    "docs": "docs differing only in case/whitespace",
    "manifest": "package.json matching the source",
    "only_in_source": "only in the source (tests, configs, not published)",
}


def flagged(report: Report) -> list[Finding]:
    """CHANGED and SUSPICIOUS findings, most severe first."""
    return sorted(
        (f for f in report.findings if f.verdict is not Verdict.EXPECTED),
        key=lambda f: (-f.severity.rank, f.verdict is not Verdict.SUSPICIOUS, f.path),
    )


def build_mappings(report: Report) -> list[Finding]:
    return [f for f in report.findings if f.verdict is Verdict.EXPECTED and f.mapped_source]


def integrity_text(report: Report) -> str:
    i = report.integrity
    if not i.checked:
        return "not checked (no registry integrity value)"
    return f"{i.algorithm} OK" if i.ok else f"{i.algorithm} MISMATCH"


def llm_text(report: Report) -> str:
    if report.llm.used:
        return f"yes: {report.llm.model} via {report.llm.server}"
    return f"no ({report.llm.reason or 'not used'})"


def source_text(report: Report) -> str:
    s = report.source
    where = f"{s.repo_url} @ {s.ref}" if s.ref and s.ref != s.repo_url else f"{s.repo_url}"
    if s.ref_kind:
        where += f" ({s.ref_kind})"
    if s.directory:
        where += f", directory {s.directory}"
    return where


def counts_lines(report: Report) -> list[str]:
    return [
        f"{n} {COUNT_LABELS.get(k, k)}" for k, n in report.expected_counts.items() if n
    ]


# ----------------------------------------------------------------------------- terminal

def render_terminal(report: Report, console: Console) -> None:
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Package", f"{report.package.name}")
    header.add_row("Version", report.package.version)
    header.add_row("Source", source_text(report))
    header.add_row("Integrity", integrity_text(report))
    header.add_row(
        "Status",
        Text(f"{report.status}  (risk score {report.score}/100)",
             style=STATUS_STYLE[report.status]),
    )
    header.add_row("Files", f"{report.files_in_package} in package, "
                            f"{report.files_in_source} in source")
    header.add_row("LLM", llm_text(report))
    console.print(Panel(header, title="IntAnalyze", border_style=STATUS_STYLE[report.status]))

    items = flagged(report)
    if items:
        table = Table(title="Findings", title_justify="left", expand=True)
        table.add_column("path", overflow="fold", ratio=3)
        table.add_column("verdict", no_wrap=True)
        table.add_column("severity", no_wrap=True)
        table.add_column("rules", overflow="fold", ratio=2)
        table.add_column("reason", overflow="fold", ratio=4)
        for f in items:
            table.add_row(
                f.path,
                Text(f.verdict, style=VERDICT_STYLE[f.verdict]),
                Text(f.severity, style=SEVERITY_STYLE[f.severity]),
                ", ".join(f.rule_ids),
                f.reason,
            )
        console.print(table)
    else:
        console.print("[green]No CHANGED or SUSPICIOUS files.[/]")

    lines = counts_lines(report)
    if lines:
        console.print("[bold]Expected differences[/] (collapsed): " + "; ".join(lines))
    for f in build_mappings(report)[:8]:
        console.print(f"  [dim]{f.path} <- {f.mapped_source}[/]")
    if len(build_mappings(report)) > 8:
        console.print(f"  [dim]... and {len(build_mappings(report)) - 8} more[/]")

    for f in items:
        exp = f.explanation
        body = []
        if exp:
            body.append(Text(exp.summary))
            body.append(Text.assemble(("Why it matters: ", "bold"), exp.why_it_matters))
            body.append(Text.assemble(("Recommended: ", "bold"), exp.recommended_action))
        body.append(Text("Evidence:", style="bold"))
        body += [Text(f"  - {e}") for e in f.evidence]
        source = "explained by " + ("the LLM" if f.explanation_source == "llm" else "rule text")
        console.print(
            Panel(
                Group(*body),
                title=f"{f.path}  [{f.verdict} / {f.severity}]",
                subtitle=source,
                border_style=VERDICT_STYLE[f.verdict],
            )
        )

    if report.summary:
        title = "Summary (LLM)" if report.llm.used else "Summary"
        console.print(Panel(report.summary, title=title, border_style=STATUS_STYLE[report.status]))


def terminal_text(report: Report, width: int = 100) -> str:
    """Terminal rendering without colours, for files."""
    buf = io.StringIO()
    render_terminal(report, Console(file=buf, width=width, no_color=True, highlight=False,
                                    emoji=False, force_terminal=False))
    return buf.getvalue()


# ----------------------------------------------------------------------- md / html / json

def _env(autoescape: bool) -> Environment:
    env = Environment(
        loader=PackageLoader("intanalyze", "templates"),
        # Package paths and evidence are attacker-controlled, so HTML is always escaped.
        autoescape=autoescape,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["mdcell"] = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    return env


def _context(report: Report) -> dict:
    return {
        "r": report,
        "flagged": flagged(report),
        "mappings": build_mappings(report),
        "counts": counts_lines(report),
        "integrity": integrity_text(report),
        "llm": llm_text(report),
        "source": source_text(report),
        "rules": RULES,
        "used_rules": sorted({r for f in flagged(report) for r in f.rule_ids}),
    }


def render_markdown(report: Report) -> str:
    return _env(False).get_template("report.md.j2").render(**_context(report))


def render_html(report: Report) -> str:
    return _env(True).get_template("report.html.j2").render(**_context(report))


def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2) + "\n"


def render(report: Report, fmt: str) -> str:
    return {
        "terminal": terminal_text,
        "md": render_markdown,
        "html": render_html,
        "json": render_json,
    }[fmt](report)
