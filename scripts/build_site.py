"""Build the static GitHub Pages site into _site/.

    python scripts/build_site.py              # examples + fresh live checks (needs network)
    python scripts/build_site.py --no-live    # examples only (offline)

Nothing on the site is hand-written output:
- examples/<name>/report.json -> _site/examples/<name>.html, re-rendered with the same HTML
  renderer as the CLI. These are the committed real runs, explained by the local model.
- Live pages are fresh `check` runs made while the site is built (rules only: GitHub Actions
  has no LM Studio, and the product never calls a cloud model).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from intanalyze import __version__
from intanalyze.llm import explain_report
from intanalyze.models import PackageSpec, Report
from intanalyze.pipeline import CheckError, check_online
from intanalyze.report import render_html

ROOT = Path(__file__).resolve().parent.parent
LIVE_PACKAGES = ["ms@2.1.3", "react@18.3.1", "date-fns@4.1.0"]
REPO_URL = "https://github.com/sharath-013/IntAnalyzer"


def _row(report: Report, href: str, label: str) -> dict:
    flagged = sum(1 for f in report.findings if f.verdict != "EXPECTED")
    llm = f"{report.llm.model} (local)" if report.llm.used else "rules only"
    return {
        "label": label,
        "href": href,
        "package": str(report.package),
        "status": str(report.status),
        "score": report.score,
        "files": report.files_in_package,
        "flagged": flagged,
        "llm": llm,
    }


def build(out: Path, live: bool = True) -> dict:
    if out.exists():
        shutil.rmtree(out)
    (out / "examples").mkdir(parents=True)
    (out / "live").mkdir()

    examples = []
    for folder in sorted((ROOT / "examples").iterdir()):
        src = folder / "report.json"
        if not src.is_file():
            continue
        report = Report.model_validate_json(src.read_text(encoding="utf-8"))
        (out / "examples" / f"{folder.name}.html").write_text(
            render_html(report), encoding="utf-8"
        )
        examples.append(_row(report, f"examples/{folder.name}.html", folder.name))

    live_rows, live_errors = [], []
    if live:
        for spec in LIVE_PACKAGES:
            try:
                report = explain_report(check_online(PackageSpec.parse(spec)), None)
            except CheckError as exc:
                live_errors.append(f"{spec}: {exc}")
                continue
            name = spec.replace("/", "_").replace("@", "-")
            (out / "live" / f"{name}.html").write_text(render_html(report), encoding="utf-8")
            live_rows.append(_row(report, f"live/{name}.html", spec))

    env = Environment(
        loader=FileSystemLoader(ROOT / "scripts" / "site"),
        autoescape=True,
        undefined=StrictUndefined,
    )
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    html = env.get_template("index.html.j2").render(
        examples=examples,
        live=live_rows,
        live_errors=live_errors,
        live_enabled=live,
        built=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        commit=sha,
        version=__version__,
        repo=REPO_URL,
    )
    (out / "index.html").write_text(html, encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return {"examples": len(examples), "live": len(live_rows), "errors": live_errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "_site")
    parser.add_argument("--no-live", action="store_true", help="skip live checks (offline)")
    args = parser.parse_args(argv)
    result = build(args.out, live=not args.no_live)
    print(f"site written to {args.out}: {result['examples']} examples, {result['live']} live")
    for err in result["errors"]:
        print(f"  live check skipped: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
