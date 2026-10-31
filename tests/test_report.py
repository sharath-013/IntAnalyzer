import json
import re
from pathlib import Path

import pytest

from intanalyze.llm import FakeLLM, explain_report
from intanalyze.models import Report
from intanalyze.pipeline import check_offline
from intanalyze.report import (
    flagged,
    integrity_text,
    render,
    render_html,
    render_json,
    render_markdown,
    terminal_text,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _report(name, llm=None):
    d = FIXTURES / name
    report = check_offline(d / "package.tgz", d / "source", registry_json=d / "registry.json")
    return explain_report(report, llm)


@pytest.fixture(scope="module")
def malicious():
    return _report("malicious")


@pytest.fixture(scope="module")
def clean():
    return _report("clean")


def test_flagged_sorted_by_severity(malicious):
    items = flagged(malicious)
    assert [f.severity.rank for f in items] == sorted((f.severity.rank for f in items),
                                                       reverse=True)
    assert all(f.verdict != "EXPECTED" for f in items)


def test_terminal_has_header_table_details_summary(malicious):
    text = terminal_text(malicious)
    assert "IntAnalyze" in text and "DANGEROUS" in text and "risk score 100/100" in text
    assert "sha512 OK" in text and "disabled with --no-llm" in text
    for path in ("package.json", "lib/x.min.js", "dist/index.js"):
        assert path in text
    assert "Expected differences (collapsed)" in text
    assert "dist/util.js <- src/util.ts" in text
    assert "lodahs" in text and "Summary" in text
    assert "\x1b[" not in text  # no colour codes in file output


def test_terminal_clean(clean):
    text = terminal_text(clean)
    assert "CLEAN" in text and "No CHANGED or SUSPICIOUS files." in text


def test_markdown(malicious):
    md = render_markdown(malicious)
    assert md.startswith("# IntAnalyze report: tiny-percent@1.0.0")
    assert "| **Status** | **DANGEROUS** (risk score 100/100) |" in md
    assert "| `package.json` | SUSPICIOUS | HIGH | IA-MANIFEST-001, IA-MANIFEST-003 |" in md
    assert "### `lib/x.min.js`: SUSPICIOUS / HIGH" in md
    assert "- **IA-CODE-001**:" in md
    assert "`dist/index.js` ← `src/index.ts`" not in md  # it is suspicious, not mapped
    assert "`dist/util.js` ← `src/util.ts`" in md


def test_markdown_escapes_pipes(malicious):
    report = malicious.model_copy(deep=True)
    report.findings[0].reason = "a | b"
    assert "a \\| b" in render_markdown(report)


def test_html_is_self_contained_and_escaped(malicious):
    report = malicious.model_copy(deep=True)
    report.findings[0].evidence.append("<script>alert(1)</script>")
    html = render_html(report)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "DANGEROUS" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # No external assets: nothing is loaded from another origin.
    assert not re.search(r'(src|href)="(https?:)?//', html)


def test_json_round_trips(malicious):
    again = Report.model_validate_json(render_json(malicious))
    assert again == malicious
    assert json.loads(render(malicious, "json"))["status"] == "DANGEROUS"


def test_llm_explanations_are_labelled():
    report = _report("malicious", FakeLLM())
    text = terminal_text(report)
    assert "explained by the LLM" in text and "fake-llm" in text
    assert "Summary (LLM)" in text
    assert "Explained by the LLM" in render_markdown(report)


def test_diff_is_included(tmp_path):
    from intanalyze.classify import classify
    from intanalyze.diff import compare_trees

    (tmp_path / "p").mkdir()
    (tmp_path / "s").mkdir()
    (tmp_path / "p/a.js").write_text("one\ntwo\n")
    (tmp_path / "s/a.js").write_text("one\n")
    result = classify(compare_trees(tmp_path / "p", tmp_path / "s"), tmp_path / "p",
                      tmp_path / "s")
    report = Report(tool_version="t", package={"name": "x", "version": "1"},
                    findings=result.findings, score=10, status="REVIEW")
    assert "```diff" in render_markdown(report) and "+two" in render_markdown(report)
    assert "<pre>" in render_html(report)


def test_integrity_text_variants(malicious):
    r = malicious.model_copy(deep=True)
    r.integrity.ok = False
    assert integrity_text(r) == "sha512 MISMATCH"
    r.integrity.checked = False
    assert integrity_text(r).startswith("not checked")
