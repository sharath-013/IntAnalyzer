"""The GitHub Pages builder (scripts/build_site.py), offline: examples only, no live checks."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("build_site", ROOT / "scripts" / "build_site.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_builds_home_page_and_example_reports(tmp_path):
    site = _load()
    out = tmp_path / "_site"
    result = site.build(out, live=False)
    assert result == {"examples": 3, "live": 0, "errors": []}
    index = (out / "index.html").read_text()
    assert "<title>IntAnalyze</title>" in index
    for name in ("clean-fixture", "malicious-fixture", "real-package"):
        assert f'href="examples/{name}.html"' in index
        report = (out / "examples" / f"{name}.html").read_text()
        assert report.startswith("<!doctype html>")
    assert "DANGEROUS" in (out / "examples" / "malicious-fixture.html").read_text()
    assert "Live checks were not run" in index
    assert (out / ".nojekyll").exists()


def test_rebuild_replaces_old_output(tmp_path):
    site = _load()
    out = tmp_path / "_site"
    out.mkdir()
    (out / "stale.html").write_text("old")
    site.build(out, live=False)
    assert not (out / "stale.html").exists()


def test_cli_entry_point(tmp_path, capsys):
    site = _load()
    assert site.main(["--no-live", "--out", str(tmp_path / "s")]) == 0
    assert "3 examples, 0 live" in capsys.readouterr().out
