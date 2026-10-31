import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from intanalyze import __version__, cli
from intanalyze.cli import app
from intanalyze.pipeline import CheckError

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _offline_args(name, *extra):
    d = FIXTURES / name
    return [
        "check",
        "--tarball", str(d / "package.tgz"),
        "--source", str(d / "source"),
        "--registry-json", str(d / "registry.json"),
        "--no-llm",
        *extra,
    ]


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"intanalyze {__version__}"


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "check" in result.output


def test_clean_fixture_exits_0():
    result = runner.invoke(app, _offline_args("clean"))
    assert result.exit_code == 0, result.output
    assert "CLEAN" in result.output


def test_malicious_fixture_exits_1_with_json(tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(app, _offline_args("malicious", "--format", "json", "--out", str(out)))
    assert result.exit_code == 1
    report = json.loads(out.read_text())
    assert report["status"] == "DANGEROUS"
    assert {"IA-MANIFEST-001", "IA-MANIFEST-003", "IA-CODE-001"} <= {
        r for f in report["findings"] for r in f["rule_ids"]
    }


def test_json_to_stdout():
    result = runner.invoke(app, _offline_args("clean", "--format", "json"))
    assert json.loads(result.output)["status"] == "CLEAN"


@pytest.mark.parametrize(("fail_on", "code"), [("never", 0), ("low", 1), ("high", 1)])
def test_fail_on(fail_on, code):
    assert runner.invoke(app, _offline_args("malicious", "--fail-on", fail_on)).exit_code == code


@pytest.mark.parametrize(
    ("fmt", "marker"),
    [("terminal", "IntAnalyze"), ("md", "# IntAnalyze report"), ("html", "<!doctype html>")],
)
def test_out_writes_the_chosen_format(tmp_path, fmt, marker):
    out = tmp_path / "report"
    result = runner.invoke(app, _offline_args("malicious", "--format", fmt, "--out", str(out)))
    assert result.exit_code == 1
    assert marker in out.read_text()


def test_md_to_stdout():
    result = runner.invoke(app, _offline_args("clean", "--format", "md"))
    assert result.output.startswith("# IntAnalyze report")


def test_unwritable_out_exits_2(tmp_path):
    out = tmp_path / "missing-dir" / "r.md"
    result = runner.invoke(app, _offline_args("clean", "--format", "md", "--out", str(out)))
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "args",
    [
        ["check"],
        ["check", "not-a-spec"],
        ["check", "--tarball", "nope.tgz"],
        ["check", "--tarball", "nope.tgz", "--source", "."],
    ],
)
def test_tool_errors_exit_2(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "error:" in result.output


def test_online_resolve_failure_exits_2(monkeypatch):
    def boom(spec, **kwargs):
        raise CheckError("no source repository declared")

    monkeypatch.setattr(cli, "check_online", boom)
    result = runner.invoke(app, ["check", "ms@2.1.3", "--no-llm"])
    assert result.exit_code == 2
    assert "no source repository declared" in result.output


def test_doctor_with_server_down(monkeypatch):
    monkeypatch.setenv("INTANALYZE_LLM_URL", "http://127.0.0.1:9/v1")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "127.0.0.1:9" in result.output and "no" in result.output
    assert "git version" in result.output


def test_doctor_with_server_up(monkeypatch):
    class Up:
        server, model = "http://fake/v1", "qwen/qwen3.5-9b"

        def models(self):
            return ["qwen/qwen3.5-9b"]

    monkeypatch.setattr(cli, "make_llm_client", lambda **kw: Up())
    result = runner.invoke(app, ["doctor"])
    assert "yes" in result.output and "qwen/qwen3.5-9b" in result.output


def test_check_without_server_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv("INTANALYZE_LLM_URL", "http://127.0.0.1:9/v1")
    out = tmp_path / "r.json"
    args = [a for a in _offline_args("malicious", "--format", "json", "--out", str(out))
            if a != "--no-llm"]
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    report = json.loads(out.read_text())
    assert report["llm"]["used"] is False and "not reachable" in report["llm"]["reason"]


def test_check_with_fake_llm(monkeypatch, tmp_path):
    from intanalyze.llm import FakeLLM

    class Fake(FakeLLM):
        model = "fake-llm"

        def __init__(self, **kw):
            super().__init__()

        def models(self):
            return ["fake-llm"]

    monkeypatch.setattr(cli, "make_llm_client", Fake)
    out = tmp_path / "r.json"
    args = [a for a in _offline_args("malicious", "--format", "json", "--out", str(out))
            if a != "--no-llm"]
    assert runner.invoke(app, args).exit_code == 1
    report = json.loads(out.read_text())
    assert report["llm"] == {"used": True, "server": "fake://llm", "model": "fake-llm",
                             "reason": None}
    assert report["summary"].startswith("[fake]")
