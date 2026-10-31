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


def test_terminal_with_out_writes_json(tmp_path):
    out = tmp_path / "r.json"
    runner.invoke(app, _offline_args("clean", "--out", str(out)))
    assert json.loads(out.read_text())["status"] == "CLEAN"


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
