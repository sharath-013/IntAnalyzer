from typer.testing import CliRunner

from intanalyze import __version__
from intanalyze.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"intanalyze {__version__}"


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "check" in result.output


def test_check_stub_exits_with_tool_error():
    result = runner.invoke(app, ["check", "ms@2.1.3"])
    assert result.exit_code == 2
