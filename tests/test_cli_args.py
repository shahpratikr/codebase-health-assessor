import subprocess
import sys
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from assessor import cli
from assessor.cli import build_parser, main

CID = "20261027T101500Z-0a1b2c3d"


@pytest.fixture(autouse=True)
def plain_output(monkeypatch):
    # Python 3.14 argparse colors help when FORCE_COLOR is set unless PYTHON_COLORS=0, and wraps usage to COLUMNS.
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.setenv("COLUMNS", "200")


def _exit_code(argv):
    with pytest.raises(SystemExit) as raised:
        main(argv)
    return raised.value.code


@pytest.mark.parametrize(
    ("argv", "usage", "listed"),
    [
        (["--help"], "usage: assess ", ["run", "decide"]),
        (["run", "--help"], "usage: assess run ", ["path", "--substance FILE"]),
        (["decide", "--help"], "usage: assess decide ", ["cid", "{continue,reject}", "--reviewer NAME", "--note TEXT"]),
    ],
)
def test_help_exits_0(capsys, argv, usage, listed):
    assert _exit_code(argv) == 0
    out = capsys.readouterr().out
    assert out.startswith(usage)
    for text in listed:
        assert text in out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([], "the following arguments are required: COMMAND"),
        (["--hel"], "the following arguments are required: COMMAND"),
        (["frobnicate"], "invalid choice: 'frobnicate'"),
        (["run"], "the following arguments are required: path"),
        (["run", "repo", "--bogus"], "unrecognized arguments: --bogus"),
        (["run", "repo", "--substance"], "argument --substance: expected one argument"),
        (["run", "repo", "--sub", "ratings.json"], "unrecognized arguments: --sub ratings.json"),
        (["decide", "--decision", "continue", "--reviewer", "ana"], "the following arguments are required: cid"),
        (["decide", CID, "--reviewer", "ana"], "the following arguments are required: --decision"),
        (["decide", CID, "--decision", "continue"], "the following arguments are required: --reviewer"),
        (["decide", CID, "--decision", "maybe", "--reviewer", "ana"], "invalid choice: 'maybe'"),
        (["decide", CID, "--decision", "Continue", "--reviewer", "ana"], "invalid choice: 'Continue'"),
        (["decide", CID, "--decision", "reject", "--reviewer", "ana", "--no", "x"], "unrecognized arguments: --no x"),
    ],
)
def test_usage_error_exits_2(capsys, argv, message):
    assert _exit_code(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("usage: assess")
    assert message in captured.err


@pytest.mark.parametrize(
    "cid",
    [
        "",
        "../../etc",
        "/tmp/20261027T101500Z-0a1b2c3d",
        "20261027T101500Z-0a1b2c3d/..",
        "20261027T101500Z-0a1b2c3d\n",
        "20261027T101500Z-0A1B2C3D",
        "20261027T101500-0a1b2c3d",
        "20261027T101500Z-0a1b2c3",
        "20261027T101500Z-0a1b2c3d9",
        "20261027T101500Z-0g1h2i3j",
        "2026102T101500Z-0a1b2c3d",
        "202610271T101500Z-0a1b2c3d",
        "20261027T10150Z-0a1b2c3d",
        "20261027T1015001Z-0a1b2c3d",
        "20261027X101500Z-0a1b2c3d",
        "2026a027T101500Z-0a1b2c3d",
        "20261027T101500Z.0a1b2c3d",
        "20261027T101500Z_0a1b2c3d",
        "20261027T101500Z0a1b2c3d",
        "20261027101500Z-0a1b2c3d",
        "20261027t101500Z-0a1b2c3d",
        "20261027T101500z-0a1b2c3d",
        "٢٠٢٦١٠٢٧T101500Z-0a1b2c3d",
    ],
)
def test_malformed_cid_exits_2(capsys, cid):
    assert _exit_code(["decide", cid, "--decision", "continue", "--reviewer", "ana"]) == 2
    assert "argument cid: must match YYYYMMDDTHHMMSSZ-<8 lowercase hex>" in capsys.readouterr().err


@pytest.mark.parametrize("reviewer", ["", " \t ", "​", "⠀", "..."])
def test_reviewer_without_letter_or_digit_exits_2(capsys, reviewer):
    assert _exit_code(["decide", CID, "--decision", "reject", "--reviewer", reviewer]) == 2
    assert "argument --reviewer: must contain a letter or digit" in capsys.readouterr().err


def test_run_parses_path_and_substance():
    args = build_parser().parse_args(["run", "client.zip", "--substance", "ratings.json"])
    assert (args.command, args.path, args.substance) == ("run", "client.zip", "ratings.json")
    assert build_parser().parse_args(["run", "repo"]).substance is None


def test_decide_parses_all_fields():
    args = build_parser().parse_args(
        ["decide", CID, "--decision", "reject", "--reviewer", "José Núñez", "--note", "seeded key"]
    )
    assert (args.command, args.cid, args.decision, args.reviewer, args.note) == (
        "decide", CID, "reject", "José Núñez", "seeded key",
    )
    unnoted = build_parser().parse_args(["decide", CID, "--decision", "continue", "--reviewer", " 李明 "])
    assert (unnoted.reviewer, unnoted.note) == (" 李明 ", None)
    assert build_parser().parse_args(["decide", CID, "--decision", "continue", "--reviewer", "42"]).reviewer == "42"


@pytest.mark.parametrize("command", ["run", "decide"])
def test_valid_command_reports_not_implemented_yet(capsys, tmp_path, command):
    argv = {"run": ["run", str(tmp_path)], "decide": ["decide", CID, "--decision", "continue", "--reviewer", "ana"]}
    assert main(argv[command]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"assess {command}: not implemented yet\n"


def test_main_reads_sys_argv_by_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["assess", "decide", "../x", "--decision", "continue", "--reviewer", "ana"])
    with pytest.raises(SystemExit) as raised:
        main()
    assert raised.value.code == 2
    assert "argument cid" in capsys.readouterr().err


def test_assess_console_script_is_cli_main():
    (script,) = entry_points(group="console_scripts", name="assess")
    assert script.value == "assessor.cli:main"
    assert script.load() is cli.main


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["--help"], 0),
        ([], 2),
        (["decide", "../x", "--decision", "continue", "--reviewer", "ana"], 2),
    ],
)
def test_installed_assess_process_exit_code(argv, code):
    assess = Path(sys.executable).with_name("assess")
    assert subprocess.run([assess, *argv], capture_output=True, timeout=60).returncode == code
