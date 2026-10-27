import argparse
import sys

from assessor.config import CORRELATION_ID


def _correlation_id(value: str) -> str:
    if not CORRELATION_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("must match YYYYMMDDTHHMMSSZ-<8 lowercase hex>")
    return value


def _reviewer_name(value: str) -> str:
    if not any(char.isalnum() for char in value):
        raise argparse.ArgumentTypeError("must contain a letter or digit")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assess", description="Assess the health of a client code repository.", allow_abbrev=False
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    run = commands.add_parser("run", help="assess a repository directory or .zip archive", allow_abbrev=False)
    run.add_argument("path", help="repository directory or .zip archive")
    run.add_argument("--substance", metavar="FILE", help="substance ratings file")

    decide = commands.add_parser(
        "decide", help="record a human decision on a run waiting for review", allow_abbrev=False
    )
    decide.add_argument("cid", type=_correlation_id, help="correlation ID of the run")
    decide.add_argument("--decision", required=True, choices=["continue", "reject"])
    decide.add_argument(
        "--reviewer", required=True, type=_reviewer_name, metavar="NAME", help="name of the person deciding"
    )
    decide.add_argument("--note", metavar="TEXT", help="reason for the decision")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Return the process exit code for argv (sys.argv when None).

    argparse raises SystemExit itself: 2 on a usage error, 0 after --help.
    """
    args = build_parser().parse_args(argv)
    print(f"assess {args.command}: not implemented yet", file=sys.stderr)
    return 1
