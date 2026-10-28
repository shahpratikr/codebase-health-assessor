import contextlib
import io
import re
import shlex

import pytest

from assessor import cli, config
from evals import run as evals_run

README = config.ROOT / "README.md"
READMES = {
    "root": README,
    "sample-runs": config.ROOT / "examples" / "sample-runs" / "README.md",
    "results": config.ROOT / "evals" / "results" / "README.md",
}
CARDS = (
    "Dispatch-only coordinator",
    "Sub-agents scoped to one workflow",
    "Adversarial review in its own context",
    "Version-controlled repo",
    "Stage 4 continuity",
    "Mega-agent counterfeit",
)
RULES = ("Final review writer", "Guardrails", "Substance", "Audit", "Decisions")
SECTIONS = ("Setup", "Commands", "ZIP packaging", "Evidence map")
HEADER = ["Item", "What it shows", "Paths"]
INSTALL = ("poetry", "install")
ASSESS = ("poetry", "run", "assess")
EVALS = ("poetry", "run", "python", "-m", "evals.run")
PROGRAMS = {ASSESS: cli.build_parser, EVALS: evals_run.build_parser}
FENCES = ("```", "~~~")
# Per README: the `assess` subcommands it shows, one entry per command, and whether it shows an evals command.
COMMANDS = {
    "root": (["decide", "run", "run"], True),
    "sample-runs": (["decide", "run", "run"], False),
    "results": ([], True),
}

MAP = """\
# Title

## Evidence map

Prose with `not/a/path.txt` in it.

| Item | What it shows | Paths |
|---|---|---|
| Dispatch-only coordinator | `launch_*` tools only | `README.md`, `docs/` |
| Guardrails | schema checks | `docs/*.md` |

## Next section
"""


def _text(path=README):
    return path.read_text(encoding="utf-8")


def _section(text, heading):
    """Return the lines of the one `## heading` section, up to the next `## ` line outside a code fence.

    Raises ValueError unless the heading appears exactly once.
    """
    lines = [line.rstrip() for line in text.splitlines()]
    if lines.count(f"## {heading}") != 1:
        raise ValueError(f"expected exactly one '## {heading}' section")
    section, inside = [], False
    for line in lines[lines.index(f"## {heading}") + 1 :]:
        if line.strip().startswith(FENCES):
            inside = not inside
        elif line.startswith("## ") and not inside:
            break
        section.append(line)
    return section


def _cells(line):
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().removeprefix("|").removesuffix("|"))]


def _rows(text):
    """Return the three cells of each body row of the evidence map's table.

    Raises ValueError unless the table is the section's only one, starts with HEADER and a separator row, and every
    body row has a label and backticked paths only.
    """
    lines = [line.strip() for line in _outside_fences(_section(text, "Evidence map"))]
    if any("<!--" in line for line in lines):
        raise ValueError("evidence map must not hold an HTML comment")
    numbers = [number for number, line in enumerate(lines) if line.startswith("|")]
    if numbers and numbers != list(range(numbers[0], numbers[-1] + 1)):
        raise ValueError("evidence map must hold one table without gaps")
    table = [lines[number] for number in numbers]
    rows = [_cells(line) for line in table]
    separator = rows[1] if len(rows) > 1 else []
    if rows[:1] != [HEADER] or len(separator) != 3 or not all(re.fullmatch(r":?-+:?", cell) for cell in separator):
        raise ValueError(f"evidence map table must start with the header {HEADER} and a separator row")
    for line, cells in zip(table[2:], rows[2:]):
        if len(cells) != 3 or not cells[0]:
            raise ValueError(f"evidence map row without three cells and a label: {line}")
        if re.sub(r"`[^`]*`", "", cells[2]).strip(" ,"):
            raise ValueError(f"evidence map row with text outside backticks in its Paths cell: {line}")
    return rows[2:]


def _outside_fences(lines):
    inside = False
    for line in lines:
        if line.strip().startswith(FENCES):
            inside = not inside
        elif not inside:
            yield line


def _labels(rows):
    return [row[0] for row in rows]


def _layout_errors(rows):
    """Return "cards" and "rules" for each part of the rows that is not the six cards, then the five rules, in order."""
    labels = _labels(rows)
    return [
        name
        for name, found, expected in (
            ("cards", labels[: len(CARDS)], CARDS),
            ("rules", labels[len(CARDS) :], RULES),
        )
        if found != list(expected)
    ]


def _paths(cell):
    return re.findall(r"`([^`]+)`", cell)


def _pathless(rows):
    return [row[0] for row in rows if not _paths(row[2])]


def _plain(path):
    # A leading "/" gives an empty first part, so an absolute path is never plain.
    parts = path.rstrip("/").split("/")
    return not any(part in ("", ".", "..") for part in parts) and not re.search(r"[*?\[]", parts[0])


def _inside(root, path):
    # Case must match exactly: macOS matches it loosely, and a ZIP unpacked on Linux does not.
    real = root.resolve()
    matches = root.glob(path, case_sensitive=True)
    return any(match.exists() and match.resolve().is_relative_to(real) for match in matches)


def _missing(root, paths):
    """Return the paths that are absolute, hold an empty, `.` or `..` segment, start with a wildcard or match no real
    file inside root.

    A glob may match below a literal first segment, and letter case must match exactly.
    """
    return [path for path in paths if not _plain(path) or not _inside(root, path)]


def _empty_sections(text):
    return [heading for heading in SECTIONS if not any(line.strip() for line in _section(text, heading))]


def _fenced_lines(text):
    """Yield the stripped lines inside code fences, with each backslash continuation joined to its first line."""
    inside, joined = False, ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(FENCES):
            inside, joined = not inside, ""
        elif inside and stripped.endswith("\\"):
            joined += stripped.removesuffix("\\") + " "
        elif inside:
            yield joined + stripped
            joined = ""


def _setup_lacks_install(text):
    return not _commands("\n".join(_section(text, "Setup")), INSTALL)


def _is_packaging(line):
    """Return whether line chains `git log --stat ... > git_log.txt`, `git archive ... -o submission.zip HEAD` and
    `zip -u submission.zip git_log.txt` with `&&`, nothing else.
    """
    commands, current = [], []
    for token in shlex.split(line):
        if token == "&&":
            commands, current = [*commands, current], []
        else:
            current.append(token)
    commands.append(current)
    if len(commands) != 3:
        return False
    log, archive, zipped = commands
    return (
        log[:3] == ["git", "log", "--stat"]
        and log[-2:] == [">", "git_log.txt"]
        and archive[:2] == ["git", "archive"]
        and archive[-3:] == ["-o", "submission.zip", "HEAD"]
        and zipped == ["zip", "-u", "submission.zip", "git_log.txt"]
    )


def _packages(text):
    lines = _fenced_lines("\n".join(_section(text, "ZIP packaging")))
    return any(_is_packaging(line) for line in lines if line.split()[:2] == ["git", "log"])


def _commands(text, program):
    """Return the arguments after `program` on each uncommented fenced line that runs it.

    A `$ ` or `env -u VIRTUAL_ENV` prefix is allowed; shlex raises ValueError for a line it cannot split.
    """
    found = []
    for line in _fenced_lines(text):
        tokens = shlex.split(line) if line.split()[:1] in (["$"], ["env"], ["poetry"]) else []
        tokens = tokens[1:] if tokens[:1] == ["$"] else tokens
        tokens = tokens[3:] if tokens[:3] == ["env", "-u", "VIRTUAL_ENV"] else tokens
        if tokens[: len(program)] == list(program):
            found.append(tokens[len(program) :])
    return found


def _subcommands(text):
    return sorted(argv[0] for argv in _commands(text, ASSESS) if argv and not argv[0].startswith("-"))


def _refused_commands(text):
    refused = []
    for program, build in PROGRAMS.items():
        for argv in _commands(text, program):
            try:
                # parse_args writes its usage error to stderr, and --help to stdout, before it exits.
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    build().parse_args(argv)
            except SystemExit as stop:
                if stop.code != 0:
                    refused.append(shlex.join([*program, *argv]))
    return refused


def _unresolved_arguments(text):
    """Return the input and ratings paths of the text's `assess run` commands that name no real file in the repo."""
    named = []
    for argv in _commands(text, ASSESS):
        if argv[:1] == ["run"]:
            args = cli.build_parser().parse_args(argv)
            named += [path for path in (args.path, args.substance) if path]
    return _missing(config.ROOT, named)


def _tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("")
    (tmp_path / "README.md").write_text("")
    (tmp_path / ".hidden").write_text("")
    return tmp_path


def test_every_path_in_the_evidence_map_exists():
    paths = [path for row in _rows(_text()) for path in _paths(row[2])]
    assert paths
    assert _missing(config.ROOT, paths) == []


def test_the_evidence_map_lists_the_six_rubric_cards_in_order_and_then_the_five_content_rules():
    assert _layout_errors(_rows(_text())) == []


def test_every_evidence_map_row_names_a_path():
    assert _pathless(_rows(_text())) == []


def test_the_readme_has_setup_commands_and_packaging_sections_and_setup_installs():
    assert _empty_sections(_text()) == []
    assert not _setup_lacks_install(_text())


def test_the_packaging_command_writes_git_log_stat_to_git_log_txt_and_adds_it_to_the_zip():
    assert _packages(_text())


@pytest.mark.parametrize("name", READMES)
def test_each_readme_shows_the_commands_it_documents_and_they_are_valid(name):
    text = _text(READMES[name])
    subcommands, shows_evals = COMMANDS[name]
    assert _subcommands(text) == subcommands
    assert bool(_commands(text, EVALS)) == shows_evals
    assert _refused_commands(text) == []
    assert _unresolved_arguments(text) == []


@pytest.mark.parametrize(
    "path",
    [
        "missing.txt",
        "missing/",
        "docs/*.json",
        "/etc/hosts",
        "../outside.txt",
        "docs/../README.md",
        "README.md/",
        "README.md/.",
        "docs//a.md",
        ".",
        "*",
        "**",
        "*/a.md",
        "[d]ocs/",
        "Readme.md",
        "Docs/",
        "docs/A.md",
    ],
)
def test_a_path_that_is_absent_or_leaves_the_repository_is_reported(tmp_path, path):
    assert _missing(_tree(tmp_path), [path]) == [path]


@pytest.mark.parametrize("path", ["README.md", "docs/", "docs/*.md", ".hidden"])
def test_a_file_a_directory_a_glob_with_a_match_and_a_dotfile_are_not_reported(tmp_path, path):
    assert _missing(_tree(tmp_path), [path]) == []


def test_an_absolute_path_to_a_real_file_inside_the_repository_is_reported(tmp_path):
    repo = _tree(tmp_path)
    absolute = [str(repo / "README.md"), str(repo / "docs")]
    assert _missing(repo, absolute) == absolute


def test_a_path_through_a_symlink_to_outside_the_repository_is_reported(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "link").symlink_to(outside, target_is_directory=True)
    assert _missing(repo, ["link/secret.txt", "link/"]) == ["link/secret.txt", "link/"]


def test_a_dangling_symlink_inside_the_repository_is_reported(tmp_path):
    (tmp_path / "dangling").symlink_to(tmp_path / "gone.txt")
    assert _missing(tmp_path, ["dangling"]) == ["dangling"]


@pytest.mark.parametrize("text", ["# Title\n\n## Setup\n", MAP + "\n## Evidence map\n\nAgain.\n"])
def test_a_readme_with_no_evidence_map_or_two_of_them_is_refused(text):
    with pytest.raises(ValueError, match="exactly one '## Evidence map' section"):
        _rows(text)


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("| Guardrails | schema checks | `docs/*.md` |", "| Guardrails | `docs/*.md` |", "without three cells"),
        ("| Guardrails | schema checks | `docs/*.md` |", "|  | schema checks | `docs/*.md` |", "and a label"),
        ("| Item | What it shows | Paths |", "| Item | Paths | What it shows |", "must start with the header"),
        ("|---|---|---|\n", "", "must start with the header"),
        ("|---|---|---|", "|---|---|", "must start with the header"),
        ("|---|---|---|", "|---|text|---|", "must start with the header"),
        ("`docs/*.md` |", "`docs/*.md`, src/gone.py |", "outside backticks"),
        ("`docs/*.md` |", "`docs/*.md` and more |", "outside backticks"),
        ("Prose with", "<!-- hidden -->\nProse with", "HTML comment"),
        (
            "| Guardrails | schema checks | `docs/*.md` |\n",
            "| Guardrails | schema checks | `docs/*.md` |\n\nMore.\n\n| Item | What it shows | Paths |\n|---|---|---|\n"
            "| Other | x | `README.md` |\n",
            "without gaps",
        ),
    ],
)
def test_a_malformed_table_is_refused(old, new, match):
    with pytest.raises(ValueError, match=match):
        _rows(MAP.replace(old, new))


@pytest.mark.parametrize("fence", ["```", "~~~"])
def test_a_table_inside_a_code_fence_is_not_the_map(fence):
    table = MAP[MAP.index("| Item"): MAP.index("\n## Next section")]
    with pytest.raises(ValueError, match="must start with the header"):
        _rows(MAP.replace(table, f"{fence}\n{table}{fence}\n"))


def test_a_map_with_no_table_is_refused():
    with pytest.raises(ValueError, match="must start with the header"):
        _rows("## Evidence map\n\nOnly prose.\n")


def test_only_the_paths_column_of_the_map_holds_paths():
    rows = _rows(MAP)
    assert _labels(rows) == ["Dispatch-only coordinator", "Guardrails"]
    assert [path for row in rows for path in _paths(row[2])] == ["README.md", "docs/", "docs/*.md"]


def test_a_row_labelled_item_or_with_dashes_is_a_row_and_its_paths_are_checked():
    planted = MAP.replace(
        "| Guardrails | schema checks | `docs/*.md` |", "| Item | again | `stale.py` |\n| - | again | `stale2.py` |"
    )
    paths = [path for row in _rows(planted) for path in _paths(row[2])]
    assert _missing(config.ROOT, paths) == ["stale.py", "stale2.py"]


@pytest.mark.parametrize("fence", ["```", "   ```", "~~~"])
def test_a_heading_line_inside_a_code_fence_does_not_end_the_section(fence):
    planted = MAP.replace("Prose with", f"{fence}\n## Not a heading\n{fence}\n\nProse with")
    assert _labels(_rows(planted)) == ["Dispatch-only coordinator", "Guardrails"]


def test_an_indented_row_a_trailing_space_and_an_escaped_pipe_are_read():
    planted = MAP.replace("| Guardrails | schema checks | `docs/*.md` |", "  | Guardrails | a \\| b | `docs/*.md` |  ")
    assert _rows(planted)[1] == ["Guardrails", "a \\| b", "`docs/*.md`"]


def test_a_heading_with_trailing_spaces_is_found():
    rows = _rows(MAP.replace("## Evidence map", "## Evidence map  "))
    assert _labels(rows) == ["Dispatch-only coordinator", "Guardrails"]


def test_a_dropped_repeated_swapped_or_extra_row_breaks_the_layout():
    rows = _rows(_text())
    cards, rules = rows[:6], rows[6:]
    extra = ["Extra", "again", "`README.md`"]
    planted = [
        ([*cards[:2], *cards[3:], *rules], ["cards", "rules"]),
        ([*cards[:2], cards[1], *cards[2:], *rules], ["cards", "rules"]),
        ([cards[1], cards[0], *cards[2:], *rules], ["cards"]),
        ([*cards[:5], *rules], ["cards", "rules"]),
        ([*cards[:4], cards[5], cards[4], *rules], ["cards"]),
        ([*cards, *rules[:2], *rules[3:]], ["rules"]),
        ([*cards, rules[1], rules[0], *rules[2:]], ["rules"]),
        ([*cards, *rules, extra], ["rules"]),
        ([*rules, *cards], ["cards", "rules"]),
    ]
    assert _layout_errors(rows) == []
    for changed, errors in planted:
        assert _layout_errors(changed) == errors


def test_a_row_without_a_path_is_reported():
    assert _pathless(_rows(MAP.replace("`docs/*.md`", ""))) == ["Guardrails"]


def test_an_empty_section_and_a_setup_without_a_fenced_poetry_install_are_reported():
    planted = "## Setup\n\n## Commands\nrun\n\n## ZIP packaging\nzip\n\n## Evidence map\ntable\n"
    assert _empty_sections(planted) == ["Setup"]
    assert _setup_lacks_install(planted)
    not_the_install = ("Do not run poetry install.", "```\n# poetry install\n```", "```\npoetry install-plugin x\n```")
    for not_the_step in not_the_install:
        assert _setup_lacks_install(planted.replace("## Setup\n", f"## Setup\n{not_the_step}\n"))
    for the_step in ("```\npoetry install\n```", "```\n$ poetry  install --only main\n```"):
        assert not _setup_lacks_install(planted.replace("## Setup\n", f"## Setup\n{the_step}\n"))


@pytest.mark.parametrize(
    "line",
    [
        "git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat --date=iso > git_log.txt && git archive --format=zip -o submission.zip HEAD && "
        "zip -u submission.zip git_log.txt",
    ],
)
def test_a_packaging_line_of_the_three_chained_commands_is_accepted(line):
    assert _packages(f"## ZIP packaging\n```\n{line}\n```\n")


@pytest.mark.parametrize(
    "line",
    [
        "git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -r submission.zip git_log.txt",
        "git log --stat > git_log.txt && git archive -o other.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt && git archive -o submission.zip main && zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt; git archive -o submission.zip HEAD; zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt; git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt && git archive -o submission.zip HEAD; zip -u submission.zip git_log.txt",
        "git archive -o submission.zip HEAD && git log --stat > git_log.txt && zip -u submission.zip git_log.txt",
        "# git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt && git archive -o submission.zip main && echo HEAD && zip -u submission.zip x",
        "git log --stat > git_log.txt && git archive -o submission.zip.bak HEAD && zip -u submission.zip git_log.txt",
        "echo git log --stat > git_log.txt && echo git archive -o submission.zip HEAD && echo zip -u submission.zip x",
        "git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt.old",
        "git log --stat && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat > other.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt",
        "git log --stat > git_log.txt && tar -o submission.zip HEAD && zip -u submission.zip git_log.txt",
    ],
)
def test_a_packaging_line_that_is_not_the_three_chained_commands_is_refused(line):
    assert not _packages(f"## ZIP packaging\n```\n{line}\n```\n")


def test_a_fenced_non_command_line_with_an_apostrophe_does_not_hide_the_packaging_command():
    line = "git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt"
    assert _packages(f"## ZIP packaging\n```\nIt's done\n{line}\n```\n")


def test_packaging_prose_outside_a_code_fence_is_not_a_command():
    line = "git log --stat > git_log.txt && git archive -o submission.zip HEAD && zip -u submission.zip git_log.txt"
    assert not _packages(f"## ZIP packaging\n{line}\n")


def test_commands_are_found_in_indented_and_tilde_fences_with_prefixes_continuations_and_extra_spaces():
    text = """\
   ~~~
   $ poetry  run assess run examples/sample-client-repo
   env -u VIRTUAL_ENV poetry run assess decide 20261028T101500Z-0a1b2c3d \\
     --decision continue --reviewer "A B"
   # poetry run assess run commented, and it's not split
   poetry run assess --help
   It's output, not a command
   ~~~
poetry run assess run outside
"""
    assert _commands(text, ASSESS) == [
        ["run", "examples/sample-client-repo"],
        ["decide", "20261028T101500Z-0a1b2c3d", "--decision", "continue", "--reviewer", "A B"],
        ["--help"],
    ]
    assert _subcommands(text) == ["decide", "run"]
    assert _refused_commands(text) == []


def test_a_text_without_a_decide_or_eval_command_shows_neither():
    text = "```\npoetry run assess run examples/sample-client-repo\n```\n"
    assert _subcommands(text) == ["run"]
    assert _commands(text, EVALS) == []


def test_a_command_its_parser_refuses_is_reported():
    text = """\
```
poetry run assess run
poetry run assess run examples/sample-client-repo
poetry run assess decide <cid> --decision continue --reviewer "A B"
poetry run python -m evals.run --agent all
poetry run python -m evals.run --agent all --runs 3
```
poetry run assess run
"""
    assert _refused_commands(text) == [
        "poetry run assess run",
        "poetry run assess decide '<cid>' --decision continue --reviewer 'A B'",
        "poetry run python -m evals.run --agent all",
    ]


def test_an_assess_run_naming_a_missing_wrong_case_absolute_or_climbing_path_is_reported():
    lines = [
        "poetry run assess run nowhere --substance nothing.json",
        "poetry run assess run Examples/sample-client-repo",
        "poetry run assess run /etc",
        "poetry run assess run ../x",
        "poetry run assess run examples --substance x",
        "poetry run assess run examples/sample-client-repo --substance examples/substance-toy.json",
    ]
    text = "```\n" + "\n".join(lines) + "\n```\n"
    unresolved = ["nowhere", "nothing.json", "Examples/sample-client-repo", "/etc", "../x", "x"]
    assert _unresolved_arguments(text) == unresolved
