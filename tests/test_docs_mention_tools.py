import re

import pytest

from assessor import config

TOOLS = ("evals.punchout", "--note", "history.jsonl", "submission.build", "submission.validate")
# Each doc and the terms it must name.
DOCS = {
    "README.md": TOOLS,
    "CLAUDE.md": TOOLS,
    "docs/ARCHITECTURE.md": TOOLS,
    "evals/results/README.md": ("history.jsonl", "punchout/"),
    "docs/PRD.md": ("evals.punchout", "submission"),
}


def _absent(text, terms):
    """Return the terms that text never names as a whole word; --notes does not name --note, nor submission.builder
    submission.build."""
    return [term for term in terms if not re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", text)]


# The sections of docs/ARCHITECTURE.md that must describe the submission tools.
ARCHITECTURE_SECTIONS = ("Repository structure", "Key flows", "Interfaces")


def _sections(text):
    """Return each `## heading` of text with the text under it, up to the next `## ` line."""
    parts = re.split(r"^## (.+)$", text, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2]))


@pytest.mark.parametrize("path", DOCS)
def test_each_doc_names_the_tools_and_files_it_must(path):
    assert _absent((config.ROOT / path).read_text(encoding="utf-8"), DOCS[path]) == []


@pytest.mark.parametrize(
    ("text", "terms", "absent"),
    [
        ("Run `python -m evals.punchout`, then --note=x.", ("evals.punchout", "--note"), []),
        ("python -m evals.punchout_v2 with --notes", ("evals.punchout", "--note"), ["evals.punchout", "--note"]),
        ("submission.builder, pre-submission.validate", TOOLS[3:], ["submission.build", "submission.validate"]),
        ("history.jsonl.", ("history.jsonl",), []),
        ("results/punchout/ holds them", ("punchout/",), []),
        ("", TOOLS, list(TOOLS)),
    ],
)
def test_a_term_counts_only_as_a_whole_word(text, terms, absent):
    assert _absent(text, terms) == absent


@pytest.mark.parametrize("section", ARCHITECTURE_SECTIONS)
def test_the_architecture_names_the_submission_tools_in_each_section_that_describes_them(section):
    sections = _sections((config.ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8"))
    assert _absent(sections[section], ("submission.build", "submission.validate")) == []


def test_a_section_that_never_names_the_tools_is_reported():
    text = "# Title\n## Key flows\nsubmission.build only\n## Interfaces\nsubmission.build and submission.validate\n"
    sections = _sections(text)
    assert list(sections) == ["Key flows", "Interfaces"]
    tools = ("submission.build", "submission.validate")
    assert {name: _absent(sections[name], tools) for name in sections} == {
        "Key flows": ["submission.validate"],
        "Interfaces": [],
    }
