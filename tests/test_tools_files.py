import json
import os

import pytest

from assessor import config, manifest, sandbox, tools

EXAMINER = manifest.load_manifests()["security_examiner"]


def _workspace(tmp_path, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative, data in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return sandbox.Workspace(repo)


def _ok(workspace, tool, **tool_input):
    result = tools.execute(EXAMINER, tool, tool_input, workspace=workspace)
    assert not result.is_error, result.content
    return json.loads(result.content)


def _error(workspace, tool, **tool_input):
    result = tools.execute(EXAMINER, tool, tool_input, workspace=workspace)
    assert (result.allowed, result.is_error) == (True, True), result.content
    return result.content


def test_list_files_lists_every_file_relative_to_the_root(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": "", "config/settings.py": "", ".env": "", ".git/HEAD": ""})
    assert _ok(workspace, "list_files", directory=".") == {
        "files": [".env", "app.py", "config/settings.py"],
        "truncated": False,
        "unreadable": [],
    }


def test_list_files_names_the_root_as_dot_or_empty(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": ""})
    assert _ok(workspace, "list_files", directory="") == _ok(workspace, "list_files", directory=".")


def test_list_files_of_a_subdirectory_keeps_root_relative_paths(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": "", "config/settings.py": "", "config/prod/db.yml": ""})
    assert _ok(workspace, "list_files", directory="config")["files"] == ["config/settings.py", "config/prod/db.yml"]


def test_list_files_of_an_empty_workspace_is_empty(tmp_path):
    expected = {"files": [], "truncated": False, "unreadable": []}
    assert _ok(_workspace(tmp_path, {}), "list_files", directory=".") == expected


def test_list_files_truncates_at_the_entry_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 3)
    exact = _workspace(tmp_path, {"a": "", "b": "", "c": ""})
    assert _ok(exact, "list_files", directory=".") == {"files": ["a", "b", "c"], "truncated": False, "unreadable": []}
    (exact.root / "d").write_text("")
    assert _ok(exact, "list_files", directory=".") == {"files": ["a", "b", "c"], "truncated": True, "unreadable": []}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_files_walks_no_further_than_one_entry_past_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 2)
    workspace = _workspace(tmp_path, {"a": "", "b": "", "c": "", "z/d": ""})
    (workspace.root / "z").chmod(0)
    try:
        assert _ok(workspace, "list_files", directory=".") == {"files": ["a", "b"], "truncated": True, "unreadable": []}
    finally:
        (workspace.root / "z").chmod(0o755)


@pytest.mark.parametrize(
    ("directory", "message"),
    [
        ("..", "list_files: ..: outside the workspace"),
        ("/etc", "list_files: /etc: absolute paths are refused; use a path relative to the workspace root"),
        (".git", "list_files: .git: files under .git are not read"),
        ("app.py", "list_files: app.py: not a directory"),
    ],
)
def test_list_files_refuses_a_directory_outside_the_readable_workspace(tmp_path, directory, message):
    workspace = _workspace(tmp_path, {"app.py": "", ".git/HEAD": ""})
    assert _error(workspace, "list_files", directory=directory) == message


def test_read_file_returns_numbered_lines(tmp_path):
    workspace = _workspace(tmp_path, {"config.py": "DEBUG = True\n\nSECRET = 'x'\n"})
    assert _ok(workspace, "read_file", path="config.py", start_line=1) == {
        "path": "config.py",
        "start_line": 1,
        "end_line": 3,
        "total_lines": 3,
        "next_start_line": None,
        "content": "1\tDEBUG = True\n2\t\n3\tSECRET = 'x'",
    }


def test_read_file_pages_by_the_line_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "READ_MAX_LINES", 2)
    workspace = _workspace(tmp_path, {"f.txt": "a\nb\nc\nd\ne\n"})
    pages = [_ok(workspace, "read_file", path="f.txt", start_line=start) for start in (1, 3, 5)]
    assert [(page["start_line"], page["end_line"], page["next_start_line"]) for page in pages] == [
        (1, 2, 3),
        (3, 4, 5),
        (5, 5, None),
    ]
    assert [page["content"] for page in pages] == ["1\ta\n2\tb", "3\tc\n4\td", "5\te"]
    assert {page["total_lines"] for page in pages} == {5}


def test_read_file_page_can_start_mid_file(tmp_path):
    workspace = _workspace(tmp_path, {"f.txt": "a\nb\nc\n"})
    assert _ok(workspace, "read_file", path="f.txt", start_line=2)["content"] == "2\tb\n3\tc"


def test_read_file_of_an_empty_file_has_no_lines(tmp_path):
    assert _ok(_workspace(tmp_path, {"empty.py": ""}), "read_file", path="empty.py", start_line=1) == {
        "path": "empty.py",
        "start_line": 1,
        "end_line": 0,
        "total_lines": 0,
        "next_start_line": None,
        "content": "",
    }


@pytest.mark.parametrize(
    ("files", "start_line", "message"),
    [
        ({"f.txt": "a\nb\nc\n"}, 4, "read_file: f.txt: start_line 4 is past the end of the file (3 lines)"),
        ({"f.txt": ""}, 2, "read_file: f.txt: start_line 2 is past the end of the file (0 lines)"),
        ({"f.txt": "a\n"}, 0, "read_file: start_line must be a whole number of at least 1, not 0"),
        ({"f.txt": "a\n"}, -1, "read_file: start_line must be a whole number of at least 1, not -1"),
        ({"f.txt": "a\nb\n"}, 2.0, "read_file: start_line must be a whole number of at least 1, not 2.0"),
    ],
)
def test_read_file_refuses_a_start_line_outside_the_file(tmp_path, files, start_line, message):
    assert _error(_workspace(tmp_path, files), "read_file", path="f.txt", start_line=start_line) == message


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("../outside.txt", "read_file: ../outside.txt: outside the workspace"),
        (
            "/etc/passwd",
            "read_file: /etc/passwd: absolute paths are refused; use a path relative to the workspace root",
        ),
        (".git/config", "read_file: .git/config: files under .git are not read"),
        ("node_modules/x/index.js", "read_file: node_modules/x/index.js: files under node_modules are not read"),
        ("missing.py", "read_file: missing.py: not a file"),
        ("src", "read_file: src: not a file"),
        ("logo.png", "read_file: logo.png: binary file"),
    ],
)
def test_read_file_refusals_are_error_results(tmp_path, path, message):
    (tmp_path / "outside.txt").write_text("secret")
    workspace = _workspace(
        tmp_path,
        {
            ".git/config": "",
            "node_modules/x/index.js": "",
            "src/a.py": "",
            "logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",
        },
    )
    assert _error(workspace, "read_file", path=path, start_line=1) == message


def test_read_file_reads_non_utf8_text_so_a_legacy_secret_stays_visible(tmp_path):
    workspace = _workspace(tmp_path, {"legacy.ini": b"password = hunter2 ; caf\xe9\n"})
    content = _ok(workspace, "read_file", path="legacy.ini", start_line=1)["content"]
    assert content == "1\tpassword = hunter2 ; caf\ufffd"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_files_skips_and_reports_an_unreadable_directory(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": "", "pgdata/base/1": "", "src/main.py": ""})
    (workspace.root / "pgdata").chmod(0)
    try:
        result = _ok(workspace, "list_files", directory=".")
    finally:
        (workspace.root / "pgdata").chmod(0o755)
    assert result == {"files": ["app.py", "src/main.py"], "truncated": False, "unreadable": ["pgdata"]}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_files_caps_the_unreadable_list_and_flags_the_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"a.py": "", "u1/x": "", "u2/y": ""})
    locked = [workspace.root / "u1", workspace.root / "u2"]
    for folder in locked:
        folder.chmod(0)
    try:
        result = _ok(workspace, "list_files", directory=".")
    finally:
        for folder in locked:
            folder.chmod(0o755)
    assert result == {"files": ["a.py"], "truncated": True, "unreadable": ["u1"]}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_files_does_not_flag_an_unreadable_list_that_fits_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"a.py": "", "u1/x": ""})
    (workspace.root / "u1").chmod(0)
    try:
        result = _ok(workspace, "list_files", directory=".")
    finally:
        (workspace.root / "u1").chmod(0o755)
    assert result == {"files": ["a.py"], "truncated": False, "unreadable": ["u1"]}


def test_list_and_read_a_file_whose_name_holds_a_no_break_space(tmp_path):
    workspace = _workspace(tmp_path, {"notes\u00a0final.env": "TOKEN=x\n"})
    assert _ok(workspace, "list_files", directory=".")["files"] == ["notes\u00a0final.env"]
    assert _ok(workspace, "read_file", path="notes\u00a0final.env", start_line=1)["content"] == "1\tTOKEN=x"


def test_read_file_refuses_a_file_over_the_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "READ_MAX_BYTES", 4)
    workspace = _workspace(tmp_path, {"big.txt": "12345"})
    assert _error(workspace, "read_file", path="big.txt", start_line=1) == (
        "read_file: big.txt: larger than the 4-byte read limit"
    )


def test_read_file_reads_a_file_listed_with_a_unicode_name(tmp_path):
    workspace = _workspace(tmp_path, {"données/café.py": "x = 'é'\n"})
    [listed] = _ok(workspace, "list_files", directory=".")["files"]
    assert _ok(workspace, "read_file", path=listed, start_line=1)["content"] == "1\tx = 'é'"
