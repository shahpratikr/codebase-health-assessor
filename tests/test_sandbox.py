import builtins
import os
import struct
import zipfile
from itertools import islice

import pytest

from assessor import config, sandbox


def _tree(root, files):
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return root


def _workspace(tmp_path, files=None):
    return sandbox.Workspace(_tree(tmp_path / "repo", files or {"app.py": "print('hi')\n"}))


def _zip(path, entries, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return path


def _patched(path, local_offset, central_offset, fmt, value):
    """Rewrite one field of the first member's local and central headers, e.g. its sizes or flag bits."""
    data = bytearray(path.read_bytes())
    struct.pack_into(fmt, data, data.find(b"PK\x03\x04") + local_offset, value)
    struct.pack_into(fmt, data, data.find(b"PK\x01\x02") + central_offset, value)
    path.write_bytes(bytes(data))
    return path


def _refuses_zip(tmp_path, archive, match):
    run_dir = tmp_path / "run"
    with pytest.raises(ValueError, match=match):
        sandbox.check_input(archive)
    with pytest.raises(ValueError, match=match):
        sandbox.open_workspace(archive, run_dir)
    assert not (run_dir / config.WORKSPACE_DIR).exists()


def test_workspace_root_is_the_resolved_directory(tmp_path):
    repo = _tree(tmp_path / "repo", {"a.txt": "a"})
    (tmp_path / "alias").symlink_to(repo, target_is_directory=True)
    assert sandbox.Workspace(tmp_path / "alias").root == repo.resolve()


def test_workspace_refuses_a_root_that_is_not_a_directory(tmp_path):
    (tmp_path / "file.txt").write_text("x")
    with pytest.raises(ValueError, match="not a directory"):
        sandbox.Workspace(tmp_path / "file.txt")


@pytest.mark.parametrize(
    ("relative", "expected"), [("app.py", "app.py"), ("src/x.py", "src/x.py"), ("./src/../app.py", "app.py")]
)
def test_resolve_returns_the_real_path_inside_the_root(tmp_path, relative, expected):
    workspace = _workspace(tmp_path, {"app.py": "", "src/x.py": ""})
    assert workspace.resolve(relative) == workspace.root / expected


@pytest.mark.parametrize("relative", ["", "."])
def test_resolve_of_an_empty_or_dot_path_is_the_root(tmp_path, relative):
    workspace = _workspace(tmp_path)
    assert workspace.resolve(relative) == workspace.root


@pytest.mark.parametrize("inside", [False, True])
def test_resolve_refuses_absolute_paths_even_inside_the_root(tmp_path, inside):
    workspace = _workspace(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        workspace.resolve(str(workspace.root / "app.py") if inside else "/etc/passwd")


@pytest.mark.parametrize("relative", ["..", "../outside.txt", "src/../../outside.txt", "./../repo/../outside.txt"])
def test_resolve_refuses_parent_escapes(tmp_path, relative):
    (tmp_path / "outside.txt").write_text("secret")
    with pytest.raises(ValueError, match="outside the workspace"):
        _workspace(tmp_path, {"src/x.py": ""}).resolve(relative)


@pytest.mark.parametrize("relative", ["file_link", "dir_link", "dir_link/secret.txt"])
def test_resolve_refuses_symlinks_that_leave_the_root(tmp_path, relative):
    _tree(tmp_path / "outside", {"secret.txt": "secret"})
    workspace = _workspace(tmp_path)
    (workspace.root / "file_link").symlink_to(tmp_path / "outside" / "secret.txt")
    (workspace.root / "dir_link").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="outside the workspace"):
        workspace.resolve(relative)


def test_resolve_follows_symlinks_that_stay_inside(tmp_path):
    workspace = _workspace(tmp_path, {"real/config.py": "x"})
    (workspace.root / "alias.py").symlink_to(workspace.root / "real" / "config.py")
    assert workspace.resolve("alias.py") == workspace.root / "real" / "config.py"


@pytest.mark.parametrize(
    "relative",
    [".git/config", "node_modules/lodash/package.json", ".venv/bin/python", "src/node_modules/x.js", ".git/../app.py"],
)
def test_resolve_refuses_skipped_directories(tmp_path, relative):
    workspace = _workspace(
        tmp_path,
        {
            "app.py": "",
            ".git/config": "",
            "node_modules/lodash/package.json": "{}",
            ".venv/bin/python": "",
            "src/node_modules/x.js": "",
        },
    )
    with pytest.raises(ValueError, match="not read"):
        workspace.resolve(relative)


@pytest.mark.parametrize("relative", [".GIT/config", ".Git/config", "Node_Modules/x/index.js", "web/.VENV/bin/python"])
def test_resolve_refuses_skipped_directories_in_any_letter_case(tmp_path, relative):
    workspace = _workspace(tmp_path, {relative: "token=x"})
    with pytest.raises(ValueError, match="not read"):
        workspace.resolve(relative)


def test_resolve_refuses_a_symlink_into_a_skipped_directory(tmp_path):
    workspace = _workspace(tmp_path, {".git/config": "[remote]"})
    (workspace.root / "gitconfig").symlink_to(workspace.root / ".git" / "config")
    with pytest.raises(ValueError, match="not read"):
        workspace.resolve("gitconfig")


@pytest.mark.parametrize("relative", ["app.py\x00.txt", "\ud800", "a\udc7f.py", "b\udd00.py", "z\udfff.py"])
def test_resolve_refuses_nul_and_unencodable_characters_without_touching_the_filesystem(tmp_path, relative):
    workspace = _workspace(tmp_path)
    with pytest.raises(ValueError) as refused:
        workspace.resolve(relative)
    assert str(refused.value) == f"{relative!r}: paths cannot contain NUL or characters the filesystem cannot encode"


@pytest.mark.parametrize("relative", ["a\udc80.py", "caf\udce9.env", "x\udcff"])
def test_resolve_accepts_surrogates_that_stand_for_name_bytes_that_are_not_utf8(tmp_path, relative):
    workspace = _workspace(tmp_path)
    assert workspace.resolve(relative) == workspace.root / relative


def test_walk_lists_and_reads_a_file_whose_name_is_not_utf8(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": ""})
    try:
        descriptor = os.open(os.fsencode(workspace.root) + b"/caf\xe9.env", os.O_CREAT | os.O_WRONLY)
    except OSError:
        pytest.skip("this filesystem refuses file names that are not UTF-8")
    os.write(descriptor, b"PASSWORD=x\n")
    os.close(descriptor)
    assert list(workspace.walk()) == ["app.py", "caf\udce9.env"]
    assert workspace.read_lines("caf\udce9.env") == ["PASSWORD=x"]


@pytest.mark.parametrize(
    "relative",
    [
        "notes\u00a0final.md",
        "Screenshot 10.00.00\u202fAM.txt",
        "family\u200d.txt",
        "doc\u3000wide.txt",
        "zero\u200bwidth.env",
        "tab\there.py",
        "new\nline.py",
        "dir\u3000x/inner.py",
    ],
)
def test_names_with_unusual_spacing_or_control_characters_stay_visible(tmp_path, relative):
    workspace = _workspace(tmp_path, {relative: "SECRET = 'x'\n"})
    assert list(workspace.walk()) == [relative]
    assert workspace.read_lines(relative) == ["SECRET = 'x'"]


@pytest.mark.parametrize("relative", ["../x", "/etc/passwd", ".git/config", "missing.txt", "bin.dat"])
def test_refusals_name_the_relative_path_never_the_absolute_root(tmp_path, relative):
    workspace = _workspace(tmp_path, {".git/config": "", "bin.dat": b"\x00"})
    with pytest.raises(ValueError) as refused:
        workspace.read_lines(relative)
    assert relative in str(refused.value)
    assert str(tmp_path) not in str(refused.value)


@pytest.mark.parametrize(
    ("data", "lines"),
    [
        (b"a\nb\n", ["a", "b"]),
        (b"a\nb", ["a", "b"]),
        (b"a\r\nb\r\n", ["a", "b"]),
        (b"", []),
        (b"\n", [""]),
        (b"a\n\nb", ["a", "", "b"]),
        (b"a\x0cb\x0bc\xe2\x80\xa8d", ["a\x0cb\x0bc\u2028d"]),
        (b"\xef\xbb\xbfa\n", ["a"]),
        ("café ✓\n".encode(), ["café ✓"]),
    ],
)
def test_read_lines_splits_only_on_newline(tmp_path, data, lines):
    assert _workspace(tmp_path, {"f.txt": data}).read_lines("f.txt") == lines


@pytest.mark.parametrize("data", [b"ab\x00cd", b"\xff\xfe\x00a", "utf-16 text".encode("utf-16")])
def test_read_lines_refuses_files_holding_a_nul_byte_as_binary(tmp_path, data):
    with pytest.raises(ValueError, match="f.bin: binary file"):
        _workspace(tmp_path, {"f.bin": data}).read_lines("f.bin")


def test_read_lines_reads_non_utf8_text_with_replacement_characters(tmp_path):
    workspace = _workspace(tmp_path, {"legacy.ini": b"[db]\npassword = hunter2\n; caf\xe9\n"})
    assert workspace.read_lines("legacy.ini") == ["[db]", "password = hunter2", "; caf\ufffd"]


def test_read_lines_refuses_a_file_over_the_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "READ_MAX_BYTES", 10)
    workspace = _workspace(tmp_path, {"exact.txt": "123456789\n", "over.txt": "1234567890\n"})
    assert workspace.read_lines("exact.txt") == ["123456789"]
    with pytest.raises(ValueError, match="over.txt: larger than the 10-byte read limit"):
        workspace.read_lines("over.txt")


@pytest.mark.parametrize("relative", ["src", "missing.py", "pipe", ""])
def test_read_lines_refuses_directories_missing_files_and_fifos(tmp_path, relative):
    workspace = _workspace(tmp_path, {"src/x.py": ""})
    os.mkfifo(workspace.root / "pipe")
    with pytest.raises(ValueError, match="not a file"):
        workspace.read_lines(relative)


def test_read_lines_reads_unicode_file_names(tmp_path):
    assert _workspace(tmp_path, {"données/café.py": "x = 1\n"}).read_lines("données/café.py") == ["x = 1"]


def test_walk_lists_files_before_subdirectories_in_name_order(tmp_path):
    workspace = _workspace(tmp_path, {"b.py": "", "a.py": "", "z/2.py": "", "z/1.py": "", "m/y/x.py": "", "m/k.py": ""})
    assert list(workspace.walk()) == ["a.py", "b.py", "m/k.py", "m/y/x.py", "z/1.py", "z/2.py"]


def test_walk_skips_git_node_modules_and_venv_at_any_depth(tmp_path):
    workspace = _workspace(
        tmp_path,
        {
            "app.py": "",
            ".git/HEAD": "",
            "node_modules/x/index.js": "",
            ".venv/lib/site.py": "",
            "web/node_modules/y/index.js": "",
            "web/main.js": "",
            ".github/workflow.yml": "",
        },
    )
    assert list(workspace.walk()) == ["app.py", ".github/workflow.yml", "web/main.js"]


def test_walk_skips_skipped_directories_in_any_letter_case(tmp_path):
    workspace = _workspace(
        tmp_path,
        {"app.py": "", ".GIT/config": "", "Node_Modules/x.js": "", "web/.Venv/y.py": "", "lib/.Git": "gitdir: ../x"},
    )
    assert list(workspace.walk()) == ["app.py"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_walk_never_enters_skipped_directories(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": "", "node_modules/x/index.js": "", "web/.GIT/HEAD": ""})
    locked = [workspace.root / "node_modules", workspace.root / "web" / ".GIT"]
    for folder in locked:
        folder.chmod(0)
    unreadable = []
    try:
        assert list(workspace.walk(unreadable=unreadable)) == ["app.py"]
    finally:
        for folder in locked:
            folder.chmod(0o755)
    assert unreadable == []


def test_walk_does_not_follow_directory_symlinks(tmp_path):
    workspace = _workspace(tmp_path, {"src/x.py": ""})
    _tree(tmp_path / "outside", {"secret.txt": ""})
    (workspace.root / "out").symlink_to(tmp_path / "outside", target_is_directory=True)
    (workspace.root / "loop").symlink_to(workspace.root, target_is_directory=True)
    assert list(workspace.walk()) == ["src/x.py"]


def test_walk_lists_only_file_symlinks_that_stay_inside(tmp_path):
    workspace = _workspace(tmp_path, {"real.py": "", ".git/config": ""})
    _tree(tmp_path / "outside", {"secret.txt": ""})
    (workspace.root / "inside_link.py").symlink_to(workspace.root / "real.py")
    (workspace.root / "outside_link.txt").symlink_to(tmp_path / "outside" / "secret.txt")
    (workspace.root / "git_link").symlink_to(workspace.root / ".git" / "config")
    (workspace.root / "dangling").symlink_to(workspace.root / "missing.py")
    assert list(workspace.walk()) == ["inside_link.py", "real.py"]


def test_walk_skips_symlink_loops_instead_of_failing(tmp_path):
    workspace = _workspace(tmp_path, {"ok.txt": ""})
    (workspace.root / "self.txt").symlink_to(workspace.root / "self.txt")
    (workspace.root / "a.txt").symlink_to(workspace.root / "b.txt")
    (workspace.root / "b.txt").symlink_to(workspace.root / "a.txt")
    assert list(workspace.walk()) == ["ok.txt"]


def test_walk_lists_unicode_file_names(tmp_path):
    assert list(_workspace(tmp_path, {"données/café.py": ""}).walk()) == ["données/café.py"]


def test_walk_starts_at_a_subdirectory_with_root_relative_paths(tmp_path):
    workspace = _workspace(tmp_path, {"app.py": "", "src/a.py": "", "src/lib/b.py": ""})
    assert list(workspace.walk("src")) == ["src/a.py", "src/lib/b.py"]


@pytest.mark.parametrize(
    ("directory", "match"), [("app.py", "not a directory"), ("missing", "not a directory"), ("..", "outside")]
)
def test_walk_refuses_a_start_that_is_not_a_workspace_directory(tmp_path, directory, match):
    with pytest.raises(ValueError, match=match):
        list(_workspace(tmp_path, {"app.py": ""}).walk(directory))


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_walk_reads_no_further_than_its_caller_takes(tmp_path):
    workspace = _workspace(tmp_path, {"a.py": "", "b.py": "", "z/c.py": ""})
    early, full = [], []
    (workspace.root / "z").chmod(0)
    try:
        assert list(islice(workspace.walk(unreadable=early), 2)) == ["a.py", "b.py"]
        assert list(workspace.walk(unreadable=full)) == ["a.py", "b.py"]
    finally:
        (workspace.root / "z").chmod(0o755)
    assert (early, full) == ([], ["z"])


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
@pytest.mark.parametrize(
    ("directory", "files", "unreadable"),
    [(".", ["a.py", "m/d.py"], ["z"]), ("z", [], ["z"]), ("m", ["m/d.py"], [])],
)
def test_walk_skips_and_reports_unreadable_directories(tmp_path, directory, files, unreadable):
    workspace = _workspace(tmp_path, {"a.py": "", "z/c.py": "", "m/d.py": ""})
    reported = []
    (workspace.root / "z").chmod(0)
    try:
        assert list(workspace.walk(directory, unreadable=reported)) == files
    finally:
        (workspace.root / "z").chmod(0o755)
    assert reported == unreadable


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_walk_reports_an_unreadable_root_as_dot(tmp_path):
    workspace, reported = _workspace(tmp_path, {"a.py": ""}), []
    workspace.root.chmod(0)
    try:
        assert list(workspace.walk(unreadable=reported)) == []
    finally:
        workspace.root.chmod(0o755)
    assert reported == ["."]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_walk_skips_an_unreadable_directory_even_when_no_one_asks_which(tmp_path):
    workspace = _workspace(tmp_path, {"a.py": "", "z/c.py": ""})
    (workspace.root / "z").chmod(0)
    try:
        assert list(workspace.walk()) == ["a.py"]
    finally:
        (workspace.root / "z").chmod(0o755)


def test_directory_input_is_read_in_place(tmp_path):
    repo = _tree(tmp_path / "repo", {"app.py": ""})
    run_dir = tmp_path / "run"
    sandbox.check_input(repo)
    workspace = sandbox.open_workspace(repo, run_dir)
    assert workspace.root == repo.resolve()
    assert not run_dir.exists()


def test_zip_input_is_extracted_into_the_run_workspace(tmp_path):
    archive = _zip(
        tmp_path / "repo.zip",
        [
            ("app.py", b"print('hi')\n"),
            ("src/", b""),
            ("src/lib/util.py", b"x = 1\n"),
            ("données/café.txt", "é".encode()),
        ],
    )
    run_dir = tmp_path / "run"
    sandbox.check_input(archive)
    workspace = sandbox.open_workspace(archive, run_dir)
    assert workspace.root == (run_dir / config.WORKSPACE_DIR).resolve()
    assert list(workspace.walk()) == ["app.py", "données/café.txt", "src/lib/util.py"]
    assert (workspace.root / "src" / "lib" / "util.py").read_bytes() == b"x = 1\n"


def test_empty_zip_gives_an_empty_workspace(tmp_path):
    workspace = sandbox.open_workspace(_zip(tmp_path / "empty.zip", []), tmp_path / "run")
    assert list(workspace.walk()) == []


def test_zip_input_with_another_suffix_is_still_a_zip(tmp_path):
    archive = _zip(tmp_path / "repo.archive", [("app.py", b"")])
    assert list(sandbox.open_workspace(archive, tmp_path / "run").walk()) == ["app.py"]


def test_missing_input_is_refused_and_nothing_is_written(tmp_path):
    run_dir = tmp_path / "run"
    with pytest.raises(ValueError, match="does not exist"):
        sandbox.check_input(tmp_path / "missing")
    with pytest.raises(ValueError, match="does not exist"):
        sandbox.open_workspace(tmp_path / "missing", run_dir)
    assert not run_dir.exists()


@pytest.mark.parametrize(
    ("name", "data"), [("notes.txt", b"hello"), ("fake.zip", b"PK not really"), ("empty.zip", b"")]
)
def test_a_file_that_is_not_a_zip_is_refused(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    _refuses_zip(tmp_path, tmp_path / name, "not a zip archive")
    assert not (tmp_path / "run").exists()


def test_a_special_file_is_refused_without_reading_it(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ValueError, match="not a directory or a zip archive"):
        sandbox.check_input(tmp_path / "pipe")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable files")
def test_an_unreadable_zip_is_an_input_error(tmp_path):
    archive = _zip(tmp_path / "repo.zip", [("app.py", b"")])
    archive.chmod(0)
    try:
        with pytest.raises(ValueError, match="repo.zip"):
            sandbox.check_input(archive)
    finally:
        archive.chmod(0o644)


@pytest.mark.parametrize(
    "name",
    ["../evil.txt", "..", "a/../../evil.txt", "a/../b.txt", "/abs/evil.txt", "..\\evil.txt", "a\\..\\..\\evil.txt",
     "\\abs\\evil.txt", "C:/evil.txt", "C:\\evil.txt", "c:evil.txt"],
)
def test_zip_entries_that_could_escape_the_root_are_refused(tmp_path, name):
    archive = tmp_path / "repo.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("app.py", b"")
        handle.writestr(zipfile.ZipInfo(name), b"pwned")
    _refuses_zip(tmp_path, archive, "escapes the workspace")
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path.parent / "evil.txt").exists()


def test_zip_entry_cap_counts_every_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ZIP_MAX_ENTRIES", 3)
    exact = _zip(tmp_path / "exact.zip", [("a/", b""), ("a/1.txt", b""), ("2.txt", b"")])
    assert list(sandbox.open_workspace(exact, tmp_path / "ok").walk()) == ["2.txt", "a/1.txt"]
    over = _zip(tmp_path / "over.zip", [("a/", b""), ("a/1.txt", b""), ("2.txt", b""), ("3.txt", b"")])
    _refuses_zip(tmp_path, over, "4 entries is over the 3-entry limit")


def test_zip_size_cap_counts_the_declared_uncompressed_total(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ZIP_MAX_BYTES", 100)
    exact = _zip(tmp_path / "exact.zip", [("a.txt", b"x" * 60), ("b.txt", b"y" * 40)])
    assert list(sandbox.open_workspace(exact, tmp_path / "ok").walk()) == ["a.txt", "b.txt"]
    over = _zip(tmp_path / "over.zip", [("a.txt", b"\0" * 60), ("b.txt", b"\0" * 41)])
    _refuses_zip(tmp_path, over, "101 bytes uncompressed is over the 100-byte limit")


def test_shipped_zip_size_cap_refuses_a_highly_compressed_bomb(tmp_path):
    bomb = _zip(tmp_path / "bomb.zip", [("zeros.bin", b"\0" * (config.ZIP_MAX_BYTES + 1))])
    assert bomb.stat().st_size < 1024 * 1024
    _refuses_zip(tmp_path, bomb, "50000001 bytes uncompressed is over the 50000000-byte limit")


def test_a_lying_size_header_cannot_write_past_its_declared_size(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ZIP_MAX_BYTES", 100)
    archive = _zip(tmp_path / "liar.zip", [("big.txt", b"A" * 5000)], compression=zipfile.ZIP_STORED)
    _patched(archive, 22, 24, "<I", 10)
    sandbox.check_input(archive)
    with pytest.raises(ValueError, match="could not extract big.txt"):
        sandbox.open_workspace(archive, tmp_path / "run")
    assert not (tmp_path / "run" / config.WORKSPACE_DIR).exists()


def test_an_unsupported_zip_version_is_an_input_error(tmp_path):
    archive = _patched(_zip(tmp_path / "future.zip", [("app.py", b"")]), 4, 6, "<H", 255)
    _refuses_zip(tmp_path, archive, "future.zip: unsupported or corrupt zip archive")
    assert not (tmp_path / "run").exists()


def test_a_zip_entry_name_that_is_not_utf8_is_an_input_error(tmp_path):
    archive = _patched(_zip(tmp_path / "names.zip", [("x.txt", b"")]), 6, 8, "<H", 0x800)
    archive.write_bytes(archive.read_bytes().replace(b"x.txt", b"\xff.txt"))
    _refuses_zip(tmp_path, archive, "names.zip: unsupported or corrupt zip archive")


def test_backslash_directory_entries_extract_as_directories(tmp_path):
    archive = tmp_path / "windows.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(zipfile.ZipInfo("src\\"), b"")
        handle.writestr(zipfile.ZipInfo("src\\app.py"), b"print('hi')\n")
    assert list(sandbox.open_workspace(archive, tmp_path / "run").walk()) == ["src/app.py"]


def test_encrypted_entries_are_refused_before_extraction(tmp_path):
    archive = _patched(_zip(tmp_path / "locked.zip", [("secret.txt", b"x")]), 6, 8, "<H", 1)
    _refuses_zip(tmp_path, archive, "secret.txt is encrypted")


def test_a_corrupt_member_leaves_no_partial_workspace(tmp_path):
    entries = [("a.txt", b"first"), ("b.txt", b"second")]
    archive = _zip(tmp_path / "corrupt.zip", entries, compression=zipfile.ZIP_STORED)
    data = archive.read_bytes()
    archive.write_bytes(data.replace(b"second", b"SECOND", 1))
    run_dir = tmp_path / "run"
    with pytest.raises(ValueError, match="could not extract b.txt"):
        sandbox.open_workspace(archive, run_dir)
    assert run_dir.is_dir()
    assert not (run_dir / config.WORKSPACE_DIR).exists()


def test_a_file_and_directory_with_one_name_is_an_extraction_error(tmp_path):
    archive = _zip(tmp_path / "clash.zip", [("a", b"file"), ("a/b.txt", b"")])
    with pytest.raises(ValueError, match="could not extract a/b.txt"):
        sandbox.open_workspace(archive, tmp_path / "run")
    assert not (tmp_path / "run" / config.WORKSPACE_DIR).exists()


def test_a_write_failure_mid_extraction_removes_the_partial_workspace(tmp_path, monkeypatch):
    archive = _zip(tmp_path / "repo.zip", [("a.txt", b"a"), ("b.txt", b"b")])
    real_open, calls = builtins.open, []

    def failing_second_open(path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 2:
            raise OSError(28, "No space left on device")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(sandbox, "open", failing_second_open, raising=False)
    with pytest.raises(ValueError, match="could not extract b.txt: .*No space left on device"):
        sandbox.open_workspace(archive, tmp_path / "run")
    assert not (tmp_path / "run" / config.WORKSPACE_DIR).exists()


def test_an_interrupt_mid_extraction_still_removes_the_partial_workspace(tmp_path, monkeypatch):
    archive = _zip(tmp_path / "repo.zip", [("a.txt", b"a"), ("b.txt", b"b")])
    real_open, calls = builtins.open, []

    def interrupted_second_open(path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(sandbox, "open", interrupted_second_open, raising=False)
    with pytest.raises(KeyboardInterrupt):
        sandbox.open_workspace(archive, tmp_path / "run")
    assert not (tmp_path / "run" / config.WORKSPACE_DIR).exists()


def test_an_existing_workspace_is_never_merged_into(tmp_path):
    run_dir = tmp_path / "run"
    _tree(run_dir / config.WORKSPACE_DIR, {"earlier.txt": "keep"})
    with pytest.raises(FileExistsError):
        sandbox.open_workspace(_zip(tmp_path / "repo.zip", [("app.py", b"")]), run_dir)
    assert (run_dir / config.WORKSPACE_DIR / "earlier.txt").read_text() == "keep"
    assert not (run_dir / config.WORKSPACE_DIR / "app.py").exists()


def test_symlink_entries_are_extracted_as_plain_files(tmp_path):
    link = zipfile.ZipInfo("link")
    link.external_attr = 0o120777 << 16
    archive = tmp_path / "links.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(link, b"../../../etc/passwd")
    workspace = sandbox.open_workspace(archive, tmp_path / "run")
    assert not (workspace.root / "link").is_symlink()
    assert workspace.read_lines("link") == ["../../../etc/passwd"]
