from itertools import islice

from assessor import config
from assessor.sandbox import Workspace


def list_files(workspace: Workspace, directory: str) -> dict:
    """Return up to config.LIST_MAX_ENTRIES file paths under directory and of directories skipped as unreadable, and
    whether either list was cut; raises ValueError as Workspace.walk does.
    """
    cap, unreadable = config.LIST_MAX_ENTRIES, []
    found = list(islice(workspace.walk(directory, unreadable), cap + 1))
    truncated = len(found) > cap or len(unreadable) > cap
    return {"files": found[:cap], "truncated": truncated, "unreadable": unreadable[:cap]}


def read_file(workspace: Workspace, path: str, start_line: int) -> dict:
    """Return the page of path's numbered lines from start_line; raises ValueError as read_lines and page do."""
    return page(path, workspace.read_lines(path), start_line)


def page(path: str, lines: list[str], start_line: int) -> dict:
    """Return up to config.READ_MAX_LINES of lines from start_line, each prefixed with its line number and a tab.

    Raises ValueError when start_line is not a whole number of at least 1 or is past the last line.
    """
    if type(start_line) is not int or start_line < 1:
        raise ValueError(f"start_line must be a whole number of at least 1, not {start_line!r}")
    if start_line > max(len(lines), 1):
        raise ValueError(f"{path}: start_line {start_line} is past the end of the file ({len(lines)} lines)")
    shown = lines[start_line - 1 : start_line - 1 + config.READ_MAX_LINES]
    end_line = start_line + len(shown) - 1
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": len(lines),
        "next_start_line": end_line + 1 if end_line < len(lines) else None,
        "content": "\n".join(f"{number}\t{line}" for number, line in enumerate(shown, start_line)),
    }
