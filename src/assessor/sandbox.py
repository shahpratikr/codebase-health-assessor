import os
import re
import shutil
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from assessor import config

# A drive letter makes an entry name absolute or drive-relative on Windows (C:/x, c:x).
_DRIVE = re.compile(r"[A-Za-z]:")


class Workspace:
    """Read-only view of one client repository that resolves every path inside its root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.is_dir():
            raise ValueError(f"{root}: not a directory")

    def resolve(self, relative: str) -> Path:
        """Return the real path of relative under the root.

        Raises ValueError naming relative, never the root, for a NUL or a character the filesystem cannot encode, an
        absolute path, a path that resolves outside the root and one through a config.SKIPPED_DIRS directory in any
        letter case.
        """
        name = relative or "."
        if "\x00" in relative or not _encodable(relative):
            raise ValueError(f"{relative!r}: paths cannot contain NUL or characters the filesystem cannot encode")
        if PurePosixPath(relative).is_absolute():
            raise ValueError(f"{name}: absolute paths are refused; use a path relative to the workspace root")
        real = (self.root / relative).resolve()
        if not real.is_relative_to(self.root):
            raise ValueError(f"{name}: outside the workspace")
        for part in (*PurePosixPath(relative).parts, *real.relative_to(self.root).parts):
            if _skipped(part):
                raise ValueError(f"{name}: files under {part} are not read")
        return real

    def read_lines(self, relative: str) -> list[str]:
        """Return the file's text less any leading BOM, split on newline, each line less one trailing CR.

        Bytes that are not UTF-8 read as U+FFFD, so a legacy-encoded file stays readable. Raises ValueError naming
        relative for a path resolve refuses, a non-file, a file over config.READ_MAX_BYTES and a binary (NUL-holding)
        file; a file that cannot be opened raises its own OSError.
        """
        path, name = self.resolve(relative), relative or "."
        if not path.is_file():
            raise ValueError(f"{name}: not a file")
        with open(path, "rb") as file:
            data = file.read(config.READ_MAX_BYTES + 1)
        if len(data) > config.READ_MAX_BYTES:
            raise ValueError(f"{name}: larger than the {config.READ_MAX_BYTES}-byte read limit")
        if b"\x00" in data:
            raise ValueError(f"{name}: binary file")
        lines = data.decode("utf-8-sig", errors="replace").split("\n")
        if lines[-1] == "":
            lines.pop()
        return [line.removesuffix("\r") for line in lines]

    def walk(self, directory: str = ".", unreadable: list[str] | None = None) -> Iterator[str]:
        """Return a lazy walk yielding the root-relative path of each file resolve accepts under directory.

        Each directory's files come in name order before its subdirectories, and directory symlinks are not followed.
        A directory the walk cannot open is skipped and its root-relative path appended to unreadable. Raises
        ValueError when resolve refuses directory or it is not a directory.
        """
        start = self.resolve(directory)
        if not start.is_dir():
            raise ValueError(f"{directory or '.'}: not a directory")
        return self._walk(start, unreadable)

    def _walk(self, start: Path, unreadable: list[str] | None) -> Iterator[str]:
        pending = [start]
        while pending:
            folder = pending.pop()
            try:
                with os.scandir(folder) as scan:
                    entries = sorted(scan, key=lambda entry: entry.name)
            except OSError:
                if unreadable is not None:
                    unreadable.append(Path(folder).relative_to(self.root).as_posix())
                continue
            for entry in entries:
                if _is_file(entry) and self._readable(relative := Path(entry.path).relative_to(self.root).as_posix()):
                    yield relative
            pending.extend(
                entry.path
                for entry in reversed(entries)
                if entry.is_dir(follow_symlinks=False) and not _skipped(entry.name)
            )

    def _readable(self, relative: str) -> bool:
        try:
            self.resolve(relative)
        except ValueError:
            return False
        return True


def _encodable(path: str) -> bool:
    # Only U+DC80-U+DCFF encode, as the name bytes that are not UTF-8; the codec error for any other lone surrogate
    # would give the root's length.
    try:
        os.fsencode(path)
    except UnicodeEncodeError:
        return False
    return True


def _skipped(part: str) -> bool:
    # A case-insensitive volume (the macOS default) opens .GIT/config as .git/config.
    return part.casefold() in {name.casefold() for name in config.SKIPPED_DIRS}


def _is_file(entry: os.DirEntry) -> bool:
    # A looping symlink makes is_file raise instead of returning False, which would end the whole walk.
    try:
        return entry.is_file()
    except OSError:
        return False


def check_input(path: Path) -> None:
    """Return when path is a directory, or a zip archive whose entries pass the count, size, name and encryption checks.

    Raises ValueError naming path otherwise; it reads only the archive's entry list and writes nothing.
    """
    if path.is_dir():
        return
    if not path.exists():
        raise ValueError(f"{path}: does not exist")
    if not path.is_file():
        raise ValueError(f"{path}: not a directory or a zip archive")
    with _open_archive(path) as archive:
        _members(archive, path)


def open_workspace(source: Path, run_dir: Path) -> Workspace:
    """Return the workspace for source: a directory read in place, or a zip archive extracted to run_dir/workspace.

    Raises ValueError naming source when check_input refuses it, or when extraction fails once the partial workspace
    is removed; an existing run_dir/workspace raises FileExistsError and is left as it was.
    """
    check_input(source)
    if source.is_dir():
        return Workspace(source)
    destination = run_dir / config.WORKSPACE_DIR
    destination.mkdir(parents=True)
    try:
        _extract(source, destination)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return Workspace(destination)


def _open_archive(path: Path) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path)
    except OSError as error:
        raise ValueError(f"{path}: cannot be read: {error.strerror}") from error
    except zipfile.BadZipFile as error:
        raise ValueError(f"{path}: not a zip archive") from error
    except Exception as error:
        # zipfile also raises NotImplementedError for a newer format version and UnicodeDecodeError for a bad name.
        raise ValueError(f"{path}: unsupported or corrupt zip archive: {error}") from error


def _members(archive: zipfile.ZipFile, source: Path) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if len(members) > config.ZIP_MAX_ENTRIES:
        raise ValueError(f"{source}: {len(members)} entries is over the {config.ZIP_MAX_ENTRIES}-entry limit")
    # zipfile stops each member at its declared size (longer data fails the CRC check), so this total bounds the writes.
    size = sum(member.file_size for member in members)
    if size > config.ZIP_MAX_BYTES:
        raise ValueError(f"{source}: {size} bytes uncompressed is over the {config.ZIP_MAX_BYTES}-byte limit")
    for member in members:
        _entry_parts(member.filename, source)
        if member.flag_bits & 0x1:
            raise ValueError(f"{source}: {member.filename} is encrypted")
    return members


def _entry_parts(name: str, source: Path) -> list[str]:
    """Return the path components of a zip entry name; raises ValueError naming source for one that could escape."""
    parts = name.replace("\\", "/").split("/")
    if name.startswith(("/", "\\")) or _DRIVE.match(parts[0]) or ".." in parts:
        raise ValueError(f"{source}: entry {name} escapes the workspace")
    return [part for part in parts if part not in ("", ".")]


def _extract(source: Path, destination: Path) -> None:
    with _open_archive(source) as archive:
        for member in _members(archive, source):
            target = destination.joinpath(*_entry_parts(member.filename, source))
            try:
                if member.is_dir() or member.filename.endswith("\\"):
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as packed, open(target, "wb") as unpacked:
                    shutil.copyfileobj(packed, unpacked)
            except Exception as error:
                raise ValueError(f"{source}: could not extract {member.filename}: {error}") from error
