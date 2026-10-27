import fnmatch
import json
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import httpx2

from assessor import config
from assessor.sandbox import Workspace
from assessor.tools.files import page

Transport = Callable[[dict], object]


def dependency_file(name: str) -> tuple[str, str] | None:
    """Return (ecosystem, kind) for a file name config.DEPENDENCY_FILES recognises, else None."""
    for pattern, ecosystem, kind in config.DEPENDENCY_FILES:
        if fnmatch.fnmatchcase(name, pattern):
            return ecosystem, kind
    return None


def _recognised(workspace: Workspace, path: str) -> tuple[str, str]:
    # Checking the name the path resolves to stops a link called package.json from reading .env.
    found = dependency_file(PurePosixPath(path).name)
    if found is None or dependency_file(workspace.resolve(path).name) != found:
        raise ValueError(f"{path}: not a recognised dependency manifest")
    return found


def list_manifests(workspace: Workspace) -> dict:
    """Return up to config.LIST_MAX_ENTRIES recognised manifests with ecosystem and kind and of directories skipped as
    unreadable, and whether either list was cut.
    """
    cap, found, unreadable = config.LIST_MAX_ENTRIES, [], []
    for path in workspace.walk(unreadable=unreadable):
        try:
            ecosystem, kind = _recognised(workspace, path)
        except ValueError:
            continue
        found.append({"path": path, "ecosystem": ecosystem, "kind": kind})
        if len(found) > cap:
            break
    truncated = len(found) > cap or len(unreadable) > cap
    return {"manifests": found[:cap], "truncated": truncated, "unreadable": unreadable[:cap]}


def read_manifest(workspace: Workspace, path: str, start_line: int) -> dict:
    """Return a page of a recognised manifest's numbered lines; raises ValueError for other files, as read_file does."""
    _recognised(workspace, path)
    return page(path, workspace.read_lines(path), start_line)


def query_osv(transport: Transport, ecosystem: str, name: str, version: str) -> dict:
    """Return up to config.LIST_MAX_ENTRIES of OSV's advisories for one package version, each cut to id, aliases,
    summary, severity and fixed versions; raises ValueError for a blank or unprintable name or version, and when the
    transport fails or answers out of shape.
    """
    for field, value in (("name", name), ("version", version)):
        if not value.strip() or not value.isprintable():
            raise ValueError(f"{field} must be non-blank printable text, not {value!r}")
    key = replay_key(ecosystem, name, version)
    try:
        body = transport({"package": {"name": name, "ecosystem": ecosystem}, "version": version})
        if not isinstance(body, dict):
            raise ValueError("response is not a JSON object")
        vulns = _advisories(body, ecosystem, name)
    except httpx2.HTTPStatusError as error:
        raise ValueError(f"OSV query for {key} failed: HTTP {error.response.status_code}") from error
    except httpx2.HTTPError as error:
        raise ValueError(f"OSV query for {key} failed: {type(error).__name__}") from error
    except ValueError as error:
        raise ValueError(f"OSV query for {key} failed: {error}") from error
    # OSV pages long answers; the agent is told it saw only part of them.
    truncated = bool(body.get("next_page_token")) or len(vulns) > config.LIST_MAX_ENTRIES
    advisories = vulns[: config.LIST_MAX_ENTRIES]
    return {"ecosystem": ecosystem, "name": name, "version": version, "vulns": advisories, "truncated": truncated}


def _advisories(body: dict, ecosystem: str, name: str) -> list[dict]:
    vulns = body.get("vulns") or []
    if not isinstance(vulns, list) or not all(
        isinstance(vuln, dict) and isinstance(vuln.get("id"), str) for vuln in vulns
    ):
        raise ValueError("unexpected response shape")
    try:
        return [
            {
                "id": vuln["id"],
                "aliases": vuln.get("aliases") or [],
                "summary": _summary(vuln),
                "severity": vuln.get("severity") or [],
                "fixed": _fixed(vuln, ecosystem, name),
            }
            for vuln in vulns
        ]
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("unexpected response shape") from error


def _fixed(vuln: dict, ecosystem: str, name: str) -> list[str]:
    versions = [
        event["fixed"]
        for affected in _entries(vuln.get("affected"))
        if _affects(affected, ecosystem, name)
        for ranged in _entries(affected.get("ranges"))
        if ranged.get("type") in config.OSV_VERSION_RANGES
        for event in _entries(ranged.get("events"))
        if isinstance(event.get("fixed"), str)
    ]
    return list(dict.fromkeys(versions))


def _entries(value: object) -> list[dict]:
    # OSV leaves optional lists out or null, and a null entry names nothing; any other non-list is out of shape.
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"expected a list, not {type(value).__name__}")
    return [entry for entry in value if isinstance(entry, dict)]


def _summary(vuln: dict) -> str:
    # PYSEC records carry only details, and a blank summary says nothing, so the first non-blank text is used.
    texts = (value.strip() for value in (vuln.get("summary"), vuln.get("details")) if isinstance(value, str))
    return next((text for text in texts if text), "")[: config.OSV_SUMMARY_MAX_CHARS]


def _affects(affected: dict, ecosystem: str, name: str) -> bool:
    # One advisory can cover several packages, and an entry without a package names none; only the queried one counts.
    package = affected.get("package") or {}
    if package.get("ecosystem") != ecosystem:
        return False
    return _normalized(ecosystem, package.get("name") or "") == _normalized(ecosystem, name)


def _normalized(ecosystem: str, name: str) -> str:
    # PyPI treats letter case and runs of -, _ and . as one name (PEP 503); npm's lodash.merge and lodash-merge differ.
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def live_osv(query: dict) -> object:
    """Return OSV's JSON answer to query from config.OSV_URL.

    Raises httpx2.HTTPError for a transport failure or any non-2xx status, a redirect included, and ValueError for a
    body that is not JSON.
    """
    response = httpx2.post(config.OSV_URL, json=query, timeout=config.OSV_TIMEOUT_SECONDS, follow_redirects=False)
    response.raise_for_status()
    return response.json()


def replay_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}/{name}@{version}"


def replay_osv(path: Path) -> Transport:
    """Return a transport that answers each query with the OSV response recorded in path under its replay_key.

    Raises ValueError naming path when it is not a JSON object; an unreadable path raises its own OSError.
    """
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ValueError(f"{path}: {error}") from error
    if not isinstance(recorded, dict):
        raise ValueError(f"{path}: an OSV replay must be a JSON object")

    def answer(query: dict) -> object:
        key = replay_key(query["package"]["ecosystem"], query["package"]["name"], query["version"])
        if key not in recorded:
            raise ValueError("no recorded response")
        return recorded[key]

    return answer


def osv_transport() -> Transport:
    """Return the replay transport for the file config.osv_replay() names, or live OSV when it names none."""
    replay = config.osv_replay()
    return live_osv if replay is None else replay_osv(replay)
