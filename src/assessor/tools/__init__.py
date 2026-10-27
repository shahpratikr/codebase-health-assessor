import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass

import jsonschema

from assessor import config
from assessor.sandbox import Workspace
from assessor.tools import deps, files


def _object(**properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


_TEXT = {"type": "string"}
# Strict tool use accepts only the structured-outputs keywords, so ranges such as start_line >= 1 are checked in code.
INPUT_SCHEMAS = {
    "list_files": _object(directory=_TEXT),
    "read_file": _object(path=_TEXT, start_line={"type": "integer"}),
    "list_manifests": _object(),
    "read_manifest": _object(path=_TEXT, start_line={"type": "integer"}),
    "query_osv": _object(ecosystem={"type": "string", "enum": list(config.OSV_ECOSYSTEMS)}, name=_TEXT, version=_TEXT),
}
_VALIDATORS = {name: jsonschema.Draft202012Validator(schema) for name, schema in INPUT_SCHEMAS.items()}
_PAGE = (
    f"Returns up to {config.READ_MAX_LINES} lines from start_line (1 is the first line), each as "
    "'<line number>\\t<text>': cite these line numbers. next_start_line is the line to ask for next, or null at the "
    "end of the file."
)
DESCRIPTIONS = {
    "list_files": (
        "List the repository's files under a directory ('.' or '' for the root), each directory's files before its "
        f"subdirectories. Returns up to {config.LIST_MAX_ENTRIES} paths relative to the root; truncated is true when "
        "the list was cut, and unreadable names directories that could not be opened. Skips "
        f"{', '.join(config.SKIPPED_DIRS)}."
    ),
    "read_file": (
        f"Read a text file of the repository by its path from list_files. {_PAGE} Binary files and files over "
        f"{config.READ_MAX_BYTES} bytes are refused."
    ),
    "list_manifests": (
        "List the repository's PyPI and npm dependency files, each with its path, ecosystem and kind (manifest or "
        "lockfile)."
    ),
    "read_manifest": (
        f"Read a dependency file that list_manifests returned, by its path. {_PAGE} Files over "
        f"{config.READ_MAX_BYTES} bytes are refused."
    ),
    "query_osv": (
        "Look up the known advisories for one exact version of a PyPI or npm package in OSV. Returns each advisory's "
        "id, aliases, summary, severity and the versions that fix it; vulns is empty when none are known. An error "
        "result means the lookup failed, not that the package is clean."
    ),
}


@dataclass(frozen=True)
class ToolResult:
    """One tool call's outcome: JSON text, or the reason when is_error; allowed is False for an undeclared tool."""

    content: str
    is_error: bool = False
    allowed: bool = True


def definition(name: str) -> dict:
    """Return the strict Messages API definition of tool name, a copy the caller may change; raises KeyError for a name
    outside INPUT_SCHEMAS.
    """
    return {
        "name": name,
        "description": DESCRIPTIONS[name],
        "input_schema": copy.deepcopy(INPUT_SCHEMAS[name]),
        "strict": True,
    }


def execute(
    manifest: Mapping, name: str, tool_input: object, *, workspace: Workspace, osv: deps.Transport | None = None
) -> ToolResult:
    """Return the result of tool name for an agent whose manifest declares it, or a refusal with allowed False.

    Input outside the tool's schema and a ValueError or OSError from the tool are is_error results; when osv is None,
    deps.osv_transport() supplies it, and a broken replay file raises instead.
    """
    if name not in manifest["tools"] or name not in INPUT_SCHEMAS:
        return _error(f"{name}: not a tool of {manifest['name']}", allowed=False)
    invalid = jsonschema.exceptions.best_match(_VALIDATORS[name].iter_errors(tool_input))
    if invalid is not None:
        return _error(f"{name}: invalid input: {invalid.message}")
    if name == "query_osv" and osv is None:
        osv = deps.osv_transport()
    try:
        output = _run(name, tool_input, workspace, osv)
    except ValueError as error:
        return _error(f"{name}: {error}")
    except OSError as error:
        # The OSError text holds the absolute path, which would tell the agent where the workspace lives.
        return _error(f"{name}: {error.strerror or type(error).__name__}")
    return ToolResult(json.dumps(output))


def _error(message: str, allowed: bool = True) -> ToolResult:
    # Error text echoes the agent's own input, and a lone surrogate in it could not be encoded into the next request.
    return ToolResult(message.encode("utf-8", "backslashreplace").decode("utf-8"), is_error=True, allowed=allowed)


def _run(name: str, tool_input: dict, workspace: Workspace, osv: deps.Transport | None) -> dict:
    match name:
        case "list_files":
            return files.list_files(workspace, tool_input["directory"])
        case "read_file":
            return files.read_file(workspace, tool_input["path"], tool_input["start_line"])
        case "list_manifests":
            return deps.list_manifests(workspace)
        case "read_manifest":
            return deps.read_manifest(workspace, tool_input["path"], tool_input["start_line"])
        case "query_osv":
            return deps.query_osv(osv, tool_input["ecosystem"], tool_input["name"], tool_input["version"])
