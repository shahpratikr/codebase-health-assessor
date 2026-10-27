import copy
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from assessor import config, llm, tools
from assessor.audit import AuditLog
from assessor.guardrails import DispatchError, redact, validate
from assessor.sandbox import Workspace
from assessor.tools import deps

_SECTION = re.compile(r"^## (?P<name>[^\n]*?)[ \t]*(?:\n|\Z)(?P<body>.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL)


def _read(path: str) -> str:
    return (config.ROOT / path).read_text(encoding="utf-8")


def checklist_section(manifest: Mapping, step: str) -> str:
    """Return the text under the "## <step>" heading of the manifest's skills, up to the next "## " heading.

    Raises ValueError when the skills hold no such section or more than one; an unreadable skill raises its OSError.
    """
    sections = [
        match["body"].strip()
        for skill in manifest["skills"]
        for match in _SECTION.finditer(_read(skill))
        if match["name"] == step
    ]
    if len(sections) != 1:
        raise ValueError(f"{manifest['name']}: its skills must hold one '## {step}' section, not {len(sections)}")
    return sections[0]


def examiner_task(
    manifest: Mapping, step: str, *, workspace_label: str, challenges: Sequence[Mapping], note: str
) -> dict:
    """Return the task for one step of an examiner: the step, its checklist section, the challenges verbatim, the note.

    Raises ValueError for a step the manifest does not declare, or as checklist_section does.
    """
    if step not in [declared["name"] for declared in manifest.get("steps", [])]:
        raise ValueError(f"{manifest['name']}: {step!r} is not one of its steps")
    return {
        "workflow": manifest["name"],
        "step": step,
        "workspace": workspace_label,
        "checklist": checklist_section(manifest, step),
        "challenges": copy.deepcopy(list(challenges)),
        "note": note,
    }


def review_task(target_id: str, target: Mapping, input_context: Mapping) -> dict:
    """Return the reviewer's task: the target output and the task it was produced from, never that conversation."""
    return copy.deepcopy({"target_id": target_id, "target": dict(target), "input_context": dict(input_context)})


def writer_task(
    disposition: Mapping,
    examinations: Mapping[str, Mapping],
    reviews: Mapping[str, Mapping],
    challenges: Sequence[Mapping],
) -> dict:
    """Return the writer's task, the moderated context: the disposition, the accepted examinations keyed by examination
    ID, their latest reviews keyed by review ID, and the challenges to the previous draft.
    """
    return copy.deepcopy(
        {
            "disposition": dict(disposition),
            "examinations": dict(examinations),
            "reviews": dict(reviews),
            "challenges": list(challenges),
        }
    )


def run_subagent(
    client: object,
    audit: AuditLog,
    manifest: Mapping,
    task: Mapping,
    ctx: object,
    *,
    workspace: Workspace,
    workflow: str | None,
    step: str | None,
    parent_step_id: str | None,
    osv: deps.Transport | None = None,
) -> dict:
    """Return the agent's answer to task, from a conversation of its own, once validate accepts it for ctx, redacted
    except the references validate checked.

    Raises DispatchError when a model call fails, a tool-use stop calls no tool, a tool call would pass max_tool_calls,
    or the answer is not JSON or fails validate (all but the first also write a guardrail_rejected line); validate's
    ValueError and TypeError, a broken OSV replay file's error and any error reading the agent's files or writing the
    audit propagate.
    """
    name, cap = manifest["name"], manifest["max_tool_calls"]
    labels = {"parent_step_id": parent_step_id, "agent": name, "workflow": workflow, "step": step}
    request = {
        "model": manifest["model"],
        "effort": manifest["effort"],
        "system": "\n\n".join(_read(path).strip() for path in [manifest["prompt"], *manifest["skills"]]),
        "tools": [tools.definition(tool) for tool in manifest["tools"]],
        "output_schema": json.loads(_read(manifest["output_schema"])),
    }
    messages, calls = [{"role": "user", "content": json.dumps(task, indent=2)}], 0
    while True:
        try:
            response = llm.call(client, audit, **labels, messages=messages, **request)
        except llm.LLMError as error:
            raise DispatchError(error.code, f"{name}: the model call ended in {error.code}") from error
        if response.stop_reason != "tool_use":
            break
        uses, results = [block for block in response.content if block.type == "tool_use"], []
        if not uses:
            error = DispatchError("API_ERROR", f"{name}: the response stopped for tool use but called no tool")
            raise _rejected(audit, labels, error)
        for block in uses:
            calls += 1
            if calls > cap:
                raise _rejected(audit, labels, DispatchError("TOOL_LOOP_LIMIT", f"{name}: more than {cap} tool calls"))
            result = tools.execute(manifest, block.name, block.input, workspace=workspace, osv=osv)
            tool = block.name if block.name in config.SUBAGENT_TOOLS else None
            audit.append("tool_call", **labels, tool=tool, allowed=result.allowed, is_error=result.is_error)
            results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": result.content, "is_error": result.is_error}
            )
        # A non-streaming response that a fallback model served leaves the declined partial out of its content, so every
        # turn goes back unchanged, which also keeps its thinking blocks valid.
        messages += [{"role": "assistant", "content": response.content}, {"role": "user", "content": results}]
    text = "".join(block.text for block in response.content if block.type == "text")
    try:
        answer = json.loads(text)
    except (ValueError, RecursionError) as error:
        reason = "nested too deeply" if isinstance(error, RecursionError) else str(error)
        raise _rejected(audit, labels, DispatchError("SCHEMA_INVALID", f"{name}: the answer is not JSON", [reason]))
    try:
        accepted = validate(Path(manifest["output_schema"]).name.removesuffix(".schema.json"), answer, ctx)
    except DispatchError as error:
        raise _rejected(audit, labels, error)
    return _redacted(accepted)


def _rejected(audit: AuditLog, labels: Mapping, error: DispatchError) -> DispatchError:
    audit.append("guardrail_rejected", **labels, code=error.code, problems=len(error.details))
    return error


def _redacted(accepted: dict) -> dict:
    """Return accepted with every string redacted except the references validate checked against the workspace or the
    run, which masking would break. A file path with a .. segment is masked anyway: what precedes the .. need not exist.
    """
    redacted = redact(accepted)
    for field in ("workflow", "step", "target_id"):
        if field in accepted:
            redacted[field] = accepted[field]
    for listed, field in (("findings", "file"), ("challenges", "finding_id"), ("sections", "key")):
        for kept, original in zip(redacted.get(listed, []), accepted.get(listed, [])):
            if field != "file" or ".." not in original[field].split("/"):
                kept[field] = original[field]
    return redacted
