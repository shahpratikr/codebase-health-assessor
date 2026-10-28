import contextlib
import copy
import posixpath
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from assessor.agents import runner
from assessor.guardrails import (
    DispatchError,
    ExaminationContext,
    ReviewContext,
    WriterContext,
    validate,
)
from assessor.sandbox import Workspace


@contextlib.contextmanager
def workspace_of(files: Mapping[str, str]) -> Iterator[Workspace]:
    """Return a context manager yielding a Workspace over a temporary directory that holds files at their relative
    paths, and removing it on exit.

    Raises ValueError naming "files", before anything is left behind, for a name Workspace.resolve refuses, two names
    for one file (letter case and Unicode form ignored) and a name or text that cannot be written beside the others.
    """
    with tempfile.TemporaryDirectory() as root:
        workspace, written = Workspace(Path(root)), {}
        for name, text in files.items():
            folded = unicodedata.normalize("NFC", posixpath.normpath(name)).casefold()
            if folded in written:
                same = f"{name} and {written[folded]} name the same file, letter case or Unicode form ignored"
                raise ValueError(f"files: {same}")
            written[folded] = name
            try:
                path = workspace.resolve(name)
            except ValueError as error:
                raise ValueError(f"files: {error}") from error
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            except (OSError, UnicodeEncodeError) as error:
                reason = getattr(error, "strerror", None) or type(error).__name__
                raise ValueError(f"files: {name}: {reason}") from error
        yield workspace


def _clean_examination(ctx: ExaminationContext) -> dict:
    return {"summary": "No findings.", "findings": [], "limitations": [], "challenge_responses": []}


def _passing_review(ctx: ReviewContext) -> dict:
    return {"verdict": "pass", "summary": "No challenges.", "challenges": []}


def _stock_draft(ctx: WriterContext) -> dict:
    sections = [{"key": f"{workflow}.{step}", "prose": "Nothing was reported."} for workflow, step in ctx.steps]
    return {"executive_summary": "Every step was examined and reviewed.", "sections": sections}


_DEFAULTS = {"examination": _clean_examination, "review": _passing_review, "writer_output": _stock_draft}


_FIXED = {"examination": ("workflow", "step"), "review": ("target_id",)}


def _labelled(contract: str, ctx: object, body: dict) -> dict:
    """Return body with the fields the dispatch fixes, which a script never states."""
    match contract:
        case "examination":
            return {**body, "workflow": ctx.workflow, "step": ctx.step}
        case "review":
            return {**body, "target_id": ctx.target_id}
    return body


def _contract(manifest: Mapping) -> str:
    return Path(manifest["output_schema"]).name.removesuffix(".schema.json")


class ScriptedDispatcher:
    """Stand-in for agents.runner.run_subagent that answers each dispatch from a script, with no model call.

    The nth call for an agent and step takes the nth attempt of its answer, the last repeating, and a key the script
    lacks gets a clean examination, a passing review or a stock draft; each goes through guardrails.validate.
    """

    def __init__(self, script: Mapping) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self._attempts = {
            (answer["agent"], answer.get("step")): copy.deepcopy(answer["attempts"])
            for answer in script.get("answers", [])
        }
        self._made: Counter[tuple[str, str | None]] = Counter()

    def __call__(
        self,
        client: object,
        audit: object,
        manifest: Mapping,
        task: Mapping,
        ctx: object,
        *,
        workspace: Workspace,
        workflow: str | None,
        step: str | None,
        parent_step_id: str | None,
        osv: Callable[[dict], object] | None = None,
    ) -> dict:
        """Return the validated, redacted answer for this dispatch; raises the DispatchError validate raises for it."""
        key = (manifest["name"], step)
        self.calls.append(key)
        self._made[key] += 1
        contract, attempts = _contract(manifest), self._attempts.get(key)
        if attempts is None:
            body = _DEFAULTS[contract](ctx)
        else:
            body = attempts[min(self._made[key], len(attempts)) - 1]["output"]
        # The runner's own redaction, so that what reaches the coordinator and the disk is what a sub-agent's would be.
        return runner._redacted(validate(contract, _labelled(contract, ctx, body), ctx))


@contextlib.contextmanager
def replacing_subagents(scripted: Callable[..., dict]) -> Iterator[None]:
    """Return a context manager that puts scripted in place of agents.runner.run_subagent and restores it on exit,
    also after an error.
    """
    original = runner.run_subagent
    runner.run_subagent = scripted
    try:
        yield
    finally:
        runner.run_subagent = original


def _why(error: DispatchError) -> str:
    return "; ".join([error.message, *error.details])


_CONTRACT_OF_ROLE = {"examiner": "examination", "reviewer": "review", "writer": "writer_output"}


def check_script(script: Mapping, manifests: Mapping[str, Mapping]) -> None:
    """Return None when each answer of script names a dispatch the coordinator can make, once, and each attempt is
    accepted by guardrails.validate, or refused with the code it is marked with, for each dispatch it would serve.

    Raises ValueError naming the answer, the attempt or "files"; the reviews of a step are paired in order with its
    accepted examinations (see _review_contexts), and an attempt that no dispatch can reach is not checked.
    """
    roles = {name: manifest["role"] for name, manifest in manifests.items()}
    codes = {
        (name, step["name"]): step["code"]
        for name, manifest in manifests.items()
        if manifest["role"] == "examiner"
        for step in manifest["steps"]
    }
    answers = script.get("answers", [])
    _check_keys(answers, roles, codes)
    found = {
        (answer["agent"], answer.get("step")): (
            [_finding_count(attempt["output"]) for attempt in answer["attempts"] if "refused" not in attempt],
            "refused" not in answer["attempts"][-1],
        )
        for answer in answers
        if roles[answer["agent"]] == "examiner"
    }
    with workspace_of(script.get("files", {})) as workspace:
        for number, answer in enumerate(answers):
            agent, step = answer["agent"], answer.get("step")
            reviews = {}
            if roles[agent] == "reviewer" and step is not None:
                (workflow, _), code = next((key, code) for key, code in codes.items() if key[1] == step)
                counts, repeats = found.get((workflow, step), ([0], True))
                reviews = _review_contexts(code, answer["attempts"], counts, repeats)
            for attempt_number, attempt in enumerate(answer["attempts"]):
                where = f"answers/{number}/attempts/{attempt_number}"
                if roles[agent] == "reviewer" and step is not None:
                    contexts = reviews.get(attempt_number, [])
                else:
                    contexts = [_context(roles[agent], agent, step, codes, workspace)]
                for ctx in contexts:
                    _check_attempt(where, _CONTRACT_OF_ROLE[roles[agent]], ctx, attempt)


def _finding_count(output: Mapping) -> int:
    findings = output.get("findings")
    return len(findings) if isinstance(findings, list) else 0


def _check_keys(answers: list, roles: Mapping[str, str], codes: Mapping[tuple[str, str], str]) -> None:
    steps = {step for _, step in codes}
    seen = set()
    for number, answer in enumerate(answers):
        agent, step = answer["agent"], answer.get("step")
        match roles.get(agent):
            case "examiner":
                if (agent, step) not in codes:
                    raise ValueError(f"answers/{number}: {step!r} is not a step of {agent}")
            case "reviewer":
                if step is not None and step not in steps:
                    raise ValueError(f"answers/{number}: {step!r} is not a step of an examiner")
            case "writer":
                if step is not None:
                    raise ValueError(f"answers/{number}: {agent} takes no step, not {step!r}")
            case _:
                raise ValueError(f"answers/{number}: {agent!r} is not an agent the coordinator launches")
        if (agent, step) in seen:
            raise ValueError(f"answers/{number}: {agent} and step {step!r} are listed twice")
        seen.add((agent, step))


def _check_attempt(where: str, contract: str, ctx: object, attempt: Mapping) -> None:
    marked, output = attempt.get("refused"), attempt["output"]
    if contract == "writer_output" and marked == "EVIDENCE_INVALID":
        raise ValueError(
            f"{where}: a writer's attempt cannot be marked EVIDENCE_INVALID, since whether it cites an ID its input "
            "lacks depends on the examinations the coordinator names"
        )
    if stated := [key for key in _FIXED.get(contract, ()) if key in output]:
        raise ValueError(f"{where}: output states {stated[0]}, which the dispatch fixes")
    try:
        validate(contract, _labelled(contract, ctx, output), ctx)
    except DispatchError as error:
        if error.code != marked:
            expected = f", not the marked {marked}" if marked else ""
            raise ValueError(f"{where}: {error.code}{expected}: {_why(error)}") from error
    else:
        if marked:
            raise ValueError(f"{where}: the guardrails accepted this attempt, which is marked refused {marked}")


def _context(
    role: str, agent: str, step: str | None, codes: Mapping[tuple[str, str], str], workspace: Workspace
) -> object:
    """Return the context for the dispatches whose context a script cannot change: an examination, the writer, given no
    input IDs to cite, and the review of a draft.
    """
    if role == "examiner":
        return ExaminationContext(agent, step, codes[agent, step], workspace)
    if role == "writer":
        return WriterContext(list(codes), ())
    return ReviewContext("DR-v1", [])


def _review_contexts(
    code: str, attempts: list[Mapping], found: list[int], repeats: bool
) -> dict[int, list[ReviewContext]]:
    """Return, by attempt index, the contexts of the review calls that attempt of a step's reviewer answer serves.

    The nth call takes the nth attempt, the last repeating; a call whose attempt is accepted moves on to the next
    examination and a refused one is retried on the same, and examination m holds the findings of the examiner's mth
    accepted attempt, the last repeating when repeats.
    """
    contexts: dict[int, list[ReviewContext]] = {}
    examination = 1
    for call in range(1, len(attempts) + len(found) + 2):
        index = min(call, len(attempts)) - 1
        if examination <= len(found) or (repeats and found):
            count = found[min(examination, len(found)) - 1]
            ids = [f"{code}-{k}" for k in range(1, count + 1)]
            contexts.setdefault(index, []).append(ReviewContext(f"EX-{code}-v{examination}", ids))
        if "refused" not in attempts[index]:
            examination += 1
    return contexts
