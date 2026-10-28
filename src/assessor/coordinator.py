import copy
import json
from collections import Counter
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field

import jsonschema

from assessor import config, llm
from assessor.agents import runner
from assessor.audit import AuditLog
from assessor.guardrails import (
    DispatchError,
    DispositionContext,
    ExaminationContext,
    ReviewContext,
    WriterContext,
    validate,
)
from assessor.manifest import COORDINATOR, LAUNCH_PREFIX
from assessor.sandbox import Workspace

_DISPOSITION = json.loads((config.SCHEMAS_DIR / "disposition.schema.json").read_text(encoding="utf-8"))
_IDS = {"type": "array", "items": {"type": "string"}}
_TEXT = {"type": "string"}
_FINDING_SUMMARY = ("id", "severity", "title", "file", "line")


def _object(**properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


@dataclass(frozen=True)
class Accepted:
    """An output the guardrails accepted, under the ID the harness gave it, with its dispatch's step labels and the
    task it was produced from."""

    id: str
    workflow: str
    step: str | None
    output: dict
    task: dict


@dataclass
class RunState:
    """What one coordinator run produced: accepted outputs by ID in order, the latest review of each reviewed output,
    the dispatches per cap key, the coordinator calls made, and the halt reason, None when the coordinator finished."""

    examinations: dict[str, Accepted] = field(default_factory=dict)
    reviews: dict[str, Accepted] = field(default_factory=dict)
    drafts: dict[str, Accepted] = field(default_factory=dict)
    latest_review: dict[str, str] = field(default_factory=dict)
    dispatches: Counter[tuple[str, str | None]] = field(default_factory=Counter)
    turns: int = 0
    halt_reason: str | None = None


def section_status(findings: Sequence[Mapping]) -> str:
    """Return FAIL when any finding has a severity in config.FAILING_SEVERITIES, otherwise PASS."""
    return "FAIL" if any(finding["severity"] in config.FAILING_SEVERITIES for finding in findings) else "PASS"


def tool_definitions(manifests: Mapping[str, Mapping]) -> list[dict]:
    """Return the strict definition of each coordinator tool, in manifest order, built from the agent it launches.

    Raises ValueError for a tool that is not launch_<agent> for a loaded sub-agent.
    """
    return [_definition(_launched(manifests, name), name) for name in manifests[COORDINATOR]["tools"]]


def _launched(manifests: Mapping[str, Mapping], name: str) -> Mapping:
    agent = manifests.get(name.removeprefix(LAUNCH_PREFIX)) if name.startswith(LAUNCH_PREFIX) else None
    if agent is None or agent["role"] == COORDINATOR:
        raise ValueError(f"{COORDINATOR}: tool {name} launches no loaded sub-agent")
    return agent


def _definition(agent: Mapping, name: str) -> dict:
    match agent["role"]:
        case "examiner":
            steps = [step["name"] for step in agent["steps"]]
            schema = _object(step={"type": "string", "enum": steps}, challenge_ids=_IDS, note=_TEXT)
            description = (
                f"Dispatch the {agent['name']} to examine one step ({', '.join(steps)}) in a fresh context. "
                "challenge_ids are IDs of review challenges to an earlier examination of that step, passed to it "
                "verbatim; leave them empty for a first examination. note is passed on as you write it. Returns the "
                "accepted examination (examination_id, step, version, status, findings) or an error."
            )
        case "reviewer":
            schema = _object(target_id=_TEXT)
            description = (
                f"Dispatch the {agent['name']} to review one output in a fresh context: an examination (EX-...) or a "
                "report draft (DR-...). Returns the review (review_id, target_id, verdict, challenges, each with its "
                "id) or an error."
            )
        case "writer":
            schema = _object(disposition=_DISPOSITION, challenge_ids=_IDS)
            description = (
                f"Dispatch the {agent['name']} to write the report's prose from your disposition: one entry per step "
                "naming the reviewed examination you accept or escalate, with your rationale, plus a summary. "
                "challenge_ids are IDs of review challenges to an earlier draft; leave them empty for a first draft. "
                "Returns the draft (draft_id, sections) or an error."
            )
    return copy.deepcopy({"name": name, "description": description, "input_schema": schema, "strict": True})


def run(
    client: object,
    audit: AuditLog,
    manifests: Mapping[str, Mapping],
    *,
    workspace: Workspace,
    workspace_label: str,
    osv: Callable[[dict], object] | None = None,
) -> RunState:
    """Return the state of one run, in which the coordinator dispatches sub-agents through its launch_ tools until it
    ends its turn or the run halts.

    Raises ValueError, before any request, for a coordinator tool that launches no loaded sub-agent; any other error
    from run_subagent, or from reading an agent's prompt or skills or writing the audit or an output, propagates.
    """
    coordinator = manifests[COORDINATOR]
    tools = tool_definitions(manifests)
    system = (config.ROOT / coordinator["prompt"]).read_text(encoding="utf-8").strip()
    dispatcher = _Dispatcher(client, audit, manifests, tools, workspace, workspace_label, osv)
    state = dispatcher.state
    steps = [{"workflow": workflow, "step": step} for workflow, step in dispatcher.steps]
    task = {"workspace": workspace_label, "steps": steps}
    messages = [{"role": "user", "content": json.dumps(task, indent=2)}]
    while True:
        state.turns += 1
        try:
            response = llm.call(
                client,
                audit,
                agent=COORDINATOR,
                workflow=None,
                step=None,
                parent_step_id=None,
                model=coordinator["model"],
                effort=coordinator["effort"],
                system=system,
                messages=messages,
                tools=tools,
            )
        except llm.LLMError as error:
            state.halt_reason = f"COORDINATOR_{error.code}"
            return state
        if response.stop_reason != "tool_use":
            return state
        uses = [block for block in response.content if block.type == "tool_use"]
        if not uses:
            state.halt_reason = "COORDINATOR_API_ERROR"
            return state
        if state.turns >= coordinator["max_turns"]:
            # No later call could read what these launches return, so they are not dispatched.
            state.halt_reason = "COORDINATOR_TURN_LIMIT"
            return state
        results = [dispatcher.launch(block.id, block.name, block.input) for block in uses]
        messages += [{"role": "assistant", "content": response.content}, {"role": "user", "content": results}]


def _problems(validator: jsonschema.Draft202012Validator, instance: object) -> list[str]:
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or 'the top level'}: {error.message}"
        for error in validator.iter_errors(instance)
    ]


def _harness_ids(task: Mapping) -> set[str]:
    """Return every ID the harness assigned that the writer's task holds: examination, finding, review and challenge."""
    examinations, reviews = task["examinations"], task["reviews"]
    return {
        *examinations,
        *(finding["id"] for examination in examinations.values() for finding in examination["findings"]),
        *reviews,
        *(challenge["id"] for review in reviews.values() for challenge in review["challenges"]),
        *(challenge["id"] for challenge in task["challenges"]),
    }


class _Dispatcher:
    """Answers the coordinator's launch_ blocks for one run; every check refuses a launch before any sub-agent runs."""

    def __init__(
        self,
        client: object,
        audit: AuditLog,
        manifests: Mapping[str, Mapping],
        tools: Sequence[dict],
        workspace: Workspace,
        workspace_label: str,
        osv: Callable[[dict], object] | None,
    ) -> None:
        self.client, self.audit, self.manifests, self.osv = client, audit, manifests, osv
        self.workspace, self.workspace_label = workspace, workspace_label
        self.cap = manifests[COORDINATOR]["max_dispatches_per_step"]
        self.validators = {tool["name"]: jsonschema.Draft202012Validator(tool["input_schema"]) for tool in tools}
        launched = [manifests[tool["name"].removeprefix(LAUNCH_PREFIX)] for tool in tools]
        self.codes = {
            (agent["name"], step["name"]): step["code"]
            for agent in launched
            if agent["role"] == "examiner"
            for step in agent["steps"]
        }
        self.steps = list(self.codes)
        self.state = RunState()

    def launch(self, tool_use_id: str, name: str, tool_input: object) -> dict:
        """Return the tool_result block for one launch_ block: the compact accepted output, or a DispatchError's."""
        result = self._result(name, tool_input)
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": json.dumps(result),
            "is_error": "error" in result,
        }

    def _result(self, name: str, tool_input: object) -> dict:
        validator = self.validators.get(name)
        if validator is None:
            error = DispatchError("SCHEMA_INVALID", "not a coordinator tool", [f"use {', '.join(self.validators)}"])
            return self._refused(error, None, None)
        agent = self.manifests[name.removeprefix(LAUNCH_PREFIX)]
        if problems := _problems(validator, tool_input):
            error = DispatchError("SCHEMA_INVALID", f"{name} input does not match its schema", problems)
            return self._refused(error, None if agent["role"] == "reviewer" else agent["name"], None)
        match agent["role"]:
            case "examiner":
                return self._examine(agent, tool_input)
            case "reviewer":
                return self._review(agent, tool_input)
            case "writer":
                return self._write(agent, tool_input)

    def _examine(self, agent: Mapping, tool_input: Mapping) -> dict:
        workflow, step = agent["name"], tool_input["step"]
        code = self.codes[workflow, step]
        try:
            self._check_cap((workflow, step), f"{workflow}.{step}")
            own = [
                examination_id
                for examination_id, examination in self.state.examinations.items()
                if (examination.workflow, examination.step) == (workflow, step)
            ]
            challenges = self._challenges(tool_input["challenge_ids"], f"an examination of {workflow}.{step}", own)
        except DispatchError as error:
            return self._refused(error, workflow, step)
        task = runner.examiner_task(
            agent, step, workspace_label=self.workspace_label, challenges=challenges, note=tool_input["note"]
        )

        def accept(output: dict) -> tuple[str, dict]:
            version = 1 + sum(
                (examination.workflow, examination.step) == (workflow, step)
                for examination in self.state.examinations.values()
            )
            accepted = Accepted(f"EX-{code}-v{version}", workflow, step, output, task)
            self._store(config.EXAMINATIONS_DIR, self.state.examinations, accepted)
            return accepted.id, {
                "examination_id": accepted.id,
                "step": step,
                "version": version,
                "status": section_status(output["findings"]),
                "findings": [{key: finding[key] for key in _FINDING_SUMMARY} for finding in output["findings"]],
            }

        ctx = ExaminationContext(workflow, step, code, self.workspace)
        return self._dispatch(agent, task, ctx, (workflow, step), (workflow, step), accept)

    def _review(self, agent: Mapping, tool_input: Mapping) -> dict:
        target_id = tool_input["target_id"]
        target = self.state.examinations.get(target_id) or self.state.drafts.get(target_id)
        if target is None:
            message = "target_id names no examination or draft of this run"
            return self._refused(DispatchError("UNKNOWN_TARGET", message, [f"target_id: {target_id}"]), None, None)
        labels, key = (target.workflow, target.step), (agent["name"], target_id)
        try:
            self._check_cap(key, target_id)
        except DispatchError as error:
            return self._refused(error, *labels)
        # A draft has no findings of its own, so a challenge to one names its finding only in the claim.
        finding_ids = [] if target_id in self.state.drafts else [finding["id"] for finding in target.output["findings"]]
        task = runner.review_task(target_id, target.output, target.task)

        def accept(output: dict) -> tuple[str, dict]:
            review_id = f"RV-{len(self.state.reviews) + 1}"
            challenges = [
                {"id": f"{review_id}-C{number}", **challenge}
                for number, challenge in enumerate(output["challenges"], 1)
            ]
            accepted = Accepted(review_id, *labels, {**output, "challenges": challenges}, task)
            self._store(config.REVIEWS_DIR, self.state.reviews, accepted)
            self.state.latest_review[target_id] = review_id
            return review_id, {
                "review_id": review_id,
                "target_id": target_id,
                "verdict": output["verdict"],
                "challenges": challenges,
            }

        return self._dispatch(agent, task, ReviewContext(target_id, finding_ids), labels, key, accept, target_id)

    def _write(self, agent: Mapping, tool_input: Mapping) -> dict:
        workflow, examinations, reviews = agent["name"], self.state.examinations, self.state.reviews
        try:
            self._check_cap((workflow, None), workflow)
            of_step = {examination_id: (e.workflow, e.step) for examination_id, e in examinations.items()}
            ctx = DispositionContext(self.steps, of_step, set(self.state.latest_review))
            disposition = validate("disposition", tool_input["disposition"], ctx)
            challenges = self._challenges(tool_input["challenge_ids"], "a draft", self.state.drafts)
        except DispatchError as error:
            return self._refused(error, workflow, None)
        named = [entry["examination_id"] for entry in disposition["steps"]]
        latest = [self.state.latest_review[examination_id] for examination_id in named]
        task = runner.writer_task(
            disposition,
            {examination_id: examinations[examination_id].output for examination_id in named},
            {review_id: reviews[review_id].output for review_id in latest},
            challenges,
        )

        def accept(output: dict) -> tuple[str, dict]:
            accepted = Accepted(f"DR-v{len(self.state.drafts) + 1}", workflow, None, output, task)
            self._store(config.DRAFTS_DIR, self.state.drafts, accepted)
            return accepted.id, {"draft_id": accepted.id, "sections": len(output["sections"])}

        ctx = WriterContext(self.steps, _harness_ids(task))
        return self._dispatch(agent, task, ctx, (workflow, None), (workflow, None), accept)

    def _check_cap(self, key: tuple[str, str | None], what: str) -> None:
        if self.state.dispatches[key] >= self.cap:
            raise DispatchError("RETRY_CAP_REACHED", f"{what} has had {self.cap} dispatches, the most one run allows")

    def _challenges(self, ids: Sequence[str], whose: str, targets: Collection[str]) -> list[dict]:
        """Return the challenge objects ids name, once each in order, or raise UNKNOWN_TARGET listing every ID that is
        not a challenge to one of targets."""
        known = {
            challenge["id"]: (challenge, review.output["target_id"])
            for review in self.state.reviews.values()
            for challenge in review.output["challenges"]
        }
        wanted = list(dict.fromkeys(ids))
        problems = [
            f"challenge_ids: {challenge_id} is not a challenge to {whose}"
            for challenge_id in wanted
            if challenge_id not in known or known[challenge_id][1] not in targets
        ]
        if problems:
            raise DispatchError("UNKNOWN_TARGET", f"challenge_ids must name challenges to {whose}", problems)
        return [known[challenge_id][0] for challenge_id in wanted]

    def _dispatch(
        self,
        agent: Mapping,
        task: dict,
        ctx: object,
        labels: tuple[str, str | None],
        key: tuple[str, str | None],
        accept: Callable[[dict], tuple[str, dict]],
        target_id: str | None = None,
    ) -> dict:
        """Return accept's result for the agent's validated answer to task, or the DispatchError's result."""
        workflow, step = labels
        names = {"agent": agent["name"], "workflow": workflow, "step": step}
        started = self.audit.append("dispatch_started", **names, target_id=target_id)["step_id"]
        self.state.dispatches[key] += 1
        try:
            output = runner.run_subagent(
                self.client,
                self.audit,
                agent,
                task,
                ctx,
                workspace=self.workspace,
                workflow=workflow,
                step=step,
                parent_step_id=started,
                osv=self.osv,
            )
        except DispatchError as error:
            self.audit.append("dispatch_finished", parent_step_id=started, **names, output_id=None, code=error.code)
            return error.to_result()
        output_id, result = accept(output)
        self.audit.append("dispatch_finished", parent_step_id=started, **names, output_id=output_id, code=None)
        return result

    def _refused(self, error: DispatchError, workflow: str | None, step: str | None) -> dict:
        labels = {"parent_step_id": None, "agent": COORDINATOR, "workflow": workflow, "step": step}
        self.audit.append("guardrail_rejected", **labels, code=error.code, problems=len(error.details))
        return error.to_result()

    def _store(self, kind: str, outputs: dict[str, Accepted], accepted: Accepted) -> None:
        # Exclusive creation keeps every accepted output written once; ASCII escapes keep a lone surrogate writable.
        directory = self.audit.path.parent / kind
        directory.mkdir(parents=True, exist_ok=True)
        with open(directory / f"{accepted.id}.json", "x", encoding="utf-8") as file:
            json.dump(accepted.output, file, indent=2)
        outputs[accepted.id] = accepted
