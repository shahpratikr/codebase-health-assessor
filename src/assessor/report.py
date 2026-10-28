import re
from collections.abc import Mapping, Sequence

from assessor import config

_GATE_TEXT = {
    "SUBSTANCE_ELEVATION": "The substance ratings call for a human: a workflow is rated toy, or at least "
    f"{config.ELEVATING_PERIPHERAL_COUNT} are rated peripheral.",
    "OPEN_CRITICAL_CHALLENGE": "The latest review of an examination or of the report draft blocks it: a critical "
    "challenge is still open.",
    "COORDINATOR_ESCALATION": "The coordinator escalated at least one step instead of accepting it.",
}
_FENCE = re.compile(r"(?m)^([ \t]*)(?=`{3}|~{3})")
_TRAIL_HEAD = ["| Step | Examination | Review verdict | Coordinator decision | Rationale |", "|---|---|---|---|---|"]


def render(
    *,
    input_name: str,
    correlation_id: str,
    generated_at: str,
    status: str,
    gates: Sequence[Mapping],
    disposition: Mapping,
    examinations: Mapping[str, Mapping],
    verdicts: Mapping[str, str],
    draft: Mapping,
) -> str:
    """Return report.md for a run: a section per step, titled from config.REPORT_TITLES with its computed status, the
    draft's prose under each, then the review trail; every other heading is a fixed literal.

    Raises ValueError for a status that is halted or disagrees with gates (as gates.open_gates returns them), a gate or
    step with no text or title, and a draft with no section for a step; KeyError for a named examination missing from
    examinations or verdicts.
    """
    if status not in config.RUN_STATUSES or status == "halted" or (status == "pending_human") != bool(gates):
        raise ValueError(f"status {status!r} cannot go with the open gates {[gate['gate'] for gate in gates]}")
    for gate in gates:
        if gate["gate"] not in _GATE_TEXT:
            raise ValueError(f"no report text for gate {gate['gate']}")
    order = list(config.REPORT_TITLES)
    entries = sorted(disposition["steps"], key=lambda entry: _position(entry, order))
    prose = {section["key"]: section["prose"] for section in draft["sections"]}
    lines = [
        f"# Codebase Health Assessment — {_inline(input_name)}",
        "",
        f"- Correlation ID: {correlation_id}",
        f"- Generated at: {generated_at}",
        f"- Status at generation: {status}",
    ]
    if gates:
        lines.append(f"- Open gates: {', '.join(gate['gate'] for gate in gates)}")
    lines += ["", "## Executive summary", "", _block(draft["executive_summary"])]
    rows = []
    for entry in entries:
        key = f"{entry['workflow']}.{entry['step']}"
        if key not in prose:
            raise ValueError(f"the draft has no section for {key}")
        title, examination_id = config.REPORT_TITLES[key], entry["examination_id"]
        section_status = _status(examinations[examination_id]["findings"])
        lines += ["", f"## {title} — {section_status}", "", _block(prose[key])]
        rows.append(
            f"| {title} | {examination_id} | {verdicts[examination_id]} | {entry['decision']} | "
            f"{_cell(entry['rationale'])} |"
        )
    lines += ["", "## Review trail", "", *_TRAIL_HEAD, *rows]
    if status == "pending_human":
        lines += ["", "## Human review", "", "This run is waiting for a human decision. Open gates:", ""]
        for gate in gates:
            lines.append(f"- {gate['gate']}: {_GATE_TEXT[gate['gate']]} Subjects: {', '.join(gate['subjects'])}.")
    return "\n".join(lines) + "\n"


def _position(entry: Mapping, order: Sequence[str]) -> int:
    key = f"{entry['workflow']}.{entry['step']}"
    if key not in order:
        raise ValueError(f"no report title for step {key}")
    return order.index(key)


def _status(findings: Sequence[Mapping]) -> str:
    return "FAIL" if any(finding["severity"] in config.FAILING_SEVERITIES for finding in findings) else "PASS"


def _escaped(text: str) -> str:
    # A raw "<" would start HTML, so a comment or tag in model text could hide or forge a heading or a status.
    return text.replace("<", "&lt;")


def _block(text: str) -> str:
    # A code fence left open would turn every later heading into code, so a line that would open one is escaped.
    return _FENCE.sub(r"\1\\", _escaped(re.sub(r"\r\n?", "\n", text.strip())))


def _inline(text: str) -> str:
    return _escaped(" ".join(text.split()))


def _cell(text: str) -> str:
    return _inline(text).replace("\\", "\\\\").replace("|", "\\|")
