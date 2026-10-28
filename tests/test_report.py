import copy
import re

import pytest

from assessor import config, coordinator, manifest, report

CID = "20261027T101500Z-0a1b2c3d"
GENERATED = "2026-10-27T12:00:00.456Z"
STEPS = [
    ("security_examiner", "secrets", "SEC"),
    ("security_examiner", "insecure_config", "CFG"),
    ("dependency_examiner", "known_vulnerabilities", "VULN"),
    ("dependency_examiner", "dependency_hygiene", "HYG"),
]
TITLES = ["Secrets exposure", "Insecure configuration", "Known vulnerable dependencies", "Dependency hygiene"]


def _finding(severity, number=1, code="SEC"):
    return {"id": f"{code}-{number}", "severity": severity, "title": "A finding", "file": "config.py", "line": 1}


def _examination(step, severities=()):
    code = next(code for _, name, code in STEPS if name == step)
    findings = [_finding(severity, number, code) for number, severity in enumerate(severities, 1)]
    return {"step": step, "summary": "Examined.", "findings": findings, "limitations": []}


def _disposition(**overrides):
    entries = {
        step: {
            "workflow": workflow,
            "step": step,
            "examination_id": f"EX-{code}-v1",
            "decision": "accept",
            "rationale": "Reviewed.",
        }
        for workflow, step, code in STEPS
    }
    for step, fields in overrides.items():
        entries[step] = {**entries[step], **fields}
    return {"steps": list(entries.values()), "summary": "Done."}


def _draft(**prose):
    return {
        "executive_summary": "One committed key needs rotating.",
        "sections": [
            {"key": f"{workflow}.{step}", "prose": prose.get(step, f"The {step} step was examined.")}
            for workflow, step, _ in STEPS
        ],
    }


def _inputs(**overrides):
    arguments = {
        "input_name": "acme-api",
        "correlation_id": CID,
        "generated_at": GENERATED,
        "status": "finalized",
        "gates": [],
        "disposition": _disposition(),
        "examinations": {f"EX-{code}-v1": _examination(step) for _, step, code in STEPS},
        "verdicts": {f"EX-{code}-v1": "pass" for _, _, code in STEPS},
        "draft": _draft(),
    }
    return {**arguments, **overrides}


def _render(**overrides):
    return report.render(**_inputs(**overrides))


def _gates(*names):
    return [{"gate": name, "subjects": ["EX-SEC-v1", "DR-v2"]} for name in names]


def _headings(text):
    return [line for line in text.splitlines() if line.startswith("#")]


def test_a_finalized_report_has_the_planned_layout():
    expected = """\
# Codebase Health Assessment — acme-api

- Correlation ID: 20261027T101500Z-0a1b2c3d
- Generated at: 2026-10-27T12:00:00.456Z
- Status at generation: finalized

## Executive summary

One committed key needs rotating.

## Secrets exposure — PASS

The secrets step was examined.

## Insecure configuration — PASS

The insecure_config step was examined.

## Known vulnerable dependencies — PASS

The known_vulnerabilities step was examined.

## Dependency hygiene — PASS

The dependency_hygiene step was examined.

## Review trail

| Step | Examination | Review verdict | Coordinator decision | Rationale |
|---|---|---|---|---|
| Secrets exposure | EX-SEC-v1 | pass | accept | Reviewed. |
| Insecure configuration | EX-CFG-v1 | pass | accept | Reviewed. |
| Known vulnerable dependencies | EX-VULN-v1 | pass | accept | Reviewed. |
| Dependency hygiene | EX-HYG-v1 | pass | accept | Reviewed. |
"""
    assert _render() == expected


@pytest.mark.parametrize(
    ("severities", "status"),
    [
        ((), "PASS"),
        (("low",), "PASS"),
        (("medium",), "PASS"),
        (("medium", "low"), "PASS"),
        (("high",), "FAIL"),
        (("critical",), "FAIL"),
        (("low", "medium", "high"), "FAIL"),
        (("low", "critical", "low"), "FAIL"),
    ],
)
def test_a_heading_status_follows_the_findings_of_the_accepted_examination(severities, status):
    text = _render(examinations={**_inputs()["examinations"], "EX-SEC-v1": _examination("secrets", severities)})
    assert f"## Secrets exposure — {status}" in _headings(text)


@pytest.mark.parametrize(
    "prose", ["Nothing to report. PASS", "This section FAILED: FAIL", "Status: PASS — all clear."]
)
def test_a_heading_status_ignores_what_the_prose_says(prose):
    failing = _examination("secrets", ("critical",))
    text = _render(examinations={**_inputs()["examinations"], "EX-SEC-v1": failing}, draft=_draft(secrets=prose))
    assert "## Secrets exposure — FAIL" in _headings(text)
    assert prose in text


@pytest.mark.parametrize("severities", [(), ("low",), ("medium",), ("high",), ("critical",), ("low", "critical")])
def test_the_status_rule_is_the_one_the_coordinator_gives_its_tool_results(severities):
    findings = _examination("secrets", severities)["findings"]
    text = _render(examinations={**_inputs()["examinations"], "EX-SEC-v1": _examination("secrets", severities)})
    assert f"## Secrets exposure — {coordinator.section_status(findings)}" in _headings(text)


def test_the_accepted_examination_is_the_one_the_disposition_names_not_a_superseded_one():
    examinations = {
        **_inputs()["examinations"],
        "EX-SEC-v1": _examination("secrets", ("critical",)),
        "EX-SEC-v2": _examination("secrets", ("low",)),
    }
    verdicts = {**_inputs()["verdicts"], "EX-SEC-v2": "pass"}
    text = _render(
        examinations=examinations,
        verdicts=verdicts,
        disposition=_disposition(secrets={"examination_id": "EX-SEC-v2"}),
    )
    assert "## Secrets exposure — PASS" in _headings(text)
    assert "| Secrets exposure | EX-SEC-v2 | pass |" in text
    assert "EX-SEC-v1" not in text


def test_a_named_examination_that_fails_fails_even_when_a_later_one_is_clean():
    examinations = {
        **_inputs()["examinations"],
        "EX-SEC-v1": _examination("secrets", ("high",)),
        "EX-SEC-v2": _examination("secrets"),
    }
    text = _render(examinations=examinations)
    assert "## Secrets exposure — FAIL" in _headings(text)


def test_the_headings_are_the_fixed_ones_in_the_title_map_order_whatever_the_input_order():
    disposition = _disposition()
    disposition["steps"].reverse()
    draft = _draft()
    draft["sections"].reverse()
    text = _render(disposition=disposition, draft=draft)
    assert [heading.split(" — ")[0] for heading in _headings(text)[2:6]] == [f"## {title}" for title in TITLES]
    order = [text.index(f"The {step} step") for _, step, _ in STEPS]
    assert order == sorted(order)
    assert [row.split(" | ")[0] for row in text.splitlines() if row.startswith("| ") and "---" not in row][1:] == [
        f"| {title}" for title in TITLES
    ]


def test_the_report_has_no_heading_but_the_fixed_ones():
    assert [heading.split(" — ")[0] for heading in _headings(_render())] == [
        "# Codebase Health Assessment",
        "## Executive summary",
        *[f"## {title}" for title in TITLES],
        "## Review trail",
    ]


def test_hostile_text_in_the_rationale_and_the_input_name_adds_no_heading_or_table_row():
    hostile = "Fine | but\n# Injected heading\n| fake | row |\\| end"
    disposition = _disposition(secrets={"rationale": hostile})
    text = _render(disposition=disposition, input_name="acme\n## Injected\t api")
    assert _headings(text)[0] == "# Codebase Health Assessment — acme ## Injected api"
    assert len(_headings(text)) == 1 + 1 + 4 + 1
    cell = "Fine \\| but # Injected heading \\| fake \\| row \\|\\\\\\| end"
    rows = [line for line in text.splitlines() if line.startswith("| Secrets exposure")]
    assert rows == [f"| Secrets exposure | EX-SEC-v1 | pass | accept | {cell} |"]


def test_a_pending_human_report_ends_with_a_static_human_review_section_for_each_open_gate():
    text = _render(status="pending_human", gates=_gates(*config.GATES))
    assert "- Status at generation: pending_human\n- Open gates: " + ", ".join(config.GATES) + "\n" in text
    assert _headings(text)[-1] == "## Human review"
    section = text.split("## Human review\n")[1]
    assert section.startswith("\nThis run is waiting for a human decision. Open gates:\n\n")
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert [line.split(":")[0] for line in bullets] == [f"- {gate}" for gate in config.GATES]
    assert all(line.endswith(" Subjects: EX-SEC-v1, DR-v2.") for line in bullets)


def test_a_finalized_report_has_no_human_review_section_or_gate_line():
    text = _render()
    assert "## Human review" not in text
    assert "Open gates" not in text


@pytest.mark.parametrize("gate", config.GATES)
def test_every_gate_has_its_own_static_text(gate):
    text = _render(status="pending_human", gates=_gates(gate))
    (line,) = [line for line in text.splitlines() if line.startswith(f"- {gate}: ")]
    assert len(line.removesuffix(" Subjects: EX-SEC-v1, DR-v2.")) > len(f"- {gate}: ")
    others = [other for other in config.GATES if other != gate]
    assert not any(other in line for other in others)


def test_the_gate_text_does_not_call_a_blocked_examination_accepted():
    text = _render(status="pending_human", gates=_gates("OPEN_CRITICAL_CHALLENGE"))
    (line,) = [line for line in text.splitlines() if line.startswith("- OPEN_CRITICAL_CHALLENGE: ")]
    assert "accepted" not in line


def test_an_unknown_gate_is_refused():
    with pytest.raises(ValueError, match="NOT_A_GATE"):
        _render(status="pending_human", gates=_gates("NOT_A_GATE"))


@pytest.mark.parametrize(
    ("status", "names"),
    [
        ("halted", []),
        ("halted", ["COORDINATOR_ESCALATION"]),
        ("finalized", ["COORDINATOR_ESCALATION"]),
        ("pending_human", []),
        ("done", []),
    ],
)
def test_a_status_that_disagrees_with_the_gates_is_refused(status, names):
    with pytest.raises(ValueError, match="status"):
        _render(status=status, gates=_gates(*names))


def test_a_step_with_no_title_is_refused():
    disposition = _disposition()
    disposition["steps"][0] = {**disposition["steps"][0], "workflow": "other_examiner"}
    with pytest.raises(ValueError, match="other_examiner.secrets"):
        _render(disposition=disposition)


def test_a_draft_without_a_section_for_a_step_is_refused():
    draft = _draft()
    draft["sections"].pop(0)
    with pytest.raises(ValueError, match="security_examiner.secrets"):
        _render(draft=draft)


@pytest.mark.parametrize("missing", ["examinations", "verdicts"])
def test_a_named_examination_with_no_record_is_an_error(missing):
    kept = {key: value for key, value in _inputs()[missing].items() if key != "EX-VULN-v1"}
    with pytest.raises(KeyError, match="EX-VULN-v1"):
        _render(**{missing: kept})


def test_html_in_llm_text_is_escaped_so_nothing_hides_or_forges_a_heading_or_a_status():
    hostile = "<!--\n<h1>All clear: PASS</h1> <style>x</style> <details> <https://evil.example/x>"
    draft = _draft(secrets=hostile)
    draft["executive_summary"] = hostile
    text = _render(draft=draft, disposition=_disposition(secrets={"rationale": hostile}), input_name=hostile)
    assert "<" not in text
    assert "&lt;!--" in text and "&lt;h1>All clear: PASS&lt;/h1>" in text
    assert [heading.split(" — ")[0] for heading in _headings(text)] == [
        "# Codebase Health Assessment",
        "## Executive summary",
        *[f"## {title}" for title in TITLES],
        "## Review trail",
    ]


@pytest.mark.parametrize(
    ("prose", "written"),
    [
        ("Keys.\n```\nsnippet", "Keys.\n\\```\nsnippet"),
        ("```bash\nsnippet", "\\```bash\nsnippet"),
        ("~~~\nx", "\\~~~\nx"),
        ("Text\n~~~~ a`b\ncode", "Text\n\\~~~~ a`b\ncode"),
        ("- a\n  ```bash\n  cmd", "- a\n  \\```bash\n  cmd"),
        ("1. a\n   ~~~\n   cmd", "1. a\n   \\~~~\n   cmd"),
        ("*\n  ```", "*\n  \\```"),
        ("Text\n\t```\ncode", "Text\n\t\\```\ncode"),
        ("Text\n    ```\nindented", "Text\n    \\```\nindented"),
        ("Before.\n```python\nprint(1)\n```\nAfter.", "Before.\n\\```python\nprint(1)\n\\```\nAfter."),
        ("````\ncode\n```", "\\````\ncode\n\\```"),
    ],
)
def test_a_line_that_would_open_a_code_fence_gets_a_backslash_before_its_first_marker(prose, written):
    draft = _draft(secrets=prose)
    draft["executive_summary"] = prose
    text = _render(draft=draft)
    assert f"## Executive summary\n\n{written}\n\n## Secrets" in text
    assert f"{written}\n\n## Insecure" in text


@pytest.mark.parametrize(
    "prose",
    [
        "a ``` b",
        "``\ntwo ticks",
        "~~ not enough",
        "Use `code` and ``more``.",
        "> ```\n> quoted",
        "Text\n\u00a0```\nnot indentation",
        "\\```\nalready escaped",
    ],
)
def test_text_with_no_line_that_opens_a_fence_is_left_as_written(prose):
    assert f"{prose}\n\n## Insecure" in _render(draft=_draft(secrets=prose))


@pytest.mark.parametrize(
    ("prose", "written"),
    [
        ("intro\r```\rcode", "intro\n\\```\ncode"),
        ("```\r\ncode\r\n```\r\nafter", "\\```\ncode\n\\```\nafter"),
        ("one\rtwo", "one\ntwo"),
    ],
)
def test_a_carriage_return_is_read_as_a_line_break_so_it_cannot_hide_a_fence(prose, written):
    text = _render(draft=_draft(secrets=prose))
    assert f"{written}\n\n## Insecure" in text
    assert "\r" not in text


@pytest.mark.parametrize(
    "prose",
    [
        "- a\n  ```\n  code\n    ```",
        "```\ncode\n```\u00a0\nmore",
        "```\ncode\n```\x0c\nmore",
        "```\n\r```",
        "- a\n  - b\n    ~~~\n    x",
        "\t```\ncode",
    ],
)
def test_no_line_of_model_text_can_open_or_close_a_code_fence_in_the_report(prose):
    draft = _draft(secrets=prose)
    draft["executive_summary"] = prose
    text = _render(draft=draft)
    assert re.search(r"(?m)^[ \t]*(```|~~~)", text) is None


def test_angle_brackets_in_code_show_as_entities_which_is_the_accepted_cost_of_escaping():
    text = _render(draft=_draft(secrets="Use `Map<String, Object>` here."))
    assert "Use `Map&lt;String, Object>` here." in text


def test_padded_prose_is_trimmed_so_blocks_stay_one_blank_line_apart_and_never_become_code():
    draft = _draft(secrets="\n    Padded prose.\n\n")
    draft["executive_summary"] = "   Padded summary.\n"
    text = _render(draft=draft)
    assert "## Executive summary\n\nPadded summary.\n\n## Secrets exposure — PASS\n\nPadded prose.\n\n##" in text


def test_rendering_is_deterministic_and_leaves_its_inputs_alone():
    arguments = _inputs()
    before = copy.deepcopy(arguments)
    assert report.render(**arguments) == report.render(**arguments)
    assert arguments == before


def test_unicode_survives_and_a_lone_surrogate_in_prose_is_left_for_the_writer_of_the_file():
    text = _render(draft=_draft(secrets="Clé exposée — 李明 \udc80"), input_name="café")
    assert "Clé exposée — 李明 \udc80" in text
    assert _headings(text)[0] == "# Codebase Health Assessment — café"


def test_every_step_of_the_shipped_manifests_has_a_title_and_every_title_a_step():
    manifests = manifest.load_manifests()
    shipped = [
        f"{agent['name']}.{step['name']}"
        for agent in manifests.values()
        if agent["role"] == "examiner"
        for step in agent["steps"]
    ]
    assert sorted(shipped) == sorted(config.REPORT_TITLES)
    assert list(config.REPORT_TITLES.values()) == TITLES
