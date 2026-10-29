# codebase-health-assessor

`assess` is a Python command line tool that assesses a client code repository for four things: committed secrets, insecure configuration, known-vulnerable dependencies and dependency hygiene. A coordinator model only dispatches: two examiners do the checking, an adversarial reviewer in its own context challenges what they and the report writer produce, and a final review writer turns the accepted findings into prose. Everything runs through the Anthropic Messages API, and the harness around the models validates, audits and gates each step.

What the project is for and what it leaves out: `docs/PRD.md`. How it is built: `docs/ARCHITECTURE.md`.

## Setup

You need Python 3.14 and [poetry](https://python-poetry.org/).

```
poetry install
export ANTHROPIC_API_KEY="<your key>"
```

The key is read from the environment and never written anywhere. `poetry run pytest` runs offline and needs no key. `assess run` and the evals call the Anthropic API and spend credit.

Two optional environment variables:
- `ASSESSOR_RUNS_DIR` is where run directories go. It defaults to `runs` in the working directory.
- `ASSESSOR_OSV_REPLAY` is a JSON file that `assess run` replays for OSV lookups instead of calling `https://api.osv.dev/v1/query`.

## Commands

```
# Run the tests
poetry run pytest

# Assess a directory or a .zip; it prints the correlation ID, the status and the open gates
poetry run assess run examples/sample-client-repo

# Assess with another substance ratings file; the toy ratings hold the run for a human
poetry run assess run examples/sample-client-repo --substance examples/substance-toy.json

# Record a human decision on a run that is waiting, using the correlation ID that assess run printed
poetry run assess decide 20261028T101500Z-0a1b2c3d --decision continue --reviewer "Your Name" --note "Reviewed the open gate"

# Run the evals for every agent, three runs each, with a note on what changed since the last execution
poetry run python -m evals.run --agent all --runs 3 --note "Tightened the reviewer prompt"

# Try to get past each human checkpoint with scripted attempts; offline, no key, no cost
poetry run python -m evals.punchout

# Write manifest.yaml and docs/iterations.md into the ZIP that the package line made (see ZIP packaging)
poetry run python -m submission.build submission.zip

# Check that ZIP against the intake rules without extracting it
poetry run python -m submission.validate submission.zip
```

A run writes `runs/<correlation_id>/` with `audit.jsonl`, `run.json` and `summary.json`, and the `examinations/`, `reviews/` and `drafts/` it accepted. A run that does not halt also writes `disposition.json` and `report.md`, a zip input adds `workspace/`, and `decisions.jsonl` appears once someone has decided the run. `assess decide` only appends to `decisions.jsonl` and `audit.jsonl`. Exit codes and every argument are in `docs/ARCHITECTURE.md`, Interfaces.

The evals write `evals/results/<agent>.json` and append one line for each agent that finishes, with the note, to `evals/results/history.jsonl`, which is never rewritten. The note is one line of at most 500 characters, counted after secrets in it are redacted; for a note that looks like an option, such as `-x`, write `--note=-x`. The bypass campaign writes `evals/results/punchout/<timestamp>-punchout.json` and exits 1 when a scenario did not hold. Both are described in `evals/results/README.md`. The sample client repo, the recorded sample runs and how to record them are described in `examples/sample-runs/README.md`.

## ZIP packaging

Commit your work first, because `git archive` packs the committed files at `HEAD` only. Then run these three lines from the repository root, in this order:

```
git log --stat --date=iso > git_log.txt && git archive --format=zip -o submission.zip HEAD && zip -u submission.zip git_log.txt
poetry run python -m submission.build submission.zip
poetry run python -m submission.validate submission.zip
```

1. The package line writes the commit history to `git_log.txt` with `git log --stat`, archives `HEAD` and adds `git_log.txt` to the archive with `zip -u`. Do not commit `git_log.txt`: export it again each time you package. `.gitignore` keeps `submission.zip` out of the repository.
2. `submission.build` reads the ZIP's own entries and never extracts them. It writes two files into the ZIP: `docs/iterations.md`, the iteration log rendered from the ZIP's `evals/results/history.jsonl`, and `manifest.yaml`, the table of contents the intake reads, whose `agents:` section comes from the ZIP's `manifests/*.json`. Every file the manifest does not cite is listed under `not_judged` with the reason of the rule in `submission/rules.py` that classifies it. It exits 1 and lists every problem when a file matches no rule, when evidence the manifest cites is missing (the five eval results files, the history with a line for each agent, a campaign file whose `all_held` is true, exactly one finalized and one elevated sample run), or when an agent manifest, a history line or a campaign file is malformed. It exits 2 when the ZIP cannot be read or already holds `manifest.yaml` or `docs/iterations.md`. It writes a new ZIP beside the old one and renames it over it, so a refused or failed build leaves the ZIP as it was.
3. `submission.validate` checks the ZIP against the published intake rules (`PATH`, R1 to R6, R8 and the log rule), lists every violation at once, prints each rule as PASS, FAIL or SKIPPED with the ZIP's SHA-256, and exits 0 only when nothing is violated. It mirrors the rules as published; it is not the real intake.

After a failed build or validation, start again from the package line: `git archive -o` overwrites the ZIP, and `submission.build` refuses a ZIP that already holds its outputs. Before you submit, read the manifest with `unzip -p submission.zip manifest.yaml` and note the SHA-256 the validator printed.

## Evidence map

The first six rows are the six rubric cards, in order. The last five are the content rules. Every path in the Paths column exists, which `tests/test_readme_evidence_map.py` checks.

| Item | What it shows | Paths |
|---|---|---|
| Dispatch-only coordinator | The coordinator's manifest declares only four `launch_*` tools, each mapped to a sub-agent, and every coordinator request carries exactly those four. A `launch_*` block in an `end_turn` response is not dispatched. | `manifests/coordinator.json`, `src/assessor/coordinator.py`, `prompts/coordinator.md`, `tests/test_coordinator_dispatch_only.py`, `evals/coordinator/` |
| Sub-agents scoped to one workflow | Each examiner's manifest names its own steps and tools. A call to an undeclared tool is refused and audited, file tools stay inside the workspace, and `query_osv` reaches one URL. | `manifests/security_examiner.json`, `manifests/dependency_examiner.json`, `src/assessor/agents/runner.py`, `src/assessor/tools/`, `src/assessor/sandbox.py`, `tests/test_runner.py`, `tests/test_sandbox.py`, `tests/test_tools_deps.py` |
| Adversarial review in its own context | Every review is a fresh API call whose messages hold only the target and its input context, never the producing agent's conversation. The prompt is organised under Challenge, Catch, Detect and Block. | `manifests/adversarial_reviewer.json`, `prompts/adversarial_reviewer.md`, `schemas/review.schema.json`, `tests/test_isolation.py`, `evals/adversarial_reviewer/` |
| Version-controlled repo | The history is the commit log, exported with `git log --stat` to `git_log.txt` in the ZIP (see ZIP packaging). `.gitignore` keeps runs, local secrets and the ZIP out of it. | `.gitignore`, `tests/test_gitignore.py`, `README.md` |
| Stage 4 continuity | All inference goes through one custom gateway on the Messages API, and a test fails on any subprocess, CLI shell or agent SDK in `src/`. Gates hold a run for a human, evals write structured results, and every LLM call is audited. | `src/assessor/llm.py`, `tests/test_no_cli_runtime.py`, `src/assessor/gates.py`, `src/assessor/audit.py`, `evals/run.py`, `evals/results/` |
| Mega-agent counterfeit | No agent holds every tool. The coordinator has no file, HTTP or shell tool and no separate disposition tool: its disposition is an argument of `launch_final_review_writer`. The loader refuses a coordinator tool that launches no sub-agent. | `src/assessor/manifest.py`, `tests/test_manifest.py`, `tests/test_coordinator_dispatch_only.py`, `manifests/final_review_writer.json` |
| Final review writer | A separate sub-agent with no tools. It is given only the disposition, the accepted examinations, their latest reviews and any challenges to its earlier draft, and cites findings as `[ID]`. The guardrail refuses an unknown ID, a missing, duplicate or extra section, empty prose and a heading line. | `manifests/final_review_writer.json`, `prompts/final_review_writer.md`, `schemas/writer_output.schema.json`, `tests/test_guardrails.py`, `evals/final_review_writer/` |
| Guardrails | Every sub-agent output is checked against its JSON schema and semantic rules before the coordinator sees it. A failure comes back as a structured error and the output is never kept. Secret-like values in the free text of sub-agent output and in a decision's note are replaced with a redacted marker before they are written. | `src/assessor/guardrails.py`, `schemas/`, `tests/test_guardrails.py`, `tests/test_redaction.py` |
| Substance | `manifests/substance.json` rates both examiners core and the writer peripheral, each with a rationale, and lists the reviewer as not rated. `SUBSTANCE_ELEVATION` holds a run for a human when a workflow is rated toy or two or more are peripheral, and `examples/substance-toy.json` shows it through `--substance`. | `manifests/substance.json`, `schemas/substance.schema.json`, `examples/substance-toy.json`, `src/assessor/gates.py`, `tests/test_gates.py`, `tests/test_manifest.py`, `tests/test_cli_run.py`, `tests/test_examples.py` |
| Audit | Every LLM call appends one flushed and fsynced `llm_call` line to `audit.jsonl` with correlation ID, model, tokens, cost and latency, and never message content. Dispatches, tool calls, rejections, gates and decisions are audited too, and `summary.json` totals the LLM calls per agent. | `src/assessor/audit.py`, `schemas/audit_event.schema.json`, `config/pricing.json`, `tests/test_audit.py`, `examples/sample-runs/` |
| Decisions | `assess decide` appends one record to `decisions.jsonl` under an exclusive lock, naming the reviewer and the operating system user, and never edits `report.md`, `run.json` or earlier audit lines. It refuses an unknown run, a run with no open gate and a run already decided. | `src/assessor/gates.py`, `tests/test_cli_decide.py`, `examples/sample-runs/` |
