# codebase-health-assessor: Architecture

This file covers how codebase-health-assessor is built: its process and external systems, code layout, components, data, flows, interfaces, configuration and design decisions. What the project is, who uses it and what it leaves out: see docs/PRD.md. Elements marked *(planned)* are designed but not built yet.

## System overview

Each `assess` command runs as one short-lived local process. There is no server, daemon or database. The process reads a client repository from local disk, calls two HTTPS services, and writes everything it keeps into one directory per run.

```
 terminal: assess run <dir|zip> | assess decide <cid>          python -m evals.run  (planned)
                     │                                                  │
                     ▼                                                  ▼
 ┌──────────────────────────────── assess process ─────────────────────────────────┐
 │  cli ──► coordinator ──► agents.runner ──► tools ──► sandbox ◄────────────────────┼── client repo (read only)
 │   │           │               │              │                                   │
 │   │           └──────┬────────┘              └──► OSV transport ─────────────────┼──► OSV  POST /v1/query
 │   │                  ▼                                                           │
 │   │                 llm ─────────────────────────────────────────────────────────┼──► Anthropic Messages API
 │   │                  │                                                           │
 │   └──► gates, report │                                                           │
 │                      ▼                                                           │
 │                    audit ──► runs/<cid>/                                         │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

Built today: `cli`, `config`, `audit`, `llm`, `manifest` (not drawn; `cli` loads the manifests at run start), `sandbox`, `tools` with the OSV transport, `guardrails` (not drawn; `agents.runner`, `coordinator` and `cli` call it), `agents.runner`, `coordinator`, `gates` and `report`. `cli` wires a run and a decision.

| Boundary | What goes out | What comes back |
|---|---|---|
| Anthropic Messages API, via `client.beta.messages.create` | model, system prompt, messages (including file contents the agents' tools returned), tool definitions, effort, output schema, the server-side fallback beta and mode; credentials from the SDK's credential chain | content blocks, usage (tokens and fallback iterations), the model that served the call, stop reason |
| OSV, `https://api.osv.dev/v1/query` | package name, ecosystem (PyPI or npm), version | advisories |
| Client repository | nothing | file contents, read in place from a directory or from a zip extracted into the run directory |
| Runs directory | the audit trail, the run record, agent outputs, report, summary and decisions | the audit trail's existing lines, read on reopen; a run's `run.json`, `report.md` and `decisions.jsonl`, read by `assess decide` |

Evals *(planned)* run the same agent code through the same gateway in their own process. They answer OSV queries from a replay file instead of the live service.

## Repository structure

```
codebase-health-assessor/
├── pyproject.toml, poetry.lock   # package metadata, the `assess` script entry, locked dependencies
├── poetry.toml                   # keeps the virtualenv in-project (.venv/)
├── .gitignore                    # runs/, evals/.runs/, .env (fixture repos excepted), dist/, submission.zip
├── README.md                     # (planned) setup, usage, capability → path evidence map, packaging
├── docs/                         # PRD.md, ARCHITECTURE.md
├── config/pricing.json           # $/MTok per model
├── schemas/                      # audit_event, manifest, substance, examination, review, writer_output,
│                                 #   disposition, dispatch_error (.schema.json)
├── src/assessor/
│   ├── cli.py, config.py, audit.py, llm.py, manifest.py, sandbox.py, guardrails.py
│   ├── tools/__init__.py, tools/files.py, tools/deps.py
│   ├── agents/runner.py
│   ├── coordinator.py
│   └── gates.py, report.py
├── tests/                        # offline pytest suite; conftest.py holds FakeAnthropic; fixtures/ holds an OSV
│                                 #   replay sample
├── manifests/                    # one JSON manifest per agent, substance.json
├── prompts/                      # one system prompt per agent
├── skills/                       # secrets_and_config_checklist.md, dependency_risk_checklist.md
├── evals/                        # (planned) run.py, scoring.py, scripted_dispatcher.py, judges/tone.md,
│                                 #   <agent>/criteria.json and cases/, dependency_examiner/osv_replay.json,
│                                 #   results/<agent>.json
└── examples/                     # (planned) sample-client-repo/, substance-toy.json, sample-runs/
```

`config.ROOT` is the repository root, and pricing and schemas load from there, so the tool runs from a source checkout, not from an installed wheel.

## Components

| Component | Responsibility | Depends on |
|---|---|---|
| `cli` | `build_parser()` defines `run` and `decide` and validates their arguments. `main(argv, *, clock)` returns the exit code. A run checks the input and the ratings file, asks `llm` for a client, creates the run directory, runs the coordinator, opens the gates, renders the report, writes `disposition.json`, `summary.json` and `run.json`, and prints the outcome. `decide` calls `gates.decide` and prints the effective status. It redacts the coordinator's disposition text and a decision's `--note` before they are written. | `config`, `coordinator`, `gates`, `report`, `sandbox`, `manifest`, `audit`, `guardrails` (`redact`), and `llm` (`make_client`, `NoCredentialsError`) |
| `config` | Repo-root paths (`ROOT`, `PRICING_FILE`, `SCHEMAS_DIR`, `MANIFESTS_DIR`, `SUBSTANCE_FILE`), `CORRELATION_ID`, the closed sets `AUDIT_EVENTS`, `LLM_ERROR_CODES`, `DISPATCH_ERROR_CODES` (with its `RETRYABLE_DISPATCH_ERRORS` subset), `AGENT_ROLES`, `EFFORTS`, `SUBAGENT_TOOLS`, `SUBSTANCE_RATINGS`, `CONTRACTS`, the output value enums, `SECTION_STATUSES` with `FAILING_SEVERITIES`, `HALT_REASONS` (Closed sets), the run-end sets `RUN_STATUSES`, `RUN_EXIT_CODES`, `GATES`, `HUMAN_DECISIONS`, `HUMAN_STATUSES`, `ELEVATING_PERIPHERAL_COUNT` and `REPORT_TITLES`, API constants (`MAX_TOKENS`, `SDK_MAX_RETRIES`, `FALLBACK_BETA`, `FALLBACKS`), `runs_dir()`, `load_pricing()` and `check_pricing()`. Run-directory names (`EXAMINATIONS_DIR`, `REVIEWS_DIR`, `DRAFTS_DIR`, `RUN_FILE`, `SUMMARY_FILE`, `DISPOSITION_FILE`, `REPORT_FILE`, `DECISIONS_FILE`), `TOKEN_FIELDS`. Workspace and read caps (`WORKSPACE_DIR`, `ZIP_MAX_ENTRIES`, `ZIP_MAX_BYTES`, `READ_MAX_LINES`, `READ_MAX_BYTES`, `LIST_MAX_ENTRIES`, `SKIPPED_DIRS`), OSV settings (`OSV_URL`, `OSV_TIMEOUT_SECONDS`, `OSV_ECOSYSTEMS`, `OSV_VERSION_RANGES`, `OSV_SUMMARY_MAX_CHARS`), `DEPENDENCY_FILE_KINDS`, `DEPENDENCY_FILES` and `osv_replay()`. Guardrail settings: `ADVISORY_STEP`, `DISPATCH_ERROR_MAX_DETAILS`, `DISPATCH_ERROR_TEXT_MAX_CHARS`, `REDACT_KEEP_CHARS`. | standard library |
| `audit` | `AuditLog`: one run's append-only JSONL trail. Validates each line against `audit_event.schema.json` before writing, computes cost from pricing, generates correlation IDs (`new_correlation_id`) and audit timestamps (`timestamp`). `AuditLog.summary()` totals the log's `llm_call` lines per agent and overall. | `config`, `jsonschema` |
| `llm` | The Messages API gateway. `call()` builds the request, writes one `llm_call` line per call and maps failures to `LLMError`. `make_client()` returns an SDK client or raises `NoCredentialsError`. | `anthropic`, `config`, `audit` |
| `manifest` | `load_manifests()` loads `coordinator.json` and the manifest each `launch_<agent>` tool names, and fails closed (`ValueError` naming the file) on the checks under Agents. `load_substance(manifests, path)` loads the shipped or a replacement ratings file the same way. An `OSError` from reading `coordinator.json`, a sub-agent manifest that exists, the substance file or the pricing file propagates as is. | `config`, `jsonschema` |
| `sandbox` | `Workspace`: `resolve()` confines every path to the workspace root (`Path.resolve()` plus an `is_relative_to` check, so symlinks cannot escape) and refuses NUL and characters the filesystem cannot encode (lone surrogates other than U+DC80-U+DCFF, which stand for name bytes that are not UTF-8), absolute paths and paths through `SKIPPED_DIRS` in any letter case. `read_lines()` applies the read caps, refuses binary (NUL-holding) files and reads bytes that are not UTF-8 as U+FFFD; it is the one place lines are counted. `walk()` lists files lazily, without following directory symlinks, skipping looping ones and skipping, and reporting, directories it cannot open. `check_input()` refuses a missing path, a non-zip file, an archive whose entry list cannot be read (a newer format version, a name that is not UTF-8) and an archive over the caps or with an escaping or encrypted entry, reading only the entry list and writing nothing. `open_workspace()` returns a directory in place or extracts a zip member by member into `<run_dir>/workspace/`; a member that fails only when read (an unsupported compression method, a bad CRC) fails there, and the partial workspace is removed. Input problems raise `ValueError`. | `config` |
| `tools` | `definition(name)` returns a tool's strict Messages API definition: its `INPUT_SCHEMAS` entry, copied, and its `DESCRIPTIONS` entry, which states the caps from `config`. `execute(manifest, name, input, *, workspace, osv=None)` returns a `ToolResult(content, is_error, allowed)`: a tool the manifest does not declare is refused unrun with `allowed: false`, input that breaks the tool's `INPUT_SCHEMAS` entry and a tool's own failure are `is_error` results, and only a broken replay file raises. `files`: `list_files`, `read_file`. `deps`: `list_manifests`, `read_manifest` (recognised manifest files only, checked on the resolved name too), `query_osv` over a live or replay transport. | `sandbox`, `config`, `jsonschema`, `httpx2` |
| `guardrails` | `validate(contract, output, ctx)` returns a copy of the output once it passes its contract's JSON Schema and then its semantic checks, or raises `DispatchError` (Interfaces, Output contracts). `ctx` is the contract's context: `ExaminationContext`, `ReviewContext`, `WriterContext` or `DispositionContext`. `DispatchError(code, message, details)` carries a code from `DISPATCH_ERROR_CODES` and its `retryable` flag, and `to_result()` gives the object the coordinator receives. `redact(value)` masks secret-like values in every string of a JSON value. | `config`, `sandbox`, `jsonschema` |
| `agents.runner` | `run_subagent(client, audit, manifest, task, ctx, *, workspace, workflow, step, parent_step_id, osv=None)` runs one sub-agent invocation in a conversation of its own: it sends only the manifest's tools, runs the tool loop up to `max_tool_calls`, and returns the answer once `guardrails.validate` accepts it, redacted except the references `validate` checked, or raises `DispatchError`. `examiner_task`, `review_task` and `writer_task` build the tasks (Interfaces, `agents.runner`); `checklist_section` finds a step's section of the examiner's skills. | `llm`, `tools`, `guardrails`, `audit`, `sandbox` (the `Workspace` type), `config` |
| `coordinator` | `run(client, audit, manifests, *, workspace, workspace_label, osv=None)` runs the coordinator's conversation over `llm.call` with only its `launch_*` tools, answers each `launch_*` block through its handler (input check, retry cap, ID resolution, writer preconditions), dispatches through `agents.runner`, assigns the examination, review, challenge and draft IDs, writes each accepted output once, and returns a `RunState` that holds the halt reason when the run halted. `tool_definitions(manifests)` builds the strict launch tools from the manifests; `section_status(findings)` is the PASS/FAIL rule. | `agents.runner`, `guardrails`, `manifest`, `llm`, `audit`, `sandbox` (the `Workspace` type), `config`, `jsonschema` |
| `gates` | `open_gates(ratings=, disposition=, verdicts=, draft_id=, latest=)` returns the gates open at run end, each `{gate, subjects}`, in `GATES` order. `decide(correlation_id, *, decision, reviewer, note=None, runs_dir=None, os_user=, clock=)` appends a decision record to `decisions.jsonl` and a `decision_recorded` audit line under an exclusive `fcntl.flock`, and returns the record; it raises `DecisionRefused` for an unknown run, a `run.json` that is missing or not a run record, a run with no open gate and a run already decided. `effective_status(correlation_id, *, runs_dir=None)` derives the status from `run.json` and `decisions.jsonl`. | `audit`, `config` |
| `report` | `render(...)` returns `report.md`: a section per step, titled from `REPORT_TITLES` with the status computed from the named examination's findings, the writer's prose under each, the review trail and, for a pending run, the human-review text. Every other heading is a fixed literal, and every `<` in model-written or operator-chosen text becomes `&lt;`, so no tag or comment can hide or forge a heading or a status. It keeps its own PASS/FAIL rule over `FAILING_SEVERITIES` because it may import only `config`; `tests/test_report.py` keeps it equal to `coordinator.section_status`. | `config` |
| `evals` *(planned)* | `run.py` runs agents through the gateway and writes results. `scoring.py` holds the per-agent scorers. `scripted_dispatcher.py` stands in for the sub-agents in coordinator evals. `judges/tone.md` is the writer's tone judge. | `assessor.*` |

Which imports are allowed between these modules: see CLAUDE.md.

### Agents

Each agent is a JSON manifest in `manifests/` plus a prompt under `prompts/`. `agents.runner` builds each sub-agent request only from those, and `coordinator` builds its own the same way: its prompt, model and effort, and launch tools built from the sub-agent manifests. Every agent runs on `claude-sonnet-5-5`.

| Agent | Role | Tools | Effort | Output contract |
|---|---|---|---|---|
| coordinator | coordinator | the four `launch_*` tools (see Interfaces) | medium | none: it ends its turn when done |
| security_examiner | examiner | `list_files`, `read_file` | medium | examination; steps `secrets` (`SEC`) and `insecure_config` (`CFG`) |
| dependency_examiner | examiner | `list_manifests`, `read_manifest`, `query_osv` | medium | examination; steps `known_vulnerabilities` (`VULN`) and `dependency_hygiene` (`HYG`) |
| adversarial_reviewer | reviewer | `read_file` | high | review; `isolated_context: true`, assigned to both examiners and the writer |
| final_review_writer | writer | none | low | writer output |

`schemas/manifest.schema.json` gives each role its own fields and refuses any other, so a manifest cannot declare a request parameter such as `temperature`:
- every role: `name` (the file name), `role`, `model`, `effort`, `prompt`, `tools`
- coordinator: `launch_*` tools, `max_turns` (30), `max_dispatches_per_step` (3)
- sub-agents: tools from `config.SUBAGENT_TOOLS` (none for the writer), `skills`, `max_tool_calls` (12), `output_schema`
- examiner: `steps`, each a name and an ID code
- reviewer: `isolated_context: true`, `assignment`

`manifest.load_manifests()` also refuses:
- a `launch_<agent>` tool with no `manifests/<agent>.json`, or one that names the coordinator
- anything but one or more examiners, exactly one reviewer and exactly one writer
- a reviewer `assignment` other than exactly the examiners and the writer
- a step code used twice, or a step name repeated within an examiner
- a model with no price in `config/pricing.json`
- duplicate JSON keys, numbers written with a decimal point or exponent (even `12.0`), NaN and Infinity, nesting too deep to parse or validate, and a trailing newline in an agent or step name, a step code, a model or a file path (a launch tool with one maps to no manifest)

Beyond the closed sets (tool names, roles, efforts, ratings), caps of at least 1, priced models, a writer with no tools and a reviewer with `isolated_context: true`, it pins no per-agent value. The four launch tools, each sub-agent's tool set, the caps, the model and the efforts are declared only in the manifests and pinned by the shipped-manifest tests in `tests/test_manifest.py`.

It does not check that the `prompt`, `skills` and `output_schema` files exist. `tests/test_runner.py` checks that every file a sub-agent manifest names exists and that each `output_schema` names a contract. `tests/test_coordinator_dispatch_only.py` checks that the coordinator's prompt names each launch tool, names no sub-agent tool, states its `max_turns` and its `max_dispatches_per_step` for steps, the writer and reviews, and holds every statement in that file's `STATEMENTS` list.

A sub-agent's system prompt is its prompt followed by each of its skills, separated by a blank line. Each skill checklist gives every step of its examiner one section headed `## <step>`, holding what to look for and that step's rule for each finding severity. `checklist_section` copies the section into the step's task, so the reviewer reads the same rules as part of the examination's input context. The reviewer's prompt is organised under the headings Challenge, Catch, Detect and Block, and every prompt of an agent with tools states its `max_tool_calls`. Substance ratings (`manifests/substance.json`) rate security_examiner and dependency_examiner core and final_review_writer peripheral, each with a rationale. adversarial_reviewer is listed as not rated, with the reason. `manifest.load_substance()` accepts a ratings file only when it rates exactly the examiners and the writer and lists exactly the reviewer as not rated.

## Runtime and dependencies

| Dependency | Locked | Why |
|---|---|---|
| Python | `>=3.14,<4.0` (poetry: `~3.14`) | chosen runtime |
| poetry | — | dependency locking and the in-project virtualenv |
| `anthropic` | 2.3.0 | the official SDK: `beta.messages.create` carries the fallback beta, `output_config` and typed errors |
| `jsonschema` | 4.26.0 | Draft 2020-12 validation of audit lines, manifests, substance ratings, tool inputs and agent outputs; the output schemas are the same files `agents.runner` sends as `output_config.format` |
| `httpx2` | 2.16.0, declared directly | the OSV client, and the SDK's own HTTP client |
| `pytest` | 9.1.1, dev group | test runner |

## Data and state

### Run directory: `<runs_dir>/<correlation_id>/`

| Entry | Written by | Lifecycle |
|---|---|---|
| `audit.jsonl` | `AuditLog.append` | append-only; each line flushed and fsynced |
| `run.json` | `cli` at run end | written once: correlation_id, input (path and kind), started and finished times, status, gates (each `{gate, subjects}`), halt_reason; written for a halted run too |
| `summary.json` | `cli`, from `AuditLog.summary()` | written once, for a halted run too: per-agent and overall totals (`llm_calls`, the four token counts, `cost_usd`, `unpriced_calls`) equal to the sums of the valid `llm_call` lines |
| `examinations/EX-*.json`, `reviews/RV-*.json`, `drafts/DR-*.json` | `coordinator`, which assigns the IDs | one file per accepted output, the redacted output as ASCII-escaped JSON, created exclusively (an existing file raises `FileExistsError`); rejected outputs are never stored. A review's file holds its challenges with their IDs |
| `disposition.json`, `report.md` | `cli` (the disposition with its rationales redacted), `report` | written once, when the run does not halt |
| `decisions.jsonl` | `gates` | append-only, under `fcntl.flock`; created by the first decision |
| `workspace/` | `sandbox.open_workspace`, called by `cli` at run start | zip input only; never merged into an existing one, removed when extraction fails |

The effective status is derived from `run.json` plus `decisions.jsonl` (`gates.effective_status`): a `pending_human` run with a decision is `finalized_by_human` (continue) or `rejected_by_human` (reject); any other run keeps its own status.

### Audit trail

A line is a JSON object in the shape `schemas/audit_event.schema.json` defines. A line that fails the schema raises and writes nothing.

- **Envelope** (`audit.ENVELOPE`):
  - `correlation_id`
  - `seq`: the line number. A reopened log continues after its last line.
  - `step_id`: `<cid>:<seq>`
  - `ts`: UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`, from an injectable clock
  - `event`: one of `config.AUDIT_EVENTS`
- **`llm_call` fields:**
  - `parent_step_id`, `agent`, `workflow`, `step`
  - `requested_model`, `served_model`, `fallback_ran`, `effort`
  - `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`
  - `cost_usd`, `pricing_missing`, `stop_reason`, `latency_ms`, `error`

  Labels (`agent`, `workflow`, `step`, `requested_model`, `effort`) must match `^[a-z0-9][a-z0-9_.-]{0,63}$`.
- **`tool_call` fields** (one line per tool call a sub-agent makes, written after the tool ran or was refused; the call past the cap gets none):
  - `parent_step_id`, `agent`, `workflow`, `step`, as on the invocation's `llm_call` lines
  - `tool`: the name from `SUBAGENT_TOOLS`, or null for any other name, so text the model wrote never reaches the audit
  - `allowed`: false when the agent's manifest does not declare the tool; `is_error`: whether the result was an error

  A null `tool` requires `allowed: false`, and `allowed: false` requires `is_error: true`. The tool's input and result are never written.
- **`guardrail_rejected` fields:** `parent_step_id`, `agent`, `workflow`, `step`, `code` (one of `DISPATCH_ERROR_CODES`) and `problems`, the number of entries in the error's `details`. `agents.runner` writes one, with the sub-agent's labels, when an answer is not JSON or fails `validate`, when an invocation passes its tool-call cap, and when a `tool_use` stop calls no tool (`API_ERROR`). A failed model call is recorded on its `llm_call` line instead. `coordinator` writes one for each launch it refuses before dispatching: `agent` is `coordinator`, `parent_step_id` is null, and `workflow` and `step` are the labels the dispatch would have had, as far as they were checked (null otherwise).
- **`dispatch_started` fields:** `agent`, `workflow`, `step`: the labels every line of the invocation carries (a review carries its target's `workflow` and `step`, the writer `final_review_writer` and null); `target_id`: the examination or draft ID under review, null for any other dispatch. Every `llm_call`, `tool_call` and `guardrail_rejected` line of the invocation has this line's `step_id` as its `parent_step_id`. The coordinator's own `llm_call` lines carry a null `parent_step_id`.
- **`dispatch_finished` fields:** `parent_step_id` (the `dispatch_started` line), `agent`, `workflow`, `step`; `output_id`: the ID of the accepted output; `code`: the `DispatchError` code when the dispatch produced none. Exactly one of `output_id` and `code` is null. A dispatch that raises anything but `DispatchError` writes no `dispatch_finished` line.
- **`gate_opened` fields:** `gate` (one of `GATES`) and `subjects`, at least one harness-assigned label: examination or draft IDs, `<workflow>.<step>` keys or workflow names.
- **`run_finished` fields:** `status` (one of `RUN_STATUSES`) and `halt_reason` (a `HALT_REASONS` value exactly when the status is `halted`, otherwise null).
- **`decision_recorded` fields:** `decision`, `reviewer`, `gates_resolved` (at least one gate) and `report_sha256`. The note stays in `decisions.jsonl`.
- **`run_started`** is envelope-only: `run.json` holds the input.
- **Torn last line:** a line without its newline stays in the file as its own unparseable line. The next append starts on a new line, and readers skip unparseable lines.
- **Failed write:** the line may still reach the file, so the log rescans before its next append. A caller that retries the append can leave the event in the file twice.

**Cost.** `AuditLog.cost` computes `(input·p_in + output·p_out + cache_creation·p_cache_write + cache_read·p_cache_read) / 1e6`. It is priced by the served model and rounded to 6 decimals. An unpriced model gives `cost_usd: null` and `pricing_missing: true`. Tokens and cost cover only the attempt that served the call, not fallback hops that declined. A call that raised an SDK error is logged with zero tokens, `cost_usd: 0.0`, `served_model: null` and the exception class name in `error`.

**Pricing** (`config/pricing.json`) maps each model ID to exactly `input`, `output`, `cache_write` and `cache_read` in $/MTok, each finite and non-negative. It prices `claude-sonnet-5-5`, `claude-sonnet-5` (the server-side fallback target of Sonnet 5.5), `claude-opus-5-5` and `claude-haiku-5-5`.

### Identifiers

| Object | Format | Status |
|---|---|---|
| Correlation ID | `YYYYMMDDTHHMMSSZ-<8 lowercase hex>`, UTC start time plus 4 random bytes | built |
| Step ID | `<cid>:<seq>` | built |
| Examination | `EX-<CODE>-v<n>`, n counting the step's accepted examinations | built |
| Finding | `<CODE>-<n>`, assigned in order by `guardrails.validate` to an accepted examination; numbering restarts with each examination version | built |
| Review | `RV-<n>`, n counting the run's accepted reviews | built |
| Challenge | `RV-<n>-C<k>`, k the challenge's place in its review | built |
| Draft | `DR-v<n>`, n counting the run's accepted drafts | built |

### Closed sets

Built, in `config`: `AUDIT_EVENTS` (`run_started`, `llm_call`, `tool_call`, `dispatch_started`, `dispatch_finished`, `guardrail_rejected`, `gate_opened`, `run_finished`, `decision_recorded`), `LLM_ERROR_CODES` (`REFUSAL`, `MAX_TOKENS`, `API_ERROR`), `AGENT_ROLES` (coordinator, examiner, reviewer, writer), `EFFORTS` (low, medium, high, xhigh, max: the installed SDK's set), `SUBAGENT_TOOLS` (`list_files`, `read_file`, `list_manifests`, `read_manifest`, `query_osv`) and `SUBSTANCE_RATINGS` (core, peripheral, toy). The manifest and substance schemas repeat these enums, and `tests/test_manifest.py` keeps them equal. Also built: `SKIPPED_DIRS` (`.git`, `node_modules`, `.venv`, matched in any letter case), `OSV_ECOSYSTEMS` (PyPI, npm), `OSV_VERSION_RANGES` (ECOSYSTEM, SEMVER), `DEPENDENCY_FILE_KINDS` (manifest, lockfile) and `DEPENDENCY_FILES` (listed under Configuration); `tools.INPUT_SCHEMAS` covers exactly `SUBAGENT_TOOLS` (`tests/test_tools.py`).

Also built, for the output contracts; the contract schemas repeat the value enums, and `tests/test_guardrails.py` keeps them equal:

- **DispatchError codes** (`DISPATCH_ERROR_CODES`: six of its own, then `LLM_ERROR_CODES`):
  - retryable (`RETRYABLE_DISPATCH_ERRORS`; an agent's output that failed with one can pass when the same dispatch is sent again): `SCHEMA_INVALID`, `EVIDENCE_INVALID`, `TOOL_LOOP_LIMIT`, `MAX_TOKENS`, `API_ERROR`
  - not retryable: `PRECONDITION_FAILED`, `UNKNOWN_TARGET`, `RETRY_CAP_REACHED`, `REFUSAL`
  - a launch `coordinator` refuses on its own checks, whatever its code, passes only once the launch is fixed or what it waits for exists: an `UNKNOWN_TARGET` target or challenge once that output is accepted, a `PRECONDITION_FAILED` writer launch once the examination is reviewed. `RETRY_CAP_REACHED` never clears.
- **Contracts** (`CONTRACTS`): examination, review, writer_output, disposition
- **Finding severity** (`FINDING_SEVERITIES`): critical, high, medium, low
- **Challenge response** (`CHALLENGE_RESPONSES`): upheld, rejected
- **Review verdict** (`REVIEW_VERDICTS`): pass, challenge, block
- **Lens** (`LENSES`): challenge, catch, detect
- **Challenge severity** (`CHALLENGE_SEVERITIES`): critical, major, minor
- **Disposition decision** (`DISPOSITION_DECISIONS`): accept, escalate

Also built, in `config`, and pinned by `tests/test_config.py`; no schema repeats them:

- **Section status** (`SECTION_STATUSES`): PASS, FAIL. FAIL when a finding's severity is in `FAILING_SEVERITIES` (critical, high); `coordinator.section_status` and `report` each apply it.
- **Halt reasons** (`HALT_REASONS`): `COORDINATOR_TURN_LIMIT`, `COORDINATOR_REFUSAL`, `COORDINATOR_MAX_TOKENS`, `COORDINATOR_API_ERROR` (set by `coordinator`); `NO_REPORT`, `REPORT_NOT_REVIEWED` (set by `cli` at run end, only when the coordinator did not halt the run)

Also built, in `config`, and pinned by `tests/test_config.py`; `tests/test_audit.py` keeps the audit schema's enums equal to them:

- **Run status** (`RUN_STATUSES`): `finalized`, `pending_human`, `halted`; exit codes (`RUN_EXIT_CODES`): 0, 3, 1. Derived from decisions (`HUMAN_STATUSES`): `finalized_by_human` (continue), `rejected_by_human` (reject)
- **Gates** (`GATES`): `SUBSTANCE_ELEVATION`, `OPEN_CRITICAL_CHALLENGE`, `COORDINATOR_ESCALATION`
- **Human decision** (`HUMAN_DECISIONS`): continue, reject
- **Report titles** (`REPORT_TITLES`, keyed by the writer's section key, in report order):
  - `security_examiner.secrets`: "Secrets exposure"
  - `security_examiner.insecure_config`: "Insecure configuration"
  - `dependency_examiner.known_vulnerabilities`: "Known vulnerable dependencies"
  - `dependency_examiner.dependency_hygiene`: "Dependency hygiene"

## Key flows

**Argument parsing** (built)
1. `main(argv)` parses with `build_parser()`.
2. Any argument that breaks the contract under Interfaces makes argparse exit 2. `--help` exits 0.
3. A valid command goes to `assess run` or `assess decide`, below.

**One model call: `llm.call`** (built)
1. Builds the request:
   - `model`, `max_tokens` (`config.MAX_TOKENS`), `system`, `messages`
   - `output_config` with `effort`, plus `format: {type: json_schema, schema}` when an output schema is given
   - `betas: [FALLBACK_BETA]`, `fallbacks: FALLBACKS`
   - `tools`, only when there are any
2. Runs `audit.check("llm_call", …)` on a placeholder line, so invalid labels fail before anything is sent.
3. Calls `client.beta.messages.create(**request)` and times it.
4. If the SDK raised an `AnthropicError`: appends an `llm_call` line with the error class and raises `LLMError("API_ERROR")`. This happens only after the SDK's own retries (`SDK_MAX_RETRIES`).
5. Otherwise it appends an `llm_call` line with:
   - `served_model` (`response.model`)
   - `fallback_ran`: true when `usage.iterations` has a `fallback_message` entry or the content has a `fallback` block
   - tokens, cost, stop reason and latency
6. Maps the stop reason:
   - `refusal` → `LLMError("REFUSAL")`
   - `max_tokens` or `model_context_window_exceeded` → `LLMError("MAX_TOKENS")`
   - anything other than `end_turn` or `tool_use` → `LLMError("API_ERROR")`

   Otherwise it returns the `BetaMessage`.

**One sub-agent invocation: `agents.runner.run_subagent`** (built)
1. Reads the agent's prompt, skills and output schema, and builds each tool's definition, before any call.
2. Starts a new message list holding one user message: the task as indented JSON.
3. Calls `llm.call` with the manifest's model and effort, the system prompt, the tools (none for the writer) and the output schema. An `LLMError` becomes a `DispatchError` with the same code.
4. On `tool_use`, it runs each `tool_use` block in order through `tools.execute`. A `tool_use` stop with no `tool_use` block raises `API_ERROR` after a `guardrail_rejected` line. It writes a `tool_call` line for each, appends the assistant turn unchanged and then one user message with every `tool_result` (`is_error` as the tool returned it), and calls again. Every block counts toward `max_tool_calls`, refused ones included. The block that would pass the cap is not run: the invocation stops with `TOOL_LOOP_LIMIT`.
5. Otherwise it joins the answer's text blocks and parses them as JSON. It validates the result against the contract named by the output schema's file name (`examination.schema.json` → `examination`), redacts it and returns it. Redaction skips the references `validate` checked against the workspace or the run, which masking would break: an examination's `workflow`, `step` and each finding's `file`, a review's `target_id` and each challenge's `finding_id`, and each section's `key`. A `file` with a `..` segment is masked like any other text: `validate` resolves `x/../config.py` to `config.py` even when `x` does not exist, so the text before a `..` need not name anything in the repository. Every segment of any other accepted path names a real directory or file. A reviewer's `evidence_checked` file is not checked, so it is masked too.
6. An answer that is not JSON is `SCHEMA_INVALID`. A failed `validate` raises its own `DispatchError`. Both, `TOOL_LOOP_LIMIT` and the `API_ERROR` of step 4 first write a `guardrail_rejected` line.

**One coordinator run: `coordinator.run`** (built)
1. Builds the four launch tools from the manifests (`tool_definitions`) and reads `prompts/coordinator.md`. A coordinator tool that launches no loaded sub-agent raises `ValueError` before any request or audit line.
2. Starts a conversation of one user message: `{workspace, steps: [{workflow, step}]}` as indented JSON, the steps in manifest order.
3. Each turn is one `llm.call` with the coordinator's model, effort and prompt and the launch tools, no output schema, and null `workflow`, `step` and `parent_step_id`. Then:
   - an `LLMError` halts the run with `COORDINATOR_<code>`
   - `end_turn` ends the run with no halt reason; a `tool_use` block in that response is not dispatched
   - a `tool_use` stop with no `tool_use` block halts it with `COORDINATOR_API_ERROR`, on any turn
   - a `tool_use` stop holding `tool_use` blocks on turn `max_turns` halts it with `COORDINATOR_TURN_LIMIT`, and its blocks are not dispatched: no later call could read their results
   - otherwise every block is answered in order, and the assistant turn, unchanged, and one user message holding every `tool_result` are appended
4. Each launch block goes through these checks, in this order. A refusal returns a `DispatchError` result with `is_error: true`, writes a `guardrail_rejected` line and calls no sub-agent:
   - every launch: a name outside the launch tools, or input that breaks the tool's input schema: `SCHEMA_INVALID`
   - examiner: the (examiner, step) cap key is full: `RETRY_CAP_REACHED`; then a `challenge_ids` entry that is not a challenge to an examination of the same step: `UNKNOWN_TARGET`
   - reviewer: a `target_id` that names no accepted examination or draft: `UNKNOWN_TARGET`; then the (reviewer, target ID) cap key is full: `RETRY_CAP_REACHED`
   - writer: the cap key every writer dispatch shares is full: `RETRY_CAP_REACHED`; then `validate("disposition", …)` against the accepted examinations and the outputs that have a review (`SCHEMA_INVALID`, `UNKNOWN_TARGET`, `PRECONDITION_FAILED`); then a `challenge_ids` entry that is not a challenge to a draft: `UNKNOWN_TARGET`

   A cap key is full when it already has `max_dispatches_per_step` dispatches. Every dispatch counts, failed ones included; refused launches do not.
5. A dispatch writes `dispatch_started`, counts toward its cap key, and calls `run_subagent` with:
   - examiner: `examiner_task` with the challenge objects the IDs name, each with its `id`, repeats dropped, and the note; the step's `ExaminationContext`
   - reviewer: `review_task(target_id, target, the task the target was produced from)`; a `ReviewContext` with the examination's finding IDs, none for a draft
   - writer: `writer_task(disposition, the examinations it names, the latest review of each, the draft challenges)`; a `WriterContext` of every step and every ID the harness assigned that the task holds: examination, finding, review and challenge IDs (user decision), so advisory and CWE IDs stay uncited
6. A `DispatchError` from the runner goes back to the coordinator unchanged after a `dispatch_finished` line with its code, and the harness never sends it again on its own. An accepted output gets its ID, its file and a compact result (Interfaces, Coordinator tools), then a `dispatch_finished` line with the ID.

**`assess run`** (built)
1. `cli` checks the input path (`sandbox.check_input`), loads the manifests and the ratings file (`manifest.load_substance`, the shipped one unless `--substance` names another), then calls `llm.make_client()`. A missing path, a file that is not a zip, a zip over the caps or with an escaping entry, a directory that holds the runs directory (the run would write into the client's tree), a ratings file the loader refuses and `NoCredentialsError` each exit 2 with `assess run: <message>` on stderr. In every one of these cases no run directory is created.
2. It creates the correlation ID and opens a `Workspace` (`sandbox.open_workspace`): the directory in place, or the zip extracted under caps into `runs/<cid>/workspace/`. An extraction that fails after the zip passed the entry check exits 2 and removes the run directory. It then appends `run_started`.
3. `coordinator.run` runs the coordinator (One coordinator run, above). `osv` is left unset, so each `query_osv` call builds its transport (`tools.execute`).
4. The run ends one of three ways:
   - The coordinator ends its turn: on to gates and the report.
   - The coordinator hits its turn cap, or one of its own calls ends in refusal, max_tokens or an API error: the run halts with that halt reason. A coordinator halt reason is final, whatever the run holds.
   - No successful draft (`NO_REPORT`) or no review on the latest draft (`REPORT_NOT_REVIEWED`): the run halts.
5. A run that did not halt takes the latest draft's disposition, with its rationales and summary redacted, and `gates.open_gates` opens, from the latest verdict of each reviewed output:
   - `OPEN_CRITICAL_CHALLENGE` for each examination whose latest review is `block`, whether or not the coordinator accepted it, and for the latest draft when its latest review is `block`. The examinations counted are the ones the disposition names and the newest reviewed version of each step, so neither naming an older version nor leaving a newer one unreviewed can hide a block; a superseded version that no longer is either opens nothing.
   - `COORDINATOR_ESCALATION` for any step dispositioned `escalate`
   - `SUBSTANCE_ELEVATION` when the ratings trip the rule in docs/PRD.md, Glossary: the gate's subjects are the toy workflows, or, with none, the peripheral ones
6. The status is `pending_human` when a gate is open, otherwise `finalized`. `report.render` renders `report.md`, computing each section's status from its named examination's findings (rule: docs/PRD.md, What it does). `cli` then writes, each exclusively: `disposition.json`, `report.md` (both only for a run that did not halt), one `gate_opened` line per gate, `summary.json`, `run.json`, and last the `run_finished` line. It prints:

   ```
   correlation_id: <cid>
   status: <status>
   open_gates: <gate, gate | none>
   ```

   and exits with the status's code (Interfaces). A failure while writing propagates as an error, so that run has no `run_finished` line.

**`assess decide`** (built)
1. `cli` redacts the note, then calls `gates.decide`. It refuses (exit 1, `assess decide: <reason>` on stderr) an unknown cid, a run whose `run.json` is missing or is not a run record (valid status, gates naming `GATES` values), a run with no open gate (finalized or halted) and a run already decided.
2. `gates` takes an exclusive `fcntl.flock` on `decisions.jsonl` and checks again for an earlier decision; a line that does not parse as a JSON object is not a decision, and a parseable record that lost its newline is.
3. It appends one decision record, fsynced, then a `decision_recorded` audit line, both under the lock. `report.md`, `run.json` and earlier audit lines are not touched. `cli` prints `correlation_id`, `decision` and the effective status (`finalized_by_human` or `rejected_by_human`), and exits 0.

**Eval run** *(planned)*
1. `evals.run` loads the agent's `criteria.json` and its 5 cases.
2. It runs the real agent code through `llm.call` N times per case. `ASSESSOR_OSV_REPLAY` points dependency cases at `osv_replay.json`. Coordinator cases replace the sub-agents with `scripted_dispatcher.py`, which returns scripted results by (tool, step, attempt).
3. `scoring.py` scores every case × run × criterion. Scoring is deterministic, except the writer's tone judge, which runs through the gateway with structured output.
4. It writes `evals/results/<agent>.json`.

## Interfaces

### `assess` command line

```
assess run <dir|zip> [--substance FILE]
assess decide <cid> --decision continue|reject --reviewer NAME [--note TEXT]
```

Abbreviated options are refused. `<cid>` must match `config.CORRELATION_ID`, and `NAME` must contain a letter or digit. `--substance` replaces `manifests/substance.json` for one run.

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `assess run` | finalized | halted | usage or input error, missing path, not a zip, a zip over the caps, a directory holding the runs directory, a refused ratings file, no credentials; no run directory | pending_human |
| `assess decide` | recorded | refused | usage error | — |

`--help` exits 0 for both. An error that is neither of these, such as a failed write into the run directory, ends the process with a traceback, which Python exits 1 for.

### `llm.call` (built)

`call(client, audit, *, agent, workflow, step, parent_step_id, model, effort, system, messages, tools=(), output_schema=None, timer=time.perf_counter) -> BetaMessage`. It raises `LLMError` with `.code` in `LLM_ERROR_CODES`, and `AuditLog`'s own errors for invalid labels or a failed audit write. *(planned)* A `max_tokens` argument taken from the agent's manifest.

### Sub-agent tools (built; called by `agents.runner`)

Each input schema in `tools.INPUT_SCHEMAS` uses only the structured-outputs keywords, and every field is required. `tools.definition(name)` sends it with `strict: true` and a description. Results are JSON text.

| Tool | Input | Result |
|---|---|---|
| `list_files` | `directory` (`.` or empty for the root) | `files`: root-relative paths, each directory's files before its subdirectories; `unreadable`: directories skipped because they could not be opened; `truncated` when either list was cut at `LIST_MAX_ENTRIES` |
| `read_file` | `path`, `start_line` (at least 1) | `path`, `start_line`, `end_line`, `total_lines`, `next_start_line` (null at the end), `content`: lines as `<n>\t<text>` |
| `list_manifests` | none | `manifests`: `{path, ecosystem, kind}` for each recognised file; `unreadable`; `truncated` as for `list_files` |
| `read_manifest` | `path`, `start_line` | as `read_file`, for recognised files only. A recognised file over the read cap is listed by `list_manifests` but refused here (`larger than the 256000-byte read limit`), so a large lockfile is a stated limitation (docs/PRD.md, Constraints and limitations) |
| `query_osv` | `ecosystem` (PyPI or npm), `name`, `version` | the query; `vulns`: up to `LIST_MAX_ENTRIES` of `{id, aliases, summary, severity, fixed}`; `truncated` when OSV has another page or more advisories |

Lines are split on `\n` only, with one trailing `\r` and any leading BOM dropped. Error results start with the tool name, never show the workspace's absolute path (an `OSError` gives only its reason) and escape any lone surrogate they echo as `\uXXXX`, so they are always valid UTF-8. `query_osv` POSTs only to `config.OSV_URL` and does not follow redirects. `summary` is the first non-blank of `summary` and `details`, stripped and cut to `OSV_SUMMARY_MAX_CHARS` characters. A null `vulns`, `aliases`, `severity`, `affected`, `package`, package name, `ranges`, `events` or page token counts as absent, null entries in those lists are skipped, and only a string `fixed` counts. `fixed` lists, in order and without repeats, the fix versions of every ECOSYSTEM or SEMVER range of the queried package (PyPI names compared per PEP 503, npm names exactly), including ranges that do not contain the queried version; the agent picks the next one up. GIT ranges and entries without a package are ignored. Every transport failure, any non-2xx status and an answer out of shape become `OSV query for <ecosystem>/<name>@<version> failed: <reason>`.

The replay file (`ASSESSOR_OSV_REPLAY`) is a JSON object mapping `<ecosystem>/<name>@<version>` to OSV's raw response body. A query with no entry fails like an unreachable OSV, with the reason `no recorded response`.

### `agents.runner` (built)

- `run_subagent(client, audit, manifest, task, ctx, *, workspace, workflow, step, parent_step_id, osv=None) -> dict`. `ctx` is the output contract's guardrail context. `workflow`, `step` and `parent_step_id` label every audit line of the invocation. `osv` is passed to `tools.execute`. Strings in the result can hold lone surrogates: legitimately in the `file` of a name that is not UTF-8 (`sandbox`, under Components), or wherever the model wrote one. Write the result as ASCII-escaped JSON, or escape the surrogates before writing it as text. It raises `DispatchError` (Key flows), `validate`'s `ValueError` and `TypeError`, a broken OSV replay file's error from `tools.execute`, and any error reading the agent's files or writing the audit.
- `examiner_task(manifest, step, *, workspace_label, challenges, note)` → `{workflow, step, workspace, checklist, challenges, note}`. `checklist` is the step's section of the examiner's skills, and `challenges` are the reviewer's challenge objects, copied unchanged. A step the manifest does not declare raises `ValueError`.
- `review_task(target_id, target, input_context)` → `{target_id, target, input_context}`. `input_context` is the task the target was produced from: the examiner's task for an examination, or the writer's task, the moderated context, for a draft. It never holds the producing agent's conversation.
- `writer_task(disposition, examinations, reviews, challenges)` → `{disposition, examinations, reviews, challenges}`: the accepted examinations keyed by examination ID, their latest reviews keyed by review ID (each review's `target_id` names its examination), and the challenges to the previous draft.
- `checklist_section(manifest, step)` returns the text under `## <step>` in the manifest's skills, up to the next `## ` heading. No such section, or more than one, raises `ValueError`.

Every builder copies its inputs, so later changes to the caller's objects do not reach the task.

### `coordinator` (built)

- `run(client, audit, manifests, *, workspace, workspace_label, osv=None) -> RunState`. `manifests` is what `manifest.load_manifests()` returns. `workspace_label` names the repository in the coordinator's and the examiners' tasks. `osv` is passed to every `run_subagent`; pass one transport to share it across the run, or none, as `cli` does, so `tools.execute` builds one per `query_osv` call. It raises `ValueError`, before any request or audit line, for a coordinator tool that launches no loaded sub-agent. Any error other than `DispatchError` from `run_subagent`, and any error reading an agent's prompt or skills or writing the audit or an output file, propagates; the dispatch it interrupts then has a `dispatch_started` line and no `dispatch_finished`.
- `RunState`: `examinations`, `reviews` and `drafts`, each mapping an ID to `Accepted(id, workflow, step, output, task)` in acceptance order; `latest_review` (target ID → review ID); `dispatches` (cap key → count); `turns` (coordinator calls made); `halt_reason`, a `HALT_REASONS` value, or null when the coordinator ended its turn. A draft's `task` holds the disposition it was written from, and a review's `output` holds its challenges with their IDs.
- `tool_definitions(manifests)` returns the launch tools below. `section_status(findings)` returns PASS or FAIL (Closed sets).

### Coordinator tools (built)

All four use `strict: true`, `additionalProperties: false` and only the structured-outputs keywords, and every field is required. `coordinator.tool_definitions` builds them from the manifests: an examiner's `step` enum is its manifest's steps, and the writer's `disposition` is `schemas/disposition.schema.json`.

- `launch_security_examiner{step: secrets|insecure_config, challenge_ids: [str], note: str}`
- `launch_dependency_examiner{step: known_vulnerabilities|dependency_hygiene, challenge_ids: [str], note: str}`
- `launch_adversarial_reviewer{target_id: str}`: an examination ID or a draft ID
- `launch_final_review_writer{disposition: {steps: [{workflow, step, examination_id, decision: accept|escalate, rationale}], summary}, challenge_ids: [str]}`

Results, as JSON text in a `tool_result` whose `is_error` is true only for an error:
- examination: `{examination_id, step, version, status, findings: [{id, severity, title, file, line}]}`, `status` being `section_status` of the findings
- review: `{review_id, target_id, verdict, challenges}`, each challenge with its `id` and every field of the review schema
- draft: `{draft_id, sections}`, `sections` being the number of sections
- otherwise: `{"error": {code, message, retryable, details}}` (`DispatchError.to_result()`, shape: `schemas/dispatch_error.schema.json`). `details` is a list of strings, one per problem found.

### Output contracts

One JSON Schema per contract under `schemas/`, checked by `guardrails.validate` with `jsonschema`. `agents.runner` sends a sub-agent's contract as `output_config.format`; the disposition schema is the `disposition` property of the strict `launch_final_review_writer` input schema. Each uses only the structured-outputs keywords, and every field is required. A JSON integer must be a whole number: `2.0` and `true` are refused. `schemas/dispatch_error.schema.json` is not a contract: it describes what the coordinator receives, is never sent to the API, and so may use any Draft 2020-12 keyword.

- **Examination:** `{workflow, step, summary, findings: [{title, severity, category, file, line, evidence, recommendation, advisory_ids: [str]}], limitations: [str], challenge_responses: [{challenge_id, response: upheld|rejected, rationale}]}`. Every finding cites a file and line. An absence is a finding only when it has a file to cite, such as a missing lockfile cited at its manifest; with nothing to cite, such as no dependency manifest at all, it is a limitation.
- **Review:** `{target_id, verdict, summary, challenges: [{finding_id, lens, severity, claim, evidence_checked: [{file, line}], rationale}]}`. An empty `finding_id` marks a challenge on no single finding. A draft has no findings of its own, so the reviewer prompt leaves `finding_id` empty in every challenge to a draft, and `coordinator` passes no finding IDs in a draft's `ReviewContext`.
- **Writer output:** `{executive_summary, sections: [{key: "<workflow>.<step>", prose}]}`
- **Disposition:** `{steps: [{workflow, step, examination_id, decision: accept|escalate, rationale}], summary}`

`validate` runs the schema first, then the semantic checks below in order, and raises at the first group with a problem. That `DispatchError` lists every problem of its group in `details`.

| Contract | Context | Check | Code |
|---|---|---|---|
| any | — | the output breaks its schema | `SCHEMA_INVALID` |
| examination | `ExaminationContext(workflow, step, code, workspace)` | `workflow` and `step` are not the dispatched ones; `advisory_ids` on a finding of any step but `ADVISORY_STEP` (known_vulnerabilities); a finding's `title`, `evidence` or `recommendation` is empty or blank | `SCHEMA_INVALID` |
| | | a finding's `file` is one `Workspace.read_lines` refuses (missing, a directory, binary, over the read cap, outside the workspace, under a skipped directory, unreadable), or its `line` is outside `1..` that file's line count | `EVIDENCE_INVALID` |
| review | `ReviewContext(target_id, finding_ids)` | `target_id` is not the dispatched target; the verdict does not follow from the challenges (rule: docs/PRD.md, Glossary, Review); a challenge's `claim` or `rationale` is empty or blank, its `evidence_checked` is empty, or an entry there has a blank `file` or a `line` below 1 | `SCHEMA_INVALID` |
| | | a non-empty `finding_id` is not a finding of the target | `EVIDENCE_INVALID` |
| writer output | `WriterContext(steps, input_ids)` | a step's section is missing or repeated, or a section names no step of the run | `SCHEMA_INVALID` |
| | | the executive summary or a section's prose is empty or blank, or has a line that renders as a heading: one whose first non-blank character is `#`, or that is a setext underline (only `=` or `-`), either also after `>` or a list marker (`-`, `*`, `+`, `1.`, `1)`); or one holding an HTML heading tag `<h1>`…`<h6>`, also at the end of the line | `SCHEMA_INVALID` |
| | | prose cites an ID not in `input_ids`: a cited ID is the longest start of any token inside `[...]`, less leading and trailing hyphens, that is made of letter-led, hyphen-joined parts whose last part holds a digit (so `[SEC-98-new]` cites `SEC-98`) (`SEC-1`, `sec-1`, `RV-2-C1`, `CVE-2018-18074`, `CWE-798`; not `x-ray` or `A-Z`), several to a bracket allowed. The caller decides what `input_ids` holds: `coordinator` passes every ID the harness assigned that the writer's task holds, so a standard such as `[CWE-798]` or an advisory ID is refused | `EVIDENCE_INVALID` |
| disposition | `DispositionContext(steps, examinations, reviewed)` | a step is missing or repeated, or an entry names no step of the run | `SCHEMA_INVALID` |
| | | an `examination_id` is unknown or belongs to another step | `UNKNOWN_TARGET` |
| | | an `examination_id` has no review | `PRECONDITION_FAILED` |

An accepted examination comes back with an `id` (`<code>-<n>`, in order) on each finding, so finding IDs are unique within it. Challenge, review, examination and draft IDs are assigned by `coordinator` (Identifiers).

**`DispatchError`** text can echo agent output, so its message and each detail are passed through `redact()`, have lone surrogates escaped as `\uXXXX`, and are cut to `DISPATCH_ERROR_TEXT_MAX_CHARS` (300) characters. `details` holds at most `DISPATCH_ERROR_MAX_DETAILS` (20) entries; past that, the last entry says how many more were not shown. A file problem gives only the `OSError` reason, never the workspace's absolute path.

**`redact(value)`** returns a copy of a JSON value in which every string, at any depth, has each secret-like substring replaced by `<redacted:XXXX…>`. `XXXX` is the secret's first `REDACT_KEEP_CHARS` (4) characters, or its first half when that is fewer, so a short password is never shown whole. Dict keys, numbers, booleans and `None` are kept, and redacting twice changes nothing more. It masks:
- AWS access key IDs: `AKIA` or `ASIA` plus 16 upper-case letters or digits, wherever they appear
- AWS secret access keys: 40 base64 characters that mix upper case, lower case and a digit or `+` (so a 40-character git SHA or path is not one)
- PEM private-key blocks, `BEGIN` to `END`, or, when no `END` comes before the next `BEGIN`, over the base64 lines that follow; literal `\n` escapes count as line breaks
- `sk-` tokens (OpenAI, Anthropic) and GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), unless a letter or digit comes right before them
- the value assigned to a name containing `password`, `secret`, `token` or `api_key` (also `apikey`, `api-key`; any letter case). The name may be a quoted or subscript key (`"Admin Password":`, `config["SECRET_KEY"] =`) and may carry a type (`password: str =`, `let password: &str =`, `var password string =`); the assignment may itself sit inside a quoted line (`Found "SECRET_KEY = 'x'"`). The value is masked whole:
  - a quoted value after `=`, `==`, `=>`, `:=` or `:`, up to its closing quote; backslash escapes and JSON-escaped quotes (`\"`) are followed, an unclosed quote runs to the end of the line, and a triple-quoted value may span lines. A value never starts with a space, `)`, `,` or `;`, so the closing quote of a prompt such as `getpass("Enter your password: ")` is not taken for the opening quote of a value
  - an unquoted value after `=`, `=>` or `:=`, up to the next whitespace, unless it is a call or subscript (`os.environ["X"]`, `get_token()`, `get ("X")`, or a call whose arguments run past the whitespace) or has no letter or digit
  - an unquoted value after `:` only when it is the last token on its line (YAML `password: x`), so prose such as "Secrets: none found" stays whole
  - when the value is a call, subscript or bracketed group, every quoted literal inside its brackets, across lines, except a call's leading literal argument: `os.environ.get("SECRET_KEY", "<redacted:dev-…>")` keeps the key it reads and masks the hard-coded default

Assignments are masked before the token kinds, so a value is masked whole even when it starts with a token, and a value that already is or holds a marker is left as it is. Masking is fail-safe, so code values are masked too: `max_tokens=4096`, `api_key: str | None = None`, a YAML-like `password: str` or `Token: none` at the end of a line. Not masked: other names (`passwd`, `pwd`, `private_key`), URL user info (`postgres://u:p@h`), `Authorization: Bearer …`, command-line flags (`--password x`, `curl -u u:p`), XML attributes and elements, YAML values followed by a comment or inside a flow mapping or block scalar, Markdown-decorated names (`**password**:`), the leading literal of a call (so `SecretStr("x")` keeps `x`), a literal after an unquoted reference (`process.env.PW || "x"`), a value continued on the next line with `\`, a PEM body line without its `BEGIN` line, and secrets inside dict keys or non-JSON values.

### `report.md`

The harness renders every heading:
1. `# Codebase Health Assessment — <input name>`
2. The correlation ID, generated-at time (the run's finish time), and status at generation with its open gates
3. `## Executive summary`
4. `## <Title> — PASS|FAIL` for each of the 4 steps, each followed by the writer's prose
5. `## Review trail`: a table of step (its title) | examination | review verdict (its latest review) | coordinator decision | rationale. The rationale is the coordinator's, redacted, with whitespace collapsed, `|` and `\` escaped and `<` written as `&lt;`
6. `## Human review`: static text listing the open gates, each with the IDs it names (`Subjects:`), only when the status is pending_human

The sections follow `REPORT_TITLES`, whatever order the disposition and the draft use. The examination behind each section is the one the disposition names. `render` refuses a status that disagrees with the gates (`pending_human` exactly when a gate is open, never `halted`), a step with no title and a draft with no section for a step. Every `<` in the executive summary, the prose, the rationales and the input name becomes `&lt;`, redaction markers included, and a backslash goes before the first marker of any line that would open a code fence (zero or more spaces or tabs, then three or more backticks or tildes), and a carriage return counts as a line break, so an unclosed fence cannot turn later headings into code. It returns text that may hold a lone surrogate from the writer's prose; `cli` writes it with backslash escapes.

### `decisions.jsonl` record

`correlation_id`, `decision`, `reviewer`, `os_user` (the account name of the process's uid from the password database, not the `USER` or `LOGNAME` variable, which the caller sets), `note` (redacted, or null), `decided_at` (UTC, the audit's timestamp format), `gates_resolved` (every gate in `run.json`) and `report_sha256` (of `report.md` as it stood). One JSON object per line, ASCII-escaped.

### Evals *(planned)*

```
python -m evals.run --agent <name>|all --runs N
```

`evals/results/<agent>.json` holds `{agent, model, effort, prompt_sha256, skills_sha256, generated_at, runs, cases: [{case_id, run, scores, passed, input_tokens, output_tokens, cost_usd}], summary: [{criterion, threshold, per_run_mean, passed_all_runs}], total_cost_usd}`.

| Agent | Cases | Criteria (threshold) |
|---|---|---|
| security_examiner | S1 AWS key in config; S2 private key and `.env` password; S3 Flask debug, CORS `*` and `verify=False`; S4 clean; S5 prompt-injection file plus a real secret | seeded_recall ≥ 0.80 (same file, line ±2, same step); clean_precision = 1.0; severity_calibration ≥ 0.80 (within one level); injection_resistance = 1.0 |
| dependency_examiner | D1 PyPI `requests==2.19.0`; D2 npm `lodash 4.17.15`; D3 unpinned, no lockfile; D4 clean pinned; D5 OSV unavailable | vuln_recall ≥ 0.80; no_fabricated_advisories = 1.0 (every advisory ID is in the replay); hygiene_recall ≥ 0.80; clean_precision = 1.0 (D5 reports a limitation) |
| adversarial_reviewer | R1 fabricated evidence; R2 correct examination; R3 understated severity; R4 report adds a finding; R5 correct report | defect_catch_rate ≥ 0.80; false_challenge_rate ≤ 0.20; critical_calibration ≥ 0.80 (R1, R4 block); evidence_verified ≥ 0.80 (`read_file` on the cited file) |
| final_review_writer | W1 all PASS; W2 mixed; W3 escalated step; W4 many findings; W5 overruled challenge | no_new_findings = 1.0; high_severity_coverage ≥ 0.90; structure_valid_first_try ≥ 0.90; tone_score ≥ 4.0/5 |
| coordinator | K1 all clean; K2 critical challenge fixed by re-examination; K3 SCHEMA_INVALID then valid; K4 critical never resolved; K5 draft blocked | review_coverage = 1.0; targeted_redispatch ≥ 0.80; no_unneeded_redispatch ≥ 0.80; escalation_correct ≥ 0.80 |

A criterion passes only when it meets its threshold in every run.

## Configuration

| Key | Where | Default | Status |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | environment | the SDK credential chain (API key, auth token or credentials provider) | built |
| `ASSESSOR_RUNS_DIR` | environment | `runs`, relative to the working directory; an empty value counts as unset. `assess run` refuses a directory input that is the runs directory or one of its ancestors, compared by file identity | built |
| `ASSESSOR_OSV_REPLAY` | environment, read by `config.osv_replay()` | unset, meaning live OSV; an empty value counts as unset | built |
| `MAX_TOKENS` | `config` | 16000 | built; *(planned)* a manifest `max_tokens` field once `llm.call` takes one, and the manifest schema refuses it until then |
| `SDK_MAX_RETRIES` | `config` | 2 | built |
| `FALLBACK_BETA`, `FALLBACKS` | `config` | `server-side-fallback-2026-07-01`, `"default"` | built |
| pricing | `config/pricing.json` | the four models listed under Data and state | built |
| `model`, `effort`, `prompt`, `tools`, and per role `skills`, `max_tool_calls`, `output_schema`, `steps`, `isolated_context`, `assignment` | each agent manifest | `claude-sonnet-5-5`; effort per the Agents table; `max_tool_calls` 12 | declared and loaded; sub-agent fields read by `agents.runner`, the coordinator's by `coordinator` |
| `max_turns`, `max_dispatches_per_step` | coordinator manifest | 30 coordinator calls; 3 dispatches per (examiner, step), per reviewed target, and for the writer in all | enforced by `coordinator` |
| zip caps | `config` | 5000 entries (directories included), 50 MB (50,000,000 bytes) declared uncompressed | built |
| read caps | `config` | 400 lines per call, 256 KB (256,000 bytes) per file, 500 list entries; skips `.git`, `node_modules`, `.venv` in any letter case; binary (NUL-holding) files refused | built |
| OSV | `config` | `https://api.osv.dev/v1/query`, 10 s timeout per connect, read or write (not a total deadline); ecosystems PyPI and npm; ranges ECOSYSTEM and SEMVER; summaries up to 300 characters | built |
| recognised dependency files | `config.DEPENDENCY_FILES` | PyPI: `requirements*.txt`, `pyproject.toml`, `Pipfile` (manifests); `Pipfile.lock`, `poetry.lock`, `uv.lock` (lockfiles). npm: `package.json` (manifest); `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` (lockfiles). Names match case-sensitively. | built |
| substance ratings | `manifests/substance.json`, or `--substance FILE` | the shipped ratings | built |
| guardrails | `config` | `DISPATCH_ERROR_MAX_DETAILS` 20, `DISPATCH_ERROR_TEXT_MAX_CHARS` 300, `REDACT_KEEP_CHARS` 4, `ADVISORY_STEP` known_vulnerabilities | built |

## Decisions

| Decision | Choice | Reason | Rejected |
|---|---|---|---|
| Agent loop | Hand-written Messages API loops in `coordinator` and `agents.runner`, over `llm.call` | Every call has to be an audited, validated step | Tool Runner (hides the per-call boundary); Claude Agent SDK (drives a CLI process); Managed Agents (the loop runs outside the harness) |
| API access | One gateway (`llm`) using `beta.messages.create`: server-side fallback, `output_config`, non-streaming, fixed `max_tokens` until manifests carry it | One place to audit, price and map errors | Several call sites (audit gaps); streaming (outputs are short) |
| Request shape | The gateway has no parameter for any field the API rejects (the fields: CLAUDE.md, Invariants) | Sonnet 5.5 returns 400 for sampling parameters, `thinking: disabled` and a forced `tool_choice`; leaving `thinking` out keeps adaptive thinking | — |
| Credentials | `make_client()` fails fast with `NoCredentialsError` | A missing key otherwise surfaces as a raw SDK `TypeError` mid-run, not an `AnthropicError` | Letting the first request fail |
| Cost scope | Tokens and cost cover the serving attempt only | One line per call prices the model that answered; declined fallback hops are left out on purpose | Summing every hop |
| Agent definitions | One JSON manifest per agent; requests built only from it | Scoping is declared and checkable, not buried in Python classes | Tools hard-coded per class |
| Manifest roles | A `role` field (coordinator, examiner, reviewer, writer) selects the fields a manifest may hold; manifests name tools, and code builds their definitions | One strict schema per role, and the launch tools' `step` enum comes from the examiner manifests | One loose schema for every agent; full tool definitions in each manifest |
| Loader scope | Load `coordinator.json` and only the manifests its `launch_*` tools name | Nothing outside the coordinator's tools can be loaded as an agent | Loading every `*.json` in `manifests/` |
| Output contracts | One JSON Schema per contract, used for both `output_config.format` and `jsonschema`; ranges and lengths live in the semantic checks | One source of truth that stays inside the structured-outputs keyword subset (the keywords: CLAUDE.md, Constraints) | Pydantic models (a second schema source); free-text parsing |
| Semantic checks | Deterministic checks in `guardrails` | Not left to the prompt | Prompt-only rules |
| Guardrail failures | `validate` raises `DispatchError`; the first check group with a problem decides the code, and every problem of that group is listed | One object carries the code, its retryable flag and the coordinator's view; the agent gets every fix to make in one retry | Returning an error value; stopping at the first problem |
| Finding IDs | `validate` assigns them to an accepted examination from the step code | They need only the step code, and the review and writer checks cite them | Model-written IDs (a duplicate-ID check would be needed); assigning them in the runner |
| Redaction scope | Pattern-based masking of the secret kinds listed under Output contracts; after `:`, an unquoted value only as the last token on its line; in a call assigned to a secret name, every literal but a leading one; a secret under 8 characters keeps only its first half | Catches YAML secrets while a `:` in prose ("Secrets: none found") stays whole; a short secret is never shown in full | Masking every `name: value` (garbles prose); leaving YAML unmasked (secrets on disk); always keeping 4 characters; entropy scanning (false positives on hashes and IDs) |
| Steps and status | Steps are check areas with codes; the harness computes section status | PASS or FAIL follows from the findings, not from the model's wording | Status declared by the model; dispatching whole workflows only |
| Disposition channel | An argument of `launch_final_review_writer` | Keeps the coordinator to dispatch verbs only | A `record_disposition` tool |
| Challenge passing | The coordinator passes `challenge_ids`; the harness resolves them verbatim | The challenge reaches the examiner unaltered | The coordinator paraphrasing |
| Audit store | JSONL per run, flush and `os.fsync` per line, metadata only | A line survives once written, and with no message content the trail holds no secrets | SQLite (more code, nothing needs it); in-memory |
| Eval stability | Thresholds must hold in every one of 3 runs | A single run does not show stability | One run |
| Gates and decisions | Gates evaluated once at run end; `run.json` written once; decisions in a separate append-only `decisions.jsonl` under `fcntl.flock` | Keeps every earlier record unchanged | Rewriting `run.json` on decision |
| OSV transport | Live POST at runtime; replay from `ASSESSOR_OSV_REPLAY` when set | Reproducible evals | Live OSV in evals (results drift as advisories change) |
| OSV HTTP client | `httpx2`, the SDK's own HTTP client, declared directly in `pyproject.toml`; `httpx` removed | No HTTP library beyond what the SDK already installs, and a direct declaration so an SDK release cannot drop it | `httpx` (an extra dependency); `requests` (an extra dependency); `httpx2` left undeclared |
| Tool outcomes | `tools.execute` returns a `ToolResult` for refusals and tool failures instead of raising | The runner can audit `allowed` and reply with `is_error` from one object, and the agent can recover from a bad path or an OSV outage | Raising, which every caller would have to translate |
| Zip extraction | Check the entry list (count, declared size, names, encryption) before writing; extract member by member | Most refusals happen before a run directory exists; `extractall` silently rewrites unsafe names instead of refusing them; `zipfile` stops each member at its declared size, so the declared total bounds the writes | `extractall`; counting bytes while writing (`zipfile` already enforces it) |
| Effort | Set per agent (values: Agents table) | Medium suits multistep tool use, low suits short prose, and the reviewer is correctness-critical | One effort for all |
| Parallel tool calls | Several `launch_*` blocks in a turn run sequentially, with one result message | Simple, and it meets the API's result-message rule | Threads (nothing needs them) |
| Sub-agent task | One JSON object in the first and only user message of a new conversation | Challenges reach the examiner unchanged and the reviewer sees only the target and its task, both checkable by parsing the message | Prose tasks (verbatim content cannot be checked); reusing a message list between invocations |
| Tool-call cap | Every `tool_use` block counts, refused ones included; the block past the cap is not run | An agent that keeps calling undeclared tools still stops | Counting turns; counting only allowed calls |
| Assistant turns | Appended to the conversation unchanged, `fallback` blocks included | Thinking blocks stay valid only in unedited history, and a non-streaming fallback response already leaves out the declined partial | Rebuilding turns from text |
| Redacting accepted outputs | Every string except the references `validate` checked against the workspace or the run (user decision); a `file` with a `..` segment is masked anyway (author's narrowing, so model-written text before a `..` cannot pass unmasked) | Masking a checked file path or ID breaks the reference without hiding anything: a path that looks like an AWS secret key would no longer open | Masking everything (paths such as `src/main/java/com/acme/aws/S3UploadServi.java` came back unusable); exempting unchecked fields too |
| Label lines in prose | The writer and reviewer prompts ask for full sentences instead of a line ending in a label and one token after a colon (user decision) | `redact`'s YAML rule masks that form, so `Secrets: [SEC-1]` would lose a citation `validate` had accepted. No check or eval criterion detects a citation lost this way yet | Exempting bracketed IDs from `redact` (changes the redaction rules under Output contracts, and a bracketed password would show) |
| Tool name in the audit | A name from `SUBAGENT_TOOLS`, or null | The audit never holds text the model wrote | Logging any name the model called |
| Workspace | A directory is read in place; a zip is extracted into the run directory | Copying a directory costs time and nothing needs it | Always copying |
| Input checks at parse time | The correlation ID and reviewer name are checked by argparse | Bad input exits 2 before any run state is read | Checking later in `decide` |
| Missing credentials | Exit 2, with no run directory | No run started, the same as a bad input path | Exit 1 as halted (it would create a run only to record that it could not start); a new exit code |
| Credential check placement | `cli` calls `llm.make_client()` before creating the run directory and passes the client to `coordinator` | The exit-2, no-run-directory outcome needs the check before any run state exists | `coordinator` wrapping the check (one more indirection) |
| Coordinator turn cap | A turn is one coordinator call; a `tool_use` stop on turn `max_turns` halts the run with `COORDINATOR_TURN_LIMIT` and its blocks are not dispatched (user decision) | No later call could read their results, so dispatching them would only spend money | Running them and then refusing the next call |
| Retry cap | Every dispatch counts toward its cap key, failed ones included; refused launches do not. Reviews are capped at `max_dispatches_per_step` per target (user decision) | A step that keeps failing validation still stops; a review cap per target also bounds the reviews one turn can launch | Counting reviews toward the reviewed step (examine, review, re-examine, review takes 4 dispatches); no review cap |
| Challenge scope | An examiner launch resolves only challenges to examinations of its own step, and the writer only challenges to drafts (user decision) | The prompts present challenges as objections to the agent's own previous output | Any challenge of the run |
| Writer citations | `WriterContext.input_ids` holds every ID the harness assigned that the writer's task holds: examination, finding, review and challenge IDs (user decision) | Every invented ID is refused and no ID the harness gave is; advisory and CWE IDs stay unbracketed, as the writer prompt says | Finding IDs only (a cited challenge ID would be refused); advisory IDs too |
| Dispatch audit | `dispatch_started` and `dispatch_finished` payloads; every line of an invocation points to its `dispatch_started` line (user decision) | The audit groups each sub-agent's calls under the dispatch that caused them | Pointing to the coordinator's `llm_call` line, which `llm.call` does not return |
| Malformed launches | A tool name outside the launch tools, or input outside a launch tool's schema, is `SCHEMA_INVALID` | Strict tool use should prevent both, and the harness checks again rather than trust it | A new error code |
| Output files | `coordinator` writes each accepted output when it accepts it, with exclusive creation | The run directory holds every accepted output even when the run later halts, and none is rewritten | Writing them all at run end |
| Examinations a gate looks at | The ones the final disposition names, the newest reviewed version of each step, and the latest draft (author's reading of "accepted") | A superseded version that was blocked and then re-examined clean must not hold the run, and naming an older version must not hide a block on a newer one | Every version (a gate on every fixed challenge); only the named ones (a coordinator could hide a block) |
| Run files for a halted run | `run.json` and `summary.json` are written; `disposition.json` and `report.md` are not | `halt_reason` lives in `run.json`, and a halted run still spent money | Writing nothing for a halted run |
| Who writes the run files | `cli` writes `disposition.json`, `run.json` and `summary.json`, and `report.md` from `report.render` | `gates` and `report` import only `audit` and `config`; the coordinator ends before the outcome is known | `coordinator` writing the disposition |
| Redaction of coordinator text | `cli` redacts the disposition's rationales and summary and a decision's note before writing | Every artifact is redacted before it is written; these are the stored texts no sub-agent produced | Writing them as given, on the argument that the coordinator only sees redacted output |
| Section status rule | `report` applies `FAILING_SEVERITIES` itself; a test keeps it equal to `coordinator.section_status` | `report` may import only `config` | `report` importing `coordinator`; passing statuses in |
| Workspace before `run_started` | The workspace is opened before the first audit line | A failed extraction then leaves no run directory | Opening it after `run_started`, leaving an audit-only run |
| Decision order | The decision record is written, then its audit line, under one lock | The record is the authority; a failed audit append leaves the run decided and is reported as an error | Audit line first (a decision-less audit line) |
| Decision identity | `os_user` comes from the password database for the process's uid, the environment's user only when the uid has no account | The field is the identity a typed reviewer name cannot supply, and `getpass.getuser()` reads `USER` and `LOGNAME` first | `getpass.getuser()` alone |
| Report text from models | `report` turns every `<` in model-written or operator-chosen text into `&lt;`, redaction markers included; a line that would open a code fence gets a backslash before its first marker, and CR line breaks are read as line breaks (verified against the commonmark and markdown-it parsers, not in the suite); markdown links and images in the writer's prose are not changed, and `<` inside code spans and fences shows as `&lt;` | A raw comment or tag could hide a heading or forge a status. Citations such as `[SEC-1]` need the brackets, so link and image syntax cannot be escaped without a check in `guardrails` | Rejecting such prose in `guardrails` (a writer-contract change, not decided) |
| Runs directory and the input | `assess run` refuses a directory input that holds the runs directory | The run would write into the client's tree and a later run would read earlier runs as client files | Skipping `runs/` in the workspace walk |
| A zip's extracted copy | `workspace/` keeps the client's files as the zip held them, secrets included; every file the tool writes is redacted | The copy is the input, not output, and the zip run reads it in place | Deleting `workspace/` at run end (the sample runs are copied without it) |

## Open questions

None.
