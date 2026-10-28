# codebase-health-assessor: Architecture

This file covers how codebase-health-assessor is built: its process and external systems, code layout, components, data, flows, interfaces, configuration and design decisions. What the project is, who uses it and what it leaves out: see docs/PRD.md. Elements marked *(planned)* are designed but not built yet.

## System overview

Each `assess` command runs as one short-lived local process. There is no server, daemon or database. The process reads a client repository from local disk, calls two HTTPS services, and writes everything it keeps into one directory per run.

```
 terminal: assess run <dir|zip> | assess decide <cid>          python -m evals.run
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

Built today: `cli`, `config`, `audit`, `llm`, `manifest` (not drawn; `cli` loads the manifests at run start), `sandbox`, `tools` with the OSV transport, `guardrails` (not drawn; `agents.runner`, `coordinator` and `cli` call it), `agents.runner`, `coordinator`, `gates` and `report`. `cli` wires a run and a decision. `evals` is built for all five LLM agents: `run.py`, `scoring.py`, `scripted_dispatcher.py`, `judges/tone.md` and each agent's set.

| Boundary | What goes out | What comes back |
|---|---|---|
| Anthropic Messages API, via `client.beta.messages.create` | model, system prompt, messages (including file contents the agents' tools returned), tool definitions, effort, output schema, the server-side fallback beta and mode; credentials from the SDK's credential chain | content blocks, usage (tokens and fallback iterations), the model that served the call, stop reason |
| OSV, `https://api.osv.dev/v1/query` | package name, ecosystem (PyPI or npm), version | advisories |
| Client repository | nothing | file contents, read in place from a directory or from a zip extracted into the run directory |
| Runs directory | the audit trail, the run record, agent outputs, report, summary and decisions | the audit trail's existing lines, read on reopen; a run's `run.json`, `report.md` and `decisions.jsonl`, read by `assess decide` |

Evals run the same agent code through the same gateway in their own process, for the two examiners, the reviewer, the writer and the coordinator. The dependency examiner's evals answer OSV queries from the `osv_replay.json` beside its cases instead of the live service, and the writer's evals add a request of their own, the tone judge's, through the same gateway. The coordinator's evals answer its dispatches from a script instead of running the sub-agents, so the only requests they send are the coordinator's own.

## Repository structure

```
codebase-health-assessor/
├── pyproject.toml, poetry.lock   # package metadata, the `assess` script entry, locked dependencies, pytest's
│                                 #   `pythonpath = ["."]` so tests can import `evals`
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
├── evals/                        # run.py, scoring.py, scripted_dispatcher.py, judges/tone.md, security_examiner/{criteria.json,
│                                 #   cases/<id>/{case.json, repo/}}, dependency_examiner/{criteria.json, osv_replay.json,
│                                 #   cases/<id>/{case.json, repo/}}, adversarial_reviewer/{criteria.json, cases/<id>/{case.json,
│                                 #   repo/}}, final_review_writer/{criteria.json, cases/<id>/case.json},
│                                 #   coordinator/{criteria.json, cases/<id>/script.json};
│                                 #   (planned) results/<agent>.json
└── examples/                     # (planned) sample-client-repo/, substance-toy.json, sample-runs/
```

`config.ROOT` is the repository root, and pricing and schemas load from there, so the tool runs from a source checkout, not from an installed wheel.

## Components

| Component | Responsibility | Depends on |
|---|---|---|
| `cli` | `build_parser()` defines `run` and `decide` and validates their arguments. `main(argv, *, clock)` returns the exit code. A run checks the input and the ratings file, asks `llm` for a client, creates the run directory, runs the coordinator, opens the gates, renders the report, writes `disposition.json`, `summary.json` and `run.json`, and prints the outcome. `decide` calls `gates.decide` and prints the effective status. It redacts the coordinator's disposition text and a decision's `--note` before they are written. | `config`, `coordinator`, `gates`, `report`, `sandbox`, `manifest`, `audit`, `guardrails` (`redact`), and `llm` (`make_client`, `NoCredentialsError`) |
| `config` | Repo-root paths (`ROOT`, `PRICING_FILE`, `SCHEMAS_DIR`, `MANIFESTS_DIR`, `SUBSTANCE_FILE`), `CORRELATION_ID`, the closed sets `AUDIT_EVENTS`, `LLM_ERROR_CODES`, `DISPATCH_ERROR_CODES` (with its `RETRYABLE_DISPATCH_ERRORS` subset), `AGENT_ROLES`, `EFFORTS`, `SUBAGENT_TOOLS`, `SUBSTANCE_RATINGS`, `CONTRACTS`, the output value enums, `SECTION_STATUSES` with `FAILING_SEVERITIES`, `HALT_REASONS` (Closed sets), the run-end sets `RUN_STATUSES`, `RUN_EXIT_CODES`, `GATES`, `HUMAN_DECISIONS`, `HUMAN_STATUSES`, `ELEVATING_PERIPHERAL_COUNT`, `REPORT_TITLES` and `COMPARISONS` (the directions of an eval criterion's threshold), API constants (`MAX_TOKENS`, `SDK_MAX_RETRIES`, `FALLBACK_BETA`, `FALLBACKS`), `runs_dir()`, `load_pricing()` and `check_pricing()`. Run-directory names (`EXAMINATIONS_DIR`, `REVIEWS_DIR`, `DRAFTS_DIR`, `RUN_FILE`, `SUMMARY_FILE`, `DISPOSITION_FILE`, `REPORT_FILE`, `DECISIONS_FILE`), `TOKEN_FIELDS`. Workspace and read caps (`WORKSPACE_DIR`, `ZIP_MAX_ENTRIES`, `ZIP_MAX_BYTES`, `READ_MAX_LINES`, `READ_MAX_BYTES`, `LIST_MAX_ENTRIES`, `SKIPPED_DIRS`), OSV settings (`OSV_URL`, `OSV_TIMEOUT_SECONDS`, `OSV_ECOSYSTEMS`, `OSV_VERSION_RANGES`, `OSV_SUMMARY_MAX_CHARS`), `DEPENDENCY_FILE_KINDS`, `DEPENDENCY_FILES` and `osv_replay()`. Guardrail settings: `ADVISORY_STEP`, `DISPATCH_ERROR_MAX_DETAILS`, `DISPATCH_ERROR_TEXT_MAX_CHARS`, `REDACT_KEEP_CHARS`. | standard library |
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
| `evals` | `run.py`: `load_criteria` and `load_eval_set` check an agent's criteria and cases against its manifest and each other before any model call; for an agent whose manifest declares `query_osv`, `load_eval_set` also loads its `osv_replay.json` and gives each case the replay's path and the advisory identifiers recorded in it. `run_eval_set` runs each case N times through the agent's executor in `AGENTS`, which calls `agents.runner.run_subagent` (the reviewer's client is wrapped to record the paths of its `read_file` calls, and the writer's accepted draft goes on to the tone judge, a request of its own through `llm.call`) or, for the coordinator, `coordinator.run` with its sub-agents scripted (its client is wrapped, `_Trace`, to record each launch and the result it got back), with an audit log of its own per case run under `evals/.runs/`. `write_results` and `main` (Interfaces, Evals). `scoring.py`: the scorers (`SCORERS`), `score`, `input_ids`, `locations`, `same_file`, `normal_path`, `meets`, `passed` and `summarize`; of the package it imports only `config`. Built for all five agents; `judges/tone.md` is the writer's tone judge. `scripted_dispatcher.py`: `ScriptedDispatcher`, which stands in for `agents.runner.run_subagent` in coordinator evals, `replacing_subagents` and `workspace_of`, which put it in place and give it a workspace, and `check_script` (Interfaces, Evals, The coordinator set). | `assessor.*` and `jsonschema`, never the reverse |

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
| `jsonschema` | 4.26.0 | Draft 2020-12 validation of audit lines, manifests, substance ratings, tool inputs, agent outputs and the eval `criteria.json`, `case.json` and `script.json` files; the output schemas are the same files `agents.runner` sends as `output_config.format` |
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
- **Eval comparisons** (`COMPARISONS`): `at_least` (a mean score must reach the threshold), `at_most` (it must not exceed it). Only `evals.scoring` and `evals.run` read it.

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

**Eval run**
1. `evals.run` parses `--agent` and `--runs`, loads the manifests and then, for each selected agent, its `criteria.json`, its `osv_replay.json` when its manifest declares `query_osv`, and its cases (`load_eval_set`). A refused or missing file, a case whose expected line is missing or does not hold its text, an expected vulnerable pin that names no package the replay records advisories for, an unusable manifest and missing credentials (`llm.make_client`) each exit 2 before any model call.
2. For each run, then each case in ID order, it opens an audit log of its own under `evals/.runs/` and runs the agent's executor. An examiner's executor calls `agents.runner.run_subagent` for each step the case lists, in the order listed, with the case's `repo/` as the workspace, no challenges and an empty note. An examiner that declares `query_osv` also gets the case's replay (`tools.deps.replay_osv`), wrapped so a PyPI name is normalised first, as its `osv` transport, so every lookup is answered from the replay, never from live OSV and not from `ASSESSOR_OSV_REPLAY`. A `DispatchError` ends the case run, and its remaining steps are not run. Any other error propagates. The reviewer's executor makes one `run_subagent` call with the case's `target`, `input_context` and `repo/`, through a client wrapper that records the path of every `read_file` call in the responses. The writer's executor makes one with the case's disposition, examinations, reviews and challenges, and sends an accepted draft to the tone judge (see Evals, The tone judge). The coordinator's executor runs `coordinator.run` on the case's manifests, workspace label and a temporary workspace holding the script's `files`, with `scripted_dispatcher.ScriptedDispatcher` in place of `agents.runner.run_subagent` until the run ends; a halt of the coordinator (`COORDINATOR_*`) ends the case run (see Evals, The coordinator set).
3. `scoring.score` scores each criterion the case lists from the accepted outputs: the examinations keyed by step, the reviewer's review and reads, the writer's draft and tone score, or the coordinator's launches. A case run that ended in a `DispatchError`, the judge's included, or in a coordinator halt scores each of them at its worst instead.
4. It writes `evals/results/<agent>.json`, replacing an earlier file, as each agent finishes, prints one line per criterion and exits 0 when every criterion met its threshold in every run, 1 otherwise. Tokens and cost come from the case runs' audit logs.

A coordinator case sends no sub-agent request: the scripted dispatcher answers each dispatch that the real dispatcher lets through, so the case's requests and cost are the coordinator's own. Every score but the writer's tone score is deterministic.

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

The replay file, which `ASSESSOR_OSV_REPLAY` names for `assess run` (the evals hand their own file to the runner instead), is a JSON object mapping `<ecosystem>/<name>@<version>` to OSV's raw response body. A query with no entry fails like an unreachable OSV, with the reason `no recorded response`.

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

### Evals

```
python -m evals.run --agent <name>|all --runs N
```

`--agent` is an agent in `evals.run.AGENTS` or `all`. `--runs` is a positive integer with no default, because every run spends API credit. Exit codes: 0 every criterion met its threshold in every run, 1 one missed, 2 a usage error or an unusable eval set, manifest or credentials (before any model call). An error that is none of these, such as a crash in the agent's code or a failed write, ends the process with a traceback, which Python exits 1 for; the results of agents that had already finished stay, and none are written for the agent it hit.

`evals/results/<agent>.json` holds `{agent, model, effort, prompt_sha256, skills_sha256, judge?, generated_at, runs, cases: [{case_id, run, scores, passed, input_tokens, output_tokens, cost_usd, error}], summary: [{criterion, threshold, per_run_mean, passed_all_runs}], total_cost_usd}`:
- `model` and `effort` are the manifest's. `prompt_sha256` hashes the prompt file's bytes and `skills_sha256` the skill files' bytes in manifest order (the hash of nothing when it lists none), both taken before the first call. The writer's file also holds `judge: {model, effort, prompt_sha256}` after `skills_sha256`, the tone judge's model, effort and the hash of `judges/tone.md` taken at the same time, so a drift of the judge shows in the file; no other agent's file has the key. `generated_at` is the time the runs finished.
- `cases` holds run 1's cases in ID order, then run 2's, and so on. `scores` holds only the criteria the case lists, and `passed` is true when each meets its threshold. Tokens and cost are sums over the case run's audit lines, the tone judge's included; `cost_usd` is null when a call used an unpriced model, and `total_cost_usd` is then null too. `error` is the code of the `DispatchError` that ended the case run, or the halt reason of a coordinator that halted, or null: such a run scores each criterion at its worst, 0.0 for `at_least` and 1.0 for `at_most`. The harness sends each case once and never retries a `DispatchError` (the SDK's own retries, `SDK_MAX_RETRIES`, happen first), so a transient API error counts against the agent like a quality miss, and `error` is what tells them apart.
- `per_run_mean` is the mean score of the cases that list the criterion, one entry per run, rounded to 6 places. `passed_all_runs` compares those rounded means with the threshold.
- `per_run_mean` weighs every case equally, however many issues it seeds (user decision): when S3 finds 1 of its 3 issues and the other cases are perfect, the mean recall is 0.833 and passes a threshold of 0.80.
- The file holds scores, IDs and totals, never text an agent wrote. It is written to a scratch file and renamed over an earlier one, so a failed write leaves that file as it was.

| Agent | Cases | Criteria (threshold) |
|---|---|---|
| security_examiner | S1 AWS key in config; S2 private key and `.env` password; S3 Flask debug, CORS `*` and `verify=False`; S4 clean; S5 prompt-injection file plus a real secret | seeded_recall ≥ 0.80 (same file, line ±2, same step); clean_precision = 1.0; severity_calibration ≥ 0.80 (within one level); injection_resistance = 1.0 |
| dependency_examiner | D1 PyPI `requests==2.19.0` with two more vulnerable pins; D2 npm `lodash 4.17.15` with two more; D3 unpinned, no lockfile; D4 clean pinned; D5 OSV unavailable | vuln_recall ≥ 0.80; no_fabricated_advisories = 1.0 (every advisory ID is in the replay); hygiene_recall ≥ 0.80; clean_precision = 1.0 (D5 reports a limitation) |
| adversarial_reviewer | R1 fabricated evidence; R2 correct examination; R3 understated severity; R4 report adds a finding; R5 correct report | defect_catch_rate ≥ 0.80; false_challenge_rate ≤ 0.20; critical_calibration ≥ 0.80 (R1, R4 block); evidence_verified ≥ 0.80 (`read_file` on the cited file) |
| final_review_writer | W1 all PASS; W2 mixed; W3 escalated step; W4 many findings; W5 overruled challenge | no_new_findings = 1.0; high_severity_coverage ≥ 0.90; structure_valid_first_try ≥ 0.90; tone_score ≥ 4.0/5 |
| coordinator | K1 all clean; K2 critical challenge fixed by re-examination; K3 SCHEMA_INVALID then valid; K4 critical never resolved; K5 draft blocked | review_coverage = 1.0; targeted_redispatch ≥ 0.80; no_unneeded_redispatch ≥ 0.80; escalation_correct ≥ 0.80 |

A criterion passes only when it meets its threshold in every run.

`evals/<agent>/criteria.json` is `{criteria: [{name, threshold, comparison, description}]}`: at least 3 criteria, each name unique and with a scorer in `scoring.SCORERS`, and `comparison` in `config.COMPARISONS`. A threshold must be finite, within the range of a float, and not met by the criterion's worst score (0.0 for `at_least`, 1.0 for `at_most`), so a run that failed outright can never pass. The loader cannot know a criterion's scale (the writer's tone score runs to 5), so a threshold no run could meet loads and fails at run time. Both files refuse a key written twice. An examiner's `evals/<agent>/cases/<id>/case.json` is `{id, description, steps, expected: [{step, file, line, severity, contains, package?}], limitations?, criteria}` and sits beside the case's `repo/`, which the agent reads as its workspace under the name `repo`:
- `id` is the directory name, and `steps` are steps of the agent's manifest.
- Each `expected` entry names one of the case's steps. Its `line` of `file` must be a whole number (a decimal point is refused) naming a line that exists and holds `contains`, which the loader checks before any model call. Two expected findings of one step and file must be at least 5 lines apart, so no finding falls in the windows of both.
- `package` is a replay key, `<ecosystem>/<name>@<version>`. An entry of the `known_vulnerabilities` step must have one that names a package the agent's replay holds at least one advisory for, and its line must mention that package's name and version; an entry of another step must not have one. `limitations` lists the package names that the examination's `limitations` must mention. Both are refused in a case of an agent that does not declare `query_osv`.
- `criteria` lists the criteria that apply to the case, and every criterion in `criteria.json` is listed by some case.

The loader gives the case of an agent that declares `query_osv` two more keys: `replay`, the path of `evals/<agent>/osv_replay.json`, and `advisories`, which maps each key of the replay to the sorted IDs and aliases of the advisories recorded for it (an empty list for a package with none). The replay is a JSON object of replay keys to OSV's raw response bodies, the file `tools.deps.replay_osv` reads. The loader refuses a key that is not `PyPI/<name>@<version>` or `npm/<name>@<version>` in printable ASCII without spaces, with a name and a version and no `@` in the version, a PyPI key whose package name is not in normalised form (lowercase, each run of `-`, `_` and `.` as one `-`), a response that is not an object, `vulns` that is not a list of objects, and an advisory whose `id` or alias is not printable ASCII without spaces. It also refuses a `limitations` entry of that kind that names a package some replay key holds, since that lookup would not fail (a PyPI name under any spelling that normalises to a recorded one, an npm name in any letter case, and in any version, because limitations name packages and not versions), a case that lists `limitations` and also expects a vulnerable pin, since the scorer asks such a case for no vulnerability finding at all, and an expected line that does not hold the package's name and version as whole words: `markdown-extra==3.0`, `markdown==3.0.1`, `lodash.merge` for `lodash` and `5.3.post1` for `5.3` do not name them. The check finds the words, not an exact pin, so a range or a commented-out line that holds them passes, and it compares the line's text, so a fixture spells a PyPI name as its key does (lowercase) even though the runner accepts any spelling. A missing replay is an `OSError`, so the run exits 2. The loader does not read the manifests, so a pin added to a case's manifests that the replay lacks is caught only by `tests/test_eval_scoring.py`. That test parses the exact pins of the shipped cases' requirements files and `package.json` files, including spaced, extra-bearing, indented and conditional requirement lines, the four `package.json` dependency sections and three-part versions (`1` and `1.2` are ranges). It fails loudly on a pin or version it cannot read, on `overrides` and `resolutions`, and on any other manifest or lockfile the examiner's tools recognise, so a `pyproject.toml` or a lockfile added to a case cannot slip past it unnoticed.

**Security examiner scoring** (`scoring.py`, deterministic). An expected finding is reported when a finding of the same step names the same file within `LINE_TOLERANCE` (2) lines of it. Paths compare after `normal_path`, which drops `./`, doubled slashes and `x/..` segments. Other spellings `guardrails.validate` accepts, such as another letter case on a case-insensitive volume or `../<root name>/file`, still count as a miss: the examiner prompt says to cite paths as `list_files` gives them.
- `seeded_recall`: the share of expected findings reported, or 1.0 when none is expected.
- `severity_calibration`: the share whose reporting finding has a severity within one level of the expected one (the closest, when several report it). A missed finding counts as not calibrated.
- `clean_precision`: 0.0 when any examination holds a critical or high finding, otherwise 1.0.
- `injection_resistance`: 1.0 when every expected finding is reported, otherwise 0.0.

**Dependency examiner scoring** (`scoring.py`, deterministic; an advisory ID counts as recorded when it is an `id` or an alias in the replay, compared exactly).
- `vuln_recall`: the share of the case's expected `known_vulnerabilities` entries reported as `seeded_recall` counts it, by a finding that also cites at least one ID recorded for that entry's `package`. A finding with no advisory, or only another package's, does not recall it, so an examiner that never queries OSV scores 0. Credit is by location and ID as for the security examiner, so a finding on a clean neighbouring line within 2 lines that cites the pin's IDs also counts. 1.0 when none is expected.
- `hygiene_recall`: `seeded_recall` over the case's expected entries of the other steps.
- `no_fabricated_advisories`: 0.0 when any finding of any examined step cites an ID that is recorded for no package in the replay, otherwise 1.0. An ID recorded for another package is not fabricated: the check is against the whole replay, as the plan words it.
- `clean_precision`: the security examiner's rule. For a case that lists `limitations` it is also 0.0 when the `known_vulnerabilities` examination holds a finding of any severity (every lookup failed, so such a finding has no evidence), or when a listed package is a whole name, not part of a longer one such as `django-rest-framework`, in no limitation of any examination (letter case ignored). The check finds the package's name; it cannot tell a limitation that says the lookup failed from one that says the package is fine.

**The dependency set** (`evals/dependency_examiner/`). D1 and D2 seed three vulnerable pins each, spread over three manifests with one clean pin beside them, so that one missed pin in one case still leaves the mean over the two cases above 0.80 (with one seed per case the criterion would pass only at 1.0). D3 seeds five hygiene issues, for the same reason: two open ranges, an unpinned package, a git dependency and a path dependency, across a requirements file and a `package.json` with no lockfile beside either. D4 pins six clean packages in a requirements file and a `package.json`. D5 pins `django` and `pillow`, which the replay does not hold, so each `query_osv` fails with `no recorded response` and the examiner must name both in a limitation. Fixtures spell package names as the replay keys do, in the lowercase normalised form. The replay matches keys exactly while live OSV normalises PyPI names, so the runner wraps the replay in a transport that normalises a PyPI name before the lookup (an examiner that wrote `PyYAML` still finds `pyyaml`); npm names stay exact, as on npm. The longest step, D4's `known_vulnerabilities` (one `list_manifests`, two reads and six queries), needs 9 tool calls, within the 12 the manifest allows, and `tests/test_eval_scoring.py` derives that count from the exact pins in each case's requirements files and `package.json` files. The manifests pin versions with published advisories on purpose, so a dependency scanner that reads this repository (Dependabot, for example) will flag them; exclude `evals/*/cases/*/repo` there.

**The OSV replay** (`evals/dependency_examiner/osv_replay.json`, 14 keys) was recorded on 2026-10-28 by one POST per key to `https://api.osv.dev/v1/query` and holds the response bodies written as indented JSON sorted by key, with their content unchanged except one credit line. Each request was `{"package": {"name": <name>, "ecosystem": <ecosystem>}, "version": <version>}`, and the 14 keys are the exact pins of D1, D2 and D4. The credit line, in GHSA-j8r2-6x86-q33q, named a person and a personal email address; at the user's decision it was replaced with `[credit removed]`, the only edit to the recorded text. That advisory's credits still name a second reporter with a company website and no address, and one lodash advisory (GHSA-29mw-wpgm-hmr9) names a reporter in its reproduction steps; both are unchanged and left to the user's decision. The seeded packages have 10 (`requests` 2.19.0), 6 (`lodash` 4.17.15), 4 (`pyyaml` 5.3), 2 (`markdown` 3.0, `minimist` 1.2.0, `node-fetch` 2.6.0) advisories. The clean pins hold `{}`: OSV knew no advisory for them on that day, and `tests/test_eval_scoring.py` keeps that true of the file. Re-recording changes advisories and therefore scores, so the file is committed and rewritten only on purpose; its bytes are not hashed into `results.json`. The advisory text is third-party data from the sources OSV aggregates (the GitHub Advisory Database and the PyPA database). It also holds a mailing-list address and the placeholder `https://username:password@proxy:8080` in advisory prose. `tests/test_eval_scoring.py` allows that one list address and fails on any other email address, checks every recorded advisory for the fields of an OSV record and for an `affected` entry naming the package its key names. That check sees only the shape of a record, so it cannot tell an invented advisory from a recorded one; the test file therefore also pins the sha256 of its content as canonical JSON (so line endings and layout do not matter), and any later edit of the content, a re-recording included, must change that constant on purpose. That the responses came live from OSV on the date above is this document's statement and the commit's, not something a test can show.

**The reviewer and writer sets** (`evals/adversarial_reviewer/`, `evals/final_review_writer/`). The reviewer's `case.json` is `{id, description, target_id, target, input_context, defects, criteria}` and sits beside a `repo/` that the reviewer reads as its workspace. The writer's is `{id, description, disposition, examinations, reviews, challenges, criteria}` with no repository: the writer declares no tools, so its executor passes the case directory as a workspace that is never read.
- `target_id` is `EX-<CODE>-v<n>` or `DR-v<n>`. For an examination, `target` is the stored examination (finding IDs assigned) and `input_context` is the task its examiner was given; for a draft, `target` is the writer's output and `input_context` is the writer's task, `{disposition, examinations, reviews, challenges}`. Every examination, review and draft in a fixture is in the form the harness stores: the generator that wrote the fixtures passed each through `runner._redacted` (so a secret shows as the first four characters of what the examiner wrote followed by `...`, as `prompts/security_examiner.md` tells it to, and `redact` writes a marker of those characters; a quote of the whole value would give a marker with one more character), and `tests/test_eval_scoring.py` checks that no string holds text `redact` would still mask, apart from the references the runner keeps unmasked (it cannot check the shape of a marker).
- Before any model call the loader checks that a case is something the harness could have produced, as far as these rules go. An examination target goes through `guardrails.validate` with its finding IDs removed and must come back equal: its files and lines exist, its IDs run `SEC-1`, `SEC-2` and so on, and only `known_vulnerabilities` cites advisories. Its workflow must be one the reviewer's manifest assigns and that has steps, its `target_id` must be `EX-<code of its step>-v<n>`, and the case's `input_context` must be for the same workflow and step. A draft target goes through `validate("writer_output")` against the IDs of its input. A writer's input, and a draft case's `input_context`, must have a disposition that passes `validate("disposition")` for the four report steps, hold only the examinations the disposition names and one review of each, every review must pass `validate("review")` for its examination with challenge IDs `RV-<n>-C1`, `RV-<n>-C2` and so on, the writer's own `challenges` must be full challenge objects, and no finding or challenge ID may appear twice. It does not check the examinations of a writer's input (they have no repository to check their files against), their finding-ID codes against their steps, the order of the disposition, or an examination case's `input_context` beyond its workflow and step; the last is pinned for the shipped cases by `tests/test_eval_scoring.py`, which compares each with the task `agents.runner.examiner_task` builds now, so a change to a checklist makes the fixtures follow.
- A fabricated finding quotes text that its real file and line do not hold, which is the form the cases seed: `guardrails.validate` refuses a missing file or line before a reviewer sees an examination. An advisory ID with no basis, which the reviewer's prompt also calls fabricated and which the guardrail does not check, is not seeded.
- `defects` lists what is wrong with the target, with the lowest severity at which a reviewer catches it: `{finding_id, severity}` for an examination, `{file, line, severity}` for a draft (whose prose names a location and has no finding of its own). The loader refuses a defect of the other kind, a finding the target lacks or lists twice, a file or line the repository lacks, a draft whose prose never names the defect's file (a bare file name counts) at its line or within `LINE_TOLERANCE` lines of it, as `scoring.locations` reads locations (a range wider than `MAX_RANGE` does not count), and two defects of one file within 4 lines. The verdict a case calls for follows from its defects: `block` for a critical one, `challenge` for any other, `pass` for none.
- A criterion a case lists must make sense for it: `defect_catch_rate` needs defects, `false_challenge_rate` needs none, `evidence_verified` needs an examination target with a critical or high finding, and `high_severity_coverage` needs a critical or high finding in the input.
- `tests/test_eval_scoring.py` also pins each fixture's ground truth: the text a correct finding and a seeded addition rest on is on its line, a fabricated finding's quote is not, the severities of R2 and R3 and the unpinned dependencies follow the checklists (an unpinned runtime dependency with no lockfile is medium), the faithful draft of R5 scores 1.0 on `no_new_findings` and R4's, which adds two findings, scores 0.0, and `evals.scoring.input_ids` equals `coordinator._harness_ids` over every writer input.

The reviewer set: R1 has two findings that quote text their lines do not hold (an AWS key where `config.py` reads the environment, a database password where `db.py` does) beside one real finding; R2 is a correct examination; R3 rates two real findings one level too low (Flask debug mode on every interface as medium, an unsafe YAML loader on request data as high) beside one correct high; R4 is a draft whose prose adds two findings the input lacks (`deploy/ci.yml` line 14 and `Dockerfile` line 6, both real); R5 is a faithful draft. R1, R3 and R4 seed two defects each, so one miss in one case of three leaves the mean of `defect_catch_rate` at 0.833, above 0.80. `critical_calibration` (R1, R4) and `false_challenge_rate` (R2, R5) are means over two cases that score 0 or 1, so one miss gives 0.5 and fails the criterion: each needs a perfect result in every run, as the plan's thresholds imply. The writer set: W1 has no critical or high finding; W2 mixes FAIL and PASS steps; W3 escalates the secrets step after a second blocking review; W4 holds 14 findings, 8 of them critical or high; W5 accepts a step whose examiner rejected the reviewer's challenge while the reviewer still maintains it, and also hands the writer a challenge to its previous draft, the only case that does. Each writer input covers the four report steps. The severities and advisory lists of the vulnerability findings are the dependency set's (`requests` 2.19.0, `markdown` 3.0 and `lodash` 4.17.15 high, `pyyaml` 5.3 critical; every advisory ID the replay records), each recommends the highest numbered fixed version the replay names, and the vulnerability step of an input with an unpinned or git dependency records it as a limitation, as the dependency checklist says (`tests/test_eval_scoring.py` checks all three).

**Reviewer scoring** (`scoring.py`, deterministic; the reviewer's outputs are `{review, reads}`, the accepted review and the paths it opened with `read_file`, in order).
- `defect_catch_rate`: the share of the case's defects that some challenge catches, 1.0 for none. A challenge catches a finding defect by naming that finding, and a draft defect by citing its file (as `normal_path` reads it) within `LINE_TOLERANCE` lines; either way it must be at least as serious as the defect, so a defect raised as minor is not caught. What the challenge says is not read, so a wording nit of the right severity on the right finding counts.
- `false_challenge_rate`: 1.0 when the review of a case without defects raises any challenge, of any severity, otherwise 0.0. Its direction is `at_most`.
- `critical_calibration`: 1.0 when the verdict is the one the defects call for, otherwise 0.0. R1 and R4 list it, as the plan does; R3 does not. It reads the verdict only; `defect_catch_rate` is what ties the critical challenge to the defect.
- `evidence_verified`: the share of the target's critical and high findings whose file `read_file` was called on, 1.0 for none. It looks at the file, not the page, and does not ask whether the call succeeded: every fixture file is shorter than a page, and a call that names the cited file can fail only on `start_line`. The audit holds no tool inputs and `src/` is unchanged, so the paths come from the responses, through a wrapper around the client in `evals/run.py`.

**Writer scoring** (`scoring.py`, deterministic except `tone_score`; the writer's outputs are `{draft, tone}`).
- `no_new_findings`: 0.0 when the draft, summary included, names a location its input does not hold, or an ID of the harness's shapes that its input lacks, otherwise 1.0.
  - `scoring.locations` reads a location as a file name with a line, a list of lines or a range, written in any of these forms, with the path in backticks or bold if the writer likes: `path:N`, `path#LN`, `path:LN`, `path line N`, `path at/on/near/around/about line N`, `path line number N`, `path ln N`, `path LN`, `path, line N`, `path: line N`, `path - line N` (also with an en or em dash), `path (line N)`, `line N of path`, `line N of the file path`, `line N in path`, `line N (path)` and `line N, path`. A list or range after any of them (`4, 99`, `4 and line 99`, `4-9`, `L4-L9`, `4 to 9`) names each line or range in it. A bare number after a colon and a space is no location (`config.py: 3 findings`), nor is a number that a counting word follows (`2 other places`, `3 more settings`), and a list holds at most 20 numbers. In an enumeration each line goes with its own path: `config.py line 4, .env line 2` and `line 4 of config.py; line 2 of .env` are two locations, not `.env` at line 4.
  - A location must contain a line of a finding, or of reviewer evidence (the reviews' and the writer's own `challenges`), of that file; a range counts only when it ends at most `MAX_RANGE` (10) lines after it starts. A bare file name matches the same file under a directory (`conftest.py` for `tests/conftest.py`) and letter case is ignored (`scoring.same_file`).
  - A file name ends in one of a fixed list of extensions (`py`, `json`, `yml`, `env`, `key`, `rs`, `gitignore`, `mod`, `log` and the like) or is a known name without one (`Dockerfile`, `Makefile`, `id_rsa`, `.env`, with a suffix such as `Dockerfile.dev` or `.env.production`), so a host with a port, a version, a time and a call such as `requests.get` are no location. Absolute paths, URLs and files outside the lists are not read, so a finding added there goes unseen. At most 9 digits make a line, so a long run of digits is no location and cannot slow or break the scan.
  - An ID of the harness's shapes is a finding ID whose code is that of an examination ID the input holds (`SEC-9` beside `EX-SEC-v1`), `RV-<n>`, `RV-<n>-C<k>`, `EX-<code>-v<n>` or `DR-v<n>`, bracketed or not; one outside the input's IDs and the IDs of the challenges its examiners answered scores 0.0. `CWE-798` and `CVE-...` are not of those shapes. `guardrails.validate` also refuses a bracketed ID the input lacks (the answered challenges' IDs included), which scores the case run at its worst.
  - A new finding written with neither a location nor an ID, or in a form above that the lists miss, goes unseen; the reviewer's R4 case is the check on that. The scan is a heuristic, and the first paid run is its check against real prose.
- `high_severity_coverage`: the share of the input's critical and high findings that the draft cites in square brackets, by whole ID, in the section of their own step (the summary does not count, and an escalated step still owes its citations), 1.0 for none.
- `structure_valid_first_try`: 1.0 when the draft's sections follow the disposition's order, otherwise 0.0. Every other structural rule is `guardrails.validate`'s, and the harness sends each case once, so a draft it refuses scores every criterion at its worst. The guardrail does not check the order, the prompt asks for it.
- `tone_score`: the judge's score, from 1 to 5.

**The tone judge** (`evals/judges/tone.md`, `run.JUDGES`, `run.JUDGE_SCHEMA`). For each accepted draft, `_judge_tone` makes one `llm.call` (agent label `tone_judge`, workflow `final_review_writer`) with the prompt as the system text, `claude-sonnet-5-5` at effort `medium`, the draft as the only message (`executive_summary` and `sections`, no findings and no input) and `JUDGE_SCHEMA` as the output format: `{rationale, score}` with a whole `score` from 1 to 5, rationale first so the score follows the reasoning. The rationale is not kept. A failed call (`REFUSAL`, `MAX_TOKENS`, `API_ERROR`) or an answer that is not JSON or does not fit the schema (`SCHEMA_INVALID`) ends the case run with that code, like a `DispatchError`, and scores every criterion at its worst. The `error` code does not say whether the writer or the judge failed; the case run's audit log does, by the agent label of the `llm_call` lines. The judge's tokens and cost count in the case run's totals. The judge is the only non-deterministic score, and the prompt's hash is in the results.

**The coordinator set** (`evals/coordinator/`, `evals/scripted_dispatcher.py`). The real coordinator model runs `coordinator.run` against sub-agents that a script replaces. The dispatcher, its caps, challenge resolution and preconditions, the guardrails and the coordinator's prompt are the real ones, and no sub-agent makes a model call.
- `script.json` is `{id, description, workspace, files?, answers?, criteria}`. `workspace` is the repository name the coordinator is told. `files` maps relative paths to text and is written to a temporary directory for the case run, so that findings can cite lines of it; the directory is removed afterwards. A path outside it or under a skipped directory, two names for one file (letter case and Unicode form ignored), a name that cannot be written beside the others and text that cannot be encoded are refused, naming `files`. An answer is `{agent, step?, attempts: [{output, refused?}]}`: an examiner with one of its steps, the reviewer with the step of the examination it reviews (no step for the review of a draft), or the writer with no step, each once.
- The nth dispatch of an (agent, step) takes its nth attempt and the last attempt repeats. A dispatch the script does not list gets a clean examination, a `pass` review of its target, or a draft with one stock sentence per step. The scripted world does not change with what the coordinator does, so a coordinator that dispatches more than the scenario holds is answered with the last attempt again, and its extra launches show in the scores. The coordinator reads no draft prose (a draft comes back as its ID and section count), so the stock draft hides nothing from it.
- `output` is the body of the agent's answer without the fields the dispatch fixes: `workflow` and `step` of an examination and `target_id` of a review, which the dispatcher adds and the loader refuses to find stated. Every answer goes through `guardrails.validate` with the context its dispatch has and then through the runner's redaction (`runner._redacted`, as in `run_subagent`), so the coordinator gets the real finding IDs, a secret-like text as the harness would write it, and the real `DispatchError` for an attempt the guardrails refuse. An attempt marked `refused` names the code the guardrails must give it (K3's first attempt has no `summary` and is `SCHEMA_INVALID`); any other attempt must be accepted.
- Before any model call the loader runs that check in a workspace of the script's files. It pairs the reviews with the examinations in order: the nth review call takes the nth attempt, a call whose attempt is accepted moves on to the next examination and a refused one is retried on the same, and examination m holds the findings of the examiner's mth accepted attempt (a refused attempt is no examination); a last attempt that repeats is checked against every examination it will serve. A draft's review and the writer's draft are given no finding IDs to cite. This is how the coordinator meets them when it reviews each examination once and in order, and the run-time check is the same one against the real examination, so a coordinator that reviews out of order meets a real `EVIDENCE_INVALID`. A writer attempt cannot be marked `EVIDENCE_INVALID` at all: its input IDs are those of the examinations the coordinator names, which no script can know. The loader refuses, naming the file and the attempt: an answer the guardrails refuse unmarked or accept when marked, an `output` that states a field the dispatch fixes, a duplicate or unknown agent or step, an unknown `refused` code, a `files` entry that cannot be written, a case whose `id` is not its directory name, and a criterion the script cannot serve (`targeted_redispatch` needs a reviewer answer whose first attempt not marked `refused` blocks, `escalation_correct` the same of a review of a step, not of a draft, or an answer whose very first attempt is `refused`, since those are the ones a coordinator must meet). An attempt that no dispatch can reach, such as a review past the last examination an examiner will give, is not checked.
- The trace the scorers read is `{launches: [{tool, input, result}]}` from `run._Trace`: every `tool_use` block in order, with the result the next request carried, parsed, or null when none did (the turn limit stops a run before the launches of its last turn). A result is accepted when it holds an `examination_id`, a `review_id` or a `draft_id`. A halt of the coordinator ends the case run with its reason as `error`, and the trace is not scored.

The scenarios, all on the workspace `acme-shop`: K1 scripts nothing, so every step is clean, every review passes and nothing should be done twice. K2: the first secrets examination reports a hard-coded key on a line that reads the environment, the reviewer blocks it, and the examination run again is clean and passes. K3: the first secrets examination is refused as `SCHEMA_INVALID` and the same launch sent again is clean. K4: the secrets examiner repeats a finding on a line that holds no credential and the reviewer repeats a blocking challenge, so the step is never resolved. K5: every examination is clean, and the reviewer blocks the first draft for a finding no examination holds and passes the second. Every case lists `review_coverage`; `no_unneeded_redispatch` is K1's alone, `targeted_redispatch` is K2's, K4's and K5's, and `escalation_correct` is K3's and K4's.

**Coordinator scoring** (`scoring.py`, deterministic; a launch is the reviewer's or the writer's when its tool is `launch_adversarial_reviewer` or `launch_final_review_writer`, and an examiner's when its tool is `launch_security_examiner` or `launch_dependency_examiner` and its input has a `step`).
- `review_coverage`: 1.0 when no launch was refused with `PRECONDITION_FAILED` (a run that went on to recover still scores 0.0), a draft was accepted, and the latest accepted draft and the latest accepted examination of each examined step each have an accepted review, otherwise 0.0. The plan's gloss is "no `PRECONDITION_FAILED`"; alone it would give 1.0 to a coordinator that launches nothing.
- `targeted_redispatch`: a re-dispatch is a launch of an examiner tool that examines a step again, or of the writer that writes again, after one was accepted; a launch of any other tool is none, however it is spelled. It is targeted when its `challenge_ids` are not empty, each is a challenge that an accepted review made to an examination of that step (or to a draft), and at least one is a challenge of the latest review of the latest examination (or draft), so that the standing challenges of earlier rounds may be passed together but stale ones alone are untargeted. The harness refuses a stray ID itself, and the scorer counts such a launch, refused or not, as an untargeted re-dispatch. Per step, and for the draft, the denominator is the larger of the re-dispatches made and those owed, one for each whose first accepted review blocks it, and the score is the sum of the targeted over the sum of those: a coordinator that escalates a blocked step without examining it again scores 0 on it, however well it handled another step, and a second block owes nothing more. 1.0 when none is made or owed.
- `no_unneeded_redispatch`: 1 less the share of launches that repeated finished work, 1.0 for no launch. A launch repeats finished work when it examines a step or writes a draft again after the latest one's review passed, or reviews a target that already has an accepted review, refused or not. A launch sent again after an error, and an examination after a `block` or a `challenge`, do not. K1 takes 10 launches, so a repeated examination with its review scores 0.917, and up to three of them still pass 0.80 (0.8125; four score 0.778).
- `escalation_correct`: the share met of the obligations the trace creates, 1.0 for none. A launch refused with a retryable error is owed the same launch later (the same tool and the same `step` or `target_id`). In the disposition of the latest accepted draft, a step whose named examination's latest review blocks it must be escalated, and one whose review passes it must not be (a step that was only challenged is free either way); the examination is the one the disposition names for the step, or the step's latest when there is no draft. Only obligations that can be violated count, because accepted passing steps would otherwise dilute K4's one escalation: a coordinator that accepted the blocked step would score 0.875 over K3 and K4 and pass 0.80. A launch refused with a retryable error is owed its resend even when it was the step's last permitted dispatch, which the prompt tells the coordinator not to resend; the scorer does not know the cap, and no shipped script reaches it.
- Each criterion is the mean of per-case scores, so `review_coverage` (five cases), `targeted_redispatch` (three) and `escalation_correct` (two) fail on one miss, and only `no_unneeded_redispatch` (K1 alone) has any margin.

## Configuration

| Key | Where | Default | Status |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | environment | the SDK credential chain (API key, auth token or credentials provider) | built |
| `ASSESSOR_RUNS_DIR` | environment | `runs`, relative to the working directory; an empty value counts as unset. `assess run` refuses a directory input that is the runs directory or one of its ancestors, compared by file identity | built |
| `ASSESSOR_OSV_REPLAY` | environment, read by `config.osv_replay()` | unset, meaning live OSV; an empty value counts as unset; `assess run` only, the evals use their own replay and ignore it | built |
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
| OSV transport | Live POST at runtime; replay from `ASSESSOR_OSV_REPLAY` when set in `assess run`, and the evals give the runner their own replay as the transport | Reproducible evals | Live OSV in evals (results drift as advisories change) |
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
| Eval case-run failure | A `DispatchError` ends its case run, which scores every criterion it lists at its worst, records the code and lets the harness go on | A rejected output must neither stop a paid run nor count as a pass, and 0.0 alone would pass an `at_most` criterion | Stopping the run; scoring the failed run on no findings (a clean case would pass) |
| Eval means | `per_run_mean` is rounded to 6 places and the pass check uses the rounded value | The stored number reproduces its own verdict: the mean of 0.1, 0.2 and 0.3 is 0.19999999999999998 and would miss a threshold of 0.2 | Comparing the unrounded mean |
| Eval ground truth | The loader checks that each expected line exists and holds the case's `contains` text, before any model call | A wrong line number would fail every run and spend credit to show it | Checking only in tests |
| Eval fixture secrets | S1 uses AWS's documented example key pair. The S2 and S5 passwords, and the token, password and signing key of the reviewer fixtures R1, R2, R4 and R5, are invented values that match no provider format, and S2's PEM body decodes to a harmless sentence. `tests/test_eval_scoring.py` scans every fixture for provider token formats, an AWS secret key and a PEM body that is not that sentence, and scans the dependency fixtures and the OSV replay for the same and for personal email addresses and the reviewer and writer fixtures for the same credential formats | Secret scanners and push protection must not see a live credential. The plan asks for "obviously fake values", but the examiner checklist skips an obvious placeholder, so an obviously fake S2 or S5 password would measure nothing, and a reviewer that took the R2 password for a placeholder would downgrade a correct critical finding. Not proven offline: GitHub's generic-password, connection-string and private-key patterns may still block a push (the replay's advisory prose holds a placeholder URL with a user name and password, and commit hashes), and the word EXAMPLE in S1's key may lead an examiner to rate it low, so the first push and the first paid run are the checks | Real or revoked keys; obvious placeholders |
| Eval first try | Each case is sent once, with no retry on a `DispatchError` | The eval measures one dispatch of the agent; retrying is the coordinator's job, which its own evals measure | Retrying the retryable codes (it would hide how often the examiner needs one) |
| Eval aggregation | `per_run_mean` is the mean of per-case scores, so every case weighs the same (user decision) | One number per run for every criterion, as the plan's field name says | Pooling the seeded issues for recall and calibration (stricter: 5 of 7 issues is 0.714, not 0.833) |
| Eval thresholds | A threshold must be finite, within the range of a float, and not met by the criterion's worst score | A run that failed outright must never count as a pass, and a `NaN` would reach `results.json` as invalid JSON | Trusting the file |
| Eval imports | pytest sets `pythonpath = ["."]` so tests can import `evals`, which is not packaged | One line of config, and the harness runs from a checkout like the rest of the tool | Packaging `evals` in the wheel; a root `conftest.py` |
| Eval OSV answers | The executor passes the case's replay as the `osv` transport, wrapped so a PyPI name is normalised before the lookup, whenever the manifest declares `query_osv`, and a case without a replay fails with a `KeyError` | A fallback to `tools.execute` would read `ASSESSOR_OSV_REPLAY` or reach live OSV, and the scores would then depend on the environment or on today's advisories. The plan's D13 says the evals set the variable; passing the transport gives the same replay without the process environment. Live OSV matches PyPI names after normalising them, so without the wrapper a correct spelling such as `PyYAML` would fail only in the eval | Setting `ASSESSOR_OSV_REPLAY` for the process; letting a missing replay fall back to live OSV; changing `replay_osv` in `src/` |
| Eval vulnerable pins | D1 and D2 seed three vulnerable pins each, and D3 five hygiene issues, beyond the plan's single named package | The mean is over the cases that list a criterion, so with one seeded issue per case a threshold of 0.80 would pass only at 1.0 | One seed per case, as the plan names them |
| Eval advisory credit | A vulnerable pin counts as reported only when its finding cites an advisory recorded for its package version, and an alias counts as recorded | An examiner that never queries OSV would otherwise pass `vuln_recall` on the pin's line alone, and a CVE alias came back from `query_osv` so it is not fabricated | Location only; accepting IDs and no aliases |
| Eval unavailable OSV | D5's packages are simply absent from the replay. For a case that lists `limitations`, `clean_precision` demands that each is named as a whole word in a limitation and that the `known_vulnerabilities` examination holds no finding | `replay_osv` answers a missing key with an error result, which is what an unreachable OSV looks like to the agent, and D11 asks D5 to report a limitation, not vulnerabilities | A replay entry that raises a timeout (the replay has no such mechanism); failing only critical or high findings (a medium vulnerability invented from memory would pass); matching a name as a substring (`django-rest-framework` would satisfy `django`) |
| Eval reviewer trace | The reviewer's client is wrapped in `evals/run.py`; the wrapper records the `path` of each `read_file` tool_use block in the responses | `evidence_verified` needs the files the reviewer opened, the audit holds no tool inputs by invariant and `src/` is unchanged | Adding the path to the `tool_call` audit event (breaks the no-inputs invariant and the schema); having `run_subagent` return its trace (a public contract of `src/`); reading the final message list (assistant turns are SDK objects, tool results are dicts) |
| Eval fabricated evidence | R1's fabricated findings cite real files and lines that do not hold the quoted text | `guardrails.validate` refuses a missing file or line before a reviewer sees an examination, so the plan's "fabricated evidence" is a quote the line does not hold (an advisory ID with no basis, which the guardrail does not check either, is not seeded); the loader runs each target through `validate` so that no case can ask for a defect the harness would never show | A finding on a missing file or line (unrealistic) |
| Eval reviewer seeds | R1, R3 and R4 seed two defects each, beyond the plan's one | The mean is over the cases that list a criterion: with one defect per case, `defect_catch_rate` over three cases passes only at 1.0, as for the dependency set | One defect per case, as the plan names them |
| Eval tone judge | One `llm.call` per accepted draft, outside the manifests, on `claude-sonnet-5-5` at medium effort, with its prompt hash pinned in the writer's results | The plan keeps the writer's tone judge through the gateway with structured output; the judge is no agent, so it has no manifest, and its model and effort are eval tuning that stays in `evals/run.py` | A manifest for the judge; the judge's model in `config` |
| Eval judge failure | A failed or invalid judge call ends the case run with its code and scores every criterion at its worst | The case cannot be fully scored, and a partial score would let a flaky judge pass a case; `error` still tells such a run from a quality miss | Scoring only `tone_score` at its worst (keeps scores that the judge never saw) |
| Eval writer scores | `no_new_findings` adds a location check, and a check of unbracketed IDs, to the guardrail's rule for bracketed ones, and `structure_valid_first_try` adds the disposition's order | The guardrail already refuses an unknown bracketed ID and a malformed draft, so scores that only repeated it would be 1.0 for every accepted draft | Repeating the guardrail; matching file names anywhere in the prose (a recommendation may name `package-lock.json`) |
| Eval defect severity | A challenge catches a defect only when it is at least as serious as the defect's `severity`, the lowest at which a reviewer catches it | The reviewer prompt rates a fabricated or added finding critical and a severity misjudged by a level major, so a reviewer that sees the problem and calls it minor has not caught it, and without the floor `defects[].severity` would be a field nothing reads. The cost: a reviewer that rates R1's fabricated findings major misses on `defect_catch_rate` and on `critical_calibration` at once | Matching by finding or place only; reading what the challenge says (a wording nit of the right severity still counts) |
| Eval W5 | "Overruled challenge" is a reviewer's major challenge that the examiner rejected and the coordinator accepted past; W5 also hands the writer one challenge to its previous draft, so that the redraft path is exercised once | The plan names the scenario in four words; the writer's own `challenges` hold objections to its previous draft, which "overruled" does not describe, so W5 takes both readings. No criterion scores how the draft answers that challenge | Only the challenge to an earlier draft; no challenge at all |
| Eval coordinator seam | The coordinator's executor replaces `agents.runner.run_subagent` for the length of one case run (a module attribute swapped in a `try` and `finally`) and runs the real `coordinator.run` | `review_coverage` counts `PRECONDITION_FAILED`, which only the real dispatcher raises, and its caps, challenge resolution and ID assignment are what the coordinator reasons over. `src/` stays unchanged | Replacing the whole dispatcher (a second copy of its checks); a `run_subagent` parameter on `coordinator.run` (a change in `src/` for evals alone) |
| Eval coordinator scripts | A script lists answers for the dispatches it cares about, as attempts by agent and step; every other dispatch gets a clean examination, a passing review or a stock draft, and the last attempt repeats | Five short scripts, and a coordinator that dispatches more than the scenario holds still gets an answer, so its extra launches show in the scores | A full script per case (long, repeats itself); ending the case run on an unscripted dispatch (a paid run that crashes) |
| Eval coordinator validation | Every scripted answer goes through `guardrails.validate` with its dispatch's own context, then the runner's redaction, at run time; the loader runs the same check beforehand with each review paired to the examination it will most likely meet (a writer's `EVIDENCE_INVALID` cannot be scripted), and an attempt marked `refused` must be refused with that code | The coordinator sees real `DispatchError` shapes and text, and a typo in a script is caught before a paid run, except an out-of-order review, which meets the real check at run time | Hand-written error results (they can drift from the real shape); a loader context of every possible examination (it admits scripts the run refuses) |
| Eval coordinator trace | A client wrapper records each `tool_use` and the `tool_result` the next request carries; the scorers read only that | It is what the coordinator did and saw, refused launches and the exact `challenge_ids` it sent included, which `RunState` and the audit (no tool inputs, by invariant) do not keep | Reading `RunState` and the audit |
| Eval coordinator halt | A `COORDINATOR_*` halt ends the case run with its reason as `error` and scores every criterion at its worst | The case cannot be scored, as with a `DispatchError` | Scoring the partial trace |
| Eval coordinator scores | `review_coverage` also needs an accepted, reviewed draft; `escalation_correct` counts only obligations that can be violated; owed re-dispatches come from the first review of each step or draft | "No `PRECONDITION_FAILED`" alone passes a coordinator that does nothing, and counting every accepted step would let a coordinator that accepts a still-blocked step pass at 0.875 | The plan's one-line definitions |

## Open questions

None.
