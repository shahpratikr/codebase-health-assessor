# codebase-health-assessor

## Commands
- If `VIRTUAL_ENV` is set in the shell, prefix every poetry command with `env -u VIRTUAL_ENV`. With a stale `VIRTUAL_ENV`, poetry deletes the in-project `.venv` (`poetry.toml`).
- install: `poetry install`
- build: none; run from the checkout (docs/ARCHITECTURE.md, Repository structure)
- run: `poetry run assess --help`, `poetry run assess run <dir|zip>`, `poetry run assess decide <cid> ...` (arguments: docs/ARCHITECTURE.md, Interfaces)
- dependency change: `poetry add <pkg>` / `poetry remove <pkg>`
- lint / format / typecheck / coverage / generate: none configured
- test (all): `poetry run pytest`
- test (single file): `poetry run pytest tests/test_audit.py`
- test (single test): `poetry run pytest tests/test_audit.py::test_each_line_is_flushed_then_fsynced`
- evals (real API, spends credit): `poetry run python -m evals.run --agent <name>|all --runs N --note "<what changed>"`; writes `evals/results/<agent>.json` and appends a line for each agent that finishes to `evals/results/history.jsonl`
- bypass campaign (offline, no key, no cost): `poetry run python -m evals.punchout`; writes `evals/results/punchout/<YYYYMMDDTHHMMSSZ>-punchout.json`, exits 1 when a scenario did not hold
- package, in this order (README.md, ZIP packaging):
  1. `git log --stat --date=iso > git_log.txt && git archive --format=zip -o submission.zip HEAD && zip -u submission.zip git_log.txt`
  2. `poetry run python -m submission.build submission.zip`: writes `manifest.yaml` and `docs/iterations.md` into the ZIP; exits 1 listing every problem, 2 when the ZIP is unreadable or already holds either file
  3. `poetry run python -m submission.validate submission.zip`: exits 1 when an intake rule is violated
- slow: the whole suite takes about 110 s; run the single file for the code you change while iterating, and the full suite once at the end

## Testing
- pytest, `testpaths = ["tests"]`. Everything is an offline unit test: no network, no API key. Evals are separate from pytest and are the only real-API runs.
- Files: `tests/test_<module or area>.py` (`test_audit.py`, `test_llm.py`, `test_config.py`).
- Names: `test_<behaviour in words>`, e.g. `test_naive_clock_is_refused`. Never put a requirement or acceptance-criterion ID (`ac13`, `AC-13`) in a test name.
- SDK: use the `fake_anthropic` fixture (`FakeAnthropic` in `tests/conftest.py`).
  - Script responses, and exception instances rather than classes.
  - Assert on `.requests`, which holds deep copies. An unscripted request fails the test.
  - Assert at that boundary: never mock `httpx`/`httpx2` transports.
- The autouse `tmp_runs_dir` fixture points `ASSESSOR_RUNS_DIR` at `tmp_path`. Still pass `runs_dir=tmp_path` explicitly where the API takes it (`tests/test_audit.py:37`).
- Build objects with per-file private helpers (`_log` at `tests/test_audit.py:37`, `_message` and `_call` at `tests/test_llm.py:29` and `:103`), not shared fixtures.
- Time: pass a fixed clock (`clock=lambda: NOW`). Never sleep or read the wall clock.
- I/O failures: monkeypatch module attributes, e.g. `audit.os.fsync` or `audit.open`.
- Case tables use pytest's `parametrize` mark.
- Every static or structural check needs a planted-violation case that makes it fail. See the `src_copy` fixture and `test_detects_planted_violation` in `tests/test_no_cli_runtime.py:128` and `:207`.
- `tests/test_gitignore.py` and `tests/test_submission_build.py` shell out to `git` and are skipped when git is missing, and the build tests also when the checkout is no git work tree. The build tests archive what `git ls-files -co --exclude-standard` lists, with stubs in place of the evidence manual runs commit, so an untracked file that no `submission/rules.py` rule classifies fails them.
- Known baseline failures: none.

## Conventions
- Lines up to 120 characters; no formatter is configured (`src/assessor/llm.py:70`, `tests/conftest.py:8`).
- Docstrings are one-line contracts starting "Return …" that name what is raised, not a restatement of the body (`config.py:41`, `audit.py:30`, `llm.py:42`).
- Comments only for a non-obvious why (`config.py:12`, `llm.py:9`, `tests/conftest.py:39`).
- Types: `X | None` and `collections.abc` types (`config.py:5`, `audit.py:4`, `llm.py:2`).
- Constants and closed sets are UPPER_CASE tuples in `config.py`, referenced as `config.X` (`config.py:15`, `config.py:27`, `audit.py:47`). The submission tools keep their closed sets in `submission/rules.py`.
- Environment variables are read only in `config.py`, at call time (`config.runs_dir()`, `config.py:36`).
- Bad input raises `ValueError` with a message that names the source and the bad value (`config.py:52`, `audit.py:25`, `audit.py:48`).
- A typed error carries a `code` from a closed set in `config` and rejects unknown codes in `__init__` (`LLMError`, `llm.py:31`). `DispatchError` (`guardrails.py:53`) does the same with `config.DISPATCH_ERROR_CODES`, which includes `config.LLM_ERROR_CODES` (`config.py:30`, `:37`).
- Time sources are injected parameters that default to the real source (`clock=utc_now`, `audit.py:46`; `timer=time.perf_counter`, `llm.py:66`).
- Repo-level files resolve from `config.ROOT` constants, never from the working directory (`config.py:8-10`). Only the runs dir is relative to the working directory.
- New files go here:
  - code: `src/assessor/<module>.py`; tools under `src/assessor/tools/`; the sub-agent runner under `src/assessor/agents/`
  - JSON Schemas: `schemas/<contract>.schema.json`, Draft 2020-12, loaded through `config.SCHEMAS_DIR` (`audit.py:15`)
  - repo data files: `config/`
  - packaging tools: `submission/<tool>.py`, run as `python -m submission.<tool>`; a file the package line ships needs a rule in `submission/rules.py` `CLASSIFICATION`, or the build fails
  - agent data: `manifests/<agent>.json`, `prompts/<agent>.md`, `skills/<name>.md`, `evals/<agent>/cases/<case_id>/{case.json, repo/…}`

## Invariants
- **Imports.** A module imports only what its row in docs/ARCHITECTURE.md, Components, "Depends on" lists. In addition:
  - Nothing imports `cli`.
  - `cli` imports `llm` only for `make_client` and `NoCredentialsError`.
  - `tools` never import `llm`.
  - `assessor` never imports `evals`.
  - `submission` imports from `assessor` only `config` and the constant `manifest.COORDINATOR`, never `evals`; nothing imports `submission`.

  Enforced in part: only `llm.py` imports `anthropic` (`tests/test_no_cli_runtime.py::test_only_the_gateway_imports_anthropic`). The rest is not enforced.
- **No process spawning in `src/` or `submission/`:** no `subprocess`, `pty`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `os.posix_spawn*`, asyncio subprocesses or `claude_agent_sdk`. `tests/` and `evals/` may shell out. (`test_src_has_no_process_spawning`, `test_the_submission_tools_have_no_process_spawning`)
- **Every Messages API request goes through `llm.call`.**
  - It sends the fallback beta and `fallbacks` (`test_request_sends_default_fallbacks_and_beta`).
  - It never sends sampling parameters, `thinking` or a forced `tool_choice` (`test_gateway_has_no_parameter_for_banned_request_fields`, `test_request_has_only_gateway_keys`).
- **Every LLM call writes exactly one `llm_call` audit line, failed calls included** (`test_sdk_error_is_audited_then_raised_as_api_error`).
- **Audit lines are validated against `schemas/audit_event.schema.json` before they are written.**
  - A new event field needs a `$defs` payload in that schema first (`test_events_without_a_defined_payload_refuse_any_field`).
  - Lines never hold message content, prompts, tool inputs or headers. The schema's `additionalProperties: false` enforces this.
- **`audit.jsonl` is append-only, flushed and fsynced per line** (`test_each_line_is_flushed_then_fsynced`). Timestamps are timezone-aware UTC (`test_naive_clock_is_refused`).
- **A correlation ID that names a path must fullmatch `config.CORRELATION_ID`** (`test_malformed_correlation_id_is_refused`; argparse in `cli.py`).
- **Each closed set is defined once, in `config`** (the submission tools' in `submission/rules.py`). Enforced in part (`test_audit_events_are_the_planned_closed_set`, `test_llm_error_codes_are_the_closed_set`; `test_the_submission_maps_match_config_and_the_eval_runner` keeps the role map, the punch-out map and the agent names equal to `config.AGENT_ROLES`, `config.GATES` and `evals.run.AGENTS`).
- **`evals/results/history.jsonl` is append-only, and every line passes `schemas/eval_history.schema.json` before it is written** (`tests/test_eval_history.py`).
- **`manifest.yaml` is derived from the ZIP it goes into, never hand-written.** Its `agents:` come from the ZIP's `manifests/*.json` (`test_the_agents_section_matches_the_runtime_manifests`, `test_agents_and_steps_follow_the_zips_manifests_not_the_checkouts`).
- **No ZIP path is excluded silently:** the build fails on a file that no rule in `submission/rules.py` classifies (`test_every_unclassified_path_is_listed_and_fails_the_build`).
- **`submission.build` and `submission.validate` never extract a ZIP** (`test_the_builder_never_extracts`, `test_the_validator_never_extracts_and_writes_nothing`).
- **`config/pricing.json` matches Anthropic's live pricing page.** Change it and `test_shipped_pricing_has_the_verified_prices` together, only from that page.
- **The coordinator manifest holds only `launch_*` tools, each mapped to a sub-agent, and the loader fails closed** (`test_coordinator_holds_exactly_the_four_launch_tools`, `test_launch_tool_without_a_subagent_manifest_is_refused` in `tests/test_manifest.py`; `tests/test_coordinator_dispatch_only.py`). The harness dispatches only on a coordinator `tool_use`: not enforced by a dedicated test.
- **Every sub-agent invocation starts a new message list, and no message list is shared** (`test_each_invocation_starts_a_new_message_list`, `test_reviewer_request_never_holds_the_examiner_conversation` in `tests/test_isolation.py`).
- **Every sub-agent output passes `guardrails.validate()` and then `redact()` before it reaches the coordinator or disk** (`test_an_answer_that_fails_its_guardrail_is_rejected_and_audited`, `test_accepted_examination_is_numbered_and_redacted` in `tests/test_runner.py`; `test_rejected_output_is_never_stored` in `tests/test_coordinator.py`).
- **Conversations are append-only, and earlier messages are never edited** (`test_coordinator_messages_are_append_only`).
- **`decisions.jsonl` is append-only, and a run file that exists is never overwritten** (`test_a_decision_changes_only_the_decisions_file_and_appends_one_audit_line`, `tests/test_cli_run.py::test_a_run_file_that_already_exists_is_never_overwritten`).
- **`report.md` headings come only from `report.py`'s title map and the computed status** (`test_the_report_has_no_heading_but_the_fixed_ones`, `test_a_heading_status_ignores_what_the_prose_says`).
- **File tools never resolve a path outside the workspace root** (`test_resolve_refuses_parent_escapes`, `test_resolve_refuses_absolute_paths_even_inside_the_root` in `tests/test_sandbox.py`).
- **Every manifest model is a `config/pricing.json` key, and every file a manifest references exists** (`test_unpriced_model_is_refused` in `tests/test_manifest.py`; `test_a_missing_agent_file_raises_before_any_call` in `tests/test_runner.py`).
- **Every path in the README evidence map exists, the Stage 4 continuity row cites `evals/results/*.json`, and the Audit and Decisions rows cite `examples/sample-runs/*/*/audit.jsonl`** (`test_every_path_in_the_evidence_map_exists`, `test_the_stage_4_audit_and_decisions_rows_cite_the_recorded_evidence_globs`).
- **`docs/PRD.md` and `docs/ARCHITECTURE.md` name the tools and files `tests/test_docs_mention_tools.py` lists** (that test).

## Constraints
- Never commit `.env`, `runs/`, `evals/.runs/`, `dist/` or `submission.zip` (`.gitignore`; `tests/test_gitignore.py::test_generated_and_local_secret_paths_are_ignored`). Never commit `git_log.txt`, `docs/iterations.md` or `manifest.yaml` either: packaging writes them into the ZIP, and `submission.build` refuses a ZIP that already holds the last two.
- Never write a real credential anywhere. `ANTHROPIC_API_KEY` comes only from the environment. Fixture secrets use AWS's documented example keys (`AKIAIOSFODNN7EXAMPLE`) or obviously fake values.
- Never run `assess run` or the evals against the real API unless the user asks: each run spends API credit.
- Never hand-edit `poetry.lock`; change dependencies through poetry.
- Schemas sent as `output_config.format` use only `type`, `properties`, `required`, `enum`, `items` and `additionalProperties: false`, since any other keyword makes the API return 400. Ranges and lengths go in the `guardrails` semantic checks.
- A change that makes docs/PRD.md or docs/ARCHITECTURE.md wrong updates it in the same change.

## Project docs
- `docs/PRD.md`: what the project is, for whom, and its scope. Read it before planning a task.
- `docs/ARCHITECTURE.md`: how it is built. Read the section for the area you change:
  - `cli.py`, exit codes → Interfaces (`assess` command line), Key flows
  - `config.py`, env vars, caps, defaults → Configuration; Data and state (Closed sets, Identifiers)
  - `audit.py`, `schemas/audit_event.schema.json`, `config/pricing.json` → Data and state (Audit trail)
  - `llm.py` → Key flows (One model call), Interfaces (`llm.call`), Decisions
  - `manifests/`, `prompts/`, `skills/` → Components (Agents)
  - `coordinator.py`, `agents/runner.py`, `tools/`, `sandbox.py`, `guardrails.py` → Key flows (`assess run`), Interfaces (Coordinator tools, Output contracts)
  - `gates.py`, `report.py` → Key flows (`assess decide`), Interfaces (`report.md`, `decisions.jsonl` record), Data and state (Run directory)
  - `evals/` → Key flows (Eval run), Interfaces (Evals)
  - `submission/` → Key flows (Packaging), Interfaces (Submission tools), Data and state (Closed sets)
  - a dependency → Runtime and dependencies, Decisions
