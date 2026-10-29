# Eval results

The eval runner writes one file per LLM agent here: `coordinator.json`, `security_examiner.json`, `dependency_examiner.json`, `adversarial_reviewer.json` and `final_review_writer.json`. Each holds the scores of every case in every run, the model and effort, the prompt hash, tokens and cost, and per criterion whether it met its threshold in every run.

`history.jsonl` keeps every execution. Each time the runner finishes an agent, it writes that agent's file and then appends one line for the agent here: the time, the runs, the model, effort and prompt, skills and judge hashes, each criterion's threshold, comparison, per-run means and whether it passed in every run, whether every criterion did, the cost, and the note given with `--note`. A line is added for every agent that finishes, failing executions included. A crash adds none for the agent it hit, and the lines of the agents that finished before it stay. Lines are only appended, never rewritten.

`punchout/` holds the bypass campaign's results, one `<YYYYMMDDTHHMMSSZ>-punchout.json` file per campaign run.

## Regenerating them

Run this from the repository root. It calls the Anthropic API, so it needs `ANTHROPIC_API_KEY` and spends credit.

```
poetry run python -m evals.run --agent all --runs 3 --note "Baseline before tuning"
```

It exits 0 when every criterion met its threshold in all 3 runs, 1 when one missed or the run crashed (a crash in an agent's run writes no file and no history line for it, and a failed history append leaves its file and adds no line), and 2 on a usage error or an unusable eval set, manifest or credentials, before any model call. A note that is longer than 500 characters once secrets in it are redacted, that holds a line break, or that cannot be written as UTF-8 is a usage error. To run one agent again, pass its name in place of `all`, and say in the note what changed. Commit a file only when every criterion of its agent met its threshold in all 3 runs, and commit `history.jsonl` with it each time. A file is replaced whole when its agent finishes, and the audit logs of the runs go under `evals/.runs/`, which git ignores.

## The bypass campaign

```
poetry run python -m evals.punchout
```

It makes no model call and needs no API key or network. It builds run directories in a temporary directory and tries, with scripted attempts against the real gate code, to get past each human checkpoint: 14 scenarios, P1 to P14. It writes `punchout/<YYYYMMDDTHHMMSSZ>-punchout.json` with each scenario's attempt, what was expected, what was observed and whether the checkpoint held, and exits 0 when every one held and 1 when one did not. When a file for the same second already exists, it exits 2 and leaves that file as it was.

The agent files and the history hold scores, IDs, hashes, totals and the maintainer's note, and a campaign file holds the outcome of each scenario; none holds text an agent wrote. `docs/ARCHITECTURE.md`, Interfaces, Evals, describes the fields.
