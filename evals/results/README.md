# Eval results

The eval runner writes one file per LLM agent here: `coordinator.json`, `security_examiner.json`, `dependency_examiner.json`, `adversarial_reviewer.json` and `final_review_writer.json`. Each holds the scores of every case in every run, the model and effort, the prompt hash, tokens and cost, and per criterion whether it met its threshold in every run.

## Regenerating them

Run this from the repository root. It calls the Anthropic API, so it needs `ANTHROPIC_API_KEY` and spends credit.

```
poetry run python -m evals.run --agent all --runs 3
```

It exits 0 when every criterion met its threshold in all 3 runs, 1 when one missed or the run crashed (a crash writes no file for the agent it hit), and 2 on a usage error or an unusable eval set, manifest or credentials, before any model call. To run one agent again, pass its name in place of `all`. Commit a file only when every criterion of its agent met its threshold in all 3 runs. A file is replaced whole when its agent finishes, and the audit logs of the runs go under `evals/.runs/`, which git ignores.

A file holds scores, IDs and totals, never text an agent wrote. `docs/ARCHITECTURE.md`, Interfaces, Evals, describes its fields.
