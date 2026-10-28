# Sample runs

This folder is where the two recorded runs of `examples/sample-client-repo` go: `finalized/<correlation_id>/` and `elevated/<correlation_id>/`. Each is a copy of a `runs/<correlation_id>/` directory made by a real `assess run`, and the elevated one also holds its `decisions.jsonl`.

## Recording them

Run these from the repository root. They call the Anthropic API, so they need `ANTHROPIC_API_KEY` and spend credit.

1. Finalized run, with the shipped ratings:

   ```
   poetry run assess run examples/sample-client-repo
   ```

   Keep it when it prints `status: finalized`. A run that ends `pending_human` or `halted` is not the one to record: run it again.

2. Elevated run, with the toy ratings, which rate the final review writer toy:

   ```
   poetry run assess run examples/sample-client-repo --substance examples/substance-toy.json
   ```

   It prints `status: pending_human` and an `open_gates` line that starts with `SUBSTANCE_ELEVATION`, and it exits with code 3, which is normal for a run waiting for a human. Another gate can follow on that line when a review blocks or a step is escalated. A halted run is run again.

3. Decide the elevated run, with the correlation ID it printed in place of the example one:

   ```
   poetry run assess decide 20261028T101500Z-0a1b2c3d --decision continue --reviewer "Your Name" --note "Reviewed the open gate"
   ```

4. Copy each run directory, as the runs directory holds it, into its folder, then commit. Replace `<finalized-cid>` and `<elevated-cid>` with the correlation IDs that steps 1 and 2 printed:

   ```
   RUNS="${ASSESSOR_RUNS_DIR:-runs}"
   mkdir -p examples/sample-runs/finalized examples/sample-runs/elevated
   cp -R "$RUNS/<finalized-cid>" examples/sample-runs/finalized/
   cp -R "$RUNS/<elevated-cid>" examples/sample-runs/elevated/
   ```

   A directory input is read in place, so these run directories have no `workspace/` to leave out. `run.json` holds the absolute path of the input directory and `decisions.jsonl` holds your operating system user name, the reviewer name and the note you gave. All of these are part of the record, so check that you are willing to publish them before you commit.

`docs/ARCHITECTURE.md`, Data and state, lists what a run directory holds.

## What the sample client repo seeds

A run may report more than this table, which lists only what was planted.

| File | Seeded issue | Step that should find it |
|---|---|---|
| `config.py` | an AWS access key ID and secret key written in source (AWS's documented example values) | secrets |
| `app.py` | Flask debug mode on, bound to every interface | insecure_config |
| `app.py` | wildcard CORS with credentials allowed | insecure_config |
| `app.py` | TLS verification off on the payment call | insecure_config |
| `requirements.txt` | `requests==2.19.0`, which has published advisories | known_vulnerabilities |
| `package.json` | `lodash` `4.17.15`, which has published advisories | known_vulnerabilities |
| `requirements.txt` | `gunicorn` has no version | dependency_hygiene |
| `package.json` | `express` is `*` | dependency_hygiene |
| both manifests | no lockfile beside either | dependency_hygiene |
