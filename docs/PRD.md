# codebase-health-assessor

codebase-health-assessor is a command-line tool that runs a technical due-diligence check on a client's code repository: exposed secrets, insecure configuration, known vulnerable dependencies and dependency hygiene. It is for consultants who do this assessment as billable work. It gives them a report in which every finding points at real code, every result has been checked by an independent reviewer, and any serious doubt the review leaves open waits for a person to decide. How it is built: see ARCHITECTURE.md.

## Problem and context

A health assessment of a client's repository is core consulting work: finding committed credentials, unsafe settings, vulnerable packages and unpinned dependencies, then writing them up. A language model can do much of the reading, but its output is only usable if it can be checked. A finding has to cite a file and line that exist. The model that produced a result cannot be the one that grades it. A section's PASS or FAIL has to follow from the findings, not from how a model phrased them. And where the review leaves a serious problem unresolved, a person decides, not the model.

Success for the operator is a report that meets all four of those conditions, with a record of what every model call did and cost, and a named person's decision on any run that needed one.

It is a standalone tool, run from a terminal against one repository at a time. It relies on two outside services: Anthropic's API for every model call, and OSV for dependency advisories.

## Users

| User | What they do with it |
|---|---|
| Operator | A consultant who runs an assessment on a client repository, reads the run's status and open gates, and takes the report from there. |
| Human reviewer | Reads a run that is waiting for a human and records continue or reject under their own name, with a note. |
| Maintainer | Tunes the agents' prompts and checklists, runs the eval suites against the real API with a note on what changed, keeps the measured results and their history with the code, runs the offline bypass campaign, and packages the repository for certification. |

The client who owns the repository is not a user: the tool only reads their code.

## What it does

The command line runs an assessment end to end and records a human decision on a run that waits for one. Running it spends API credit and needs credentials.

- Assesses a repository given as a directory, read in place, or as a zip archive, unpacked into the run's own workspace.
- Examines four steps in two workflows: secrets exposure and insecure configuration (security), known vulnerable dependencies and dependency hygiene (dependency).
- Backs every finding with a file and line that exist in the repository. Output that fails the tool's checks is rejected and never reaches the report.
- Has every examination, and every report draft, checked by an adversarial reviewer that sees only the output and what it was built from, never the conversation that produced it.
- Re-examines a challenged step with the reviewer's challenges passed on word for word.
- Writes a report with an executive summary, one section per step marked PASS or FAIL, and a review trail giving each step's examination, review verdict and coordinator decision. A section fails when its accepted examination has a critical or high finding. Headings and statuses are computed by the tool, never written by a model.
- Keeps the report's prose to the reviewed findings: the writer explains them and adds none of its own.
- Replaces secret values with a redacted marker in everything it writes or shows. A zip's extracted copy is the client's own files and is kept as sent.
- Holds a run for a human when, at the end, a critical challenge is still open, the coordinator escalated a step, or the substance ratings call for it. It never finalizes past an open gate.
- Records the human decision with the reviewer's name, the system user, a note and a fingerprint of the report it applies to, without changing the report or any earlier record.
- Keeps a per-run audit trail under one run ID: every model call with the model requested, the model that served it, tokens, cost and latency, plus every dispatch, tool call, rejection, gate and decision, with per-agent totals. It never records message content.

For the maintainer it also:
- Records each eval execution in an append-only history: one line for each agent that finishes, with its scores against each threshold, fingerprints of the prompts and checklists it ran with, its cost and a one-line note on what changed. A failing execution is recorded too, so each change to a prompt can be read next to its effect.
- Keeps committed measurements of each of its five agents with the code, from real eval runs against the API.
- Ships a sample client repository and two recorded runs of it: one that finalized, and one that waited for a human and was decided.
- Tests its own human checkpoints with an offline bypass campaign (`evals.punchout`): scripted attempts to get past each gate, or to record a decision the rules refuse, run against the real gate code with no model call, no API key and no cost. It fails when a checkpoint does not hold.
- Packages the repository for certification. A build step writes into the archive the submission manifest, derived from the archive's own files, and the iteration log, rendered from the eval history. It refuses to build while evidence the manifest would cite is missing or a file has no classification. A validation step checks the archive against the published intake rules, all violations at once, without unpacking it.

## What it does not do

- No web interface or HTTP API: it is command-line only.
- No CI integration.
- No package ecosystems other than PyPI and npm.
- No git history: it reads the working tree only, so a secret removed in a later commit is not found.
- Never writes to, fixes or runs the client's code.
- Is not the certification intake: the archive validation mirrors the intake rules as published, so a pass does not prove the submission will be accepted.
- No checks beyond the four steps. Licence audits, infrastructure-as-code review and similar assessments are out of scope.

## How it is used

1. The operator gets the client's repository as a directory or a zip archive and starts a run on it.
2. The tool examines each step, has each examination reviewed, re-examines steps whose challenges hold, and accepts or escalates each step.
3. The tool drafts the report, has the draft reviewed, and redrafts it if the review challenges it.
4. The tool prints the run ID, the run's status and any open gates.
5. A finalized run's report is ready. A halted run ends without a reviewed report, and its halt reason and audit trail show why.
6. For a run waiting for a human, the reviewer reads the report and its review trail, then records continue or reject with their name and a note. That settles the run's final status.

## Constraints and limitations

- Runs on macOS and Linux. Keep run records on a local disk: recording a decision relies on file locking that network filesystems do not guarantee.
- Needs an Anthropic API key and network access to Anthropic's API and to OSV. When OSV is unreachable, the dependency examiner reports that as a limitation instead of claiming vulnerabilities.
- A run sends the client's file contents, including any secrets in them, to Anthropic's API. Redaction covers only what the tool writes and shows, not what the model reads or a zip's extracted copy.
- Every run, and every eval run, spends API credit. Each call's cost is recorded. When a fallback model with no known price serves a call, its cost is recorded as unknown, so totals can be incomplete.
- Findings come from a language model. An examiner can miss an issue or misjudge its severity. The eval suites measure how often, and a PASS section is not proof the issue is absent.
- Some files are not read: binary files, files over the size cap (large dependency lockfiles among them), the git folder and installed-dependency folders. Archives over the entry or size cap are refused. Values: see ARCHITECTURE.md, Configuration.
- Every run is bounded: re-examinations per step, tool calls per agent and coordinator turns are capped. A run whose coordinator reaches its cap halts.
- A run can be decided only once, and a decision cannot be changed.

## Glossary

- **Run**: one assessment of one repository, from start to final status. Its run ID (correlation ID) ties together the run's outputs, audit trail and decision.
- **Step**: one check area of the assessment, reported as one section.
- **Workflow**: the steps one examiner owns, examined with only that workflow's tools.
- **Examiner**: the agent that examines one step of its workflow.
- **Examination**: an examiner's result for one step: findings, limitations and responses to challenges. A re-examination produces a new version.
- **Finding**: one issue, with a title, a severity (critical, high, medium or low), a file and line, evidence and a recommendation.
- **Adversarial reviewer**: the agent that checks an examination or a report draft in a fresh context.
- **Review**: the reviewer's verdict on one examination or draft, with its challenges. The verdict is pass (no challenges), challenge (challenges, none critical) or block (at least one critical challenge).
- **Challenge**: one objection in a review, giving the claim, the evidence checked and the rationale, with a lens (challenge, catch or detect) and a severity (critical, major or minor).
- **Coordinator**: the agent that decides which agent to dispatch next and whether to accept or escalate each step. It does no examination itself.
- **Disposition**: the coordinator's accept or escalate for each step, with its rationale.
- **Final review writer**: the agent that turns the accepted examinations and their reviews into the report's prose.
- **Draft**: one version of the writer's prose.
- **Gate**: a checkpoint, opened at the end of a run, that holds the run for a human decision.
- **Substance rating**: core, peripheral or toy, saying how much of the billable assessment work a workflow carries. The tool ships its own ratings and accepts a replacement ratings file for a run. The reviewer is not rated. The substance elevation gate opens when any workflow is rated toy or more than one is rated peripheral.
- **Status**: finalized, pending human or halted when a run ends. A decision on a pending run makes it finalized by human (continue) or rejected by human (reject).
- **Decision**: a human reviewer's continue or reject on a run that is pending human.
- **OSV**: Open Source Vulnerabilities, the public advisory database.
- **Eval suite**: a set of cases for one agent, scored against named criteria with pass thresholds.
- **Eval history**: the append-only record of eval executions, one line for each agent that finishes, with the maintainer's note.
- **Bypass campaign**: scripted attempts to get past the human checkpoints without a human decision, run offline against the real gate code.
- **Iteration log**: the eval history rendered as a table per agent, with the first and last execution's results side by side. It is written into the submission archive, not kept in the repository.
- **Submission manifest**: the table of contents at the root of the submission archive. It tells the certification intake what each file is: the coordinator, the agents and their tools, the workflows with each step's prompt, evals and logs, the punch-outs and their evidence, the adversarial review, the exported commit log and, with a reason each, the files not judged.

## Open questions

- What consent does a client need to give before their code is sent to Anthropic's API, and who confirms it for each engagement? Decides: the engagement lead or legal.
