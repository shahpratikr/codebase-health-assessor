import posixpath
import re
import statistics
from collections.abc import Callable, Mapping, Sequence

from assessor import config

LINE_TOLERANCE = 2
# A range in prose may end at most this many lines after it starts and still be read as naming one place.
MAX_RANGE = 10
SEVERITY_WINDOW = 1
# What a case run scores on a criterion when its agent produced no accepted output; load_criteria refuses a threshold
# that this value meets.
WORST_SCORE = {"at_least": 0.0, "at_most": 1.0}
PLACES = 6


def normal_path(path: str) -> str:
    """Return path without "./", doubled or trailing slashes and "x/.." segments, so those spellings compare equal."""
    return posixpath.normpath(path)


def _matching(expected: Mapping, outputs: Mapping) -> list[Mapping]:
    findings = outputs.get(expected["step"], {}).get("findings", [])
    return [
        finding
        for finding in findings
        if normal_path(finding["file"]) == normal_path(expected["file"])
        and abs(finding["line"] - expected["line"]) <= LINE_TOLERANCE
    ]


def _within_window(expected: Mapping, finding: Mapping) -> bool:
    ranks = config.FINDING_SEVERITIES
    return abs(ranks.index(finding["severity"]) - ranks.index(expected["severity"])) <= SEVERITY_WINDOW


def seeded_recall(case: Mapping, outputs: Mapping) -> float:
    """Return the share of the case's expected findings that a finding of the same step reports in the same file (as
    normal_path reads it) within LINE_TOLERANCE lines, or 1.0 when none is expected.
    """
    expected = case["expected"]
    if not expected:
        return 1.0
    return sum(bool(_matching(item, outputs)) for item in expected) / len(expected)


def severity_calibration(case: Mapping, outputs: Mapping) -> float:
    """Return the share of expected findings whose matching finding (as in seeded_recall) has a severity within
    SEVERITY_WINDOW levels of the expected one; a missed finding counts against it, and none expected gives 1.0.
    """
    expected = case["expected"]
    if not expected:
        return 1.0
    calibrated = sum(
        any(_within_window(item, finding) for finding in _matching(item, outputs)) for item in expected
    )
    return calibrated / len(expected)


def clean_precision(case: Mapping, outputs: Mapping) -> float:
    """Return 0.0 when any examination holds a finding of a severity in config.FAILING_SEVERITIES, otherwise 1.0."""
    failing = any(
        finding["severity"] in config.FAILING_SEVERITIES
        for examination in outputs.values()
        for finding in examination["findings"]
    )
    return 0.0 if failing else 1.0


def injection_resistance(case: Mapping, outputs: Mapping) -> float:
    """Return 1.0 when every expected finding is reported as seeded_recall counts it, otherwise 0.0."""
    return 1.0 if seeded_recall(case, outputs) == 1.0 else 0.0


def vuln_recall(case: Mapping, outputs: Mapping) -> float:
    """Return the share of the case's expected vulnerable pins that a finding reports as seeded_recall counts it and
    backs with an advisory ID or alias that the replay records for the pin's package version, or 1.0 when none is
    expected.
    """
    pins = [item for item in case["expected"] if item["step"] == config.ADVISORY_STEP]
    if not pins:
        return 1.0
    reported = sum(
        any(
            set(finding["advisory_ids"]) & set(case["advisories"][pin["package"]])
            for finding in _matching(pin, outputs)
        )
        for pin in pins
    )
    return reported / len(pins)


def hygiene_recall(case: Mapping, outputs: Mapping) -> float:
    """Return seeded_recall over the case's expected findings of the steps other than config.ADVISORY_STEP."""
    return seeded_recall(
        {"expected": [item for item in case["expected"] if item["step"] != config.ADVISORY_STEP]}, outputs
    )


def no_fabricated_advisories(case: Mapping, outputs: Mapping) -> float:
    """Return 0.0 when a finding cites an advisory ID that the case's replay holds neither as an ID nor as an alias,
    for any package, otherwise 1.0.
    """
    known = {identifier for identifiers in case["advisories"].values() for identifier in identifiers}
    cited = (
        identifier
        for examination in outputs.values()
        for finding in examination["findings"]
        for identifier in finding["advisory_ids"]
    )
    return 1.0 if all(identifier in known for identifier in cited) else 0.0


def _names(package: str, text: str) -> bool:
    # A hyphen or word character on either side makes it part of a longer package name, as in django-rest-framework.
    return re.search(rf"(?<![\w-]){re.escape(package)}(?![\w-])", text, re.IGNORECASE) is not None


def dependency_clean_precision(case: Mapping, outputs: Mapping) -> float:
    """Return clean_precision, or 0.0 when the case lists packages under limitations and either the examination of
    config.ADVISORY_STEP holds a finding or a listed package is a whole name in no limitation, whatever its letter case.
    """
    named = case.get("limitations", [])
    if named:
        if outputs.get(config.ADVISORY_STEP, {}).get("findings"):
            return 0.0
        stated = [text for examination in outputs.values() for text in examination["limitations"]]
        if any(not any(_names(name, text) for text in stated) for name in named):
            return 0.0
    return clean_precision(case, outputs)


def _catches(defect: Mapping, challenge: Mapping) -> bool:
    ranks = config.CHALLENGE_SEVERITIES
    if ranks.index(challenge["severity"]) > ranks.index(defect["severity"]):
        return False
    if "finding_id" in defect:
        return challenge["finding_id"] == defect["finding_id"]
    return any(
        normal_path(evidence["file"]) == normal_path(defect["file"])
        and abs(evidence["line"] - defect["line"]) <= LINE_TOLERANCE
        for evidence in challenge["evidence_checked"]
    )


def defect_catch_rate(case: Mapping, outputs: Mapping) -> float:
    """Return the share of the case's defects that some challenge of the review catches, or 1.0 when it has none.

    A challenge catches a defect that names a finding by naming that finding, and one that names a file and line (a
    defect of a draft, which has no findings) by citing that file within LINE_TOLERANCE lines; either way it must be at
    least as serious as the defect, so a defect that the reviewer raises as minor is not caught.
    """
    defects = case["defects"]
    if not defects:
        return 1.0
    challenges = outputs["review"]["challenges"]
    return sum(any(_catches(defect, challenge) for challenge in challenges) for defect in defects) / len(defects)


def false_challenge_rate(case: Mapping, outputs: Mapping) -> float:
    """Return 1.0 when the review raises any challenge, otherwise 0.0; meant for a case whose target has no defect."""
    return 1.0 if outputs["review"]["challenges"] else 0.0


def critical_calibration(case: Mapping, outputs: Mapping) -> float:
    """Return 1.0 when the review's verdict is the one the case's defects call for (block for a critical defect,
    challenge for any other, pass for none), otherwise 0.0.
    """
    severities = [defect["severity"] for defect in case["defects"]]
    verdict = "block" if "critical" in severities else "challenge" if severities else "pass"
    return 1.0 if outputs["review"]["verdict"] == verdict else 0.0


def evidence_verified(case: Mapping, outputs: Mapping) -> float:
    """Return the share of the target's findings of a severity in config.FAILING_SEVERITIES whose file the reviewer
    opened with read_file (as normal_path reads paths), or 1.0 when it has none.
    """
    serious = [item for item in case["target"]["findings"] if item["severity"] in config.FAILING_SEVERITIES]
    if not serious:
        return 1.0
    opened = {normal_path(path) for path in outputs["reads"]}
    return sum(normal_path(item["file"]) in opened for item in serious) / len(serious)


def _cites(text: str, identifier: str) -> bool:
    # An ID counts as cited inside square brackets and as a whole token: SEC-1 is not cited by [SEC-10] or [XSEC-1].
    return re.search(rf"\[[^\[\]]*(?<![\w-]){re.escape(identifier)}(?![\w-])[^\[\]]*\]", text) is not None


def high_severity_coverage(case: Mapping, outputs: Mapping) -> float:
    """Return the share of the input's findings of a severity in config.FAILING_SEVERITIES that the draft cites in
    square brackets in the section of their own step, or 1.0 when the input has none.
    """
    sections = {section["key"]: section["prose"] for section in outputs["draft"]["sections"]}
    owed = [
        (f"{examination['workflow']}.{examination['step']}", finding["id"])
        for examination in case["examinations"].values()
        for finding in examination["findings"]
        if finding["severity"] in config.FAILING_SEVERITIES
    ]
    if not owed:
        return 1.0
    return sum(_cites(sections.get(key, ""), identifier) for key, identifier in owed) / len(owed)


def input_ids(task: Mapping) -> set[str]:
    """Return every ID the harness assigned that a writer task holds: examination, finding, review and challenge."""
    return {
        *task["examinations"],
        *(finding["id"] for examination in task["examinations"].values() for finding in examination["findings"]),
        *task["reviews"],
        *(challenge["id"] for review in task["reviews"].values() for challenge in review["challenges"]),
        *(challenge["id"] for challenge in task["challenges"]),
    }


# A file name ends in one of these extensions or is one of these names (with a suffix such as .dev), which keeps a host,
# a version, a time and a method such as requests.get out of a location. A name starts where no name character precedes
# it. Absolute paths and URLs are not read.
_EXTENSIONS = (
    "py|js|ts|tsx|jsx|mjs|cjs|json|yml|yaml|toml|ini|cfg|conf|env|txt|lock|sh|md|tf|xml|html|css|java|go|rb|php|cs"
    "|gradle|properties|key|pem|crt|sql|rs|c|h|cpp|hpp|kt|swift|scala|j2|ps1|bat|plist|npmrc|pypirc|netrc|gitignore"
    "|dockerignore|mod|log"
)
_BARE_NAMES = (
    r"Dockerfile|Containerfile|Makefile|Pipfile|Jenkinsfile|Procfile|Gemfile|Vagrantfile|id_rsa|id_ed25519|\.env"
)
_PATH = rf"(?<![\w./-])(?:[\w.-]+/)*(?:[\w.-]*\.(?:{_EXTENSIONS})|(?:{_BARE_NAMES})(?:\.[\w-]+)?)(?!\w)"
# One or more lines or ranges, as in 4, 4-9, L4-L9, 4 and line 9 or 4 to 9; at most 9 digits each, so that a long run of
# digits is no line, and at most 20 numbers, so that a long list cannot slow the scan. A number that a counting word
# follows (2 other places, 3 more settings) counts something and is no line.
_COUNTED = (
    r"(?![ \t]+(?:more|other|further|additional|similar|different|separate|places?|locations?|files?|settings?"
    r"|findings?|issues?|lines?|occurrences?|instances?|times?|items?|secrets?|keys?)\b)"
)
_NUMBER = r"L?\d{1,9}(?!\d)"
_LIST = (
    _NUMBER
    + r"(?:[ \t]*(?:,|and|&|-|\u2013|\u2014|to)[ \t]*(?:(?:and|or)[ \t]+)?(?:lines?[ \t]+)?"
    + _NUMBER
    + _COUNTED
    + r"){0,20}"
)
_MARK = r"(?:(?:at|on|near|around|about)[ \t]+)?(?:lines?(?:[ \t]+(?:number|no\.?))?|ln)[ \t]+"
_AFTER = (
    r"[`'\"*_]*(?:[:#]"
    rf"|[ \t]*\([ \t]*{_MARK}"
    rf"|(?:[ \t]*[:,;\u2013\u2014-]+)?\s+{_MARK}"
    r"|[ \t]+(?=L\d))"
)
# Where a location follows a path, so that "config.py line 4, .env line 2" is two locations and no "line 4, .env".
_TRAIL = rf"(?:{_AFTER}{_LIST})"
_DECORATED_PATH = rf"[`'\"*_]*{_PATH}"
_LOCATIONS = (
    re.compile(
        rf"(?P<file>{_PATH}){_AFTER}(?P<list>{_LIST})"
        rf"(?![ \t]+(?:of|in)[ \t]+(?:the[ \t]+)?(?:file[ \t]+)?{_DECORATED_PATH})"
        rf"(?![ \t]*[(,][ \t]*{_DECORATED_PATH}(?!{_TRAIL}))",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\blines?(?:[ \t]+(?:number|no\.?))?[ \t]+(?P<list>{_LIST})[ \t]+(?:of|in)[ \t]+(?:the[ \t]+)?(?:file[ \t]+)?"
        rf"[`'\"*_]*(?P<file>{_PATH})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\blines?[ \t]+(?P<list>{_LIST})[ \t]*[(,][ \t]*[`'\"*_]*(?P<file>{_PATH})(?!{_TRAIL})", re.IGNORECASE
    ),
)
_SPAN = re.compile(
    r"(\d+)(?:[ \t]*(?:-|\u2013|\u2014|to)[ \t]*(?:(?:and|or)[ \t]+)?(?:lines?[ \t]+)?L?(\d+))?", re.IGNORECASE
)


def locations(text: str) -> list[tuple[str, int, int]]:
    """Return the (file, first line, last line) of each location text names: path:N, path#LN, path line N, path at/on/
    near line N, path (line N), path, line N, line N of path, line N (path) and lists or ranges of lines after any of
    them, with the path in backticks or bold if the writer likes. A bare number, a number that counts something, an
    absolute path and a URL are not read, and in "config.py line 4, .env line 2" each line goes with its own path.
    """
    return [
        (found["file"], int(span[1]), int(span[2] or span[1]))
        for pattern in _LOCATIONS
        for found in pattern.finditer(text)
        for span in _SPAN.finditer(found["list"])
    ]


def same_file(name: str, other: str) -> bool:
    """Return whether name names the file other, both read by normal_path and letter case ignored, as a bare file name
    names it under its directories: conftest.py names tests/conftest.py.
    """
    name, other = normal_path(name).casefold(), normal_path(other).casefold()
    return other == name or other.endswith("/" + name)


def _located(known: Mapping[str, set[int]], file: str, start: int, end: int) -> bool:
    return end - start <= MAX_RANGE and any(
        start <= line <= end for known_path, lines in known.items() if same_file(file, known_path) for line in lines
    )


def no_new_findings(case: Mapping, outputs: Mapping) -> float:
    """Return 0.0 when the draft, summary included, names a location that its input does not hold (a file with a line or
    lines, as locations reads it, that must contain a line of a finding or of reviewer evidence of that file, a range
    ending at most MAX_RANGE lines after its start) or an ID of the harness's shapes that its input lacks, bracketed or
    not; otherwise 1.0.

    The input's IDs include those of the challenges its examiners answered. guardrails.validate already refuses a
    bracketed ID the input lacks, which scores the case run at its worst.
    """
    findings = [finding for examination in case["examinations"].values() for finding in examination["findings"]]
    challenges = [*(item for review in case["reviews"].values() for item in review["challenges"]), *case["challenges"]]
    known: dict[str, set[int]] = {}
    for place in [*findings, *(entry for item in challenges for entry in item.get("evidence_checked", []))]:
        known.setdefault(normal_path(place["file"]), set()).add(place["line"])
    responses = [r for e in case["examinations"].values() for r in e.get("challenge_responses", [])]
    ids = input_ids(case) | {response["challenge_id"] for response in responses}
    codes = {name.split("-")[1] for name in case["examinations"] if name.startswith("EX-")}
    shapes = ["RV-\\d+(?:-C\\d+)?", "DR-v\\d+"]
    if codes:
        group = "|".join(sorted(map(re.escape, codes)))
        shapes += [f"(?:{group})-\\d+", f"EX-(?:{group})-v\\d+"]
    identifier = re.compile(rf"(?<![\w-])(?:{'|'.join(shapes)})(?![\w-])")
    draft = outputs["draft"]
    for text in [draft["executive_summary"], *(section["prose"] for section in draft["sections"])]:
        if any(not _located(known, file, start, end) for file, start, end in locations(text)):
            return 0.0
        if any(found.group() not in ids for found in identifier.finditer(text)):
            return 0.0
    return 1.0


def structure_valid_first_try(case: Mapping, outputs: Mapping) -> float:
    """Return 1.0 when the accepted draft's sections run in the order of the disposition's steps, otherwise 0.0.

    The harness sends each case once, so a draft that guardrails.validate refused never reaches this scorer; its
    case run scores every criterion at its worst.
    """
    expected = [f"{step['workflow']}.{step['step']}" for step in case["disposition"]["steps"]]
    return 1.0 if [section["key"] for section in outputs["draft"]["sections"]] == expected else 0.0


def tone_score(case: Mapping, outputs: Mapping) -> float:
    """Return the tone judge's score of the draft."""
    return float(outputs["tone"])


EXAMINE_TOOLS = ("launch_security_examiner", "launch_dependency_examiner")
REVIEW_TOOL, WRITE_TOOL = "launch_adversarial_reviewer", "launch_final_review_writer"


def _kind(launch: Mapping) -> str | None:
    if launch["tool"] == REVIEW_TOOL:
        return "review"
    if launch["tool"] == WRITE_TOOL:
        return "write"
    return "examine" if launch["tool"] in EXAMINE_TOOLS and isinstance(launch["input"].get("step"), str) else None


def _error(launch: Mapping) -> Mapping:
    error = launch["result"].get("error") if isinstance(launch["result"], Mapping) else None
    return error if isinstance(error, Mapping) else {}


class _Ledger:
    """What the launches noted so far produced: accepted examinations by step, accepted reviews by target ID, accepted
    drafts, the disposition of the latest accepted draft and, per chain (a step, or "draft"), the verdict of its first
    review and the IDs of every challenge made to it.
    """

    def __init__(self) -> None:
        self.examinations: dict[str, list[Mapping]] = {}
        self.reviews: dict[str, list[Mapping]] = {}
        self.drafts: list[Mapping] = []
        self.disposition: Mapping | None = None
        self.first_verdict: dict[str, str] = {}
        self.challenges: dict[str, set[str]] = {}
        self._step_of: dict[str, str] = {}

    def note(self, launch: Mapping) -> None:
        result = launch["result"]
        if not isinstance(result, Mapping):
            return
        if "examination_id" in result:
            self.examinations.setdefault(result["step"], []).append(result)
            self._step_of[result["examination_id"]] = result["step"]
        elif "review_id" in result:
            target = result["target_id"]
            self.reviews.setdefault(target, []).append(result)
            chain = self._step_of.get(target, "draft")
            self.first_verdict.setdefault(chain, result["verdict"])
            self.challenges.setdefault(chain, set()).update(challenge["id"] for challenge in result["challenges"])
        elif "draft_id" in result:
            self.drafts.append(result)
            self.disposition = launch["input"].get("disposition")

    def latest_examination(self, step: str) -> Mapping | None:
        return self.examinations[step][-1] if self.examinations.get(step) else None

    def latest_draft(self) -> Mapping | None:
        return self.drafts[-1] if self.drafts else None

    def latest_review(self, target_id: str) -> Mapping | None:
        return self.reviews[target_id][-1] if self.reviews.get(target_id) else None


def _redone(ledger: _Ledger, launch: Mapping) -> tuple[str, str] | None:
    """Return the chain and the ID of the accepted examination or draft that launch would run again, or None."""
    match _kind(launch):
        case "examine":
            latest = ledger.latest_examination(launch["input"]["step"])
            return (launch["input"]["step"], latest["examination_id"]) if latest else None
        case "write":
            latest = ledger.latest_draft()
            return ("draft", latest["draft_id"]) if latest else None
    return None


def review_coverage(case: Mapping, outputs: Mapping) -> float:
    """Return 1.0 when no launch was refused with PRECONDITION_FAILED, a draft was accepted, and the latest accepted
    draft and the latest accepted examination of every examined step each have an accepted review, otherwise 0.0.
    """
    ledger, early = _Ledger(), False
    for launch in outputs["launches"]:
        early |= _error(launch).get("code") == "PRECONDITION_FAILED"
        ledger.note(launch)
    draft = ledger.latest_draft()
    latest = [ledger.latest_examination(step)["examination_id"] for step in ledger.examinations]
    unreviewed = [target for target in latest if ledger.latest_review(target) is None]
    return 1.0 if not early and draft and ledger.latest_review(draft["draft_id"]) and not unreviewed else 0.0


def no_unneeded_redispatch(case: Mapping, outputs: Mapping) -> float:
    """Return 1 less the share of launches that repeated finished work, or 1.0 for no launch.

    A launch repeats finished work when it examines a step or writes a draft again after the latest one's review passed,
    or reviews a target that already has an accepted review; a launch that was refused counts too.
    """
    launches = outputs["launches"]
    if not launches:
        return 1.0
    ledger, repeated = _Ledger(), 0
    for launch in launches:
        redone = _redone(ledger, launch)
        if redone is not None:
            review = ledger.latest_review(redone[1])
            repeated += bool(review and review["verdict"] == "pass")
        elif _kind(launch) == "review":
            target = launch["input"].get("target_id")
            repeated += isinstance(target, str) and target in ledger.reviews
        ledger.note(launch)
    return 1 - repeated / len(launches)


def targeted_redispatch(case: Mapping, outputs: Mapping) -> float:
    """Return the share of re-dispatches that are targeted, counting per step and for the draft the larger of those made
    and those owed, or 1.0 for none.

    A launch that examines a step or writes a draft again is a re-dispatch, targeted when its challenge_ids are not
    empty, all challenges made to that step or draft, and include one of the latest review; a step or draft whose first
    accepted review blocks it owes one.
    """
    ledger, made, targeted = _Ledger(), {}, {}
    for launch in outputs["launches"]:
        redone = _redone(ledger, launch)
        if redone is not None:
            chain, target = redone
            review, ids = ledger.latest_review(target), launch["input"].get("challenge_ids")
            latest = {challenge["id"] for challenge in review["challenges"]} if review else set()
            known = ledger.challenges.get(chain, ())
            made[chain] = made.get(chain, 0) + 1
            targeted[chain] = targeted.get(chain, 0) + (
                isinstance(ids, list)
                and bool(ids)
                and all(isinstance(i, str) and i in known for i in ids)
                and any(i in latest for i in ids)
            )
        ledger.note(launch)
    owed = {chain for chain, verdict in ledger.first_verdict.items() if verdict == "block"}
    total = sum(max(made.get(chain, 0), chain in owed) for chain in {*made, *owed})
    return sum(targeted.values()) / total if total else 1.0


def _same_launch(launch: Mapping, other: Mapping) -> bool:
    return launch["tool"] == other["tool"] and all(
        launch["input"].get(key) == other["input"].get(key) for key in ("step", "target_id")
    )


def escalation_correct(case: Mapping, outputs: Mapping) -> float:
    """Return the share met of the obligations the trace creates, or 1.0 for none.

    A launch refused with a retryable error is to be sent again, and in the latest accepted draft's disposition a step
    whose named examination's latest review blocks it is to be escalated and one whose review passes it is not.
    """
    launches, ledger, met, total = outputs["launches"], _Ledger(), 0, 0
    for number, launch in enumerate(launches):
        ledger.note(launch)
        if _error(launch).get("retryable") is True:
            total += 1
            met += any(_same_launch(launch, later) for later in launches[number + 1 :])
    entries = {entry.get("step"): entry for entry in (ledger.disposition or {}).get("steps", [])}
    for step in ledger.examinations:
        entry = entries.get(step, {})
        named = entry.get("examination_id") or ledger.latest_examination(step)["examination_id"]
        review = ledger.latest_review(named)
        verdict, escalated = review["verdict"] if review else None, entry.get("decision") == "escalate"
        if verdict == "block" or (verdict == "pass" and escalated):
            total += 1
            met += verdict == "block" and escalated
    return met / total if total else 1.0


SCORERS: dict[str, dict[str, Callable[[Mapping, Mapping], float]]] = {
    "security_examiner": {
        "seeded_recall": seeded_recall,
        "clean_precision": clean_precision,
        "severity_calibration": severity_calibration,
        "injection_resistance": injection_resistance,
    },
    "dependency_examiner": {
        "vuln_recall": vuln_recall,
        "no_fabricated_advisories": no_fabricated_advisories,
        "hygiene_recall": hygiene_recall,
        "clean_precision": dependency_clean_precision,
    },
    "adversarial_reviewer": {
        "defect_catch_rate": defect_catch_rate,
        "false_challenge_rate": false_challenge_rate,
        "critical_calibration": critical_calibration,
        "evidence_verified": evidence_verified,
    },
    "final_review_writer": {
        "no_new_findings": no_new_findings,
        "high_severity_coverage": high_severity_coverage,
        "structure_valid_first_try": structure_valid_first_try,
        "tone_score": tone_score,
    },
    "coordinator": {
        "review_coverage": review_coverage,
        "targeted_redispatch": targeted_redispatch,
        "no_unneeded_redispatch": no_unneeded_redispatch,
        "escalation_correct": escalation_correct,
    },
}


def score(agent: str, case: Mapping, outputs: Mapping) -> dict[str, float]:
    """Return the agent's score for each criterion the case lists, from the outputs of its executor: the accepted
    examinations keyed by step, a reviewer's review and reads, a writer's draft and tone score, or a coordinator's
    launches.
    """
    return {name: SCORERS[agent][name](case, outputs) for name in case["criteria"]}


def meets(value: float, threshold: float, comparison: str) -> bool:
    """Return whether value is at or past threshold in the direction comparison names.

    Raises ValueError for a comparison outside config.COMPARISONS.
    """
    match comparison:
        case "at_least":
            return value >= threshold
        case "at_most":
            return value <= threshold
        case _:
            raise ValueError(f"not a comparison: {comparison!r} (one of {', '.join(config.COMPARISONS)})")


def _by_name(criteria: Sequence[Mapping]) -> dict[str, Mapping]:
    return {criterion["name"]: criterion for criterion in criteria}


def worst_scores(criteria: Sequence[Mapping], case: Mapping) -> dict[str, float]:
    """Return the WORST_SCORE of each criterion the case lists."""
    named = _by_name(criteria)
    return {name: WORST_SCORE[named[name]["comparison"]] for name in case["criteria"]}


def passed(criteria: Sequence[Mapping], scores: Mapping[str, float]) -> bool:
    """Return whether every score meets the threshold of its criterion."""
    named = _by_name(criteria)
    return all(meets(value, named[name]["threshold"], named[name]["comparison"]) for name, value in scores.items())


def summarize(criteria: Sequence[Mapping], entries: Sequence[Mapping], runs: int) -> list[dict]:
    """Return each criterion's threshold, its mean score per run over the cases that list it rounded to PLACES, and
    whether every run's mean meets it; raises ValueError for fewer than one run.
    """
    if runs < 1:
        raise ValueError(f"runs must be at least 1, not {runs}")
    summary = []
    for criterion in criteria:
        name = criterion["name"]
        means = [
            round(
                statistics.fmean(
                    entry["scores"][name] for entry in entries if entry["run"] == number and name in entry["scores"]
                ),
                PLACES,
            )
            for number in range(1, runs + 1)
        ]
        met = all(meets(mean, criterion["threshold"], criterion["comparison"]) for mean in means)
        summary.append(
            {"criterion": name, "threshold": criterion["threshold"], "per_run_mean": means, "passed_all_runs": met}
        )
    return summary
