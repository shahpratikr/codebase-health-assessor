import copy
import functools
import json
import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass

import jsonschema

from assessor import config
from assessor.sandbox import Workspace

# jsonschema counts 2.0 as an integer, but a line number must be a whole JSON number.
_Validator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator,
    type_checker=jsonschema.Draft202012Validator.TYPE_CHECKER.redefine(
        "integer", lambda _checker, instance: type(instance) is int
    ),
)
_VALIDATORS = {
    contract: _Validator(json.loads((config.SCHEMAS_DIR / f"{contract}.schema.json").read_text(encoding="utf-8")))
    for contract in config.CONTRACTS
}
# Every ID-shaped token in a bracket is a cited ID, so a made-up ID cannot hide beside a real one or behind a hyphen;
# an ID is the longest letter-led run of parts ending in one that holds a digit (SEC-1, RV-2-C1, not [x-ray]).
_BRACKETS = re.compile(r"\[([^\[\]]*)\]")
_TOKEN = re.compile(r"[A-Za-z0-9-]+")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-[A-Za-z]*[0-9][A-Za-z0-9]*")
# A line renders as a heading when it starts with # or is a setext underline, also inside a quote or list item, or
# when it holds an HTML heading tag.
_HEADING = re.compile(r"(?:>\s*|[-*+]\s+|\d{1,9}[.)]\s+)*(?:#|[=-]+\s*$)|.*<h[1-6](?:[\s/>]|$)", re.IGNORECASE)
_MARKER = re.compile(rf"<redacted:[^\n]{{0,{config.REDACT_KEEP_CHARS}}}…>")
_ALPHANUMERIC = re.compile(r"[^\W_]")
_IDENTIFIER = re.compile(r"[A-Za-z_][\w.]*")
_CALL_START = re.compile(r"[A-Za-z_][\w.]*[(\[]")
_BRACKET_NEXT = re.compile(r"[ \t]*[(\[]")
# A name is tried only where it starts and is then taken whole, never backtracked into, so the scan stays linear
# however long or repetitive the name is.
_NAME = r"(?<![\w.-])(?=[\w.-]*?(?i:password|secret|token|api[_-]?key))[\w.-]++"
# Between a name and its operator may come the closing quote and bracket of a key ("password":, config["password"] =)
# or a type (password: str =, var password string =); possessive spaces keep a long run of them linear.
_GAP = r"\\?[\"']?\]?(?:(?:\s*+:[ \t]*+[\w.\[\]|&<>, ]{1,40}?|[ \t]++\w{1,40})(?=\s*=))?\s*+"
_ASSIGN = r"(?:=>|:=|=(?!=))[ \t]*+"
_QUOTE = r"(?P<quote>\\?[\"'])"
# A value does not start with a space, ), , or ;, so the closing quote of a prompt such as "Enter your password: " is
# not read as the opening quote of a value.
_QUOTED = r"(?P<secret>(?![\s),;])(?:(?!(?P=quote))(?:\\.|[^\\\n]))+)"
_LITERAL = re.compile(_QUOTE + r"(?P<secret>(?:(?!(?P=quote))(?:\\.|[^\\\n]))+)(?P=quote)")
_CALL_ASSIGNMENT = re.compile(_NAME + _GAP + _ASSIGN + r"(?P<callee>[A-Za-z_][\w.]*)?[ \t]*[(\[]")


class DispatchError(Exception):
    """A dispatch the coordinator gets back only as an error; code is one of config.DISPATCH_ERROR_CODES.

    Message and details can echo agent output, so they are redacted, made valid UTF-8 and cut to the caps in config.
    """

    def __init__(self, code: str, message: str, details: Iterable[str] = ()) -> None:
        if code not in config.DISPATCH_ERROR_CODES:
            raise ValueError(f"not a dispatch error code: {code}")
        self.code = code
        self.retryable = code in config.RETRYABLE_DISPATCH_ERRORS
        self.message = _clean(message)
        listed, cap = [_clean(detail) for detail in details], config.DISPATCH_ERROR_MAX_DETAILS
        if len(listed) > cap:
            listed = [*listed[: cap - 1], f"{len(listed) - cap + 1} more not shown"]
        self.details = listed
        super().__init__(f"{code}: {self.message}")

    def to_result(self) -> dict:
        """Return the {"error": {code, message, retryable, details}} object the coordinator receives."""
        error = {"code": self.code, "message": self.message, "retryable": self.retryable, "details": list(self.details)}
        return {"error": error}


def _clean(text: str) -> str:
    # A lone surrogate from the agent's JSON could not be encoded into the coordinator's next request.
    text = redact(text).encode("utf-8", "backslashreplace").decode("utf-8")
    cap = config.DISPATCH_ERROR_TEXT_MAX_CHARS
    return text if len(text) <= cap else text[: cap - 1] + "…"


@dataclass(frozen=True)
class ExaminationContext:
    """The step an examination was dispatched for, its ID code, and the workspace its findings cite."""

    workflow: str
    step: str
    code: str
    workspace: Workspace


@dataclass(frozen=True)
class ReviewContext:
    """The examination or draft a review was dispatched for, and the IDs of the findings it holds."""

    target_id: str
    finding_ids: Collection[str]


@dataclass(frozen=True)
class WriterContext:
    """The run's (workflow, step) pairs, each owed one prose section, and every ID the writer's input holds."""

    steps: Sequence[tuple[str, str]]
    input_ids: Collection[str]


@dataclass(frozen=True)
class DispositionContext:
    """The run's (workflow, step) pairs, each examination's (workflow, step) by ID, and the IDs of reviewed ones."""

    steps: Sequence[tuple[str, str]]
    examinations: Mapping[str, Sequence[str]]
    reviewed: Collection[str]


def validate(contract: str, output: object, ctx: object) -> dict:
    """Return a copy of output that passed contract's schema and semantic checks, with finding IDs for an examination.

    Raises DispatchError (codes per check: docs/ARCHITECTURE.md, Output contracts), ValueError for a contract outside
    config.CONTRACTS and TypeError for a ctx that is not the contract's context class.
    """
    if contract not in config.CONTRACTS:
        raise ValueError(f"not a contract: {contract}")
    context, check = _CONTRACTS[contract]
    if not isinstance(ctx, context):
        raise TypeError(f"{contract} needs a {context.__name__}, not {type(ctx).__name__}")
    try:
        errors = _VALIDATORS[contract].iter_errors(output)
        problems = [f"{_where(error.absolute_path)}: {error.message}" for error in errors]
    except RecursionError:
        # A deeply nested value overflows the stack while jsonschema builds the error's repr.
        problems = ["the top level: nested too deeply"]
    _reject("SCHEMA_INVALID", f"{contract} does not match schemas/{contract}.schema.json", problems)
    return check(copy.deepcopy(output), ctx)


def _where(path: Iterable[object]) -> str:
    return "/".join(str(part) for part in path) or "the top level"


def _reject(code: str, message: str, problems: list[str]) -> None:
    if problems:
        raise DispatchError(code, message, problems)


def _examination(output: dict, ctx: ExaminationContext) -> dict:
    findings, problems = output["findings"], []
    if (output["workflow"], output["step"]) != (ctx.workflow, ctx.step):
        claimed = f"{output['workflow']}.{output['step']}"
        problems.append(f"step: {claimed} is not the dispatched {ctx.workflow}.{ctx.step}")
    if ctx.step != config.ADVISORY_STEP:
        problems += [
            f"findings/{index}/advisory_ids: only {config.ADVISORY_STEP} findings cite advisories"
            for index, finding in enumerate(findings)
            if finding["advisory_ids"]
        ]
    problems += [
        f"findings/{index}/{field}: empty"
        for index, finding in enumerate(findings)
        for field in ("title", "evidence", "recommendation")
        if not finding[field].strip()
    ]
    _reject("SCHEMA_INVALID", "examination does not fit its dispatch or leaves required text empty", problems)
    counts: dict[str, int | str] = {}
    problems = []
    for index, finding in enumerate(findings):
        path, line = finding["file"], finding["line"]
        if path not in counts:
            counts[path] = _line_count(ctx.workspace, path)
        if isinstance(count := counts[path], str):
            problems.append(f"findings/{index}/file: {count}")
        elif not 1 <= line <= count:
            problems.append(f"findings/{index}/line: {line} is not a line of {path} ({count} lines)")
    _reject("EVIDENCE_INVALID", "examination cites a file or line the workspace does not have", problems)
    output["findings"] = [{"id": f"{ctx.code}-{number}", **finding} for number, finding in enumerate(findings, 1)]
    return output


def _line_count(workspace: Workspace, path: str) -> int | str:
    """Return the number of lines read_file would page through for path, or the reason it cannot read path."""
    try:
        return len(workspace.read_lines(path))
    except ValueError as error:
        return str(error)
    except OSError as error:
        # The OSError text holds the absolute path, which would tell the agent where the workspace lives.
        return f"{path}: {error.strerror or type(error).__name__}"


def _review(output: dict, ctx: ReviewContext) -> dict:
    challenges, problems = output["challenges"], []
    if output["target_id"] != ctx.target_id:
        problems.append(f"target_id: {output['target_id']} is not the dispatched {ctx.target_id}")
    critical = sum(challenge["severity"] == "critical" for challenge in challenges)
    verdict = "block" if critical else "challenge" if challenges else "pass"
    if output["verdict"] != verdict:
        problems.append(
            f"verdict: {output['verdict']} does not match {len(challenges)} challenge(s), {critical} critical; "
            f"it must be {verdict}"
        )
    for index, challenge in enumerate(challenges):
        where = f"challenges/{index}"
        problems += [f"{where}/{field}: empty" for field in ("claim", "rationale") if not challenge[field].strip()]
        if not challenge["evidence_checked"]:
            problems.append(f"{where}/evidence_checked: empty; cite at least one file and line")
        for number, evidence in enumerate(challenge["evidence_checked"]):
            if not evidence["file"].strip():
                problems.append(f"{where}/evidence_checked/{number}/file: empty")
            if evidence["line"] < 1:
                problems.append(f"{where}/evidence_checked/{number}/line: {evidence['line']} is not a line")
    _reject("SCHEMA_INVALID", "review does not fit its target or its challenges", problems)
    problems = [
        f"challenges/{index}/finding_id: {challenge['finding_id']} is not a finding of {ctx.target_id}"
        for index, challenge in enumerate(challenges)
        if challenge["finding_id"] and challenge["finding_id"] not in ctx.finding_ids
    ]
    _reject("EVIDENCE_INVALID", "review challenges a finding its target does not have", problems)
    return output


def _writer_output(output: dict, ctx: WriterContext) -> dict:
    keys = [f"{workflow}.{step}" for workflow, step in ctx.steps]
    problems = _coverage("sections", keys, [section["key"] for section in output["sections"]])
    _reject("SCHEMA_INVALID", "writer output does not have one prose section per step", problems)
    prose = [("executive_summary", output["executive_summary"])]
    prose += [(f"sections/{index}/prose", section["prose"]) for index, section in enumerate(output["sections"])]
    problems = []
    for where, text in prose:
        if not text.strip():
            problems.append(f"{where}: empty")
        problems += [
            f"{where}: line {number} renders as a heading"
            for number, line in enumerate(text.splitlines(), 1)
            if _HEADING.match(line.lstrip())
        ]
    _reject("SCHEMA_INVALID", "writer output has empty prose or a line that renders as a heading", problems)
    problems = [
        f"{where}: cites {cited}, which is not in the input"
        for where, text in prose
        for cited in dict.fromkeys(_cited(text))
        if cited not in ctx.input_ids
    ]
    _reject("EVIDENCE_INVALID", "writer output cites an ID its input does not have", problems)
    return output


def _cited(text: str) -> list[str]:
    return [
        cited[0]
        for group in _BRACKETS.findall(text)
        for token in _TOKEN.findall(group)
        if (cited := _ID.match(token.strip("-")))
    ]


def _disposition(output: dict, ctx: DispositionContext) -> dict:
    entries = output["steps"]
    keys = [f"{workflow}.{step}" for workflow, step in ctx.steps]
    problems = _coverage("steps", keys, [f"{entry['workflow']}.{entry['step']}" for entry in entries])
    _reject("SCHEMA_INVALID", "disposition does not cover each step exactly once", problems)
    problems = [
        f"steps/{index}/examination_id: {entry['examination_id']} is not an examination of "
        f"{entry['workflow']}.{entry['step']}"
        for index, entry in enumerate(entries)
        if tuple(ctx.examinations.get(entry["examination_id"], ())) != (entry["workflow"], entry["step"])
    ]
    _reject("UNKNOWN_TARGET", "disposition names an examination that is not of its step", problems)
    problems = [
        f"steps/{index}/examination_id: {entry['examination_id']} has no review"
        for index, entry in enumerate(entries)
        if entry["examination_id"] not in ctx.reviewed
    ]
    _reject("PRECONDITION_FAILED", "disposition names an examination that has no review", problems)
    return output


def _coverage(where: str, expected: Sequence[str], given: Sequence[str]) -> list[str]:
    """Return a problem for each expected key that given lacks or repeats, and for each given key not expected."""
    counts = Counter(given)
    problems = [f"{where}: {key} is missing" for key in expected if key not in counts]
    for key, count in counts.items():
        if key not in expected:
            problems.append(f"{where}: {key} is not a step of this run")
        elif count > 1:
            problems.append(f"{where}: {key} appears {count} times")
    return problems


_CONTRACTS: dict[str, tuple[type, Callable[[dict, object], dict]]] = {
    "examination": (ExaminationContext, _examination),
    "review": (ReviewContext, _review),
    "writer_output": (WriterContext, _writer_output),
    "disposition": (DispositionContext, _disposition),
}


def _marker(secret: str) -> str:
    return f"<redacted:{secret[: min(config.REDACT_KEEP_CHARS, len(secret) // 2)]}…>"


def _mask(match: re.Match) -> str:
    """Return match with its secret group replaced by a marker, or unchanged when that group already is one."""
    secret, (start, end), offset = match["secret"], match.span("secret"), match.start()
    if _MARKER.fullmatch(secret):
        return match[0]
    return match[0][: start - offset] + _marker(secret) + match[0][end - offset :]


def _mask_token(match: re.Match) -> str:
    """Return match with its unquoted value masked, unless the value holds a marker, has no letter or digit, or is a
    call or subscript.
    """
    token = match["secret"]
    if "<redacted:" in token or not _ALPHANUMERIC.search(token) or _reference(token, match.string, match.end()):
        return match[0]
    return _mask(match)


def _reference(token: str, text: str, end: int) -> bool:
    """Return whether token, which ends at end in text, is a call or subscript rather than a value."""
    if _IDENTIFIER.fullmatch(token):
        return _BRACKET_NEXT.match(text, end) is not None
    if not _CALL_START.match(token):
        return False
    return (
        token.rstrip(",;")[-1:] in (")", "]")
        or token.count("(") > token.count(")")
        or token.count("[") > token.count("]")
    )


def _mask_calls(text: str) -> str:
    """Return text with every quoted literal inside a bracketed value assigned to a secret name masked, except a call's
    leading literal argument, the key or prompt it reads; the brackets may span lines.
    """
    pieces, kept, position = [], 0, 0
    while match := _CALL_ASSIGNMENT.search(text, position):
        index, depth, first = match.end(), 1, True
        while index < len(text) and depth:
            literal = _LITERAL.match(text, index) if text[index] in "\"'\\" else None
            if literal is None:
                depth += (text[index] in "([{") - (text[index] in ")]}")
                index += 1
                continue
            leading = first and match["callee"] is not None and not text[match.end() : literal.start()].strip()
            if not leading and not _MARKER.fullmatch(secret := literal["secret"]):
                pieces += [text[kept : literal.start("secret")], _marker(secret)]
                kept = literal.end("secret")
            index, first = literal.end(), False
        position = index
    return "".join(pieces) + text[kept:]


def _substitute(pattern: re.Pattern, replace: Callable[[re.Match], str]) -> Callable[[str], str]:
    return functools.partial(pattern.sub, replace)


_SCRUBS: tuple[Callable[[str], str], ...] = (
    # A PEM block runs to its END line or, when that is missing before the next BEGIN, over the base64 lines that
    # follow; stopping at the next BEGIN keeps many unterminated headers linear.
    _substitute(
        re.compile(
            r"(?P<secret>-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----(?:(?:(?!-----BEGIN ).)*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----|(?:(?:\s|\\[nr])*[A-Za-z0-9+/=]{16,})*))",
            re.DOTALL,
        ),
        _mask,
    ),
    # Assignments come before the token kinds, so a value is masked whole even when it starts with a token; a
    # triple-quoted value may span lines.
    _substitute(
        re.compile(
            _NAME + _GAP + r"(?:=>|==|:=|=|:)\s*(?P<quote>\"\"\"|''')(?P<secret>(?:(?!(?P=quote))(?:\\[\s\S]|[^\\]))+)"
        ),
        _mask,
    ),
    _substitute(re.compile(_NAME + _GAP + r"(?:=>|==|:=|=|:)\s*" + _QUOTE + _QUOTED), _mask),
    _mask_calls,
    _substitute(re.compile(_NAME + _GAP + _ASSIGN + r"(?P<secret>(?!\\?[\"'])\S++)"), _mask_token),
    # After a colon an unquoted value counts only as the last token on its line (YAML), so prose such as "Secrets: none
    # found" stays whole; the name must follow a space, quote or bracket, which keeps a token full of names linear.
    _substitute(
        re.compile(
            r"(?<![^\s\"'{\[(])" + _NAME + r"\\?[\"']?[ \t]*+:(?!=)[ \t]*+(?P<secret>(?!\\?[\"'])\S++)[ \t\r]*+$",
            re.MULTILINE,
        ),
        _mask_token,
    ),
    _substitute(re.compile(r"(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})"), _mask),
    _substitute(re.compile(r"(?<![A-Za-z0-9])(?P<secret>sk-[\w-]{20,})"), _mask),
    _substitute(re.compile(r"(?<![A-Za-z0-9])(?P<secret>gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{22,})"), _mask),
    # An AWS secret access key: 40 base64 characters mixing upper case, lower case and a digit or +, which rules out
    # git SHAs and 40-character paths.
    _substitute(
        re.compile(
            r"(?<![A-Za-z0-9/+])(?P<secret>(?=[A-Za-z0-9/+]{0,39}[A-Z])(?=[A-Za-z0-9/+]{0,39}[a-z])"
            r"(?=[A-Za-z0-9/+]{0,39}[0-9+])[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"
        ),
        _mask,
    ),
)


def redact(value: object) -> object:
    """Return a copy of value with each secret-like substring of every string in it replaced by <redacted:XXXX…>.

    XXXX is the secret's first config.REDACT_KEEP_CHARS characters, or its first half when that is fewer; dict keys,
    numbers, booleans and None stay as they are, and a tuple comes back as a list.
    """
    if isinstance(value, str):
        for scrub in _SCRUBS:
            value = scrub(value)
        return value
    if isinstance(value, Mapping):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value
