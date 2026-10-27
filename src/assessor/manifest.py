import json
from collections.abc import Mapping
from pathlib import Path
from typing import NoReturn

import jsonschema

from assessor import config

COORDINATOR = "coordinator"
LAUNCH_PREFIX = "launch_"
_MANIFEST = jsonschema.Draft202012Validator(
    json.loads((config.SCHEMAS_DIR / "manifest.schema.json").read_text(encoding="utf-8"))
)
_SUBSTANCE = jsonschema.Draft202012Validator(
    json.loads((config.SCHEMAS_DIR / "substance.schema.json").read_text(encoding="utf-8"))
)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    # json keeps the last of two equal keys, so a second "tools" would silently replace the first.
    keys = [key for key, _ in pairs]
    if repeated := sorted({key for key in keys if keys.count(key) > 1}):
        raise ValueError(f"duplicate key {', '.join(repeated)}")
    return dict(pairs)


def _integers_only(text: str) -> NoReturn:
    # jsonschema counts 12.0 as an integer, so any decimal point or exponent, NaN and Infinity are refused at parse.
    raise ValueError(f"numbers must be written as integers, not {text}")


def _read(path: Path, validator: jsonschema.Draft202012Validator) -> dict:
    """Return the JSON in path once validator accepts it; raises ValueError naming path for bad JSON or a schema error.

    An unreadable file raises its own OSError.
    """
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_keys,
            parse_float=_integers_only,
            parse_constant=_integers_only,
        )
        invalid = jsonschema.exceptions.best_match(validator.iter_errors(data))
    except RecursionError as error:
        # Deep nesting overflows the stack in json.loads, or, when it parses, while jsonschema builds an error's repr.
        raise ValueError(f"{path}: nested too deeply") from error
    except ValueError as error:
        raise ValueError(f"{path}: {error}") from error
    if invalid is not None:
        where = "/".join(str(part) for part in invalid.absolute_path) or "the top level"
        raise ValueError(f"{path}: {invalid.message} at {where}")
    return data


def _manifest(path: Path) -> dict:
    manifest = _read(path, _MANIFEST)
    if manifest["name"] != path.stem:
        raise ValueError(f"{path}: name {manifest['name']!r} must match the file name {path.stem!r}")
    return manifest


def load_manifests(
    directory: Path = config.MANIFESTS_DIR, pricing: Mapping[str, Mapping[str, float]] | None = None
) -> dict[str, dict]:
    """Return the coordinator's manifest and that of each agent its launch_ tools start, keyed by agent name.

    Raises ValueError naming the file when a manifest breaks manifest.schema.json or a check below, or when pricing is
    malformed; an OSError reading coordinator.json, a sub-agent manifest that exists or the pricing file propagates.
    """
    priced = config.load_pricing() if pricing is None else config.check_pricing(pricing)
    source = directory / f"{COORDINATOR}.json"
    coordinator = _manifest(source)
    if coordinator["role"] != COORDINATOR:
        raise ValueError(f"{source}: role must be {COORDINATOR}, not {coordinator['role']}")
    manifests = {COORDINATOR: coordinator}
    for tool in coordinator["tools"]:
        path = directory / f"{tool.removeprefix(LAUNCH_PREFIX)}.json"
        try:
            agent = _manifest(path)
        except FileNotFoundError as error:
            raise ValueError(f"{source}: tool {tool} maps to no sub-agent manifest ({path.name} is missing)") from error
        if agent["role"] == COORDINATOR:
            raise ValueError(f"{source}: tool {tool} must launch a sub-agent, not a {COORDINATOR}")
        manifests[agent["name"]] = agent
    _check_roles(manifests, directory)
    _check_steps(manifests, directory)
    for name, manifest in manifests.items():
        if manifest["model"] not in priced:
            raise ValueError(f"{directory / f'{name}.json'}: model {manifest['model']} has no price")
    return manifests


def _named(manifests: Mapping[str, dict], *roles: str) -> list[str]:
    return [name for name, manifest in manifests.items() if manifest["role"] in roles]


def _check_roles(manifests: Mapping[str, dict], directory: Path) -> None:
    examiners, reviewers, writers = (_named(manifests, role) for role in ("examiner", "reviewer", "writer"))
    if not examiners or len(reviewers) != 1 or len(writers) != 1:
        raise ValueError(
            f"{directory / f'{COORDINATOR}.json'}: launch_ tools must start one or more examiners, exactly one "
            f"reviewer and exactly one writer, not examiners {examiners}, reviewers {reviewers}, writers {writers}"
        )
    # Every examination and every report draft must be reviewable, and the reviewer must not review itself.
    assignment, path = manifests[reviewers[0]]["assignment"], directory / f"{reviewers[0]}.json"
    if set(assignment) != {*examiners, *writers}:
        raise ValueError(
            f"{path}: assignment must be exactly {', '.join([*examiners, *writers])}, "
            f"not {', '.join(assignment) or 'none'}"
        )


def _check_steps(manifests: Mapping[str, dict], directory: Path) -> None:
    # Codes prefix examination and finding IDs (EX-SEC-v1, SEC-1), so one code must not name two steps.
    holders: dict[str, str] = {}
    for name in _named(manifests, "examiner"):
        path, seen = directory / f"{name}.json", set()
        for step in manifests[name]["steps"]:
            if step["name"] in seen:
                raise ValueError(f"{path}: step {step['name']} is declared twice")
            if step["code"] in holders:
                raise ValueError(f"{path}: step code {step['code']} is already used by {holders[step['code']]}")
            seen.add(step["name"])
            holders[step["code"]] = f"{name}.{step['name']}"


def load_substance(manifests: Mapping[str, dict], path: Path = config.SUBSTANCE_FILE) -> dict:
    """Return the substance file at path if it rates exactly the examiners and writer and lists the reviewer unrated.

    Raises ValueError naming path otherwise; a path that cannot be read raises its own OSError.
    """
    substance = _read(path, _SUBSTANCE)
    workflows, reviewers = _named(manifests, "examiner", "writer"), _named(manifests, "reviewer")
    if sorted(substance["ratings"]) != sorted(workflows):
        raise ValueError(
            f"{path}: ratings must cover exactly {', '.join(workflows)}, "
            f"not {', '.join(substance['ratings']) or 'none'}"
        )
    if sorted(substance["not_rated"]) != sorted(reviewers):
        raise ValueError(
            f"{path}: not_rated must list exactly {', '.join(reviewers)}, "
            f"not {', '.join(substance['not_rated']) or 'none'}"
        )
    return substance
