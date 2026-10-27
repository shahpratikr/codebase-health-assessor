import importlib
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNTIME = ["anthropic", "httpx", "jsonschema"]


def _normalized_name(requirement):
    return re.sub(r"[-_.]+", "-", re.match(r"[A-Za-z0-9_.-]+", requirement)[0]).lower()


def test_runtime_dependencies_are_declared_without_markers():
    requirements = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"].get("dependencies", [])
    unconditional = {_normalized_name(requirement) for requirement in requirements if ";" not in requirement}
    assert set(RUNTIME) <= unconditional


def test_runtime_dependencies_are_locked_in_the_main_group():
    locked = {package["name"]: package for package in tomllib.loads((ROOT / "poetry.lock").read_text())["package"]}
    assert {name: "main" in locked.get(name, {}).get("groups", []) for name in RUNTIME} == dict.fromkeys(RUNTIME, True)


@pytest.mark.parametrize("name", RUNTIME)
def test_runtime_dependency_imports_on_this_python(name):
    assert importlib.import_module(name).__name__ == name
