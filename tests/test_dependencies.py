import importlib
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNTIME = ["anthropic", "httpx2", "jsonschema"]


def _normalized_name(requirement):
    return re.sub(r"[-_.]+", "-", re.match(r"[A-Za-z0-9_.-]+", requirement)[0]).lower()


def test_runtime_dependencies_are_declared_without_markers():
    requirements = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"].get("dependencies", [])
    unconditional = {_normalized_name(requirement) for requirement in requirements if ";" not in requirement}
    assert set(RUNTIME) <= unconditional


def _httpx_references(pyproject, lock):
    """List where the httpx package is declared in pyproject text or locked in poetry.lock text."""
    requirements = tomllib.loads(pyproject)["project"].get("dependencies", [])
    locked = {package["name"] for package in tomllib.loads(lock).get("package", [])}
    declared = "httpx" in {_normalized_name(requirement) for requirement in requirements}
    return [where for where, found in (("pyproject.toml", declared), ("poetry.lock", "httpx" in locked)) if found]


def test_httpx_is_neither_declared_nor_locked():
    assert _httpx_references((ROOT / "pyproject.toml").read_text(), (ROOT / "poetry.lock").read_text()) == []


@pytest.mark.parametrize(
    ("pyproject", "lock", "expected"),
    [
        ('[project]\ndependencies = ["httpx (>=0.28.1)"]', "", ["pyproject.toml"]),
        ('[project]\ndependencies = ["HTTPX>=0.28"]', "", ["pyproject.toml"]),
        ('[project]\ndependencies = ["httpx2 (>=2.16.0)"]', '[[package]]\nname = "httpx"', ["poetry.lock"]),
        ('[project]\ndependencies = ["httpx2 (>=2.16.0)"]', '[[package]]\nname = "httpx2"', []),
    ],
)
def test_httpx_check_detects_a_planted_declaration_or_lock_entry(pyproject, lock, expected):
    assert _httpx_references(pyproject, lock) == expected


def test_runtime_dependencies_are_locked_in_the_main_group():
    locked = {package["name"]: package for package in tomllib.loads((ROOT / "poetry.lock").read_text())["package"]}
    assert {name: "main" in locked.get(name, {}).get("groups", []) for name in RUNTIME} == dict.fromkeys(RUNTIME, True)


@pytest.mark.parametrize("name", RUNTIME)
def test_runtime_dependency_imports_on_this_python(name):
    assert importlib.import_module(name).__name__ == name
