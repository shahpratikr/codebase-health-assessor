import os
import shutil
import subprocess
from pathlib import Path

import pytest

GITIGNORE = Path(__file__).parents[1] / ".gitignore"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(*args):
    # Inherited GIT_DIR or GIT_WORK_TREE would point these calls at another repository.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(["git", *args], env=env, capture_output=True, text=True, timeout=30)


def _scratch_repo(path):
    # No template means no info/exclude, so only the copied .gitignore decides.
    assert _git("init", "-q", "--template=", str(path)).returncode == 0
    shutil.copy(GITIGNORE, path / ".gitignore")
    return path


def _ignored(repo, path):
    result = _git("-C", str(repo), "-c", "core.excludesFile=/dev/null", "check-ignore", "-q", "--no-index", path)
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0


@pytest.fixture(scope="module")
def scratch_repo(tmp_path_factory):
    return _scratch_repo(tmp_path_factory.mktemp("repo"))


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "evals/.env",
        "evals/results/.env",
        "evals/security_examiner/.env",
        "evals/security_examiner/cases/.env",
        "evals/security_examiner/cases/S2/.env",
        "examples/.env",
        "examples/sample-runs/finalized/.env",
        "runs/20261027T101500Z-0a1b2c3d/audit.jsonl",
        "evals/.runs/security_examiner.json",
        "dist/codebase_health_assessor-0.1.0.tar.gz",
        "submission.zip",
        ".venv/bin/python",
        ".pytest_cache/README.md",
        "src/assessor/__pycache__/cli.cpython-314.pyc",
    ],
)
def test_generated_and_local_secret_paths_are_ignored(scratch_repo, path):
    assert _ignored(scratch_repo, path)


@pytest.mark.parametrize(
    "path",
    [
        "evals/security_examiner/cases/S2/repo/.env",
        "evals/security_examiner/cases/S2/repo/config/.env",
        "examples/sample-client-repo/.env",
        "examples/sample-client-repo/dist/app.js",
        "evals/results/security_examiner.json",
        "examples/sample-runs/finalized/20261027T101500Z-0a1b2c3d/audit.jsonl",
        "src/assessor/runs/__init__.py",
        "src/assessor/cli.py",
        "poetry.lock",
    ],
)
def test_fixture_and_source_paths_are_not_ignored(scratch_repo, path):
    assert not _ignored(scratch_repo, path)


def test_inherited_git_dir_does_not_redirect_the_check(tmp_path, monkeypatch):
    decoy = _scratch_repo(tmp_path / "decoy")
    (decoy / ".git" / "info").mkdir()
    (decoy / ".git" / "info" / "exclude").write_text("*.py\n")
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    repo = _scratch_repo(tmp_path / "repo")
    assert (repo / ".git").is_dir()
    assert not _ignored(repo, "src/assessor/cli.py")
