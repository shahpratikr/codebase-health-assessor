import json

import pytest

from assessor import config, gates, guardrails, manifest, sandbox, tools
from assessor.tools import deps

EXAMPLES = config.ROOT / "examples"
SAMPLE = EXAMPLES / "sample-client-repo"
TOY = EXAMPLES / "substance-toy.json"
REPLAY = config.ROOT / "evals" / "dependency_examiner" / "osv_replay.json"
AWS_EXAMPLES = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
MANIFESTS = manifest.load_manifests()


def _toy_ratings():
    return manifest.load_substance(MANIFESTS, TOY)["ratings"]


def _lockfiles(names):
    return [name for name in names if (deps.dependency_file(name) or ("", ""))[1] == "lockfile"]


def _secret_like(text):
    # The documented AWS example values are the one secret-like text allowed; whatever redact still changes is not them.
    for example in AWS_EXAMPLES:
        text = text.replace(example, "")
    return guardrails.redact(text) != text


def _lines(name):
    return [line.strip() for line in (SAMPLE / name).read_text(encoding="utf-8").splitlines()]


def _ok(agent, tool, tool_input):
    result = tools.execute(MANIFESTS[agent], tool, tool_input, workspace=sandbox.Workspace(SAMPLE))
    assert not result.is_error, result.content
    return json.loads(result.content)


def test_the_toy_ratings_pass_the_substance_loader_and_rate_only_the_writer_toy():
    ratings = _toy_ratings()
    assert [workflow for workflow, entry in ratings.items() if entry["rating"] == "toy"] == ["final_review_writer"]


def test_the_toy_ratings_keep_the_shipped_examiner_ratings_and_the_reviewer_entry():
    shipped, toy = manifest.load_substance(MANIFESTS), manifest.load_substance(MANIFESTS, TOY)
    assert toy["not_rated"] == shipped["not_rated"]
    for examiner in ("security_examiner", "dependency_examiner"):
        assert toy["ratings"][examiner] == shipped["ratings"][examiner]


def test_the_toy_ratings_open_the_substance_elevation_naming_the_toy_workflow():
    opened = gates.open_gates(
        ratings=_toy_ratings(),
        disposition={"steps": []},
        verdicts={"DR-v1": "pass"},
        draft_id="DR-v1",
        latest=[],
    )
    assert opened == [{"gate": "SUBSTANCE_ELEVATION", "subjects": ["final_review_writer"]}]


def test_the_sample_client_repo_is_a_directory_the_run_command_accepts():
    sandbox.check_input(SAMPLE)


def test_the_examiner_tools_list_every_sample_file_and_both_dependency_manifests():
    listed = _ok("security_examiner", "list_files", {"directory": "."})
    assert sorted(listed["files"]) == ["README.md", "app.py", "config.py", "package.json", "requirements.txt"]
    assert (listed["truncated"], listed["unreadable"]) == (False, [])
    found = _ok("dependency_examiner", "list_manifests", {})["manifests"]
    assert sorted((entry["path"], entry["ecosystem"], entry["kind"]) for entry in found) == [
        ("package.json", "npm", "manifest"),
        ("requirements.txt", "PyPI", "manifest"),
    ]


@pytest.mark.parametrize(
    ("name", "line"),
    [
        pytest.param("config.py", f'AWS_ACCESS_KEY_ID = "{AWS_EXAMPLES[0]}"', id="aws-access-key-id"),
        pytest.param("config.py", f'AWS_SECRET_ACCESS_KEY = "{AWS_EXAMPLES[1]}"', id="aws-secret-key"),
        pytest.param("app.py", 'app.run(host="0.0.0.0", port=8080, debug=True)', id="debug-on-every-interface"),
        pytest.param("app.py", 'response.headers["Access-Control-Allow-Origin"] = "*"', id="wildcard-cors"),
        pytest.param("app.py", 'response.headers["Access-Control-Allow-Credentials"] = "true"', id="cors-credentials"),
        pytest.param("app.py", "verify=False,", id="tls-verification-off"),
        pytest.param("requirements.txt", "requests==2.19.0", id="vulnerable-pypi-pin"),
        pytest.param("package.json", '"lodash": "4.17.15"', id="vulnerable-npm-pin"),
        pytest.param("requirements.txt", "gunicorn", id="unpinned-pypi-package"),
        pytest.param("package.json", '"express": "*",', id="unpinned-npm-package"),
    ],
)
def test_the_sample_client_repo_seeds_the_issue(name, line):
    assert line in _lines(name)


def test_the_sample_client_repo_has_no_lockfile():
    names = [path.name for path in SAMPLE.rglob("*") if path.is_file()]
    assert names
    assert _lockfiles(names) == []


def test_a_lockfile_of_either_ecosystem_is_found_by_name():
    assert _lockfiles(["app.py", "package-lock.json", "poetry.lock", "requirements.txt"]) == [
        "package-lock.json",
        "poetry.lock",
    ]


def test_the_recorded_osv_replay_holds_advisories_for_both_vulnerable_pins():
    replay = json.loads(REPLAY.read_text(encoding="utf-8"))
    assert replay["PyPI/requests@2.19.0"]["vulns"]
    assert replay["npm/lodash@4.17.15"]["vulns"]


def test_the_sample_client_repo_and_the_toy_ratings_hold_no_secret_but_the_documented_aws_examples():
    files = [*(path for path in SAMPLE.rglob("*") if path.is_file()), TOY]
    assert len(files) > 1
    assert [path for path in files if _secret_like(path.read_text(encoding="utf-8"))] == []


@pytest.mark.parametrize(
    "text",
    [
        'KEY = "AKIAABCDEFGHIJKLMNOP"',
        'password = "Tr0ub4dor&3xyz"',
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
        f'AWS_ACCESS_KEY_ID = "{AWS_EXAMPLES[0]}"\nother = "AKIAABCDEFGHIJKLMNOP"',
    ],
)
def test_a_secret_other_than_the_documented_aws_examples_is_found(text):
    assert _secret_like(text)


def test_the_documented_aws_examples_alone_are_not_a_find():
    assert not _secret_like(f'AWS_ACCESS_KEY_ID = "{AWS_EXAMPLES[0]}"\nAWS_SECRET_ACCESS_KEY = "{AWS_EXAMPLES[1]}"')
