import json
import os
from pathlib import Path

import httpx2
import pytest

from assessor import config, manifest, sandbox, tools
from assessor.tools import deps

EXAMINER = manifest.load_manifests()["dependency_examiner"]
REPLAY = Path(__file__).parent / "fixtures" / "osv_replay_sample.json"
REQUESTS = {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}
REQUESTS_PACKAGE = {"ecosystem": "PyPI", "name": "requests"}
REQUESTS_VULNS = [
    {
        "id": "GHSA-test-0001",
        "aliases": ["CVE-0000-0001"],
        "summary": "Sample advisory: credentials forwarded across redirects",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "fixed": ["2.20.0"],
    },
    {"id": "PYSEC-0000-1", "aliases": [], "summary": "", "severity": [], "fixed": ["2.31.0", "2.20.0"]},
]


def _workspace(tmp_path, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative, data in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
    return sandbox.Workspace(repo)


def _execute(tool, tool_input, workspace=None, osv=None):
    return tools.execute(EXAMINER, tool, tool_input, workspace=workspace, osv=osv)


def _ok(tool, tool_input, workspace=None, osv=None):
    result = _execute(tool, tool_input, workspace, osv)
    assert not result.is_error, result.content
    return json.loads(result.content)


def _error(tool, tool_input, workspace=None, osv=None):
    result = _execute(tool, tool_input, workspace, osv)
    assert (result.allowed, result.is_error) == (True, True), result.content
    return result.content


@pytest.fixture
def replay(monkeypatch):
    monkeypatch.setenv("ASSESSOR_OSV_REPLAY", str(REPLAY))


@pytest.fixture
def live(monkeypatch):
    """Answer httpx2.post with scripted responses or exceptions and record each call; nothing reaches the network."""
    monkeypatch.delenv("ASSESSOR_OSV_REPLAY", raising=False)
    calls, script = [], []

    def post(url, **kwargs):
        calls.append({"url": url, **kwargs})
        item = script.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, body = item
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx2.Response(status, content=content, request=httpx2.Request("POST", url))

    monkeypatch.setattr(deps.httpx2, "post", post)
    return calls, script


@pytest.mark.parametrize(
    ("name", "ecosystem", "kind"),
    [
        ("requirements.txt", "PyPI", "manifest"),
        ("requirements-dev.txt", "PyPI", "manifest"),
        ("requirements_test.txt", "PyPI", "manifest"),
        ("pyproject.toml", "PyPI", "manifest"),
        ("Pipfile", "PyPI", "manifest"),
        ("Pipfile.lock", "PyPI", "lockfile"),
        ("poetry.lock", "PyPI", "lockfile"),
        ("uv.lock", "PyPI", "lockfile"),
        ("package.json", "npm", "manifest"),
        ("package-lock.json", "npm", "lockfile"),
        ("npm-shrinkwrap.json", "npm", "lockfile"),
        ("yarn.lock", "npm", "lockfile"),
        ("pnpm-lock.yaml", "npm", "lockfile"),
    ],
)
def test_list_manifests_finds_each_recognised_file_with_its_ecosystem_and_kind(tmp_path, name, ecosystem, kind):
    workspace = _workspace(tmp_path, {name: "", "app.py": ""})
    assert _ok("list_manifests", {}, workspace) == {
        "manifests": [{"path": name, "ecosystem": ecosystem, "kind": kind}],
        "truncated": False,
        "unreadable": [],
    }


def test_list_manifests_ignores_lookalikes(tmp_path):
    lookalikes = [
        "setup.py",
        "setup.cfg",
        "requirements.in",
        "Requirements.txt",
        "dev-requirements.txt",
        "requirements.txt.orig",
        "package.json.bak",
        "my-package.json",
        "pyproject.toml~",
        "Pipfile.txt",
        "web/package-lock.yaml",
    ]
    workspace = _workspace(tmp_path, dict.fromkeys(lookalikes, ""))
    assert _ok("list_manifests", {}, workspace) == {"manifests": [], "truncated": False, "unreadable": []}


def test_no_manifests_is_an_empty_list_not_an_error(tmp_path):
    expected = {"manifests": [], "truncated": False, "unreadable": []}
    assert _ok("list_manifests", {}, _workspace(tmp_path, {"app.py": ""})) == expected


def test_list_manifests_finds_nested_files_and_skips_installed_dependencies(tmp_path):
    workspace = _workspace(
        tmp_path,
        {
            "requirements.txt": "",
            "web/package.json": "{}",
            "web/yarn.lock": "",
            "web/node_modules/lodash/package.json": "{}",
            ".venv/lib/pkg/pyproject.toml": "",
            ".git/package.json": "{}",
        },
    )
    assert [entry["path"] for entry in _ok("list_manifests", {}, workspace)["manifests"]] == [
        "requirements.txt",
        "web/package.json",
        "web/yarn.lock",
    ]


def test_list_manifests_omits_a_manifest_name_that_links_to_another_file(tmp_path):
    workspace = _workspace(tmp_path, {".env": "PASSWORD=x", "requirements.txt": ""})
    (workspace.root / "package.json").symlink_to(workspace.root / ".env")
    (workspace.root / "deps.txt").symlink_to(workspace.root / "requirements.txt")
    assert [entry["path"] for entry in _ok("list_manifests", {}, workspace)["manifests"]] == ["requirements.txt"]


def test_list_manifests_truncates_at_the_entry_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 2)
    workspace = _workspace(tmp_path, {"a/package.json": "", "b/package.json": "", "app.py": ""})
    assert _ok("list_manifests", {}, workspace)["truncated"] is False
    (workspace.root / "c").mkdir()
    (workspace.root / "c" / "package.json").write_text("")
    assert _ok("list_manifests", {}, workspace) == {
        "manifests": [
            {"path": "a/package.json", "ecosystem": "npm", "kind": "manifest"},
            {"path": "b/package.json", "ecosystem": "npm", "kind": "manifest"},
        ],
        "truncated": True,
        "unreadable": [],
    }


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_manifests_walks_no_further_than_one_manifest_past_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"a/package.json": "", "b/package.json": "", "z/package.json": ""})
    (workspace.root / "z").chmod(0)
    try:
        assert _ok("list_manifests", {}, workspace) == {
            "manifests": [{"path": "a/package.json", "ecosystem": "npm", "kind": "manifest"}],
            "truncated": True,
            "unreadable": [],
        }
    finally:
        (workspace.root / "z").chmod(0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_manifests_skips_and_reports_an_unreadable_directory(tmp_path):
    workspace = _workspace(tmp_path, {"package.json": "{}", "pgdata/base/1": "", "api/requirements.txt": ""})
    (workspace.root / "pgdata").chmod(0)
    try:
        result = _ok("list_manifests", {}, workspace)
    finally:
        (workspace.root / "pgdata").chmod(0o755)
    assert [entry["path"] for entry in result["manifests"]] == ["package.json", "api/requirements.txt"]
    assert result["unreadable"] == ["pgdata"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_manifests_caps_the_unreadable_list_and_flags_the_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"package.json": "{}", "u1/x": "", "u2/y": ""})
    locked = [workspace.root / "u1", workspace.root / "u2"]
    for folder in locked:
        folder.chmod(0)
    try:
        result = _ok("list_manifests", {}, workspace)
    finally:
        for folder in locked:
            folder.chmod(0o755)
    assert (result["truncated"], result["unreadable"]) == (True, ["u1"])


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_list_manifests_does_not_flag_an_unreadable_list_that_fits_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"package.json": "{}", "u1/x": ""})
    (workspace.root / "u1").chmod(0)
    try:
        result = _ok("list_manifests", {}, workspace)
    finally:
        (workspace.root / "u1").chmod(0o755)
    assert (result["truncated"], result["unreadable"]) == (False, ["u1"])


def test_list_manifests_finds_a_manifest_under_a_name_with_an_ideographic_space(tmp_path):
    workspace = _workspace(tmp_path, {"web\u3000app/package.json": "{}"})
    listed = [entry["path"] for entry in _ok("list_manifests", {}, workspace)["manifests"]]
    assert listed == ["web\u3000app/package.json"]


def test_a_recognised_manifest_over_the_read_cap_is_listed_but_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "READ_MAX_BYTES", 10)
    workspace = _workspace(tmp_path, {"package-lock.json": '{"lockfileVersion": 3}'})
    assert [entry["path"] for entry in _ok("list_manifests", {}, workspace)["manifests"]] == ["package-lock.json"]
    assert _error("read_manifest", {"path": "package-lock.json", "start_line": 1}, workspace) == (
        "read_manifest: package-lock.json: larger than the 10-byte read limit"
    )


def test_list_manifests_counts_only_manifests_toward_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 1)
    workspace = _workspace(tmp_path, {"a.py": "", "b.py": "", "c.py": "", "z/requirements.txt": ""})
    assert _ok("list_manifests", {}, workspace) == {
        "manifests": [{"path": "z/requirements.txt", "ecosystem": "PyPI", "kind": "manifest"}],
        "truncated": False,
        "unreadable": [],
    }


def test_read_manifest_returns_numbered_lines_like_read_file(tmp_path):
    workspace = _workspace(tmp_path, {"web/package.json": '{\n  "dependencies": {"lodash": "4.17.15"}\n}\n'})
    assert _ok("read_manifest", {"path": "web/package.json", "start_line": 2}, workspace) == {
        "path": "web/package.json",
        "start_line": 2,
        "end_line": 3,
        "total_lines": 3,
        "next_start_line": None,
        "content": '2\t  "dependencies": {"lodash": "4.17.15"}\n3\t}',
    }


@pytest.mark.parametrize(
    ("path", "message"),
    [
        (".env", "read_manifest: .env: not a recognised dependency manifest"),
        ("app.py", "read_manifest: app.py: not a recognised dependency manifest"),
        ("setup.py", "read_manifest: setup.py: not a recognised dependency manifest"),
        ("package.json", "read_manifest: package.json: not a recognised dependency manifest"),
        ("deps.txt", "read_manifest: deps.txt: not a recognised dependency manifest"),
        ("../requirements.txt", "read_manifest: ../requirements.txt: outside the workspace"),
        (
            "web/node_modules/x/package.json",
            "read_manifest: web/node_modules/x/package.json: files under node_modules are not read",
        ),
        ("missing/requirements.txt", "read_manifest: missing/requirements.txt: not a file"),
    ],
)
def test_read_manifest_refuses_anything_but_a_recognised_manifest(tmp_path, path, message):
    (tmp_path / "requirements.txt").write_text("outside")
    workspace = _workspace(
        tmp_path,
        {".env": "PASSWORD=x", "app.py": "", "setup.py": "", "real.txt": "", "web/node_modules/x/package.json": "{}"},
    )
    (workspace.root / "package.json").symlink_to(workspace.root / ".env")
    (workspace.root / "deps.txt").symlink_to(workspace.root / "real.txt")
    assert _error("read_manifest", {"path": path, "start_line": 1}, workspace) == message


def test_a_link_between_different_kinds_of_manifest_is_refused(tmp_path):
    workspace = _workspace(tmp_path, {"web/package.json": "{}"})
    (workspace.root / "requirements.txt").symlink_to(workspace.root / "web" / "package.json")
    assert [entry["path"] for entry in _ok("list_manifests", {}, workspace)["manifests"]] == ["web/package.json"]
    assert _error("read_manifest", {"path": "requirements.txt", "start_line": 1}, workspace) == (
        "read_manifest: requirements.txt: not a recognised dependency manifest"
    )


def test_read_manifest_follows_a_link_to_another_recognised_manifest(tmp_path):
    workspace = _workspace(tmp_path, {"web/package.json": '{"name": "web"}\n'})
    (workspace.root / "package.json").symlink_to(workspace.root / "web" / "package.json")
    assert _ok("read_manifest", {"path": "package.json", "start_line": 1}, workspace)["content"] == '1\t{"name": "web"}'


def test_query_osv_replays_the_recorded_response_without_the_network(replay, monkeypatch):
    monkeypatch.setattr(deps.httpx2, "post", lambda *args, **kwargs: pytest.fail("query_osv reached the network"))
    assert _ok("query_osv", REQUESTS) == {**REQUESTS, "vulns": REQUESTS_VULNS, "truncated": False}


def test_query_osv_reports_no_advisories_for_an_empty_osv_answer(replay):
    query = {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}
    assert _ok("query_osv", query) == {**query, "vulns": [], "truncated": False}


def test_query_osv_flags_a_paged_osv_answer_as_truncated(replay):
    assert _ok("query_osv", {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"})["truncated"] is True


@pytest.mark.parametrize(
    ("ecosystem", "name", "fixed"),
    [
        ("npm", "lodash-merge", ["2.0.0"]),
        ("npm", "lodash.merge", ["4.6.2"]),
        ("PyPI", "zope-interface", ["5.0.0"]),
        ("PyPI", "Zope.Interface", ["5.0.0"]),
    ],
)
def test_fixed_versions_follow_each_ecosystems_name_rules(ecosystem, name, fixed):
    affected = [
        ("npm", "lodash.merge", "4.6.2"),
        ("npm", "lodash-merge", "2.0.0"),
        ("PyPI", "zope.interface", "5.0.0"),
        ("npm", "zope-interface", "9.9.9"),
    ]
    vuln = {
        "id": "GHSA-test-0002",
        "affected": [
            {
                "package": {"ecosystem": owner, "name": package},
                "ranges": [{"type": "ECOSYSTEM" if owner == "PyPI" else "SEMVER", "events": [{"fixed": version}]}],
            }
            for owner, package, version in affected
        ],
    }
    query = {"ecosystem": ecosystem, "name": name, "version": "1.0.0"}
    assert _ok("query_osv", query, osv=lambda _: {"vulns": [vuln]})["vulns"][0]["fixed"] == fixed


def test_fixed_versions_leave_out_git_commit_ranges(tmp_path):
    vuln = {
        "id": "PYSEC-test-2",
        "affected": [
            {
                "package": REQUESTS_PACKAGE,
                "ranges": [
                    {"type": "GIT", "repo": "https://example.invalid/requests", "events": [{"fixed": "c45d7c49ea75"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]},
                ],
            }
        ],
    }
    assert _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": [vuln]})["vulns"][0]["fixed"] == ["2.20.0"]


def test_an_affected_entry_without_a_package_or_events_does_not_hide_the_other_advisories():
    vulns = [
        {"id": "GHSA-test-0003", "affected": [{"ranges": [{"type": "GIT", "events": [{"fixed": "abc"}]}]}]},
        {"id": "GHSA-test-0004", "affected": [{"package": REQUESTS_PACKAGE, "ranges": [{"type": "ECOSYSTEM"}]}]},
        {"id": "GHSA-test-0005", "affected": [{"package": REQUESTS_PACKAGE}]},
    ]
    result = _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": vulns})
    assert [(vuln["id"], vuln["fixed"]) for vuln in result["vulns"]] == [
        ("GHSA-test-0003", []),
        ("GHSA-test-0004", []),
        ("GHSA-test-0005", []),
    ]


@pytest.mark.parametrize(
    ("record", "summary"),
    [
        ({"summary": "Short summary", "details": "Long details"}, "Short summary"),
        ({"details": "  Leaks credentials.\n\nMore text.\n"}, "Leaks credentials.\n\nMore text."),
        ({"details": "x" * 301}, "x" * 300),
        ({"summary": "", "details": "From details"}, "From details"),
        ({}, ""),
        ({"summary": "y" * 301}, "y" * 300),
        ({"summary": None, "details": None}, ""),
        ({"summary": "   ", "details": "real details"}, "real details"),
        ({"summary": ["x"], "details": 5}, ""),
    ],
)
def test_summary_falls_back_to_the_start_of_the_details(monkeypatch, record, summary):
    monkeypatch.setattr(config, "OSV_SUMMARY_MAX_CHARS", 300)
    vuln = {"id": "PYSEC-test-3", **record}
    assert _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": [vuln]})["vulns"][0]["summary"] == summary


@pytest.mark.parametrize(
    "record",
    [
        {"details": None},
        {"aliases": None, "severity": None},
        {"affected": None},
        {"affected": [{"package": None}]},
        {"affected": [{"package": REQUESTS_PACKAGE, "ranges": None}]},
        {"affected": [{"package": REQUESTS_PACKAGE, "ranges": [{"type": "ECOSYSTEM", "events": None}]}]},
        {"affected": [None]},
        {"affected": [{"package": {"ecosystem": "PyPI", "name": None}}]},
        {"affected": [{"package": REQUESTS_PACKAGE, "ranges": [None]}]},
        {"affected": [{"package": REQUESTS_PACKAGE, "ranges": [{"type": "SEMVER", "events": [None, {"fixed": 2}]}]}]},
        {"affected": [{"package": REQUESTS_PACKAGE, "ranges": [{"type": "SEMVER", "events": [{"fixed": None}]}]}]},
    ],
)
def test_a_null_field_in_one_advisory_does_not_hide_the_others(record):
    vulns = [{"id": "GHSA-test-0006", **record}, {"id": "GHSA-test-0007", "summary": "ok"}]
    result = _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": vulns})
    assert [(vuln["id"], vuln["aliases"], vuln["severity"], vuln["fixed"]) for vuln in result["vulns"]] == [
        ("GHSA-test-0006", [], [], []),
        ("GHSA-test-0007", [], [], []),
    ]


def test_a_null_vulns_list_or_page_token_means_none():
    result = _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": None, "next_page_token": None})
    assert (result["vulns"], result["truncated"]) == ([], False)


def test_query_osv_caps_the_advisories_it_returns(monkeypatch):
    monkeypatch.setattr(config, "LIST_MAX_ENTRIES", 2)
    vulns = [{"id": f"GHSA-test-{n}"} for n in range(3)]
    result = _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": vulns[: len(vulns)]})
    assert ([vuln["id"] for vuln in result["vulns"]], result["truncated"]) == (["GHSA-test-0", "GHSA-test-1"], True)
    exact = _ok("query_osv", REQUESTS, osv=lambda _: {"vulns": vulns[:2]})
    assert (len(exact["vulns"]), exact["truncated"]) == (2, False)


def test_a_replay_miss_is_an_error_result(replay):
    assert _error("query_osv", {"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}) == (
        "query_osv: OSV query for PyPI/flask@3.0.0 failed: no recorded response"
    )


def test_query_osv_posts_the_package_query_only_to_the_fixed_osv_url(live):
    calls, script = live
    script.append((200, json.loads(REPLAY.read_text())["PyPI/requests@2.19.0"]))
    assert _ok("query_osv", REQUESTS)["vulns"] == REQUESTS_VULNS
    assert calls == [
        {
            "url": "https://api.osv.dev/v1/query",
            "json": {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"},
            "timeout": 10.0,
            "follow_redirects": False,
        }
    ]


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (httpx2.ReadTimeout("timed out"), "ReadTimeout"),
        (httpx2.ConnectTimeout("timed out"), "ConnectTimeout"),
        (httpx2.ConnectError("no route"), "ConnectError"),
        ((500, {"code": 13}), "HTTP 500"),
        ((404, {}), "HTTP 404"),
        ((302, {}), "HTTP 302"),
        ((200, b"<html>maintenance</html>"), "Expecting value: line 1 column 1 (char 0)"),
        ((200, []), "response is not a JSON object"),
        ((200, {"vulns": "none"}), "unexpected response shape"),
        ((200, {"vulns": [{"summary": "no id"}]}), "unexpected response shape"),
        ((200, {"vulns": [{"id": 5}]}), "unexpected response shape"),
        ((200, {"vulns": ["GHSA-test-0001"]}), "unexpected response shape"),
        ((200, {"vulns": [{"id": "X-1", "affected": "everything"}]}), "unexpected response shape"),
    ],
)
def test_osv_failures_are_error_results(live, answer, reason):
    calls, script = live
    script.append(answer)
    assert _error("query_osv", REQUESTS) == f"query_osv: OSV query for PyPI/requests@2.19.0 failed: {reason}"
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value"), [("name", ""), ("name", "  "), ("name", "a\nb"), ("version", ""), ("version", "1.0\t")]
)
def test_query_osv_refuses_a_blank_or_multiline_package_without_calling_osv(live, field, value):
    calls, _ = live
    message = _error("query_osv", {**REQUESTS, field: value})
    assert message == f"query_osv: {field} must be non-blank printable text, not {value!r}"
    assert calls == []
