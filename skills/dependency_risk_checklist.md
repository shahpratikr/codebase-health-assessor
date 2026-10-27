# Dependency risk checklist

Covers PyPI and npm dependencies only.

## known_vulnerabilities

Find the dependencies that have published advisories:
1. Call `list_manifests`, then read the manifests and lockfiles with `read_manifest`. Where a lockfile exists, prefer its resolved versions to the manifest's ranges.
2. Collect each dependency pinned to one exact version: `name==1.2.3` in a requirements file, an exact version in `package.json` (`"1.2.3"`, not `"^1.2.3"`), or the version a lockfile resolved.
3. Call `query_osv` once per pinned package and version, direct dependencies first.
4. Report one finding per vulnerable package version, at the line that pins it. Put the OSV `id` of every advisory `query_osv` returned for it into `advisory_ids`, and nothing else.
5. Rate the finding by its worst advisory. OSV gives an advisory's `severity` as CVSS vectors, not numbers: each entry's `score` is a string such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. For a CVSS v3 vector, work out its base score and rate critical for 9.0 or more, high for 7.0 to 8.9, medium for 4.0 to 6.9 and low below 4.0. A CVSS v4 score comes from a lookup table, not a formula, so estimate instead: critical when `AV:N`, `AT:N`, `PR:N` and `UI:N` come with a High (`H`) value for `VC`, `VI` or `VA`; high when any of `VC`, `VI` or `VA` is High otherwise; medium when the highest of them is Low; low when all are None. Say in the finding's `evidence` that a v4 rating is estimated. When an advisory has no vector, rate it medium unless its summary states a severity.
6. Recommend upgrading to the lowest version in `fixed` that is above the pinned one, or say that no fixed version is published.

Record these as limitations, never as findings:
- a `query_osv` error: name the package and version, and say its advisories were not checked
- pinned dependencies you could not query within your tool calls: name them
- dependencies without an exact version: they cannot be looked up, and the dependency_hygiene step covers them
- a dependency file the tools refused, such as a lockfile over the size limit: name it

## dependency_hygiene

Find declarations that make builds unreproducible or risky:
- an unpinned runtime dependency: no version at all, or an open range such as `>=`, `>`, `~=`, `*` or `latest`
- npm `^` and `~` ranges: normal practice when a lockfile is committed, so rate them low then
- a manifest with ranges and no lockfile beside it: cite the manifest's first dependency line
- a dependency installed from a URL, a git repository or a local path
- the same package declared twice with different versions
- a test or build tool in the runtime dependencies, or a runtime package in the development-only ones, when it is clear

Rate medium an unpinned runtime dependency with no lockfile to pin it, and a URL, git or path dependency. Rate low a range a lockfile pins, a duplicate declaration and a misplaced dependency. Hygiene findings are never critical or high.

When the repository has no dependency manifest at all, report no finding and record the absence as a limitation.
