# sbomcheck reference

`sbomcheck` uses only the Python standard library (3.11+). It reads CycloneDX (1.5 to 1.7) and SPDX 2.3 JSON.

## Commands

```bash
python3 -m sbomcheck conform SBOM [--json] [--strict] [--max-failures N]
python3 -m sbomcheck diff SBOM LOCKFILE [--pyproject PATH] [--pom PATH] [--json] [--max-failures N] [--fail-on-unexplained]
python3 -m sbomcheck evaluate [--corpus corpus] [--out results] [--fail-on-unexplained]
```

- `conform`: per-field CISA minimum-element verdict, with a JSON path for every failing location. `--strict` exits 1 if any field fails. `--max-failures` sets how many failing locations are printed per field (default 3).
- `diff`: compares an SBOM with ground truth from `package-lock.json`, `poetry.lock` or `mvn dependency:tree` output. `--pyproject` and `--pom` default to the file next to the lockfile. `--max-failures` sets mismatches printed per cause (default 5). `--fail-on-unexplained` exits 1 if any mismatch has cause `unexplained`.
- `evaluate`: runs every SBOM in a corpus directory and writes `summary.json`, `per_sbom.json`, `mismatches.csv` and `report.md` to `--out`.

`--json` gives machine-readable output for `conform` and `diff`.

Example:

```text
$ python3 -m sbomcheck conform corpus/koa/sboms/syft.cdx.json
  FAIL  sbom_author                1/1 locations failing
          $.metadata.authors: no SBOM author (metadata.authors/manufacturer)
  FAIL  component_hash             36/36 locations failing
          $.components[0].hashes: no hash
  FAIL  transitive_completeness    36/36 locations failing
          $.components[0]: not reachable from the primary component through dependency edges
  ...
```

## Ground truth

The reference set is what ships: every locked package outside dev/test scope, including optional and platform-conditional packages, which are flagged as such.

- npm (lockfile v2/v3): the resolver reproduces Node's nested `node_modules` lookup to find which copy each package actually uses.
- Poetry: reads lock 2.x `groups`/`markers` (and 1.x `category`), and takes direct dependencies from PEP 621 or `tool.poetry` tables.
- Maven: parses `dependency:tree` with scopes and `(optional)` markers, and reads `pom.xml` to find dependencies that exist only in profiles or plugin configuration.

The scanned directory, lockfile "application" entries and the project's own package all map to `ROOT`, so tools that wrap their graph differently can still be compared edge for edge.

## PURL canonicalization

Two PURLs compare equal when they name the same artifact:

- `pkg:PyPI/Typing_Extensions@4.9.0` equals `pkg:pypi/typing-extensions@4.9` (PEP 503 names, PEP 440 versions).
- `%40Babel` equals `@babel`.
- `?type=jar` is dropped as the Maven default.
- Tool-specific qualifiers such as Syft's `package-id` are ignored.
- npm names and Maven coordinates stay case-sensitive, because their registries are.

## Mismatch causes

Every disagreement gets exactly one cause:

- `dev_test_dependency_included`: dev/test/provided-scope package or edge reported as shipped
- `optional_or_platform_dependency`: optional, extras-only or platform/python-marker package or edge, included or omitted
- `bundled_vendored_package`: package shipped inside another (`inBundle`)
- `name_normalization_mismatch`: same artifact, different spelling
- `range_instead_of_locked_version`: version range, property (`${x}`) or missing version instead of the locked one
- `different_locked_version`: concrete version that differs from the lockfile
- `missing_transitive_dependency`: indirect package absent from the SBOM
- `missing_direct_edge` / `missing_transitive_edge`: both packages present, the edge between them missing
- `no_dependency_graph`: SBOM states no edges at all
- `transitive_reported_as_direct`: an indirect dependency drawn as a direct one
- `edge_to_wrong_version`: edge points to another installed version of the right package
- `inactive_build_profile_dependency`: declared only in a Maven profile or plugin config
- `duplicate_component`: same canonical component listed more than once
- `component_without_purl`: component that cannot be identified
- `unexplained`: anything left over

Dev/test packages count as over-reporting. A team with the opposite policy can filter `dev_test_dependency_included` out of `mismatches.csv`. Optional and platform packages stay in the reference set, so a tool that omits them loses recall but the cause says why.

## Conformance rules worth knowing

- A hash passes when it has an algorithm and a hex value of the right length, on the component or on its distribution reference (where cyclonedx-npm puts the npm `integrity` hash). A SHA-512 value labelled `SHA-1` fails.
- SPDX 2.3 has no lifecycle field, so generation context passes only when `creationInfo.comment` names a phase (build, source, analyzed and so on).
- The checker verifies presence and form only. It does not download artifacts to confirm hashes or check that licenses are correct.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

The 80 tests cover PURL canonicalization cases, Hypothesis planted-defect tests over random graphs with CycloneDX and SPDX output, small hand-written lockfiles, end-to-end CLI runs on the corpus (the `cpeinfer` run is skipped until `data/` is built), version-range translation against brute force, and planted aliases for the CPE resolver.
