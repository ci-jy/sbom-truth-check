# SBOM Truth Check

I collected 88 SBOMs that Syft, Trivy, cyclonedx-npm and cyclonedx-py produced for 20 pinned open-source repositories and checked them against CISA's minimum elements. None of them passed. Only 21.6% carried component hashes, and not one said at what stage it was generated. This repo holds the checker (`sbomcheck`), which also compares an SBOM with the dependency graph in the project's own lockfile, and a second tool (`cpeinfer`) that proposes NVD CPEs for CVEs NIST no longer enriches. On held-out CVEs it gets `vendor:product` right 97.2% of the time, against 83.1% for plain string matching, and finds more than twice as many (27.8% recall vs 12.4%).

## What the generators get wrong

Most tools list the right packages. The trouble is everything around them:

| Tool (format) | SBOMs | Component precision | Edge recall |
|---|---|---|---|
| cyclonedx-npm (cdx) | 7 | 2.7% | 100.0% |
| cyclonedx-py (cdx) | 2 | 11.4% | 27.6% |
| syft (cdx) | 20 | 45.0% | 86.2% |
| syft (spdx) | 20 | 45.0% | 86.2% |
| trivy (cdx) | 20 | 100.0% | 98.9% |
| trivy (spdx) | 19 | 100.0% | 70.7% |

Low precision mostly comes from dev and test packages. Those account for 12,805 of the 13,489 disagreements. Trivy's SPDX output has no `DEPENDS_ON` from the lockfile, so the direct edges just vanish. Syft links a package to every installed version of a dependency name, not the one the lockfile resolves. Some tools also crashed outright: cyclonedx-py on Poetry 2 projects with a PEP 621 `[project]` table, and Trivy on a Maven Central rate limit. I kept those error files because they're part of the result.

Full tables, conformance pass rates and corpus details are in [docs/results.md](docs/results.md).

## Running it

```bash
python3 -m sbomcheck diff corpus/koa/sboms/syft.cdx.json corpus/koa/src/package-lock.json
python3 -m cpeinfer evaluate --train-years 2023 2024 --test-year 2025 --min-precision 0.95 --must-beat-baseline
python3 -m cpeinfer resolve CVE-2025-0395 CVE-2025-0638 CVE-2025-27152
```

`sbomcheck` uses only the standard library. `cpeinfer` needs `pip install -r requirements-dev.txt`, and its first run downloads about 70 MB of NVD feeds, an 81 MB CPE dictionary and a sparse cvelistV5 checkout. After that it takes about 4 minutes and 1.8 GB of memory. The diff on koa looks like this:

```text
  components all        precision 100.0%  recall 100.0%  (matched 35, reported 35, expected 35)
  edges      all        precision  73.2%  recall 100.0%  (matched 41, reported 56, expected 41)
  [edge_to_wrong_version] 15
      extra_edge: ROOT -> pkg:npm/content-type@2.0.0
      ... 14 more
```

All 35 packages are right, but koa points at both `content-type` 1.0.5 and 2.0.0. Commands and flags (including the CI exit-code options) are in [docs/sbomcheck.md](docs/sbomcheck.md) and [docs/cpeinfer.md](docs/cpeinfer.md).

## How it works

Ground truth comes from the lockfile, never from another SBOM generator. For npm that meant reproducing Node's nested `node_modules` lookup, because otherwise `a -> b@2` gets confused with a hoisted `b@1`. Poetry and Maven have their own quirks (lock groups and markers, `dependency:tree` scopes, dependencies that only exist in a profile). Before anything is compared, PURLs are canonicalized, so `pkg:PyPI/Typing_Extensions@4.9.0` and `pkg:pypi/typing-extensions@4.9` count as the same thing. Each disagreement then gets exactly one named cause, and on this corpus none are left unexplained.

`cpeinfer` learns how CNAs spell vendors and products by lining up their affected entries with the CPEs NIST assigned to older CVEs. It pulls candidates from those aliases and the CPE dictionary, then scores them with a small logistic regression in NumPy. Below a threshold chosen on validation data for 95% precision it abstains, because one wrong CPE raises false alerts everywhere. The test year never leaks into training: even the CPE dictionary is cut off before it. On CVEs NIST left unenriched, it proposed CPEs for 4,104 of 27,714.

![Precision and recall of CPE inference on held-out CVEs against a string-match baseline](docs/cpeinfer_precision_recall.png)

There are 80 pytest tests. The ones I trust most are Hypothesis tests that build a random dependency graph, plant one defect in an otherwise perfect SBOM, and check that exactly that defect comes back.

## Known issues

- Only npm lockfile v2/v3, `poetry.lock` and single-module `mvn dependency:tree` output are understood. Yarn, pnpm, Gradle and multi-module Maven are not.
- Conformance checks that a hash is present and well-formed, not that it matches the real artifact.
- Exact version-range agreement with NIST is only 17.1%. The translation follows what the CNA wrote, and CNAs and NIST often disagree.
- The SBOM gap list doesn't check the ecosystem, so PyPI `babel` gets matched to the JavaScript `babeljs:babel` CPE. An ecosystem guard would fix it.

Project period: 2026-09-24 to 2026-10-13.
