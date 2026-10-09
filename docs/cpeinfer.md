# cpeinfer reference

`cpeinfer` proposes NVD CPE configurations for a CVE from its CNA affected block, or abstains. Install dependencies with `pip install -r requirements-dev.txt`.

## Commands

```bash
python3 -m cpeinfer [--data data] build [--years 2023 2024 2025]
python3 -m cpeinfer evaluate [--train-years 2023 2024] [--test-year 2025] [--min-precision 0.95] [--margin 0.01] [--out results/cpeinfer] [--must-beat-baseline]
python3 -m cpeinfer resolve CVE_FILE_OR_DIR_OR_ID ... [--json]
python3 -m cpeinfer sbom-gaps [SBOM ...] [--corpus DIR] [--out results/cpeinfer] [--max-rows 20]
```

- `build` downloads (if needed) and compacts the cvelistV5, NVD CVE 2.0 and CPE dictionary inputs into `data/built/`. `evaluate` calls it automatically.
- `evaluate` runs the time-split evaluation and writes `report.md`, `metrics.csv`, `precision_coverage.csv` and `calibration.csv`. It exits 1 if vendor:product precision falls below `--min-precision`, or with `--must-beat-baseline` if recall doesn't beat string matching at equal precision. `--margin` is the extra precision required on validation.
- `resolve` takes CVE JSON 5 files, directories of them, or CVE IDs already in `data/`. Each affected entry gets a proposed CPE with a confidence, `propose` or `abstain`, and translated `cpeMatch` ranges.
- `sbom-gaps` joins SBOM components to CVEs and lists hits that NVD CPE matching would miss. Output goes to `sbom_gaps.csv` and `sbom_gaps.md`.

`resolve` and `sbom-gaps` need the model from a previous `evaluate` run.

## Method

- Alias model: for each CVE NIST enriched in the training window, every CNA affected entry is aligned with the NVD `vendor:product` it describes (the CNA's own `cpes`, a single entry, or the most similar name). It counts how often each key mapped to each CPE: normalized vendor+product, product, CNA+product, and a package URL built from `packageURL`, `collectionURL`+`packageName` or a GitHub `repo`.
- Candidates come from those aliases, CPEs the CNA listed, and the CPE dictionary by normalized tokens. Deprecated names follow their `deprecatedBy` chain.
- Scoring: logistic regression (NumPy, Newton's method) over 20 features, including alias shares and counts, name similarity, a rename flag, popularity, and whether the candidate's dictionary versions fall inside the CNA's affected range.
- Time split: aliases for validation are learned from the first eighteen months of the training years, and the scorer and threshold from the last six, with 5-fold cross-fitted probabilities. The chosen threshold is 0.91 (validation precision 96.1%). For the test year, aliases are re-learned from all training years and the CPE dictionary is cut to entries created before the test year, so CPEs NIST made while enriching test CVEs are invisible.
- Version ranges: CNA `versions` lists (semver, custom, `lessThan`, `lessThanOrEqual`, `4.19.*` branch bounds, `changes`, `defaultStatus`, GitHub-style `"< 1.8.2"`) become a minimal list of `versionStart*`/`versionEnd*` ranges. Hypothesis checks that the ranges flag exactly the versions a brute-force reading of the CNA rules flags.

## Results on the test year

28,340 NIST-enriched CVEs with CNA affected blocks. The baseline is plain string matching.

```text
field            resolver P   R      baseline P   R
vendor           98.7%  36.5%        95.3%  24.0%
vendor:product   97.2%  27.8%        83.1%  12.4%
version range    17.1%   4.9%        31.4%   4.7%
```

At the baseline's own precision (83.1%) the resolver's recall is 37.2%. Recall counts every NIST `vendor:product` pair, including CVEs whose CNA wrote `n/a` and products that only got a CPE during the test year, which nothing could reach. On correct pairs, translated ranges have a mean Jaccard overlap of 66.8% with NIST's.

Of 27,714 CVEs with CNA affected data and no NIST configuration, 4,104 get at least one CPE at the operating point, nearly all of them in NVD's `Deferred` status.

## SBOM gaps

A component is joined to a CVE when a CNA affected entry has the same canonical package URL, or when both resolve to the same CPE and the component's resolution clears the threshold. The component version must fall inside the translated range. On the corpus's 20 Syft SBOMs this finds 15 CVE hits among 638 components, 8 of which CPE-only matching misses.

## Limitations

- The SBOM join doesn't check the ecosystem, so PyPI `babel` maps to `babeljs:babel`.
- Range disagreement with NIST is often a convention difference. pip's CVE-2023-5752 lists only `23.3` as unaffected with `defaultStatus: affected`, so pip 26.2.1 counts as affected.
- CNA records come from cvelistV5 as downloaded. A CNA may have revised an entry after NIST enriched it, which slightly favours the training labels.
- Inventing new CPE names is out of scope.
