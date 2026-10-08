# SBOM gap list

638 versioned components, 9 mapped to a CPE at the threshold; 15 component-CVE hits from CNA data, 7 of them also found by NVD CPE matching, 8 missed by CPE-only matching.

| SBOM | Component | CVE | Inferred CPE | Confidence | NVD status | Why CPE-only matching misses it |
|---|---|---|---|---|---|---|
| cleo | pkg:pypi/babel@2.17 | CVE-2025-27789 | `cpe:2.3:a:babeljs:babel:2.17` | 0.98 | Deferred | no NVD CPE configuration |
| cleo | pkg:pypi/pytest@8.4.2 | CVE-2025-71176 | `` | 0.00 | Deferred | no CPE |
| poetry-core | pkg:pypi/pip@26.2.1 | CVE-2023-5752 | `cpe:2.3:a:pypa:pip:26.2.1` | 0.99 | Modified | NVD range excludes this version |
| rich | pkg:pypi/pytest@7.4.4 | CVE-2025-71176 | `` | 0.00 | Deferred | no CPE |
| textual | pkg:pypi/babel@2.17 | CVE-2025-27789 | `cpe:2.3:a:babeljs:babel:2.17` | 0.98 | Deferred | no NVD CPE configuration |
| textual | pkg:pypi/pytest@8.4.2 | CVE-2025-71176 | `` | 0.00 | Deferred | no CPE |
| tomlkit | pkg:pypi/babel@2.14 | CVE-2025-27789 | `cpe:2.3:a:babeljs:babel:2.14` | 0.98 | Deferred | no NVD CPE configuration |
| tomlkit | pkg:pypi/pytest@7.4.4 | CVE-2025-71176 | `` | 0.00 | Deferred | no CPE |
