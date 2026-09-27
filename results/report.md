# SBOM Truth Check: corpus results

88 SBOMs from 20 repositories; 0 fully conformant; 13489 mismatches against lockfile ground truth, 0 unexplained.

## Accuracy against lockfile ground truth (micro-averaged)

| Tool (format) | SBOMs | Component precision | Component recall | Edge precision | Edge recall | Transitive edge recall |
|---|---|---|---|---|---|---|
| cyclonedx-npm (cdx) | 7 | 2.7% | 100.0% | 1.8% | 100.0% | 100.0% |
| cyclonedx-py (cdx) | 2 | 11.4% | 27.5% | 7.2% | 27.6% | 21.9% |
| syft (cdx) | 20 | 45.0% | 100.0% | 25.7% | 86.2% | 100.0% |
| syft (spdx) | 20 | 45.0% | 100.0% | 25.7% | 86.2% | 100.0% |
| trivy (cdx) | 20 | 100.0% | 99.0% | 99.5% | 98.9% | 99.2% |
| trivy (spdx) | 19 | 100.0% | 99.0% | 99.2% | 70.7% | 99.2% |

## Direct vs transitive components

| Tool (format) | Direct precision | Direct recall | Transitive precision | Transitive recall |
|---|---|---|---|---|
| cyclonedx-npm (cdx) | 19.7% | 100.0% | 1.6% | 100.0% |
| cyclonedx-py (cdx) | 25.7% | 34.6% | 5.7% | 20.0% |
| syft (cdx) | 53.9% | 100.0% | 40.8% | 100.0% |
| syft (spdx) | 53.9% | 100.0% | 40.8% | 100.0% |
| trivy (cdx) | 100.0% | 99.1% | 100.0% | 98.9% |
| trivy (spdx) | 100.0% | 99.1% | 100.0% | 98.9% |

## CISA minimum-element conformance (share of SBOMs passing each field)

| Field | All SBOMs | cyclonedx-npm (cdx) | cyclonedx-py (cdx) | syft (cdx) | syft (spdx) | trivy (cdx) | trivy (spdx) |
|---|---|---|---|---|---|---|---|
| format_version | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| sbom_author | 44.3% | 0.0% | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% |
| timestamp | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| tool_name | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| generation_context | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| component_name | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| component_version | 98.9% | 85.7% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| software_identifier | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| component_producer | 13.6% | 0.0% | 0.0% | 0.0% | 0.0% | 30.0% | 31.6% |
| component_hash | 21.6% | 71.4% | 100.0% | 0.0% | 0.0% | 30.0% | 31.6% |
| license | 46.6% | 28.6% | 0.0% | 30.0% | 30.0% | 70.0% | 68.4% |
| dependency_relationships | 63.6% | 100.0% | 100.0% | 0.0% | 85.0% | 100.0% | 52.6% |
| transitive_completeness | 39.8% | 100.0% | 100.0% | 0.0% | 0.0% | 100.0% | 31.6% |

## Mismatches per cause class

| Cause | Count |
|---|---|
| dev_test_dependency_included | 12805 |
| optional_or_platform_dependency | 240 |
| bundled_vendored_package | 0 |
| name_normalization_mismatch | 0 |
| range_instead_of_locked_version | 56 |
| different_locked_version | 0 |
| missing_transitive_dependency | 0 |
| missing_transitive_edge | 0 |
| missing_direct_edge | 155 |
| no_dependency_graph | 0 |
| transitive_reported_as_direct | 0 |
| edge_to_wrong_version | 44 |
| inactive_build_profile_dependency | 12 |
| duplicate_component | 177 |
| component_without_purl | 0 |
| unexplained | 0 |

## Mismatch causes per tool

- **cyclonedx-npm (cdx)**: dev_test_dependency_included 10103, duplicate_component 177
- **cyclonedx-py (cdx)**: dev_test_dependency_included 314, optional_or_platform_dependency 79
- **syft (cdx)**: dev_test_dependency_included 1194, optional_or_platform_dependency 65, missing_direct_edge 33, range_instead_of_locked_version 28, edge_to_wrong_version 20, inactive_build_profile_dependency 6
- **syft (spdx)**: dev_test_dependency_included 1194, optional_or_platform_dependency 65, missing_direct_edge 33, range_instead_of_locked_version 28, edge_to_wrong_version 20, inactive_build_profile_dependency 6
- **trivy (cdx)**: optional_or_platform_dependency 6, edge_to_wrong_version 2, missing_direct_edge 1
- **trivy (spdx)**: missing_direct_edge 88, optional_or_platform_dependency 25, edge_to_wrong_version 2

## Generator failures

| Repository | Tool | Last error line |
|---|---|---|
| winston | cyclonedx-npm | `Error: npm-ls exited with errors: 1 noSignal` |
| poetry | cyclonedx-py | `CRITICAL \| CDX > 'name'` |
| poetry-core | cyclonedx-py | `CRITICAL \| CDX > 'name'` |
| poetry-plugin-export | cyclonedx-py | `CRITICAL \| CDX > 'name'` |
| cleo | cyclonedx-py | `CRITICAL \| CDX > 'name'` |
| tomlkit | cyclonedx-py | `CRITICAL \| CDX > 'name'` |
| commons-text | trivy-spdx | `To avoid this, populate the local Maven cache before scanning (e.g. run `mvn dependency:resolve`, or `mvn install` for a multi-module project, and cache ~/.m2 in CI).` |
