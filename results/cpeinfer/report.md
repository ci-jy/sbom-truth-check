# cpeinfer evaluation

Train [2023, 2024] (validation = second half of 2024), test 2025: 28340 NIST-enriched CVEs with CNA affected blocks.
Threshold 0.91, chosen on validation for >= 95% vendor:product precision.

| Field | Resolver precision | Resolver recall | Baseline precision | Baseline recall |
|---|---|---|---|---|
| vendor | 98.7% | 36.5% | 95.3% | 24.0% |
| vendor_product | 97.2% | 27.8% | 83.1% | 12.4% |
| version_range | 17.1% | 4.9% | 31.4% | 4.7% |

Mean range overlap (Jaccard) on correct vendor:product pairs: resolver 66.8%, baseline 70.1%.
Resolver recall at the baseline's precision (83.1%): 37.2% vs baseline 12.4%.

## Unenriched CVEs covered at the operating point

4104 of 27714 CVEs with CNA affected data and no NIST CPE configuration get at least one CPE.

| NVD status | CVEs | covered |
|---|---|---|
| Awaiting Analysis | 334 | 29 |
| Deferred | 27374 | 4074 |
| Received | 2 | 1 |
| Undergoing Analysis | 4 | 0 |

| Published | CVEs | covered |
|---|---|---|
| 2023 | 1 | 0 |
| 2024 | 7585 | 1042 |
| 2025 | 17368 | 2743 |
| 2026 | 2760 | 319 |

## Precision-coverage curve (test)

| Threshold | vendor:product precision | recall | version-range precision | recall |
|---|---|---|---|---|
| 0.05 | 86.3% | 37.2% | 19.4% | 8.4% |
| 0.15 | 87.7% | 36.5% | 19.3% | 8.0% |
| 0.25 | 88.5% | 35.4% | 19.4% | 7.8% |
| 0.35 | 89.5% | 34.3% | 19.7% | 7.5% |
| 0.45 | 90.9% | 33.8% | 19.5% | 7.3% |
| 0.55 | 92.0% | 33.3% | 19.2% | 7.0% |
| 0.65 | 92.4% | 32.6% | 18.8% | 6.6% |
| 0.75 | 92.9% | 31.9% | 18.1% | 6.2% |
| 0.85 | 94.0% | 30.1% | 17.0% | 5.4% |
| 0.95 | 97.7% | 25.0% | 15.0% | 3.8% |

## Calibration (validation, cross-fitted)

| Probability bin | entries | mean probability | accuracy |
|---|---|---|---|
| (-0.001, 0.1] | 819 | 0.04 | 0.56 |
| (0.1, 0.2] | 493 | 0.15 | 0.47 |
| (0.2, 0.3] | 677 | 0.25 | 0.40 |
| (0.3, 0.4] | 545 | 0.36 | 0.36 |
| (0.4, 0.5] | 653 | 0.44 | 0.47 |
| (0.5, 0.6] | 538 | 0.55 | 0.66 |
| (0.6, 0.7] | 479 | 0.65 | 0.61 |
| (0.7, 0.8] | 931 | 0.76 | 0.59 |
| (0.8, 0.9] | 2344 | 0.86 | 0.89 |
| (0.9, 1.0] | 14322 | 0.96 | 0.96 |
