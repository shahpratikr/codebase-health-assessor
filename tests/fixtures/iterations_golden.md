# Iteration log

## security_examiner

| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-20 | 11111111 | aaaaaaaa | seeded_recall: 1.0/0.75/0.833333; clean_precision: 1.0/1.0/1.0 | no | $0.012300 | baseline |
| 2 | 2026-10-20 | 11111111 | aaaaaaaa | seeded_recall: 1.0/0.75/0.833333; clean_precision: 1.0/1.0/1.0 | no | $0.012300 | baseline |
| 3 | 2026-10-22 | 22222222 | aaaaaaaa | seeded_recall: 0.9/0.9/0.9; injection_resistance: 1/1/1 | yes | $1.500000 | Tightened the \| rule and C:\\temp |

### Before and after

| Criterion | First | Last |
|---|---|---|
| seeded_recall | 0.8611 | 0.9000 |
| clean_precision | 1.0000 | - |
| injection_resistance | - | 1.0000 |

## dependency_examiner

| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-21 | 33333333 | bbbbbbbb | vuln_recall: 0.666667/0.666667/1.0; hygiene_recall: 1.0/1.0/1.0 | no | $0.250000 | first run |
| 2 | 2026-10-23 | 33333333 | bbbbbbbb | vuln_recall: 1.0/1.0/1.0; hygiene_recall: 1.0/0.8/1.0 | yes | $0.300000 | Recorded OSV again |

### Before and after

| Criterion | First | Last |
|---|---|---|
| vuln_recall | 0.7778 | 1.0000 |
| hygiene_recall | 1.0000 | 0.9333 |

## adversarial_reviewer

| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-21 | 44444444 | e3b0c442 | defect_catch_rate: 1.0/1.0/1.0; false_challenge_rate: 0.0/0.0/0.5 | no | $0.000000 | a\|b |

One execution recorded.

## final_review_writer

| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-21 | 55555555 | e3b0c442 | tone_score: 4.2/4.4/4.0 | yes | $0.100000 | Tone judge pinned |

One execution recorded.

## coordinator

| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-21 | cccccccc | e3b0c442 | review_coverage: 1.0/1.0/1.0; no_unneeded_redispatch: 0.916667/1.0/1.0; escalation_correct: 1.0/0.5/1.0 | no | unknown |  |

One execution recorded.
