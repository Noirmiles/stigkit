# stigkit

**Parse DISA STIG/SCAP scan results, map findings to NIST 800-53 controls, and gate a CI pipeline on the outcome.**

[![CI](https://github.com/Noirmiles/stigkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Noirmiles/stigkit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## The problem

Security compliance in a DoD or FedRAMP programme runs on two artefacts: a **STIG**
(DISA's hardening baseline, published as XCCDF XML) and a **scan result** (what a
scanner or an analyst actually found, published as XCCDF results or a STIG Viewer
checklist). Turning those into a compliance picture is, at most organisations, a
person with a spreadsheet:

- The scanner says `SV-230221r991589_rule` failed. The programme manager needs to
  hear "AC-8 is non-compliant." Translating between them means walking DISA's CCI
  list by hand.
- The monthly continuous-monitoring report is assembled by copying numbers
  between tools, so it is out of date the moment it is finished.
- Nothing is connected to the pipeline that produced the system. A configuration
  change that breaks a control is discovered weeks later, in a review, instead of
  in the pull request that caused it.

`stigkit` closes that loop. It parses the scan output, resolves every finding to
its NIST 800-53 controls, reports the posture, and **returns a non-zero exit code
when the system is non-compliant** — so compliance becomes a build gate rather
than a document.

## What it does

| | |
|---|---|
| **Parses** | XCCDF 1.1 and 1.2 benchmarks, XCCDF `TestResult` scan output, and `.cklb` STIG Viewer checklists |
| **Maps** | CCI → NIST SP 800-53 (Rev 4 or Rev 5) via DISA's public CCI list |
| **Reports** | Terminal tables, JSON, CSV, Markdown, and **SARIF** |
| **Gates** | `--fail-on cat1` exits 1 on an open CAT I; `diff --fail-on-new` exits 1 on regression |
| **Integrates** | SARIF output lands STIG findings in GitHub Code Scanning next to Semgrep and Trivy |

## Install

```bash
git clone https://github.com/Noirmiles/stigkit
cd stigkit
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

Generate the synthetic sample data (this repository ships no scan data — see
[Data policy](#data-policy)) and scan it:

```bash
python examples/generate_sample_data.py
stigkit scan examples/current
```

```
╭──────────────────────────────── STIG compliance ─────────────────────────────────╮
│ 58.97% compliant  (39 rules assessed, 1 N/A, 4 host(s))                          │
│ 15 open finding(s)  CAT I: 5                                                     │
╰──────────────────────────────────────────────────────────────────────────────────╯
                      Hosts, worst first
┏━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃ Host            ┃ Open ┃ CAT I ┃ CAT II ┃ CAT III ┃  Score ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ demo-web-02     │    6 │     3 │      2 │       1 │  30.0% │
│ demo-web-01     │    5 │     0 │      3 │       2 │  50.0% │
│ demo-bastion-01 │    2 │     1 │      1 │       0 │ 77.78% │
│ demo-db-01      │    2 │     1 │      1 │       0 │  80.0% │
└─────────────────┴──────┴───────┴────────┴─────────┴────────┘
```

### Map findings to NIST 800-53

Download DISA's CCI list from
[public.cyber.mil/stigs/cci](https://public.cyber.mil/stigs/cci/) (public,
unclassified) and pass it in:

```bash
stigkit scan examples/current --cci-list U_CCI_List.xml
```

```
Open findings by NIST 800-53 family
┏━━━━━━━━┳━━━━━━┓
┃ Family ┃ Open ┃
┡━━━━━━━━╇━━━━━━┩
│ AC     │    2 │
│ IA     │    2 │
│ AU     │    1 │
└────────┴──────┘
```

`--nist-revision 4` resolves against Rev 4 instead. A CCI with no reference for
the requested revision maps to nothing rather than silently falling back — Rev 4
and Rev 5 moved requirements between controls, and a quiet fallback would
attribute findings to the wrong control invisibly.

### Gate a pipeline

```bash
stigkit scan examples/current --fail-on cat1
echo $?   # 1
```

Exit codes are the contract with CI:

| Code | Meaning |
|---:|---|
| `0` | Ran, gate passed |
| `1` | Ran, **gate failed** — open findings at or above `--fail-on` |
| `2` | **Did not run** — bad input, unreadable file, refused XML |

`1` and `2` are deliberately distinct. "The system is non-compliant" and "the
scanner broke" call for different people; collapsing them into a generic non-zero
teaches everyone to re-run the job until it goes green.

### Track regressions between scans

```bash
stigkit diff examples/baseline examples/current --fail-on-new
```

```
| Change                      | Count |
| --------------------------- | ----: |
| 🆕 New findings              |    11 |
| ✅ Resolved                  |     4 |
| ➡️ Still open                |     4 |
| ❓ Disappeared (unexplained) |     0 |
```

**Disappeared ≠ resolved.** A rule open in the baseline and absent from the
current scan may have been fixed — or the benchmark was updated, the profile
narrowed, or the scan did not finish. Only evidence of a pass proves
remediation, so absences are reported as their own category for a human to
explain rather than being quietly credited.

### Feed GitHub Code Scanning

```bash
stigkit scan examples/current --format sarif --output stig.sarif
```

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: stig.sarif
    category: stig-compliance
```

STIG findings then appear in the repository's Security tab beside Semgrep and
Trivy results, with the same triage, dismissal and branch-protection workflow.
CAT I maps to SARIF `error`, CAT II to `warning`, CAT III to `note`.

## Design notes

The reasoning behind the decisions below is in [`docs/DESIGN.md`](docs/DESIGN.md).
The short version:

**XML is parsed with `defusedxml`, never `xml.etree`.** This tool reads XML it did
not author. Stock ElementTree resolves external entities, so a hostile benchmark
can read local files (XXE) or exhaust memory (billion laughs). A compliance
scanner compromised by the file it is auditing is not a compliance scanner. Two
tests in [`tests/test_xml_hardening.py`](tests/test_xml_hardening.py) fail if
anyone swaps it back.

**Not-reviewed rules count against the score.** The compliance score is
`compliant / assessed`, where `assessed` excludes not-applicable rules and
*includes* not-reviewed ones. A half-finished scan therefore reports as
half-compliant, not as compliant-so-far. The number cannot be improved by not
looking.

**Errors are open findings.** A check that failed to execute is not a pass.

**Unknown severity is `unknown`, not `low`.** Content in the wild does omit
`@severity`. Defaulting it downward is the one direction a compliance tool must
never round.

**Unrecognised statuses become not-reviewed, never compliant.** If the tool does
not understand the evidence, the safe reading is "nobody has answered yet."

**Control IDs keep enhancements and drop clause letters.** `AC-8 a` → `AC-8`;
`IA-5 (1) (h)` → `IA-5 (1)`. Clause granularity produces a control list nobody
can reconcile against eMASS; the enhancement *is* a separately assessed control.

## The pipeline

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs four security gates
in parallel with a four-version test matrix:

| Gate | Tool | Catches |
|---|---|---|
| SAST | Semgrep | flaws in code we wrote |
| SCA | pip-audit | flaws in code we imported |
| Secrets | gitleaks (full history) | credentials committed by mistake |
| Filesystem / config | Trivy | misconfiguration, vulnerable files |
| Compliance | **stigkit itself** | open CAT I findings |

Notes on the choices:

- **Separate jobs, not steps.** A Semgrep failure still tells you whether your
  dependencies are clean. One combined job stops at the first failure and hides
  the other three findings.
- **Actions pinned to commit SHAs, not tags.** `@v4` is a mutable pointer — a
  promise from the maintainer that they will not change what it references. The
  SHA is the only immutable reference GitHub offers. Dependabot watches both
  ecosystems so the pins still get updated.
- **`permissions: contents: read` at the top level.** Jobs that need
  `security-events: write` request it individually, so the blast radius of a
  compromised action is visible in the diff that grants it.
- **gitleaks runs with `fetch-depth: 0`.** A secret deleted from the working tree
  is still live if it is reachable in an earlier commit. Scanning only the tip is
  the most common way secret scanning gives false assurance.
- **Semgrep uses explicit rulesets, not `--config=auto`.** Auto resolves rules
  from the network at run time, so the checks applied to a given commit are
  neither reproducible nor reviewable.
- **The pipeline dogfoods the tool.** The `compliance-gate` job generates
  synthetic scans, publishes the posture to the job summary, uploads SARIF to
  Code Scanning, and demonstrates the CAT I gate firing.

## Data policy

**This repository contains no scan data, and none was derived from any real
system.**

Real STIG checklists name real hosts and enumerate their open findings; that is a
target list, and it does not belong in a public repository. So:

- Sample scans are **generated on demand** by
  [`examples/generate_sample_data.py`](examples/generate_sample_data.py), not
  committed.
- Test fixtures under `tests/fixtures/` are hand-authored against the public
  XCCDF, CCI and CKLB schemas. Identifiers (`V-000001`, `DEMO-00-000010`) are
  reserved placeholders outside any real DISA range.
- Addresses come from `192.0.2.0/24` — RFC 5737 TEST-NET-1, reserved for
  documentation and never routable.
- `.gitignore` refuses `*.ckl`, `*.cklb` and `U_*.zip` outside the fixtures
  directory, so a real checklist dropped into a working copy cannot be committed
  by accident.

The formats this tool implements are public: XCCDF is a NIST specification, and
DISA publishes the STIG library and CCI list at
[public.cyber.mil](https://public.cyber.mil/stigs/).

## Development

```bash
pip install -e ".[dev]"
pytest --cov          # 105 tests, 96% coverage
ruff check .
```

## Licence

MIT — see [LICENSE](LICENSE).
