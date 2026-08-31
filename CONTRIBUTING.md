# Contributing to stigkit

## Data policy — read this before adding any file

**This repository contains no scan data, and nothing in it is derived from any
real system.** A real STIG checklist names a real host and enumerates its open
findings. That is a target list, and it does not belong in a public repository.

When adding fixtures or examples:

- Sample scans are **generated, never committed** — see
  `examples/generate_sample_data.py`.
- Test fixtures under `tests/fixtures/` are hand-authored against the public
  XCCDF / CCI / CKLB schemas. Identifiers (`V-000001`, `DEMO-00-000010`) are
  placeholders chosen to sit outside any real DISA range.
- Addresses come from `192.0.2.0/24` — RFC 5737 TEST-NET-1, which is never
  routable.
- `.gitignore` refuses `*.ckl`, `*.cklb` and `U_*.zip` outside `tests/fixtures/`.
  Please do not weaken those rules.

Never commit a real checklist, real scan output, real hostnames, real IP
addresses, or text copied from any organisation's internal documents. If a
change would need real data to be meaningful, say so in the issue rather than
inventing a workaround.

## Getting set up

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Everything below runs in CI, so it is worth running locally first:

```bash
pytest -q                                    # test suite
pytest -q --cov --cov-report=term-missing    # branch coverage
ruff check .                                 # lint

python examples/generate_sample_data.py      # regenerate sample scans
stigkit scan examples/current --fail-on cat1 # exercise the gate end to end
```

## Conventions

These are load-bearing. Each one is a decision with a reason behind it, and
`docs/DESIGN.md` records the reasoning — please read the relevant section before
arguing with one.

- **XML is parsed only through `stigkit.parsers.xml.load_xml`**, which uses
  `defusedxml`. Never import `xml.etree` for parsing. `tests/test_xml_hardening.py`
  fails if you do, and that is deliberate — untrusted XML is this tool's entire
  input surface.
- **Compliance semantics are encoded in `ComplianceStatus`**, not re-derived by
  callers. `counts_toward_score` and `is_open_finding` are the source of truth.
- **Never round a severity down.** Content in the wild omits `@severity`;
  unknown severity stays `UNKNOWN` rather than becoming "low".
- **Never let an unrecognised status become `COMPLIANT`.** Default to
  `NOT_REVIEWED`.
- Reporting tests assert on content with whitespace collapsed, not on table
  borders. `rich` re-wraps narrow table titles, and pinning the exact layout
  makes the suite break on cosmetic changes.
