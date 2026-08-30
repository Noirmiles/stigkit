# Design notes

Why the tool behaves the way it does. Every section below is a decision that
could reasonably have gone the other way; the reasoning is recorded so it can be
argued with rather than rediscovered.

---

## 1. Parsing untrusted XML

`stigkit` reads XML it did not author. A benchmark is downloaded from DISA, a
results file is produced by a scanner, a CCI list is handed over by an operator.
None of those are trusted inputs in the security sense — they are files that
arrived from somewhere.

Python's `xml.etree.ElementTree` resolves external entities and expands nested
ones. That makes two concrete attacks available to anyone who can influence a
file this tool reads:

**XXE.** A document containing

```xml
<!DOCTYPE Benchmark [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<Benchmark><title>&xxe;</title></Benchmark>
```

causes the parser to read a local file and splice its contents into the
document — where it lands in the compliance report, gets attached to a ticket,
or is uploaded to Code Scanning. `SYSTEM "http://..."` turns the same trick into
SSRF from whatever host runs the scan, which in a compliance context is often a
management workstation with more network reach than most.

**Entity expansion.** The "billion laughs" pattern exhausts memory before any of
our code runs, so no amount of defensive logic downstream helps.

Every XML read goes through `stigkit.parsers.xml.load_xml`, which uses
`defusedxml` with `forbid_dtd`, `forbid_entities` and `forbid_external` all
enabled. Nothing in the package imports `xml.etree` for parsing.

Two consequences worth stating:

- **DTDs are refused outright**, not just entity declarations. Real DISA XCCDF
  content does not use DTDs, so the stricter setting costs nothing and removes a
  category of parser behaviour rather than a specific exploit.
- **The error message never contains resolved content.** A rejected XXE payload
  must not leak through the exception text, so `XmlSecurityError` names the file
  and the construct and nothing else. `test_xxe_payload_never_reaches_output`
  pins this.

`tests/test_xml_hardening.py` fails if anyone swaps the parser back for
convenience. That is the point of it existing as a test rather than a comment.

### The Semgrep suppression in `xml.py`

Semgrep's `use-defused-xml` rule flags *any* `xml.etree` import, including the
type-only `Element` import used for annotations. Rather than exclude the rule in
the Semgrep configuration — which would also stop it catching a genuine
`xml.etree.parse()` added later — the import is moved behind `TYPE_CHECKING`, so
it has no run-time existence at all, and the one remaining line carries a scoped
`# nosemgrep` with the reason written next to it.

A suppression a reviewer can audit in place is worth more than a clean scan
achieved by narrowing the ruleset.

---

## 2. Compliance arithmetic

The score is:

```
compliance = compliant / assessed
assessed   = every rule except NOT_APPLICABLE
```

Three decisions are packed into that.

**Not-applicable is excluded from the denominator.** A rule that does not apply
to a host is not a question anyone owes an answer to. Counting it as a failure
punishes correct scoping; counting it as a pass inflates the score with rules
nobody evaluated.

**Not-reviewed is *included* in the denominator.** This is the load-bearing one.
The alternative — scoring only what has been assessed — means a system with one
reviewed passing rule and four hundred unreviewed ones reports 100% compliant.
Every compliance dashboard that has ever embarrassed an organisation did roughly
this. Including unreviewed rules means an unfinished scan reports as unfinished,
and the number cannot be improved by not looking.

**Errors are open findings.** A check that failed to execute is evidence of
nothing. Treating it as a pass means a broken scanner produces a perfect report,
which is the failure mode most likely to go unnoticed because it looks like
success.

`ComplianceStatus.counts_toward_score` and `.is_open_finding` are the two
properties that encode this, and everything downstream defers to them rather
than re-deriving the rules. `tests/test_analyze.py` pins each case.

---

## 3. Status normalisation

XCCDF and CKLB describe the same facts in different vocabularies, and the
mapping is not mechanical.

| XCCDF | CKLB | stigkit | Why |
|---|---|---|---|
| `pass`, `fixed` | `not_a_finding` | `COMPLIANT` | |
| `fail` | `open` | `NON_COMPLIANT` | |
| `notapplicable`, `notselected` | `not_applicable` | `NOT_APPLICABLE` | `notselected` means excluded from the profile — a completed judgement |
| `notchecked`, `informational` | `not_reviewed` | `NOT_REVIEWED` | in scope, no verdict rendered |
| `error`, `unknown` | — | `ERROR` | the check could not complete |

The distinction that matters most is **`NOT_APPLICABLE` vs `NOT_REVIEWED`**.
"This rule does not apply to this host" is a finished assessment. "Nobody has
looked at this yet" is a gap in the assessment. They land in the same visual
bucket on most dashboards, and collapsing them is precisely how a system nobody
has finished scanning reports as 98% compliant.

An **unrecognised** status becomes `NOT_REVIEWED`, never `COMPLIANT`. If the tool
does not understand the evidence, the safe reading of "I don't understand this"
is "nobody has answered yet."

---

## 4. Severity

`Severity.UNKNOWN` exists because content in the wild does omit `@severity`, and
there is no honest default. Rounding an unknown severity down to CAT III
understates risk — the one direction a compliance tool must never round. It
surfaces as `unknown` and sorts last, so it is visible rather than absorbed.

`Severity.rank` gives CAT I the *lowest* number so `sorted()` puts the most
severe first without a `reverse=` flag that someone will eventually drop.

---

## 5. CCI → NIST 800-53 attribution

A STIG rule cites CCIs. A CCI is DISA's atomic, testable restatement of one
clause of one 800-53 control. The CCI list is the join table between "host X
failed `SV-000001`" and "this system has an open finding against AC-8" — and
only the second form is actionable by an ISSO, an eMASS record, or a programme
manager.

**Control IDs keep enhancements and drop clause letters.**

```
AC-8 a        -> AC-8
IA-5 (1) (h)  -> IA-5 (1)
AU-12 c       -> AU-12
```

The reference index points at a clause. Reporting at clause granularity produces
a control list nobody can reconcile against eMASS. But a control *enhancement*
is separately assessed and separately tracked, so collapsing `IA-5 (1)` into
`IA-5` would merge two distinct compliance obligations.

**A CCI with no reference for the requested revision maps to nothing.** Rev 4 and
Rev 5 moved requirements between controls. Falling back to another revision when
the requested one is missing would attribute findings to the wrong control, and
the error would be invisible in the output — the report would look complete and
be wrong. Reporting nothing is louder.

**Attribution is a separate step from parsing.** `attribute_controls()` runs
after the parse, so a missing or unreadable CCI list degrades the report —
findings still appear, without control IDs — rather than failing the run.
Compliance tooling that refuses to tell you anything because one reference file
is absent gets worked around, and a tool people work around is a tool nobody
runs.

---

## 6. Why SARIF

SARIF is the format GitHub Code Scanning, Azure DevOps and most security
dashboards ingest. Emitting it means STIG findings get the same triage,
dismissal and branch-protection workflow as Semgrep or Trivy results.

The argument is not about file formats. A compliance finding nobody sees until
the monthly report is a document. A compliance finding that appears on the pull
request that caused it is a control.

Two implementation details matter more than they look:

**`partialFingerprints` must be stable.** GitHub uses them to decide whether an
alert in today's upload is the same alert as yesterday's. Derive the fingerprint
from anything volatile — a timestamp, a file path, a list index — and every scan
closes the old alerts and opens identical new ones, destroying the triage history
and any dismissal an analyst recorded. The fingerprint here is
`sha256(host + V-ID)` and nothing else.

**Every result needs a location.** Code Scanning silently drops results without
one. STIG findings describe a host, not a source line, so results are anchored to
the scan artefact with `startLine: 1` — enough structure to render, honest about
what it is.

Passing rules are not emitted. `--include-not-reviewed` optionally emits
unreviewed rules as `note`, off by default: an unreviewed rule is a gap in the
assessment, not a defect in the system, and mixing the two trains people to
ignore the queue.

---

## 7. Exit codes

```
0  ran, gate passed
1  ran, gate FAILED
2  did not run
```

A pipeline should block on `1` and page someone on `2`. "The system is
non-compliant" and "the scanner crashed" call for different humans and different
urgency. Tools that return a generic non-zero for both teach everyone to re-run
the job until it goes green, which is how a broken scanner survives in a pipeline
for months.

`--fail-on cat2` blocks on CAT I *and* CAT II and lets CAT III through, which is
how most programmes actually gate: stop the release for a real hole, track the
paperwork findings. The threshold names the least severe category that still
blocks.

---

## 8. Delta semantics: disappeared ≠ resolved

`stigkit diff` reports four categories, not three. The fourth is **disappeared**:
open in the baseline scan, absent from the current one.

The tempting simplification is to count those as resolved. They are not. A rule
can vanish from a scan because it was fixed — or because the benchmark was
updated, the profile was narrowed, the scanner was misconfigured, or the scan did
not finish. Only *evidence of a pass* proves remediation.

Crediting absences as fixes produces a burndown chart that improves fastest when
scanning breaks. Reporting them separately puts them in front of a human to
explain.

---

## 9. Dependencies

Two runtime dependencies: `defusedxml` and `rich`.

Every dependency in a security tool is attack surface inherited from someone
else's release process, and a compliance scanner is exactly the kind of thing
that runs with elevated access on a management network. `defusedxml` earns its
place by removing a vulnerability class. `rich` is the only presentation
dependency and is confined to `report/console.py`.

Everything else — XCCDF parsing, CCI resolution, SARIF generation, CSV, the CLI —
is standard library.
