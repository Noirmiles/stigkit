#!/usr/bin/env python3
"""Generate the synthetic sample scans used by the README and the demo workflow.

Why a generator instead of committed sample files
-------------------------------------------------
Everything this tool is designed to read -- STIG checklists, SCAP results -- is
exactly the kind of artefact that must never be committed to a public
repository. Real checklists name real hosts and enumerate their real open
findings; that is a target list.

So this repository contains no scan data at all. It contains a deterministic
generator, and the sample scans are built on demand. The hostnames are drawn
from a fixed synthetic list, the addresses come from the RFC 5737
documentation range, and the rule identifiers are reserved placeholder values.
Nothing here describes any real system, because nothing here was derived from
one.

Usage:
    python examples/generate_sample_data.py
    stigkit scan examples/current --cci-list <U_CCI_List.xml> --fail-on cat1
"""

from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).parent

# RFC 5737 TEST-NET-1: reserved for documentation, never routable.
DOC_NET = "192.0.2."

HOSTS = [
    ("demo-web-01", "Computing"),
    ("demo-web-02", "Computing"),
    ("demo-db-01", "Computing"),
    ("demo-bastion-01", "Computing"),
]

# Placeholder rule catalogue. V-0000NN / DEMO-00-0000NN are deliberately outside
# any real DISA identifier range.
RULES = [
    ("V-000001", "DEMO-00-000010", "high",
     "The demo OS must display a logon banner before granting access.",
     ["CCI-000048", "CCI-000050"]),
    ("V-000002", "DEMO-00-000020", "medium",
     "The demo OS must enforce a minimum password length of 15 characters.",
     ["CCI-000205"]),
    ("V-000003", "DEMO-00-000030", "low",
     "The demo OS must set a session inactivity timeout.",
     ["CCI-000057"]),
    ("V-000004", "DEMO-00-000040", "medium",
     "The demo OS must audit privileged command execution.",
     ["CCI-000172"]),
    ("V-000005", "DEMO-00-000050", "high",
     "The demo OS must disable unauthenticated remote access.",
     ["CCI-000213"]),
    ("V-000006", "DEMO-00-000060", "medium",
     "The demo OS must encrypt data in transit.",
     ["CCI-002418"]),
    ("V-000007", "DEMO-00-000070", "low",
     "The demo OS must limit concurrent sessions.",
     ["CCI-000054"]),
    ("V-000008", "DEMO-00-000080", "high",
     "The demo OS must remove default accounts.",
     ["CCI-000764"]),
    ("V-000009", "DEMO-00-000090", "medium",
     "The demo OS must forward audit records to a central collector.",
     ["CCI-001851"]),
    ("V-000010", "DEMO-00-000100", "low",
     "The demo OS must display last-logon information.",
     ["CCI-000052"]),
]

STATUSES = ["open", "not_a_finding", "not_applicable", "not_reviewed"]
# Weighted so the sample looks like a system mid-remediation rather than a
# uniformly random one -- mostly passing, a handful open, a few unreviewed.
WEIGHTS = [0.25, 0.60, 0.08, 0.07]


def build_checklist(host: str, target_type: str, index: int, rng: random.Random) -> dict:
    rules = []
    for group_id, stig_id, severity, title, ccis in RULES:
        status = rng.choices(STATUSES, weights=WEIGHTS, k=1)[0]
        rules.append(
            {
                "group_id": group_id,
                "rule_id": f"SV-{group_id[2:]}r1_rule",
                "rule_version": stig_id,
                "rule_title": title,
                "severity": severity,
                "status": status,
                "finding_details": (
                    "Synthetic finding detail; no real system was assessed."
                    if status == "open"
                    else ""
                ),
                "comments": f"Tracked under synthetic ticket DEMO-{rng.randint(100, 999)}."
                if status == "open"
                else "",
                "ccis": ccis,
                "check_content": "Synthetic check text.",
                "fix_text": "Synthetic remediation text.",
            }
        )
    return {
        "title": f"Synthetic Demo OS checklist - {host}",
        "id": f"00000000-0000-4000-8000-{index:012d}",
        "cklb_version": "1.0",
        "target_data": {
            "target_type": target_type,
            "host_name": host,
            "ip_address": f"{DOC_NET}{10 + index}",
            "is_web_database": False,
        },
        "stigs": [
            {
                "stig_name": "Synthetic Demo OS Security Technical Implementation Guide",
                "display_name": "Synthetic Demo OS",
                "stig_id": "Synthetic_Demo_OS_STIG",
                "version": "1",
                "release_info": "Release: 1 Benchmark Date: 01 Aug 2026",
                "rules": rules,
            }
        ],
    }


def write_set(directory: Path, seed: int) -> None:
    """Write one checklist per host into *directory*, seeded for reproducibility."""
    directory.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)  # noqa: S311 - sample data, not a security decision
    for index, (host, target_type) in enumerate(HOSTS):
        payload = build_checklist(host, target_type, index, rng)
        (directory / f"{host}.cklb").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
    print(f"wrote {len(HOSTS)} checklists to {directory}")


def main() -> None:
    # Two different seeds produce two different postures, so `stigkit diff`
    # has something real to compare.
    write_set(HERE / "baseline", seed=1)
    write_set(HERE / "current", seed=7)


if __name__ == "__main__":
    main()
