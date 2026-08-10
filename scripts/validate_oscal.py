#!/usr/bin/env python3
"""Validate this tool's OSCAL output against the PUBLISHED NIST schema.

Not part of the package and not a runtime dependency: it needs the schema file
and `jsonschema`, neither of which belongs in a tool that must run offline. It
exists so "OSCAL 1.2.3 conformant" is a checked claim rather than a sentence in a
README — the first run of it found four real defects (parenthesised HIPAA control
ids and a colon in a prop name are not legal OSCAL tokens).

    curl -sLO https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_assessment-results_schema.json
    python scripts/validate_oscal.py oscal_assessment-results_schema.json

Two adjustments are made to the schema before validating, both mechanical and
both reported in the output so they cannot quietly hide a failure:

* nested ``$id`` values of the form ``#/definitions/...`` are removed. They
  re-base ``$ref`` resolution and make every reference unresolvable under a
  standards-compliant 2020-12 resolver.
* the single ECMA-262 ``\\p{L}``/``\\p{N}`` pattern (``TokenDatatype``) is
  translated to the equivalent Python character classes, because Python's ``re``
  cannot compile Unicode property escapes. The translation is faithful, not a
  relaxation: letters stay letters and digits stay digits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compliance_aiops import frameworks, oscal  # noqa: E402

#: The one pattern in the schema Python's `re` cannot compile, and its faithful
#: equivalent: `[^\W\d_]` is "word character, not digit, not underscore" = letter.
ECMA_TOKEN = r"^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$"
PY_TOKEN = r"^([^\W\d_]|_)([^\W\d_]|\d|[.\-_])*$"


def prepare(schema: dict) -> tuple[dict, int, int]:
    """Return (schema, ids_removed, patterns_translated)."""
    removed = translated = 0

    def walk(node: object, top: bool = True) -> None:
        nonlocal removed, translated
        if isinstance(node, dict):
            if not top and str(node.get("$id", "")).startswith("#/"):
                node.pop("$id")
                removed += 1
            if node.get("pattern") == ECMA_TOKEN:
                node["pattern"] = PY_TOKEN
                translated += 1
            for value in node.values():
                walk(value, False)
        elif isinstance(node, list):
            for value in node:
                walk(value, False)

    walk(schema)
    return schema, removed, translated


def synthetic_bundle(framework: str) -> dict:
    """A bundle covering every shape the emitter has to handle for a framework.

    Deliberately exercises both statuses and both evidence strengths, plus a
    truncated scan and a signed seal, so validation sees the whole surface rather
    than the happy path.
    """
    controls = frameworks.controls_for(framework)
    rows = []
    for index, control in enumerate(controls):
        covered = index % 2 == 0
        rows.append({
            "controlId": control.control_id,
            "title": control.title,
            "strength": control.strength,
            "evidenceCount": 7 if covered else 0,
            "covered": covered,
            "gap": None if covered else "No matching evidence in the audit trail.",
            "caveat": control.caveat or None,
        })
    return {
        "seal": {
            "schemaVersion": 1,
            "framework": framework,
            "frameworkTitle": frameworks.FRAMEWORK_TITLES.get(framework, framework),
            "organization": "Acme Health Systems: EU & US",  # punctuation on purpose
            "period": {"start": "2026-08-01T00:00:00+00:00",
                       "end": "2026-08-08T00:00:00+00:00"},
            "sources": [{"name": "proxmox:prod", "path": "/x/a.db", "rowCount": 9,
                         "dbSha256": "ab" * 32}],
            "recordCount": 9,
            "scanLimit": 100000,
            "scanTruncated": True,
            "genesisHash": "0" * 64,
            "chainHead": "cd" * 32,
            "generatedAt": "2026-08-08T00:00:00+00:00",
            "generator": "compliance-aiops test",
            "signature": {"alg": "HMAC-SHA256", "value": "ef" * 32},
        },
        "coverage": {
            "framework": framework,
            "frameworkTitle": frameworks.FRAMEWORK_TITLES.get(framework, framework),
            "controlsTotal": len(controls),
            "controlsCovered": sum(1 for r in rows if r["covered"]),
            "eventsScanned": 9,
            "controls": rows,
        },
        "records": [],
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    try:
        import jsonschema
    except ImportError:
        print("jsonschema is not installed: pip install jsonschema")
        return 2

    schema, removed, translated = prepare(json.loads(Path(sys.argv[1]).read_text()))
    print(f"schema      : {schema.get('$id')}")
    print(f"emitter says: OSCAL {oscal.OSCAL_VERSION}")
    print(f"prepared    : {removed} nested $id removed, {translated} pattern translated")
    if oscal.OSCAL_VERSION not in str(schema.get("$id", "")):
        print("!! the emitter's OSCAL_VERSION does not match this schema")
        return 1

    validator = jsonschema.Draft202012Validator(schema)
    total = 0
    for framework in frameworks.FRAMEWORKS:
        bundle = synthetic_bundle(framework)
        document = oscal.to_assessment_results(bundle, bundle_href="bundle.json")
        errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
        structural = oscal.structural_check(document)
        total += len(errors) + len(structural)
        status = "ok" if not errors and not structural else "FAIL"
        print(f"  {status:4} {framework:10} "
              f"{len(document['assessment-results']['results'][0]['findings'])} findings, "
              f"{len(errors)} schema error(s), {len(structural)} structural")
        for error in errors[:6]:
            print("        path:", "/".join(str(p) for p in error.absolute_path))
            print("         msg:", error.message[:200])
        for problem in structural[:6]:
            print("        structural:", problem)

    print(f"\n{'ALL VALID' if total == 0 else f'{total} PROBLEM(S)'}")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
