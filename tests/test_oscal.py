"""OSCAL Assessment Results export: determinism, token safety, and the three
places OSCAL cannot say what this tool knows.

The claim "OSCAL 1.2.3 conformant" is checked against the published NIST schema
by ``scripts/validate_oscal.py`` (which needs the schema file and ``jsonschema``,
neither of which belongs in an offline tool's runtime). These tests hold the line
in CI without that dependency, and the token test is the durable fix for the
defect the first schema run found: a prop name containing ``:`` and control ids
containing parentheses are not legal OSCAL tokens.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from compliance_aiops import oscal

pytestmark = pytest.mark.unit

# The OSCAL TokenDatatype pattern, with \p{L}/\p{N} written in Python's dialect.
TOKEN_RE = re.compile(r"^([^\W\d_]|_)([^\W\d_]|\d|[.\-_])*$")
UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-"
    r"[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
)


def _bundle(controls, *, truncated=False, framework="hipaa"):
    return {
        "seal": {
            "framework": framework,
            "frameworkTitle": "HIPAA Security Rule (§164.312)",
            "organization": "Acme Health: EU & US",
            "period": {"start": "2026-08-01T00:00:00+00:00",
                       "end": "2026-08-08T00:00:00+00:00"},
            "sources": [{"name": "proxmox:prod", "path": "/x/a.db",
                         "rowCount": 3, "dbSha256": "ab" * 32}],
            "recordCount": 3,
            "scanLimit": 100000,
            "scanTruncated": truncated,
            "genesisHash": "0" * 64,
            "chainHead": "cd" * 32,
            "generatedAt": "2026-08-08T00:00:00+00:00",
            "generator": "compliance-aiops test",
            "signature": None,
        },
        "coverage": {
            "controlsTotal": len(controls),
            "controlsCovered": sum(1 for c in controls if c["covered"]),
            "eventsScanned": 3,
            "controls": controls,
        },
    }


STRONG_COVERED = {"controlId": "164.312(b)", "title": "Audit controls",
                  "strength": "strong", "evidenceCount": 3, "covered": True,
                  "gap": None, "caveat": None}
PARTIAL_COVERED = {"controlId": "164.312(a)(1)", "title": "Access control",
                   "strength": "partial", "evidenceCount": 2, "covered": True,
                   "gap": None, "caveat": "Trail shows use, not configuration."}
NOT_COVERED = {"controlId": "164.312(c)(1)", "title": "Integrity",
               "strength": "strong", "evidenceCount": 0, "covered": False,
               "gap": "No matching evidence in the audit trail for this period.",
               "caveat": None}


def _doc(controls, **kw):
    return oscal.to_assessment_results(_bundle(controls, **kw), bundle_href="b.json")


def _walk(node):
    """Yield every dict in the document."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


# ─── token safety: the defect the published schema caught ──────────────────


def test_every_prop_name_and_control_id_is_a_legal_oscal_token():
    """A prop name of `source-sha256:proxmox` and a control id of `164.312(b)`
    both fail OSCAL's TokenDatatype. This asserts the shape for the WHOLE
    document, so a future prop or id cannot reintroduce it."""
    document = _doc([STRONG_COVERED, PARTIAL_COVERED, NOT_COVERED])
    names, ids = [], []
    for node in _walk(document):
        for prop in node.get("props") or []:
            if isinstance(prop, dict) and "name" in prop:
                names.append(prop["name"])
        target = node.get("target")
        if isinstance(target, dict) and "target-id" in target:
            ids.append(target["target-id"])
        if "control-id" in node:
            ids.append(node["control-id"])
    assert names and ids
    for name in names:
        assert TOKEN_RE.match(name), f"prop name {name!r} is not an OSCAL token"
    for value in ids:
        assert TOKEN_RE.match(value), f"control id {value!r} is not an OSCAL token"


def test_derived_control_id_keeps_the_native_one_reachable():
    """Deriving the id must not lose the join back to the framework."""
    document = _doc([STRONG_COVERED])
    finding = document["assessment-results"]["results"][0]["findings"][0]
    assert finding["target"]["target-id"] == "hipaa_164.312-b"
    assert finding["target"]["title"] == "164.312(b)"
    assert any(p["name"] == "framework-control-id" and p["value"] == "164.312(b)"
               for p in finding["props"])
    assert "164.312(b)" in finding["description"]


def test_token_handles_the_hostile_shapes_each_framework_actually_uses():
    assert oscal.control_token("hipaa", "164.312(a)(1)") == "hipaa_164.312-a-1"
    assert oscal.control_token("soc2", "CC6.1") == "soc2_CC6.1"
    assert oscal.control_token("iso27001", "A.5.15") == "iso27001_A.5.15"
    # A digit-initial id is illegal on its own; the framework prefix fixes it.
    assert TOKEN_RE.match(oscal.control_token("pci_dss", "10.2"))
    assert TOKEN_RE.match(oscal.control_token("djcp_l3", "8.1.5.4"))
    # Degenerate input must still produce something legal, never an empty id.
    assert TOKEN_RE.match(oscal.control_token("", ""))
    assert TOKEN_RE.match(oscal.token("()"))


def test_source_name_travels_in_remarks_because_a_prop_name_cannot_hold_it():
    document = _doc([STRONG_COVERED])
    resources = document["assessment-results"]["back-matter"]["resources"]
    props = resources[0]["props"]
    digest = next(p for p in props if p["name"] == "source-sha256")
    assert digest["value"] == "ab" * 32
    assert "proxmox:prod" in digest["remarks"]


def test_all_uuids_are_v4_or_v5_as_oscal_requires():
    document = _doc([STRONG_COVERED, NOT_COVERED])
    found = [node["uuid"] for node in _walk(document) if "uuid" in node]
    assert len(found) >= 6
    for value in found:
        assert UUID_RE.match(value), f"{value} is not an OSCAL-acceptable UUID"


# ─── determinism: the bundle's reproducibility must survive the export ─────


def test_the_same_bundle_exports_byte_identically():
    """The bundle's chainHead is reproducible; an export with random v4 UUIDs
    would throw that away. Same input twice must give the same bytes."""
    first = json.dumps(_doc([STRONG_COVERED, PARTIAL_COVERED]), sort_keys=True)
    second = json.dumps(_doc([STRONG_COVERED, PARTIAL_COVERED]), sort_keys=True)
    assert first == second


def test_a_different_chain_head_yields_a_different_document_identity():
    bundle = _bundle([STRONG_COVERED])
    first = oscal.to_assessment_results(bundle, bundle_href="b.json")
    bundle["seal"]["chainHead"] = "ff" * 32
    second = oscal.to_assessment_results(bundle, bundle_href="b.json")
    assert first["assessment-results"]["uuid"] != second["assessment-results"]["uuid"]
    assert (first["assessment-results"]["results"][0]["uuid"]
            != second["assessment-results"]["results"][0]["uuid"])


# ─── the three things OSCAL cannot express ─────────────────────────────────


def test_partial_evidence_is_satisfied_but_never_silently():
    """OSCAL has no 'partially satisfied'. A bare `satisfied` on partial evidence
    upgrades the claim, so the qualification has to be somewhere a reader lands."""
    document = _doc([PARTIAL_COVERED])
    result = document["assessment-results"]["results"][0]
    finding = result["findings"][0]
    assert finding["target"]["status"]["state"] == "satisfied"
    assert any(p["name"] == "evidence-strength" and p["value"] == "partial"
               for p in finding["props"])
    assert "PARTIAL evidence" in finding["remarks"]
    assert "OPERATED" in finding["remarks"] and "DESIGNED" in finding["remarks"]
    # …and counted in the description, which a skimming consumer does read.
    assert "1 of those rest on PARTIAL evidence" in result["description"]
    assert any(p["name"] == "partial-evidence-findings" and p["value"] == "1"
               for p in result["props"])


def test_strong_evidence_carries_no_partial_qualification():
    document = _doc([STRONG_COVERED])
    finding = document["assessment-results"]["results"][0]["findings"][0]
    assert finding["target"]["status"]["state"] == "satisfied"
    assert "PARTIAL evidence" not in (finding.get("remarks") or "")
    assert "0 of those rest on PARTIAL evidence" in (
        document["assessment-results"]["results"][0]["description"])


def test_a_gap_becomes_not_satisfied_and_carries_its_reason():
    document = _doc([NOT_COVERED])
    finding = document["assessment-results"]["results"][0]["findings"][0]
    assert finding["target"]["status"]["state"] == "not-satisfied"
    assert finding["target"]["status"]["reason"] == "fail"
    assert "No matching evidence" in finding["description"]


def test_import_ap_points_at_a_resource_that_states_no_plan_exists():
    """OSCAL requires import-ap. Inventing a plan reference would be a lie about
    provenance, so it resolves to a back-matter resource saying there is none."""
    root = _doc([STRONG_COVERED])["assessment-results"]
    href = root["import-ap"]["href"]
    assert href.startswith("#")
    resources = {r["uuid"]: r for r in root["back-matter"]["resources"]}
    assert href[1:] in resources, "import-ap dangles — no such back-matter resource"
    assert "No OSCAL assessment plan" in resources[href[1:]]["title"]


def test_a_truncated_scan_leads_the_description():
    """A partial population presented as a complete assessment is the worst
    failure this tool can have, so it goes first, in prose, not just a prop."""
    document = _doc([STRONG_COVERED], truncated=True)
    result = document["assessment-results"]["results"][0]
    assert result["description"].startswith("POPULATION INCOMPLETE")
    assert any(p["name"] == "scan-truncated" and p["value"] == "True"
               for p in result["props"])
    clean = _doc([STRONG_COVERED], truncated=False)["assessment-results"]["results"][0]
    assert not clean["description"].startswith("POPULATION INCOMPLETE")


def test_the_document_says_it_did_not_resolve_a_catalog():
    result = _doc([STRONG_COVERED])["assessment-results"]["results"][0]
    assert "NOT resolved against an imported OSCAL catalog" in result["description"]
    assert any(p["name"] == "catalog-resolved" and p["value"] == "False"
               for p in result["props"])


def test_the_bundle_resource_binds_the_document_to_the_sealed_evidence():
    resources = _doc([STRONG_COVERED])["assessment-results"]["back-matter"]["resources"]
    bundle_resource = resources[0]
    assert bundle_resource["rlinks"][0]["href"] == "b.json"
    assert any(p["name"] == "chain-head" and p["value"] == "cd" * 32
               for p in bundle_resource["props"])


# ─── the structural guard actually catches damage ──────────────────────────


def test_structural_check_is_clean_on_a_real_document():
    assert oscal.structural_check(_doc([STRONG_COVERED, NOT_COVERED])) == []


def test_structural_check_catches_each_kind_of_damage():
    document = _doc([STRONG_COVERED])
    root = document["assessment-results"]
    root.pop("import-ap")
    root["results"][0]["findings"][0]["target"]["status"]["state"] = "partially-satisfied"
    root["results"][0]["observations"][0].pop("methods")
    root["uuid"] = "not-a-uuid"
    problems = oscal.structural_check(document)
    joined = " | ".join(problems)
    assert "import-ap" in joined
    assert "partially-satisfied" in joined
    assert "methods" in joined
    assert "not a v4/v5 UUID" in joined


def test_structural_check_on_a_non_document():
    assert oscal.structural_check({}) == ["missing 'assessment-results' root object"]


def test_a_framework_with_no_controls_is_refused_not_emitted():
    """The earlier version of this test asserted an empty document was a "valid
    shell" — structural_check said so and the test agreed, fossilising a wrong
    belief. The published schema disagreed on four counts: control-selections must
    name include-all or a non-empty include-controls, and observations/findings
    are minItems 1. include-all would claim every control was in scope, the
    opposite of the truth, so the emitter refuses instead."""
    with pytest.raises(oscal.OscalNotExpressible, match="nothing to assess"):
        _doc([])


def test_props_with_an_empty_value_are_dropped_not_emitted_blank():
    """OSCAL strings must match ^\\S(.*\\S)?$, so a prop carrying an absent
    field invalidates the whole document. Absent beats blank: an omitted prop
    says "not stated", an empty one asserts a blank value."""
    bundle = _bundle([STRONG_COVERED])
    bundle["seal"]["genesisHash"] = ""
    document = oscal.to_assessment_results(bundle, bundle_href="b.json")
    for node in _walk(document):
        for prop in node.get("props") or []:
            assert str(prop["value"]).strip(), f"empty prop value on {prop['name']}"
    resource = document["assessment-results"]["back-matter"]["resources"][0]
    assert not any(p["name"] == "genesis-hash" for p in resource["props"])


def test_a_control_with_no_id_omits_the_target_title_rather_than_blanking_it():
    document = _doc([{**STRONG_COVERED, "controlId": ""}])
    target = document["assessment-results"]["results"][0]["findings"][0]["target"]
    assert "title" not in target
    assert TOKEN_RE.match(target["target-id"])


# ─── the write path is as strict as the read path ──────────────────────────


def test_export_refuses_to_write_a_document_that_fails_its_structural_check(
    tmp_path, monkeypatch
):
    """The read path checked; the write path did not, so the malformed document
    was the one that reached an auditor while the inspectable one was fine."""
    from compliance_aiops.ops import bundle as bundle_ops

    bundle_file = tmp_path / "hipaa.json"
    bundle_file.write_text(json.dumps(_bundle([STRONG_COVERED])), "utf-8")

    # Capture first: monkeypatching the module attribute means a _broken that
    # calls the public helper would call itself.
    original = bundle_ops.oscal.to_assessment_results

    def _broken(*args, **kwargs):
        document = original(*args, **kwargs)
        document["assessment-results"].pop("import-ap")
        return document

    monkeypatch.setattr(bundle_ops.oscal, "to_assessment_results", _broken)
    with pytest.raises(ValueError, match="failed its structural check"):
        bundle_ops.export_bundle(str(bundle_file), fmt="oscal")
    assert not (tmp_path / "hipaa.oscal.json").exists(), "a bad document was written"


def test_export_writes_a_deterministic_document_on_the_happy_path(tmp_path):
    from compliance_aiops.ops import bundle as bundle_ops

    bundle_file = tmp_path / "hipaa.json"
    bundle_file.write_text(json.dumps(_bundle([STRONG_COVERED, NOT_COVERED])), "utf-8")
    first = bundle_ops.export_bundle(str(bundle_file), fmt="oscal")
    written = pathlib.Path(first["outPath"])
    assert written.name == "hipaa.oscal.json"
    before = written.read_bytes()
    bundle_ops.export_bundle(str(bundle_file), fmt="oscal")
    assert written.read_bytes() == before
    # the href resolves relative to the bundle, not to the generating machine
    document = json.loads(before)
    resource = document["assessment-results"]["back-matter"]["resources"][0]
    assert resource["rlinks"][0]["href"] == "hipaa.json"


def test_unknown_format_names_oscal_among_the_choices(tmp_path):
    from compliance_aiops.ops import bundle as bundle_ops

    bundle_file = tmp_path / "hipaa.json"
    bundle_file.write_text(json.dumps(_bundle([STRONG_COVERED])), "utf-8")
    with pytest.raises(ValueError, match="markdown, csv, json, or oscal"):
        bundle_ops.export_bundle(str(bundle_file), fmt="xml")
