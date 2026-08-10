"""Sealed evidence bundle → OSCAL Assessment Results (NIST OSCAL 1.2.3).

A pure transformation: bundle dict in, OSCAL document out. No I/O, no clock, no
randomness — which is what lets a re-export of the same bundle be byte-identical,
the same reproducibility property the bundle's ``chainHead`` already has. UUIDs
are therefore **version 5** (namespace + stable name) rather than v4; OSCAL's own
UUID pattern accepts ``[45]``, checked against the published schema.

Three places where OSCAL cannot express what this tool knows, handled explicitly
rather than papered over — a compliance artifact that overstates is worse than no
artifact:

1. **``import-ap`` is a required field and there is no assessment plan.** The
   evidence comes from infrastructure audit trails, not from a planned
   assessment. Rather than invent a plan reference, ``href`` points at a
   back-matter resource that states the absence.
2. **Control ids are framework-native, not resolved into an imported OSCAL
   catalog.** ``164.312(b)``, ``CC6.1``, ``A.5.15`` are the identifiers this tool
   maps to; nothing here fetched or validated against a published catalog, so a
   consumer must do that mapping. Said in the result description and in a prop,
   not left for someone to assume.
3. **``status.state`` has exactly two values, ``satisfied`` and
   ``not-satisfied``.** There is no "partially satisfied". This tool's own model
   is more careful: an audit trail evidences *operating effectiveness* strongly
   but control *design* only partially. Emitting bare ``satisfied`` for a
   partial-strength control silently upgrades the claim. Those findings therefore
   carry ``evidence-strength=partial``, a ``remarks`` naming what the trail does
   NOT prove, and — because a reader may skim past both — a **count in the result
   description itself**, plus the same count in the returned summary.
"""

from __future__ import annotations

import uuid
from typing import Any

#: The OSCAL release these documents target. Not a guess: taken from the
#: published schema's ``$id`` (``.../ns/oscal/1.2.3/oscal-ar-schema.json``) and
#: validated against that schema. Pinning an upstream version without checking is
#: how a tool ends up emitting a shape the current release rejects.
OSCAL_VERSION = "1.2.3"

#: Namespace for this tool's own ``props``. OSCAL requires a URI here; anything
#: not in the OSCAL vocabulary must be namespaced or a consumer cannot tell our
#: extensions from the standard's.
PROP_NS = "https://github.com/AIops-tools/Compliance-AIops/ns/oscal"

#: Fixed namespace for the version-5 UUIDs. Constant on purpose: the same bundle
#: must always produce the same document.
_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, PROP_NS)


def _uuid(*parts: Any) -> str:
    """A deterministic v5 UUID for the given logical identity."""
    return str(uuid.uuid5(_UUID_NAMESPACE, "|".join(str(p) for p in parts)))


def token(value: Any, *, prefix: str = "x") -> str:
    """Coerce a string into an OSCAL ``TokenDatatype``.

    OSCAL tokens are ``^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$`` — a letter or
    underscore, then letters, digits, dot, hyphen, underscore. **Most of this
    tool's control identifiers do not qualify**, which the published schema
    catches and a hand-rolled emitter would not: `164.312(b)` has parentheses,
    `164.312(a)(1)` has two pairs, and `10.2` / `8.1.5.4` start with a digit.
    Only the SOC 2 (`CC6.1`) and ISO (`A.5.15`) styles happen to be legal.

    So the OSCAL identifier is *derived*, and the native identifier is carried
    beside it (a ``framework-control-id`` prop, plus the finding's title and
    description) — losing it to satisfy a syntax rule would break the one join a
    consumer needs back to the framework.
    """
    cleaned = _token_chars(value)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"{prefix}_{cleaned}" if cleaned else prefix
    return cleaned


def _token_chars(value: Any) -> str:
    """The charset half of :func:`token`: legal characters only, no start rule.

    Split out because :func:`control_token` supplies its own legal start (the
    framework prefix); running the start rule twice produced ``hipaa_c_164.312-b``,
    an id with a stray marker in the middle of it.
    """
    cleaned = "".join(
        ch if (ch.isalnum() or ch in "._-") else "-" for ch in str(value or "")
    )
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-")


def control_token(framework: Any, control_id: Any) -> str:
    """The OSCAL ``control-id`` for a framework-native control identifier.

    Framework-prefixed both because it guarantees the required letter start and
    because ids collide across frameworks (`A.5.15` exists in more than one).
    """
    prefix = token(str(framework or "framework").lower(), prefix="framework")
    body = _token_chars(control_id)
    return f"{prefix}_{body}" if body else prefix


def _prop(name: str, value: Any) -> dict:
    return {"name": name, "value": str(value), "ns": PROP_NS}


def _control_observation(
    bundle_id: str, framework: str, control: dict, collected: str, evidence_href: str
) -> dict:
    """One observation per control: what was examined, and how much of it."""
    control_id = control.get("controlId", "")
    count = control.get("evidenceCount", 0)
    observation = {
        "uuid": _uuid(bundle_id, "observation", control_id),
        "title": f"Audit-trail examination for {control_id}",
        "description": (
            f"Examined the sealed governed-operations audit trail for evidence of "
            f"control {control_id} ({control.get('title', '')}). "
            f"{count} matching audit record(s) in the assessed period."
        ),
        "methods": ["EXAMINE"],
        "types": ["control-objective"],
        "props": [
            _prop("evidence-count", count),
            _prop("evidence-strength", control.get("strength", "unknown")),
            _prop("framework-control-id", control_id),
        ],
        "relevant-evidence": [
            {
                "href": evidence_href,
                "description": (
                    "Hash-chained evidence bundle; the records for this control are "
                    "selectable with control_evidence(framework, control_id) and the "
                    "chain head in the bundle seal fixes the population."
                ),
            }
        ],
        "collected": collected,
    }
    caveat = control.get("caveat")
    if caveat:
        observation["remarks"] = str(caveat)
    return observation


def _control_finding(
    bundle_id: str, framework: str, control: dict, observation_uuid: str
) -> dict:
    """One finding per control, with the honest status and the reason for it."""
    control_id = control.get("controlId", "")
    covered = bool(control.get("covered"))
    strength = str(control.get("strength", "unknown"))
    gap = control.get("gap")
    partial = covered and strength == "partial"

    status: dict[str, Any] = {"state": "satisfied" if covered else "not-satisfied"}
    status["reason"] = "pass" if covered else "fail"

    description = (
        f"Control {control_id} ({control.get('title', '')}): "
        + (
            f"{control.get('evidenceCount', 0)} audit record(s) evidence this control "
            f"operating during the assessed period."
            if covered
            else f"not satisfied — {gap or 'no matching evidence in the audit trail.'}"
        )
    )
    finding = {
        "uuid": _uuid(bundle_id, "finding", control_id),
        "title": f"{control_id} — {control.get('title', '')}",
        "description": description,
        "props": [
            _prop("evidence-strength", strength),
            _prop("evidence-count", control.get("evidenceCount", 0)),
            # The native id, because target-id below had to be derived to satisfy
            # OSCAL's token syntax. This is the join back to the framework.
            _prop("framework-control-id", control_id),
        ],
        "target": {
            "type": "objective-id",
            "target-id": control_token(framework, control_id),
            "title": control_id,
            "status": status,
        },
        "related-observations": [{"observation-uuid": observation_uuid}],
    }
    remarks: list[str] = []
    if partial:
        remarks.append(
            "This 'satisfied' rests on PARTIAL evidence. OSCAL's status has no "
            "'partially satisfied' state, so the distinction lives here: the audit "
            "trail evidences that the control OPERATED (these records exist, with "
            "actor, timestamp and outcome), and does NOT evidence that the control "
            "is correctly DESIGNED or configured — e.g. that MFA is required, or "
            "that roles are least-privilege. Pair with configuration/policy "
            "evidence before treating this control as fully assessed."
        )
    if control.get("caveat"):
        remarks.append(str(control["caveat"]))
    if gap and covered:
        remarks.append(f"Noted during assessment: {gap}")
    if remarks:
        finding["remarks"] = "\n\n".join(remarks)
    return finding


def _back_matter(seal: dict, bundle_href: str, no_plan_uuid: str) -> dict:
    """Resources: the sealed bundle (hash-bound) and the missing-plan statement."""
    bundle_resource: dict[str, Any] = {
        "uuid": _uuid(seal.get("chainHead", ""), "resource", "bundle"),
        "title": "Sealed evidence bundle (compliance-aiops)",
        "description": (
            f"Hash-chained audit-trail evidence sealed by "
            f"{seal.get('generator', 'compliance-aiops')}. Chain head "
            f"{seal.get('chainHead', '')} over {seal.get('recordCount', 0)} record(s); "
            f"the chain is computed over the ordered records only, so the head is "
            f"reproducible from the same sources and period."
        ),
        "rlinks": [{"href": bundle_href, "media-type": "application/json"}],
        "props": [
            _prop("chain-head", seal.get("chainHead", "")),
            _prop("genesis-hash", seal.get("genesisHash", "")),
            _prop("record-count", seal.get("recordCount", 0)),
            _prop("bundle-signed", bool(seal.get("signature"))),
        ],
    }
    for source in seal.get("sources") or []:
        digest = source.get("dbSha256")
        if digest:
            # A prop NAME is an OSCAL token, and a source name is operator-chosen
            # free text (":" alone is enough to make the document invalid). The
            # name therefore travels in remarks, where free text is allowed.
            prop = _prop("source-sha256", digest)
            prop["remarks"] = f"Source database: {source.get('name', '?')}"
            bundle_resource["props"].append(prop)

    no_plan = {
        "uuid": no_plan_uuid,
        "title": "No OSCAL assessment plan (import-ap placeholder)",
        "description": (
            "OSCAL requires assessment-results to import an assessment plan. No "
            "such plan exists for this evidence: it was collected continuously by "
            "the governance harness of infrastructure operations tools, not "
            "produced by a planned assessment with defined activities and subjects. "
            "This resource stands in for that reference so the document is "
            "schema-valid without fabricating a plan. Supply the real "
            "assessment-plan URI here if this evidence is being folded into one."
        ),
    }
    return {"resources": [bundle_resource, no_plan]}


def to_assessment_results(
    bundle: dict,
    *,
    bundle_href: str,
    assessor: str | None = None,
) -> dict:
    """Render a sealed evidence bundle as an OSCAL Assessment Results document.

    ``bundle_href`` is what the evidence resource points at (normally the bundle
    filename). ``assessor`` names the party that ran the assessment; it defaults
    to the bundle's generator, since that is literally what collected the
    evidence.
    """
    seal = bundle.get("seal") or {}
    coverage = bundle.get("coverage") or {}
    controls = coverage.get("controls") or []

    chain_head = str(seal.get("chainHead") or "")
    generated_at = str(seal.get("generatedAt") or "")
    # The chain head IS the bundle's identity — same sources, same period, same
    # head — so deriving every UUID from it makes the document reproducible.
    bundle_id = chain_head or _uuid("no-chain-head", generated_at)
    organization = str(seal.get("organization") or "Unnamed Organization")
    generator = str(seal.get("generator") or "compliance-aiops")
    framework = str(seal.get("framework") or "framework")
    framework_title = str(seal.get("frameworkTitle") or seal.get("framework") or "")

    period = seal.get("period") or {}
    start = period.get("start") or generated_at
    end = period.get("end") or generated_at

    observations = []
    findings = []
    for control in controls:
        observation = _control_observation(
            bundle_id, framework, control, generated_at, bundle_href
        )
        observations.append(observation)
        findings.append(_control_finding(bundle_id, framework, control, observation["uuid"]))

    satisfied = [f for f in findings if f["target"]["status"]["state"] == "satisfied"]
    partial_satisfied = [
        f
        for f in findings
        if f["target"]["status"]["state"] == "satisfied"
        and any(
            p["name"] == "evidence-strength" and p["value"] == "partial"
            for p in f.get("props", [])
        )
    ]
    truncated = bool(seal.get("scanTruncated"))

    # Everything a reader must not miss goes in the description, because props and
    # remarks are the first things a skimming consumer drops.
    caveats = [
        f"{len(satisfied)} of {len(findings)} reviewed controls are reported "
        f"satisfied.",
        f"{len(partial_satisfied)} of those rest on PARTIAL evidence: an audit "
        f"trail evidences operating effectiveness, not control design — see each "
        f"finding's remarks.",
        "Control identifiers are DERIVED (framework-prefixed, token-safe) because "
        "most framework-native ids are not legal OSCAL tokens; the native id is on "
        "each finding as target.title and a framework-control-id prop. They are "
        "NOT resolved against an imported OSCAL catalog — a consumer must map them.",
    ]
    if truncated:
        caveats.insert(
            0,
            f"POPULATION INCOMPLETE: the source scan hit its cap of "
            f"{seal.get('scanLimit')} records, so this assessment covers a "
            f"truncated population and coverage counts are lower bounds.",
        )

    no_plan_uuid = _uuid(bundle_id, "resource", "no-assessment-plan")
    result = {
        "uuid": _uuid(bundle_id, "result"),
        "title": f"{framework_title} — governed-operations audit evidence",
        "description": " ".join(caveats),
        "start": start,
        "end": end,
        "props": [
            _prop("chain-head", chain_head),
            _prop("controls-covered", coverage.get("controlsCovered", 0)),
            _prop("controls-total", coverage.get("controlsTotal", 0)),
            _prop("events-scanned", coverage.get("eventsScanned", 0)),
            _prop("scan-truncated", truncated),
            _prop("partial-evidence-findings", len(partial_satisfied)),
            _prop("catalog-resolved", False),
        ],
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": (
                        f"All {len(controls)} controls this tool maps for "
                        f"{framework_title}."
                    ),
                    "include-controls": [
                        {"control-id": control_token(framework, c.get("controlId", ""))}
                        for c in controls
                    ],
                }
                if controls
                else {"description": "No controls mapped for this framework."}
            ]
        },
        "observations": observations,
        "findings": findings,
    }

    document = {
        "assessment-results": {
            "uuid": _uuid(bundle_id, "assessment-results"),
            "metadata": {
                "title": (
                    f"{framework_title} assessment results — {organization} "
                    f"(governed-operations audit evidence)"
                ),
                "last-modified": generated_at,
                "version": chain_head[:16] or "0",
                "oscal-version": OSCAL_VERSION,
                "props": [_prop("generator", generator)],
                "parties": [
                    {
                        "uuid": _uuid(bundle_id, "party", "organization"),
                        "type": "organization",
                        "name": organization,
                    },
                    {
                        "uuid": _uuid(bundle_id, "party", "assessor"),
                        "type": "organization",
                        "name": assessor or generator,
                        "remarks": (
                            "The evidence was collected continuously by the "
                            "governance harness of the operations tools, not by a "
                            "human assessment team."
                        ),
                    },
                ],
            },
            "import-ap": {
                "href": f"#{no_plan_uuid}",
                "remarks": (
                    "No OSCAL assessment plan exists for this evidence; the "
                    "referenced back-matter resource states so explicitly rather "
                    "than this document naming a plan that was never written."
                ),
            },
            "results": [result],
            "back-matter": _back_matter(seal, bundle_href, no_plan_uuid),
        }
    }
    return document


# ── structural self-check (NOT schema validation) ──────────────────────────

_UUID_RE_PARTS = (8, 4, 4, 4, 12)


def _looks_like_uuid(value: Any) -> bool:
    parts = str(value).split("-")
    if len(parts) != 5 or [len(p) for p in parts] != list(_UUID_RE_PARTS):
        return False
    if parts[2][:1] not in ("4", "5"):  # OSCAL accepts only v4/v5
        return False
    return all(all(ch in "0123456789abcdefABCDEF" for ch in p) for p in parts)


def structural_check(document: dict) -> list[str]:
    """Return a list of structural problems (empty = looks well-formed).

    Deliberately **not** called schema validation: it checks the required fields
    and the UUID shape this module is responsible for, and nothing else. The
    document was validated against the published OSCAL ``1.2.3``
    assessment-results JSON Schema during development (see docs/VERIFICATION.md);
    this function is the cheap runtime guard against a regression here, not a
    substitute for that.
    """
    problems: list[str] = []
    root = document.get("assessment-results")
    if not isinstance(root, dict):
        return ["missing 'assessment-results' root object"]
    for key in ("uuid", "metadata", "import-ap", "results"):
        if key not in root:
            problems.append(f"assessment-results is missing required '{key}'")
    if not _looks_like_uuid(root.get("uuid")):
        problems.append("assessment-results.uuid is not a v4/v5 UUID")
    metadata = root.get("metadata") or {}
    for key in ("title", "last-modified", "version", "oscal-version"):
        if not metadata.get(key):
            problems.append(f"metadata is missing required '{key}'")
    for index, result in enumerate(root.get("results") or []):
        for key in ("uuid", "title", "description", "start", "reviewed-controls"):
            if not result.get(key):
                problems.append(f"results[{index}] is missing required '{key}'")
        for observation in result.get("observations") or []:
            for key in ("uuid", "description", "methods", "collected"):
                if not observation.get(key):
                    problems.append(
                        f"observation {observation.get('uuid', '?')} is missing '{key}'"
                    )
        for finding in result.get("findings") or []:
            for key in ("uuid", "title", "description", "target"):
                if not finding.get(key):
                    problems.append(f"finding {finding.get('uuid', '?')} is missing '{key}'")
            target = finding.get("target") or {}
            if target.get("type") not in ("statement-id", "objective-id"):
                problems.append(f"finding target type {target.get('type')!r} is not an OSCAL value")
            state = (target.get("status") or {}).get("state")
            if state not in ("satisfied", "not-satisfied"):
                problems.append(f"finding target status state {state!r} is not an OSCAL value")
    return problems
