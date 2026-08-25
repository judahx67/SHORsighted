"""Corroboration and dedup across detectors (FR-10, design §6).

This stage exists as a stage. Detectors could merge their own results and the
code would be shorter, but the evaluation reports per-detector precision and
recall (NFR-5), and that needs each detector's raw independent output. Merging
inside a detector would destroy the measurement before it could be taken — which
is D-13, and the reason `.importlinter` forbids detectors from importing each
other.

What merging buys, concretely: an OpenSSL `AES_encrypt` import and an AES S-box
in `.rdata` are two independent observations of the same fact. Reported
separately they are two components claiming AES in one file, which is noise and
invalid CBOM besides. Merged they are one component with two kinds of evidence
and higher confidence than either alone, which is what FR-10 asks for and what a
reviewer actually wants to read.
"""

from collections.abc import Sequence

from shorsighted.core.model import Evidence, Finding, ScannedFile, ScanResult

CONFIDENCE_CEILING = 0.99
"""Never 1.0. The tool is reasoning statically about a binary it did not build,
and a claim of certainty would be false however much evidence agreed."""


def merge_result(result: ScanResult, corroboration_bonus: float) -> ScanResult:
    """Apply the merge rules to every file in a scan."""
    from dataclasses import replace

    return replace(
        result,
        files=tuple(
            replace(scanned, findings=merge_findings(scanned.findings, corroboration_bonus))
            for scanned in result.files
        ),
    )


def merge_findings(findings: Sequence[Finding], corroboration_bonus: float) -> tuple[Finding, ...]:
    """Collapse findings about the same family into one, per design §6.

    Grouped by `family` rather than `algorithm` because that is the level at
    which two detectors can agree: the import table may say only "AES" while a
    UTF-16 string says "AES" and a constant table says "AES" — same family,
    different specificity. The most specific label wins for the component name
    (`AES-256-GCM` subsumes `AES`), and every observation is kept as evidence.
    """
    grouped: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        key = _merge_key(finding)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)

    return tuple(_combine(grouped[key], corroboration_bonus) for key in order)


def _merge_key(finding: Finding) -> str:
    """Findings merge when they name the same family in the same file.

    Asset type is part of the key: a `certificate` and an `algorithm` that
    happen to share a family name are different claims about different things,
    and collapsing them would be a lie of category rather than of degree.
    """
    return f"{finding.asset_type.value}/{finding.family or finding.algorithm or '?'}"


def _combine(group: list[Finding], corroboration_bonus: float) -> Finding:
    if len(group) == 1:
        return group[0]

    best = _most_specific(group)
    detectors = {evidence.detector for finding in group for evidence in finding.evidence}

    confidence = max(finding.confidence for finding in group)
    if len(detectors) > 1:
        # Independent detectors agreeing is the corroboration FR-10 means.
        # Two hits from the *same* detector are one kind of observation seen
        # twice, which is not the same thing and gets no bonus.
        confidence = min(CONFIDENCE_CEILING, confidence + corroboration_bonus)

    return Finding(
        asset_type=best.asset_type,
        algorithm=best.algorithm,
        family=best.family,
        primitive=best.primitive or _first(group, "primitive"),
        parameter_set=best.parameter_set or _first(group, "parameter_set"),
        oid=best.oid or _first(group, "oid"),
        nist_quantum_level=_quantum_level(group),
        confidence=confidence,
        evidence=_dedup_evidence(group),
    )


def _most_specific(group: list[Finding]) -> Finding:
    """The finding whose label a reader should see.

    A named algorithm beats a bare family: "AES-256-GCM" tells a migration
    planner something "AES" does not. Confidence breaks ties, then the label
    itself so the choice never depends on detector ordering (NFR-6).
    """
    return max(
        group,
        key=lambda f: (
            f.algorithm is not None,
            f.parameter_set is not None,
            len(f.algorithm or ""),
            f.confidence,
            f.algorithm or "",
        ),
    )


def _first(group: list[Finding], attribute: str) -> str | None:
    """First non-empty value across the group, in deterministic order.

    One detector often knows a field another does not — a UTF-16 string names
    the curve, the import that corroborated it does not — and dropping that
    would make the merged finding poorer than its parts.
    """
    for finding in sorted(group, key=lambda f: (-f.confidence, f.algorithm or "")):
        value = getattr(finding, attribute)
        if value:
            return str(value)
    return None


def _quantum_level(group: list[Finding]) -> int | None:
    """The most alarming level any contributor reported.

    Deliberately not the average or the most specific finding's value. If any
    evidence says a file contains something Shor breaks, that is the fact the
    migration planner needs, and a merge that could soften it would be working
    against the tool's purpose.
    """
    levels = [f.nist_quantum_level for f in group if f.nist_quantum_level is not None]
    if not levels:
        return None
    return min(levels)


def _dedup_evidence(group: list[Finding]) -> tuple[Evidence, ...]:
    """Every observation, once each, in a stable order.

    Two detectors can produce byte-identical evidence records; a reader gains
    nothing from seeing the same line twice.
    """
    seen: dict[tuple[str, str, str, tuple[int, ...], str | None], Evidence] = {}
    for finding in group:
        for evidence in finding.evidence:
            key = (
                evidence.detector,
                evidence.signature_id,
                evidence.description,
                evidence.offsets,
                evidence.symbol,
            )
            seen.setdefault(key, evidence)
    return tuple(sorted(seen.values(), key=lambda e: (e.detector, e.signature_id, e.offsets)))


def suppress_below(scanned: ScannedFile, minimum: float) -> ScannedFile:
    """Drop findings under `minimum` confidence (FR-12, US-4).

    Applied after merging on purpose: corroboration can lift a finding above the
    threshold, and filtering first would discard the evidence that would have
    raised it.
    """
    from dataclasses import replace

    return replace(
        scanned,
        findings=tuple(f for f in scanned.findings if f.confidence >= minimum),
    )
