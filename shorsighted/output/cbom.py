"""CycloneDX 1.6 serializer, hand-rolled (D-10, design §7).

No `cyclonedx-python-lib`. The slice of the spec this tool touches is small and
stable, keeping the runtime dependency budget at `pefile` alone was a stated
goal, and the conformance guarantee the library would give is instead bought by
CI validating every emitted document against the official 1.6 schema (AC-5).
That trade only holds while the schema check actually runs — if it is ever
skipped, this module becomes a liability rather than a saving.

Two rules shape what goes in the document:

Honesty (FR-13). Optional fields are omitted rather than guessed. The spec has
somewhere to put `executionEnvironment` and `mode`; static analysis of a PE
cannot establish either, so they stay absent. An omitted field reads as "not
established". A wrong one reads as fact.

Silence about secrets (non-goal 9). Occurrences carry offsets, never bytes. A
CBOM that quotes key material is itself a leak, and this tool's whole posture is
that it reports where material lives without lifting it out.
"""

import json
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from shorsighted.core.model import (
    AnalysisStatus,
    Evidence,
    Finding,
    ScannedFile,
    ScanResult,
)

SPEC_VERSION = "1.6"

_MACHINE_PLATFORM = {"x86": "x86_32", "x64": "x86_64"}
"""PE machine word to the spec's `implementationPlatform` enum. This one we can
actually support: it comes straight out of the COFF header."""

_PROPERTY_NAMESPACE = "shorsighted"


def serialize(result: ScanResult, *, reproducible: bool = False, indent: int | None = 2) -> str:
    """Render a scan as CycloneDX 1.6 JSON."""
    return json.dumps(build(result, reproducible=reproducible), indent=indent) + "\n"


def build(result: ScanResult, *, reproducible: bool = False) -> dict[str, object]:
    """Build the document as plain dicts.

    Arrays are sorted here regardless of `reproducible`, because determinism is
    free and a diffable CBOM is worth having by default. `--reproducible` (NFR-6)
    additionally drops the two fields that cannot be deterministic: the random
    serial number and the wall-clock timestamp.
    """
    components: list[dict[str, object]] = []
    dependencies: list[dict[str, object]] = []
    taken: set[str] = set()

    for scanned in sorted(result.files, key=lambda f: f.path.as_posix()):
        file_ref = _unique(f"file:{scanned.path.as_posix()}", taken)
        components.append(_file_component(scanned, file_ref))

        asset_refs = []
        for finding in _sorted_findings(scanned.findings):
            asset_ref = _unique(f"crypto:{scanned.path.as_posix()}/{_slug(finding)}", taken)
            components.append(_crypto_component(scanned, finding, asset_ref))
            asset_refs.append(asset_ref)

        dependencies.append({"ref": file_ref, "dependsOn": sorted(asset_refs)})

    document: dict[str, object] = {"bomFormat": "CycloneDX", "specVersion": SPEC_VERSION}
    if not reproducible:
        document["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    document["version"] = 1
    document["metadata"] = _metadata(result, reproducible=reproducible)
    document["components"] = components
    document["dependencies"] = dependencies
    return document


def _metadata(result: ScanResult, *, reproducible: bool) -> dict[str, object]:
    metadata: dict[str, object] = {}
    if not reproducible:
        metadata["timestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    metadata["tools"] = {
        "components": [
            {"type": "application", "name": "shorsighted", "version": result.tool_version}
        ]
    }
    metadata["properties"] = _properties(
        {
            "signature-version": result.signature_version,
            "skipped-non-pe": str(result.skipped_non_pe),
            "scan-root": result.scan_root,
            # What was asked of the scan, not what it found. A reader holding
            # only this document cannot otherwise tell a clean result from a
            # narrow one: `--detectors imports --min-confidence 0.9` and a full
            # scan produce identical-looking emptiness (FR-13).
            "detectors-run": ",".join(result.detectors_run),
            "min-confidence": f"{result.min_confidence:.2f}",
        }
    )
    return metadata


def _file_component(scanned: ScannedFile, bom_ref: str) -> dict[str, object]:
    """One component per file scanned, findings or not.

    A file with nothing found still appears, carrying its analysis status. That
    is FR-13 expressed in the data model: a reader must be able to tell "looked
    and saw nothing" from "could not look", and omitting clean files would
    silently collapse the two.
    """
    component: dict[str, object] = {
        "type": "file",
        "bom-ref": bom_ref,
        "name": scanned.path.name,
    }
    if scanned.sha256:
        component["hashes"] = [{"alg": "SHA-256", "content": scanned.sha256}]

    properties = {"analysis": scanned.status.value, "path": scanned.path.as_posix()}
    if scanned.error_class:
        properties["error-class"] = scanned.error_class
    if scanned.status is not AnalysisStatus.ERROR:
        properties["machine"] = scanned.machine
    component["properties"] = _properties(properties)
    return component


def _crypto_component(scanned: ScannedFile, finding: Finding, bom_ref: str) -> dict[str, object]:
    crypto: dict[str, object] = {"assetType": finding.asset_type.value}

    algorithm_properties = _compact(
        {
            "primitive": finding.primitive,
            "parameterSetIdentifier": finding.parameter_set,
            "implementationPlatform": _MACHINE_PLATFORM.get(scanned.machine),
            "nistQuantumSecurityLevel": finding.nist_quantum_level,
        }
    )
    if algorithm_properties:
        crypto["algorithmProperties"] = algorithm_properties
    if finding.oid:
        crypto["oid"] = finding.oid

    component: dict[str, object] = {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": finding.algorithm or finding.family or "unknown",
        "cryptoProperties": crypto,
    }

    occurrences = _occurrences(scanned, finding.evidence)
    if occurrences:
        component["evidence"] = {"occurrences": occurrences}

    component["properties"] = _properties(
        {
            "confidence": f"{finding.confidence:.2f}",
            "detectors": ",".join(sorted({e.detector for e in finding.evidence})),
        }
    )
    return component


def _occurrences(scanned: ScannedFile, evidence: Iterable[Evidence]) -> list[dict[str, object]]:
    """Evidence as spec occurrences.

    `confidence` rides in `properties` rather than here: CycloneDX's
    evidence-confidence fields are about component *identity* — how sure we are
    this is the component we say it is — which is a different question from how
    sure we are the algorithm is present at all.
    """
    occurrences: list[dict[str, object]] = []
    location = scanned.path.as_posix()

    for item in evidence:
        context = f"{item.detector}/{item.signature_id}: {item.description}"
        if not item.offsets:
            occurrences.append(
                _compact(
                    {
                        "location": location,
                        "symbol": item.symbol,
                        "additionalContext": context,
                    }
                )
            )
            continue
        # One occurrence per offset: the spec's offset field is singular, and a
        # reader chasing a finding wants every place to look, not the first.
        occurrences.extend(
            _compact(
                {
                    "location": location,
                    "offset": offset,
                    "symbol": item.symbol,
                    "additionalContext": context,
                }
            )
            for offset in item.offsets
        )

    return sorted(occurrences, key=_occurrence_order)


def _occurrence_order(occurrence: dict[str, object]) -> tuple[str, int]:
    offset = occurrence.get("offset")
    return (
        str(occurrence.get("additionalContext", "")),
        offset if isinstance(offset, int) else -1,
    )


def _properties(values: dict[str, str]) -> list[dict[str, str]]:
    """Namespaced `shorsighted:*` properties, sorted by name.

    Everything this tool wants to say that the spec has no field for lives here
    rather than in an invented top-level key, so the document stays valid
    CycloneDX for consumers that ignore us entirely.
    """
    return [
        {"name": f"{_PROPERTY_NAMESPACE}:{name}", "value": value}
        for name, value in sorted(values.items())
        if value
    ]


def _compact(mapping: dict[str, object]) -> dict[str, object]:
    """Drop unset fields. Absent means "not established", never "no"."""
    return {key: value for key, value in mapping.items() if value is not None}


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.family or "",
            f.algorithm or "",
            f.parameter_set or "",
            -f.confidence,
        ),
    )


def _slug(finding: Finding) -> str:
    name = finding.algorithm or finding.family or "unknown"
    return "".join(character if character.isalnum() else "-" for character in name).lower()


def _unique(candidate: str, taken: set[str]) -> str:
    """Guarantee bom-ref uniqueness, which the spec requires.

    ponytail: two findings for one family in one file can still both arrive
    here — an OpenSSL import and a CNG string both saying AES — and get refs
    `.../aes` and `.../aes-2`. Slice 6's merge stage collapses those into one
    component with combined evidence (D-14), which is the real fix; this
    suffix only stops a duplicate ref producing an invalid document until then.
    """
    if candidate not in taken:
        taken.add(candidate)
        return candidate
    index = 2
    while f"{candidate}-{index}" in taken:
        index += 1
    unique = f"{candidate}-{index}"
    taken.add(unique)
    return unique
