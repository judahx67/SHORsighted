"""Human-readable summary table (FR-15).

No stability guarantee in v0.1: the CBOM JSON is the contract, this is for
reading over someone's shoulder. Written with `str.format` and nothing else,
because a terminal table is not worth a runtime dependency.

Strictly ASCII, deliberately. NFR-4 has this running on Windows, Linux, and
macOS, and a Windows console on a legacy codepage will mangle or refuse a
U+2026 the moment it meets one. Nothing here is worth an encoding crash.

The one rule this output must never break is FR-13. A file with no findings
prints "none detected" together with whatever caveats apply, never "no
cryptography present" — those are different claims, and only one of them is
true.
"""

from collections.abc import Sequence

from shorsighted.core.model import (
    AnalysisStatus,
    AssetType,
    Finding,
    ScannedFile,
    ScanResult,
)

_KIND = {
    AssetType.ALGORITHM: "algorithm",
    AssetType.CERTIFICATE: "cert",
    AssetType.RELATED_MATERIAL: "material",
}
"""What kind of claim a row makes.

Without this column a certificate appears under a heading that says ALGORITHM,
which reads as "this binary performs X.509" - a category error, and exactly the
conflation D-5 exists to prevent.
"""

_STATUS_NOTE = {
    AnalysisStatus.DEGRADED_PACKED: (
        "this binary looks packed, so absence of findings means very little here"
    ),
    AnalysisStatus.UNSUPPORTED_MANAGED: (
        "managed (.NET) assembly: its cryptography lives in CLR metadata, which "
        "this version does not read"
    ),
}


def render(result: ScanResult) -> str:
    """Render a whole scan."""
    blocks = [_render_file(scanned) for scanned in result.files]
    blocks.append(_render_footer(result))
    return "\n".join(blocks)


def _render_file(scanned: ScannedFile) -> str:
    lines = [f"{scanned.path}"]

    if scanned.status is AnalysisStatus.ERROR:
        lines.append(f"  could not analyse: {scanned.error_class}")
        return "\n".join(lines) + "\n"

    lines.append(f"  {scanned.machine}  {scanned.size:,} bytes  sha256:{scanned.sha256[:16]}...")

    note = _STATUS_NOTE.get(scanned.status)
    if note:
        lines.append(f"  note: {note}")

    if not scanned.findings:
        lines.append("  none detected" + (" (see note above)" if note else ""))
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.extend(_render_table(scanned.findings))
    return "\n".join(lines) + "\n"


def _render_table(findings: Sequence[Finding]) -> list[str]:
    rows = [_row(finding) for finding in _sorted(findings)]
    headers = ("ASSET", "KIND", "PRIMITIVE", "QUANTUM", "CONF", "EVIDENCE")
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        for column in range(len(headers))
    ]

    def line(cells: tuple[str, ...]) -> str:
        padded = [cell.ljust(widths[column]) for column, cell in enumerate(cells)]
        return "  " + "  ".join(padded).rstrip()

    return [
        line(headers),
        "  " + "  ".join("-" * width for width in widths),
        *(line(r) for r in rows),
    ]


def _row(finding: Finding) -> tuple[str, str, str, str, str, str]:
    return (
        finding.algorithm or finding.family or "unknown",
        _KIND[finding.asset_type],
        finding.primitive or "-",
        _quantum(finding),
        f"{finding.confidence:.2f}",
        _evidence_summary(finding),
    )


def _quantum(finding: Finding) -> str:
    """FR-14's headline number for the migration planner.

    Level 0 is called out in words rather than left as a digit, because "0" in
    a column of small integers reads like "least severe" when it means the
    opposite: broken outright by Shor's algorithm.
    """
    if finding.nist_quantum_level is None:
        return "n/a"
    if finding.nist_quantum_level == 0:
        return "0 BROKEN"
    return str(finding.nist_quantum_level)


def _evidence_summary(finding: Finding) -> str:
    if not finding.evidence:
        return "-"
    first = finding.evidence[0]
    extra = len(finding.evidence) - 1
    detail = first.symbol or (f"@{first.offsets[0]:#x}" if first.offsets else first.signature_id)
    summary = f"{first.detector}/{first.signature_id} {detail}"
    return f"{summary} (+{extra} more)" if extra else summary


def _sorted(findings: Sequence[Finding]) -> list[Finding]:
    """Most alarming first: quantum-broken, then by confidence.

    Deterministic all the way down, because NFR-6 wants byte-identical output
    for identical input and a stable order is free here.
    """
    return sorted(
        findings,
        key=lambda f: (
            f.nist_quantum_level != 0,
            -f.confidence,
            f.algorithm or f.family or "",
        ),
    )


def _render_footer(result: ScanResult) -> str:
    scanned = len(result.files)
    errored = sum(1 for f in result.files if f.status is AnalysisStatus.ERROR)
    total = sum(len(f.findings) for f in result.files)
    broken = sum(
        1 for f in result.files for finding in f.findings if finding.nist_quantum_level == 0
    )

    counts = f"{scanned} file(s) scanned, {errored} errored"
    if result.skipped_non_pe:
        # FR-1 skips non-PE files silently, but "we looked at 4 and ignored
        # 9,960" is what tells a reader whether the scan covered what they meant.
        counts += f", {result.skipped_non_pe} non-PE skipped"

    lines = [
        f"{counts}, {total} finding(s), {broken} quantum-broken",
        f"signatures {result.signature_version}  |  shorsighted {result.tool_version}",
        "findings are evidence of presence, not proof of use",
    ]
    return "\n".join(lines)
