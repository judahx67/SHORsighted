"""Printable evidence report (design §1-§8).

Input is a CycloneDX 1.6 document as text, never a `ScanResult`. That is the
whole architecture of this module: with no scanner state in reach, rendering a
CBOM from another tool is the same code path as rendering our own, and cannot
silently start depending on something only our scans produce.

No JavaScript is emitted. The document is inert HTML plus CSS, printed to PDF
by the browser. That makes `escape()` on every interpolation the entire attack
surface, which matters more here than it looks: filenames come off a scanned
tree, so they are attacker-controlled strings landing in markup.

Bar widths are computed here and emitted as literal percentages. Client-side
math would need script, and would break the byte-exact golden file.
"""

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from html import escape
from importlib import resources
from typing import Any

PLACEHOLDER = "—"
"""Em dash. A missing value is shown, never hidden — a blank cell reads as zero
and the layout must not change shape between documents (design §6)."""

APPENDIX_LIMIT = 200
"""Clean files listed individually before appendix A collapses to a count."""

NAMESPACE = "shorsighted"

CLAIM = (
    "Findings show evidence of presence, not proof of use. No detections means "
    "nothing was found by the detectors and signatures listed above, not that a "
    "file is free of cryptography."
)

_STATUS_MEANING = {
    "ok": "Fully analysed",
    "degraded-packed": "Packed, reduced coverage",
    "unsupported-managed": ".NET assemblies, not analysed in v0.1",
    "error": "Could not be parsed, listed in section 3",
}

_LEVEL_NAMES = {
    0: "Level 0, broken",
    1: "Level 1",
    2: "Level 2",
    3: "Level 3",
    4: "Level 4",
    5: "Level 5",
}


def render(document_json: str, *, appendix_limit: int = APPENDIX_LIMIT) -> str:
    """Render a CycloneDX 1.6 document to a self-contained HTML report.

    Takes the serialized text rather than the parsed object so the CBOM digest
    printed on the report is over the exact bytes a reader can diff, not over a
    re-serialization that might differ in whitespace.
    """
    document = json.loads(document_json)
    if not isinstance(document, dict):
        raise ValueError("not a CycloneDX document: top level is not an object")
    digest = hashlib.sha256(document_json.encode("utf-8")).hexdigest()
    return _Report(document, digest, appendix_limit).render()


class _Report:
    def __init__(self, document: Mapping[str, Any], digest: str, appendix_limit: int) -> None:
        self.document = document
        self.digest = digest
        self.appendix_limit = appendix_limit

        components = _sequence(document.get("components"))
        self.files = [c for c in components if c.get("type") == "file"]

        # Every crypto component is a finding, whether or not it can be joined
        # to a file. `bom-ref` is optional in CycloneDX and `dependencies` may
        # be absent entirely, so counting through the join would silently drop
        # real assets out of a foreign document - and would let "Findings" and
        # "Quantum-vulnerable" print different totals for the same set.
        self.crypto = [c for c in components if c.get("type") == "cryptographic-asset"]
        self.assets = {ref: c for c in self.crypto if (ref := c.get("bom-ref"))}
        self.by_file = {
            ref: [self.assets[d] for d in _strings(entry.get("dependsOn")) if d in self.assets]
            for entry in _sequence(document.get("dependencies"))
            if (ref := entry.get("ref"))
        }
        joined = {id(asset) for assets in self.by_file.values() for asset in assets}
        self.unattributed = [c for c in self.crypto if id(c) not in joined]

        self.statuses = [_prop(f, "analysis") for f in self.files]
        self.has_status = any(s is not None for s in self.statuses)

    # --- document -----------------------------------------------------------

    def render(self) -> str:
        body = "\n".join(
            [
                _sheet(self._cover(), page_break=True),
                _sheet(self._summary(), page_break=True),
                _sheet(self._body()),
            ]
        )
        css = resources.files(__package__).joinpath("report.css").read_text(encoding="utf-8")
        title = self._scan_root() or "Evidence report"
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} - cryptographic bill of materials</title>\n"
            f"<style>\n{css}</style>\n</head>\n<body>\n"
            f"{body}\n"
            f"{self._footer()}\n"
            "</body>\n</html>\n"
        )

    # --- page 1 -------------------------------------------------------------

    def _cover(self) -> str:
        # Paired explicitly rather than sliced into columns: index arithmetic
        # over this list would drop a row silently the first time someone adds
        # a seventh, and a provenance table that quietly loses a field is worse
        # than one that looks lopsided.
        rows = [
            (
                ("Generated", _metadata_value(self.document, "timestamp") or PLACEHOLDER),
                ("Tool", self._tool()),
            ),
            (
                ("Detectors", _meta_prop(self.document, "detectors-run") or PLACEHOLDER),
                ("Signatures", _meta_prop(self.document, "signature-version") or PLACEHOLDER),
            ),
            (
                ("Min confidence", _meta_prop(self.document, "min-confidence") or PLACEHOLDER),
                ("Source CBOM", f"sha256 {_short_hash(self.digest)}"),
            ),
        ]
        cells = "".join(
            "<tr>"
            + "".join(f"<th>{escape(label)}</th><td>{escape(value)}</td>" for label, value in pair)
            + "</tr>"
            for pair in rows
        )
        return (
            '<p class="kind">Cryptographic bill of materials, evidence report</p>\n'
            f'<h1 class="scan-root">{escape(self._scan_root() or PLACEHOLDER)}</h1>\n'
            f'<table class="provenance">{cells}</table>\n'
            f'<p class="claim">{escape(CLAIM)}</p>'
        )

    # --- page 2 -------------------------------------------------------------

    def _summary(self) -> str:
        findings = len(self.crypto)
        with_findings = sum(1 for v in self.by_file.values() if v)
        vulnerable = sum(1 for asset in self.crypto if _level(asset) == 0)

        metrics = [
            ("Files scanned", str(len(self.files)), False),
            ("Files with findings", str(with_findings), False),
            ("Findings", str(findings), False),
            ("Quantum-vulnerable", str(vulnerable), vulnerable > 0),
        ]
        cards = "".join(
            f'<div class="metric"><div class="metric-label">{escape(label)}</div>'
            f'<div class="metric-value{" danger" if danger else ""}">{escape(value)}</div></div>'
            for label, value, danger in metrics
        )
        return (
            f'<section><h2>Summary</h2>\n<div class="metrics">{cards}</div>\n'
            f"{self._level_chart()}</section>\n"
            f"{self._coverage()}"
        )

    def _level_chart(self) -> str:
        counts: dict[int, int] = {}
        for asset in self.crypto:
            level = _level(asset)
            if level is not None:
                counts[level] = counts.get(level, 0) + 1
        if not counts:
            return ""

        # Scaled against the largest count, not the total, so a category of one
        # is still a visible bar rather than a hairline nobody reads.
        largest = max(counts.values())
        rows = "".join(
            f'<tr class="level-{level}">'
            f'<td class="level-name">{escape(_LEVEL_NAMES.get(level, f"Level {level}"))}</td>'
            f'<td><div class="bar" style="width:{count / largest * 100:.1f}%"></div></td>'
            f'<td class="level-count">{count}</td></tr>'
            for level, count in sorted(counts.items())
        )
        return (
            '<p class="chart-label">Findings by NIST quantum security level</p>\n'
            f'<table class="levels">{rows}</table>'
        )

    def _coverage(self) -> str:
        if not self.has_status:
            return (
                "<section><h2>Analysis coverage</h2>"
                f'<p class="empty">{escape("analysis coverage not recorded in this document")}'
                "</p></section>"
            )

        # Known statuses first, in severity order, then anything else the
        # document carries. A status this build does not recognise still has to
        # appear: dropping it would leave the bar covering less than the files
        # it claims to describe, which is a coverage chart that under-reports
        # exactly where coverage is least understood.
        extra = sorted({s for s in self.statuses if s is not None and s not in _STATUS_MEANING})
        counts = {status: self.statuses.count(status) for status in (*_STATUS_MEANING, *extra)}
        total = len(self.files) or 1
        segments = "".join(
            f'<span class="{_fill(status)}" style="width:{count / total * 100:.2f}%"></span>'
            for status, count in counts.items()
            if count
        )
        rows = "".join(
            f'<tr><td><span class="swatch {_fill(status)}"></span></td>'
            f'<td>{escape(status)}</td><td class="num">{count}</td>'
            f"<td>{escape(_STATUS_MEANING.get(status, 'not a status this version records'))}"
            "</td></tr>"
            for status, count in counts.items()
        )
        return (
            "<section><h2>Analysis coverage</h2>\n"
            f'<div class="coverage">{segments}</div>\n'
            '<table class="data"><thead><tr><th style="width:8mm"></th><th>Status</th>'
            '<th style="width:16mm">Files</th><th>Meaning for this report</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>\n"
            f"{self._skipped_note()}</section>"
        )

    def _skipped_note(self) -> str:
        skipped = _meta_prop(self.document, "skipped-non-pe")
        clean = list(self._clean_files())
        parts = []
        if skipped is not None:
            parts.append(f"{skipped} non-PE files were skipped.")
        if clean and len(clean) <= self.appendix_limit:
            parts.append(
                f"{len(clean)} files were analysed with no detections and are listed in appendix A."
            )
        elif clean:
            parts.append(
                f"{len(clean)} files were analysed with no detections. Above "
                f"{self.appendix_limit} files these are not listed individually; "
                "see the CBOM JSON for the complete file inventory."
            )
        return f'<p class="note">{escape(" ".join(parts))}</p>' if parts else ""

    # --- pages 3+ -----------------------------------------------------------

    def _body(self) -> str:
        return "\n".join(
            filter(
                None,
                [
                    self._findings_section(),
                    self._notes_section(),
                    self._errors_section(),
                    self._appendix(),
                ],
            )
        )

    def _findings_section(self) -> str:
        blocks = [
            self._file_block(component, assets)
            for component in self.files
            if (assets := self.by_file.get(component.get("bom-ref", ""), []))
        ]
        if self.unattributed:
            blocks.append(self._unattributed_block())
        inner = "\n".join(blocks) if blocks else f'<p class="empty">{escape("No findings.")}</p>'
        return f"<section><h2>1. Findings by file</h2>\n{inner}</section>"

    def _unattributed_block(self) -> str:
        """Findings the document does not tie to a file.

        Our own CBOMs always tie them, so this is the foreign-document path: a
        tool that omits `dependencies`, or assets carrying no `bom-ref` to join
        on. They are counted in the summary either way, so they have to be
        listed somewhere or the page contradicts itself.
        """
        rows = "".join(self._finding_rows(asset) for asset in self.unattributed)
        label = "Findings not linked to a file in this document"
        return (
            '<table class="data file"><thead>'
            f'<tr><th colspan="3" class="file-head">'
            f'<div class="file-head-row"><span class="file-path">{escape(label)}</span></div>'
            "</th></tr>"
            '<tr><th>Asset</th><th style="width:20mm">Level</th>'
            '<th style="width:20mm">Conf.</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
        )

    def _file_block(self, component: Mapping[str, Any], assets: Sequence[Mapping[str, Any]]) -> str:
        """The file identity lives in `<thead>`, not in a heading above it.

        Design §8 wants a continued file section to name its file at the top of
        the next page, and `thead` is the only mechanism that does that without
        script: browsers repeat a table header group across page breaks, and
        repeat nothing else. A `break-inside: avoid` div is not a substitute —
        browsers ignore it once the block is taller than a page, which is
        exactly the case where the repeat is needed.
        """
        rows = "".join(self._finding_rows(asset) for asset in assets)
        return (
            '<table class="data file"><thead>'
            f'<tr><th colspan="3" class="file-head">'
            f'<div class="file-head-row">{self._file_head(component)}</div></th></tr>'
            '<tr><th>Asset</th><th style="width:20mm">Level</th>'
            '<th style="width:20mm">Conf.</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
        )

    def _file_head(self, component: Mapping[str, Any]) -> str:
        facts = [
            _prop(component, "machine") or PLACEHOLDER,
            f"sha256 {_short_hash(_sha256(component))}",
        ]
        status = _prop(component, "analysis")
        badge = f'<span class="badge">{escape(_status_label(component))}</span>' if status else ""
        return (
            f'<span class="file-path">{escape(_path(component))} {badge}</span>'
            f'<span class="file-facts">{escape(" · ".join(facts))}</span>'
        )

    def _finding_rows(self, asset: Mapping[str, Any]) -> str:
        level = _level(asset)
        level_text = str(level) if level is not None else "unknown"
        confidence = _prop(asset, "confidence") or PLACEHOLDER
        evidence = self._evidence(asset)
        return (
            f'<tr class="finding"><td><span class="asset-name">'
            f"{escape(str(asset.get('name', 'unknown')))}</span>{evidence}</td>"
            f'<td class="mono level{" zero" if level == 0 else ""}">{escape(level_text)}</td>'
            f'<td class="mono">{escape(confidence)}</td></tr>'
        )

    def _evidence(self, asset: Mapping[str, Any]) -> str:
        occurrences = _sequence(_mapping(asset.get("evidence")).get("occurrences"))
        if not occurrences:
            return f'<div class="evidence empty">{escape("no evidence recorded")}</div>'
        rows = "".join(
            "<tr>"
            f'<td class="detector">{escape(detector)}</td>'
            f'<td class="signature">{escape(signature)}</td>'
            f"<td>{escape(description)}</td>"
            f'<td class="offset">{escape(offset)}</td></tr>'
            for detector, signature, description, offset in map(_evidence_row, occurrences)
        )
        return f'<table class="evidence">{rows}</table>'

    def _notes_section(self) -> str:
        noted = [
            component
            for component in self.files
            if _prop(component, "analysis") in ("degraded-packed", "unsupported-managed")
        ]
        if not noted:
            return ""
        rows = "".join(
            f'<tr><td class="mono">{escape(_path(component))}</td>'
            f"<td>{escape(_status_label(component))}</td>"
            f"<td>{escape(_STATUS_MEANING.get(_prop(component, 'analysis') or '', ''))}</td></tr>"
            for component in noted
        )
        return (
            "<section><h2>2. Analysis notes</h2>\n"
            '<table class="data"><thead><tr><th>File</th><th style="width:45mm">Status</th>'
            "<th>Meaning</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>"
        )

    def _errors_section(self) -> str:
        errored = [c for c in self.files if _prop(c, "analysis") == "error"]
        if not errored:
            return ""
        rows = "".join(
            f'<tr><td class="mono">{escape(_path(component))}</td>'
            f"<td>{escape(_status_label(component))}</td></tr>"
            for component in errored
        )
        return (
            "<section><h2>3. Errors</h2>\n"
            '<table class="data"><thead><tr><th>File</th>'
            '<th style="width:60mm">Status</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></section>"
        )

    def _appendix(self) -> str:
        clean = list(self._clean_files())
        if not clean:
            return ""
        heading = "<h2>Appendix A. Files with no detections</h2>"
        if len(clean) > self.appendix_limit:
            return (
                f"<section>{heading}\n"
                f'<p class="empty">{escape(f"{len(clean)} files, not listed individually.")}</p>'
                "</section>"
            )
        rows = "".join(f'<tr><td class="mono">{escape(_path(c))}</td></tr>' for c in clean)
        return f'<section>{heading}\n<table class="data"><tbody>{rows}</tbody></table></section>'

    def _clean_files(self) -> Iterator[Mapping[str, Any]]:
        """Literally `status == ok AND findings == 0` (design §4, amendment 1).

        A managed assembly with no findings is unexamined, not clean, and a
        packed binary with no findings is uninformative. Routing either in here
        would make the report claim something it did not establish.
        """
        for component in self.files:
            status = _prop(component, "analysis")
            if status is not None and status != "ok":
                continue
            if not self.by_file.get(component.get("bom-ref", ""), []):
                yield component

    # --- shared -------------------------------------------------------------

    def _footer(self) -> str:
        parts = [
            self._tool(),
            f"signatures {_meta_prop(self.document, 'signature-version') or PLACEHOLDER}",
            f"cbom {_short_hash(self.digest)}",
        ]
        return f'<div class="footer">{escape(" · ".join(parts))}</div>'

    def _tool(self) -> str:
        tools = _sequence(
            _mapping(_mapping(self.document.get("metadata")).get("tools")).get("components")
        )
        for tool in tools:
            name = tool.get("name")
            if name:
                return f"{name} {tool.get('version', '')}".strip()
        return PLACEHOLDER

    def _scan_root(self) -> str:
        return _meta_prop(self.document, "scan-root") or ""


# --- document helpers -------------------------------------------------------


def _sheet(content: str, *, page_break: bool = False) -> str:
    classes = "sheet page-break" if page_break else "sheet"
    return f'<div class="{classes}">\n{content}\n</div>'


def _sequence(value: Any) -> list[Mapping[str, Any]]:
    """Foreign documents are only schema-valid, not shaped how we expect."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _fill(status: str) -> str:
    """A status with no swatch of its own borrows the neutral one, rather than
    rendering an undefined class and therefore no swatch at all."""
    return f"fill-{status}" if status in _STATUS_MEANING else "fill-other"


def _strings(value: Any) -> list[str]:
    """`dependsOn` is a list of bom-refs, not of objects."""
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _prop(component: Mapping[str, Any], name: str) -> str | None:
    for entry in _sequence(component.get("properties")):
        if entry.get("name") == f"{NAMESPACE}:{name}":
            value = entry.get("value")
            return value if isinstance(value, str) else None
    return None


def _meta_prop(document: Mapping[str, Any], name: str) -> str | None:
    return _prop(_mapping(document.get("metadata")), name)


def _metadata_value(document: Mapping[str, Any], key: str) -> str | None:
    value = _mapping(document.get("metadata")).get(key)
    return value if isinstance(value, str) else None


def _level(asset: Mapping[str, Any]) -> int | None:
    algorithm = _mapping(_mapping(asset.get("cryptoProperties")).get("algorithmProperties"))
    level = algorithm.get("nistQuantumSecurityLevel")
    return level if isinstance(level, int) and not isinstance(level, bool) else None


def _path(component: Mapping[str, Any]) -> str:
    """`name` is a basename; the full path rides in a property (design §6)."""
    path = _prop(component, "path")
    if path:
        return path
    name = component.get("name")
    return name if isinstance(name, str) else PLACEHOLDER


def _sha256(component: Mapping[str, Any]) -> str:
    for entry in _sequence(component.get("hashes")):
        if entry.get("alg") == "SHA-256" and isinstance(entry.get("content"), str):
            return str(entry["content"])
    return ""


def _short_hash(digest: str) -> str:
    return f"{digest[:4]}…{digest[-4:]}" if len(digest) >= 8 else PLACEHOLDER


def _status_label(component: Mapping[str, Any]) -> str:
    """Verbatim enum string, with the error class appended (design §7)."""
    status = _prop(component, "analysis") or PLACEHOLDER
    error_class = _prop(component, "error-class")
    return f"{status} · {error_class}" if error_class else status


def _evidence_row(occurrence: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """Split `"<detector>/<signature>: <description>"` (design §6, A-4).

    CycloneDX seals `occurrences` with `additionalProperties: false`, so the
    detector and signature id cannot travel as their own fields without failing
    the conformance gate. When the split does not match — a foreign document —
    the whole string goes in the description cell rather than being mangled into
    columns it was never shaped for.
    """
    context = occurrence.get("additionalContext")
    context = context if isinstance(context, str) else ""
    offset = occurrence.get("offset")
    offset_text = f"offset 0x{offset:X}" if isinstance(offset, int) else ""

    detector, separator, tail = context.partition("/")
    if separator:
        signature, colon, description = tail.partition(": ")
        if colon:
            return detector, signature, description, offset_text
    return "", "", context, offset_text
