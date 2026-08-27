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
import math
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

TITLE = "Cryptographic Bill of Materials"

_FILE_COLUMNS = '<colgroup><col><col style="width:20mm"><col style="width:20mm"></colgroup>'
"""Column widths for the finding tables.

A `colgroup`, not widths on the `th`s: under `table-layout: fixed` the widths
come from the *first* row, and the first row here is a single `colspan=3`
file-identity cell. With no colgroup the three columns split evenly, the asset
column lands around 180px, and the nested evidence table - whose own fixed
columns total more than that - overflows it and collapses the description to
one character per line. A colgroup outranks the first row, so the identity
header can span without destroying the layout underneath it."""

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

_UNSTATED_LEVEL = "Not stated"
"""Bucket for a finding whose document states no quantum security level.

It has to be a bar like any other. Dropping it left the chart totalling less
than the "Findings" metric printed directly above it, which is the class of
defect this report exists in order not to have."""

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
        head = self._running_head()
        body = "\n".join(
            [
                _sheet(head, self._cover(), page_break=True, extra="cover"),
                _sheet(head, self._summary(), page_break=True),
                _sheet(head, self._body()),
            ]
        )
        css = resources.files(__package__).joinpath("report.css").read_text(encoding="utf-8")
        title = self._scan_root() or TITLE
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} - {escape(TITLE.lower())}</title>\n"
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
        # The block is one flex child so it can centre in whatever height is
        # left between the running head and the claim, which stays at the foot.
        return (
            '<div class="cover-block">'
            f'<h1 class="doc-title">{escape(TITLE)}</h1>\n'
            '<p class="field-label">Directory scanned</p>'
            f'<p class="scan-root">{escape(self._scan_root() or PLACEHOLDER)}</p>\n'
            f'<table class="provenance">{cells}</table></div>\n'
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
        # A table, not four padded cards. The cards were the one element on
        # the page that spent a lot of paper to carry four integers, and this
        # report is read next to a migration backlog, not on a wall.
        labels = "".join(f"<th>{escape(label)}</th>" for label, _, _ in metrics)
        values = "".join(
            f'<td class="figure{" danger" if danger else ""}">{escape(value)}</td>'
            for _, value, danger in metrics
        )
        return (
            f'<section><h2>Summary</h2>\n<table class="data metrics">'
            f"<thead><tr>{labels}</tr></thead><tbody><tr>{values}</tr></tbody></table>\n"
            f"{self._level_chart()}</section>\n"
            f"{self._coverage()}"
        )

    def _level_chart(self) -> str:
        """Every finding gets a bar, including the ones stating no level.

        The chart therefore totals the "Findings" metric printed above it. An
        earlier version charted only assets carrying a level, so a scan whose
        findings were all CryptoAPI - a generic API with no algorithm, hence no
        level - drew no chart at all beside a non-zero count.
        """
        counts: dict[int | None, int] = {}
        for asset in self.crypto:
            level = _level(asset)
            counts[level] = counts.get(level, 0) + 1
        if not counts:
            return ""

        ordered = sorted(counts.items(), key=_level_order)
        rows = "".join(
            f'<tr class="{_level_class(level)}">'
            f'<td class="swatch-cell"><span class="swatch {_level_fill(level)}"></span></td>'
            f'<td class="level-name">{escape(_level_name(level))}</td>'
            f'<td class="level-count">{count}</td></tr>'
            for level, count in ordered
        )
        pie = _pie(
            [(_level_fill(level), count) for level, count in ordered],
            "Findings by NIST quantum security level",
        )
        return (
            '<p class="chart-label">Findings by NIST quantum security level</p>\n'
            f'<div class="chart-row">{pie}'
            f'<table class="data levels">{rows}</table></div>'
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
        pie = _pie(
            [(_fill(status), count) for status, count in counts.items()],
            "Analysis coverage by status",
        )
        rows = "".join(
            f'<tr><td class="swatch-cell"><span class="swatch {_fill(status)}"></span></td>'
            f'<td>{escape(status)}</td><td class="num">{count}</td>'
            f"<td>{escape(_STATUS_MEANING.get(status, 'not a status this version records'))}"
            "</td></tr>"
            for status, count in counts.items()
        )
        return (
            "<section><h2>Analysis coverage</h2>\n"
            f'<div class="chart-row">{pie}'
            '<table class="data"><thead><tr><th style="width:7mm"></th><th>Status</th>'
            '<th style="width:14mm">Files</th><th>Meaning for this report</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>\n"
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
        return _file_table(f'<span class="file-path">{escape(label)}</span>', rows)

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
        return _file_table(self._file_head(component), rows)

    def _file_head(self, component: Mapping[str, Any]) -> str:
        facts = [
            _prop(component, "machine") or PLACEHOLDER,
            f"sha256 {_short_hash(_sha256(component))}",
        ]
        status = _prop(component, "analysis")
        badge = f'<span class="badge">{escape(_status_label(component))}</span>' if status else ""
        # The badge is a sibling of the path, not inside it: the path carries
        # `word-break: break-all`, so a badge inline within it is pushed onto a
        # line of its own as soon as the path wraps, which is most of them.
        return (
            f'<span class="file-id"><span class="file-path">{escape(_path(component))}</span>'
            f"{badge}</span>"
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
        parsed = [_evidence_row(occurrence) for occurrence in occurrences]
        # Import evidence carries no offset: an import is a table entry, not a
        # byte position. The column only exists when something fills it, since
        # a boxed empty cell on every row reads as a value that failed to
        # render rather than as one that was never there.
        with_offsets = any(offset for *_, offset in parsed)
        rows = "".join(
            "<tr>"
            f'<td class="detector">{escape(detector)}</td>'
            f'<td class="signature">{escape(signature)}</td>'
            f"<td>{escape(description)}</td>"
            + (f'<td class="offset">{escape(offset)}</td>' if with_offsets else "")
            + "</tr>"
            for detector, signature, description, offset in parsed
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

    def _provenance(self) -> str:
        """Tool version, signature version, CBOM digest.

        This is what lets a reader diff the bytes the report was rendered from,
        so it appears on every sheet as a running head and again in the running
        footer. Twice is deliberate: the footer is `position: fixed`, which is
        what carries it onto the *continuation* pages of a long findings
        section, and that is the mechanism print engines disagree about.
        """
        parts = [
            self._tool(),
            f"signatures {_meta_prop(self.document, 'signature-version') or PLACEHOLDER}",
            f"cbom {_short_hash(self.digest)}",
        ]
        return escape(" · ".join(parts))

    def _running_head(self) -> str:
        root = self._scan_root() or TITLE
        return (
            '<div class="running-head">'
            f'<span class="rh-root">{escape(root)}</span>'
            f"<span>{self._provenance()}</span></div>"
        )

    def _footer(self) -> str:
        return f'<div class="footer">{self._provenance()}</div>'

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


def _file_table(head: str, rows: str) -> str:
    return (
        f'<table class="data file">{_FILE_COLUMNS}<thead>'
        f'<tr><th colspan="3" class="file-head">'
        f'<div class="file-head-row">{head}</div></th></tr>'
        "<tr><th>Asset</th><th>Level</th><th>Conf.</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _sheet(head: str, content: str, *, page_break: bool = False, extra: str = "") -> str:
    classes = " ".join(filter(None, ["sheet", "page-break" if page_break else "", extra]))
    return f'<div class="{classes}">\n{head}\n{content}\n</div>'


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


def _pie(slices: Sequence[tuple[str, int]], label: str) -> str:
    """A pie as inert SVG. No script, no image, no external anything.

    Slice geometry is computed from running totals rather than by accumulating
    each sweep, so the last slice closes on the first and rounding cannot leave
    a hairline wedge of blank paper that reads as a category nobody counted.

    The fill classes are the same ones the legend swatches use, so a slice and
    its row cannot come to disagree about which colour means what.
    """
    drawn = [(fill, count) for fill, count in slices if count > 0]
    total = sum(count for _, count in drawn)
    if not total:
        return ""

    radius = 50.0
    if len(drawn) == 1:
        # A single slice is the whole circle, and an arc from a point back to
        # itself draws nothing at all.
        body = f'<circle cx="0" cy="0" r="{radius}" class="{drawn[0][0]}"/>'
    else:
        paths = []
        seen = 0
        for fill, count in drawn:
            start = _pie_point(seen, total, radius)
            seen += count
            end = _pie_point(seen, total, radius)
            large = 1 if count * 2 > total else 0
            paths.append(
                f'<path class="{fill}" d="M0 0L{start}A{radius} {radius} 0 {large} 1 {end}Z"/>'
            )
        body = "".join(paths)
    return (
        f'<svg class="pie" viewBox="-52 -52 104 104" role="img" aria-label="{escape(label)}">'
        f"{body}</svg>"
    )


def _pie_point(seen: int, total: int, radius: float) -> str:
    """Position on the circle after `seen` of `total`, clockwise from twelve."""
    angle = 2 * math.pi * seen / total - math.pi / 2
    return f"{radius * math.cos(angle):.2f} {radius * math.sin(angle):.2f}"


def _level_fill(level: int | None) -> str:
    """Darkest at level 0, lightening as the level rises, so the weight of the
    chart sits where the migration work is."""
    if level is None:
        return "fill-other"
    return f"fill-level-{level}" if 0 <= level <= 6 else "fill-other"


def _level_name(level: int | None) -> str:
    return _UNSTATED_LEVEL if level is None else _LEVEL_NAMES.get(level, f"Level {level}")


def _level_class(level: int | None) -> str:
    return "level-unknown" if level is None else f"level-{level}"


def _level_order(item: tuple[int | None, int]) -> tuple[int, int]:
    """Numeric levels ascending, then the unstated bucket last."""
    return (1, 0) if item[0] is None else (0, item[0])


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
