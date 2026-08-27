"""Printable evidence report (design §9, UI-1 … UI-8).

The report's job is to be read by someone who did not run the scan, so most of
what matters here is whether it can mislead: a count that disagrees with the
document, a status renamed into something friendlier, an omission that is not
labelled, a filename that escapes into markup. Layout is checked by eye
(`docs/print-check.md`); everything below is checked by machine.
"""

import json
import os
import re
from pathlib import Path

import pytest

from shorsighted.core.model import AnalysisStatus
from shorsighted.core.scanner import scan_tree
from shorsighted.output import cbom, report
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import SignatureSet
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe, minimal_pe
from tools.derive_constants import aes_sbox

CSS = Path(report.__file__).with_name("report.css")


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


def ordinary_pe(**kwargs: object) -> bytes:
    return build_pe(sections=(SectionSpec(".text", b"\x90" * 512, SCN_CODE),), **kwargs)  # type: ignore[arg-type]


def mixed_tree(root: Path) -> Path:
    """The AC-4 tree: native PE with findings, managed, packed, malformed, junk."""
    root.mkdir(exist_ok=True)
    (root / "app.exe").write_bytes(
        build_pe(
            sections=(
                SectionSpec(".text", b"\x55\x8b\xec" * 200, SCN_CODE),
                SectionSpec(".rdata", b"\x00" * 32 + aes_sbox()),
            ),
            imports=(("libcrypto-3-x64.dll", ("AES_encrypt", "RSA_sign")),),
        )
    )
    (root / "plugin.dll").write_bytes(ordinary_pe(clr=True, is_dll=True))
    (root / "packed.exe").write_bytes(
        build_pe(sections=(SectionSpec("UPX1", os.urandom(2048), SCN_CODE),))
    )
    (root / "broken.exe").write_bytes(ordinary_pe()[:200])
    (root / "clean.exe").write_bytes(minimal_pe())
    (root / "notes.txt").write_text("not a binary")
    return root


def render_tree(root: Path, signatures: SignatureSet, **kwargs: int) -> str:
    result = scan_tree(root, signatures, tool_version="0.1.0.test")
    return report.render(cbom.serialize(result, reproducible=True), **kwargs)


@pytest.fixture(scope="module")
def mixed_report(tmp_path_factory: pytest.TempPathFactory, signatures: SignatureSet) -> str:
    return render_tree(mixed_tree(tmp_path_factory.mktemp("tree") / "bin"), signatures)


# --- UI-1: the mixed tree renders every category ----------------------------


def test_every_status_appears_with_its_file(mixed_report: str) -> None:
    for name in ("app.exe", "plugin.dll", "packed.exe", "broken.exe"):
        assert name in mixed_report
    for status in ("degraded-packed", "unsupported-managed", "error · truncated"):
        assert status in mixed_report


def test_findings_carry_their_evidence_inline(mixed_report: str) -> None:
    """US-3 makes evidence the product, and §2 forbids putting it behind a
    disclosure. In a document with no script there is nothing to click, so the
    only way to fail this is to omit it."""
    assert "AES" in mixed_report
    assert "aes-sbox-fwd" in mixed_report
    assert "offset 0x" in mixed_report


def test_the_claim_note_is_printed_not_linked(mixed_report: str) -> None:
    """The report gets forwarded. If the caveat is a link, it does not travel."""
    assert report.CLAIM in mixed_report


def test_no_script_element_is_emitted(mixed_report: str) -> None:
    """§1. Also the reason escaping is the whole attack surface (UI-7)."""
    assert "<script" not in mixed_report.lower()
    assert "javascript:" not in mixed_report.lower()


def test_cover_and_summary_are_their_own_sheets(mixed_report: str) -> None:
    assert mixed_report.count('class="sheet page-break') == 2
    assert 'class="sheet page-break cover"' in mixed_report


def test_the_scan_root_reaches_the_cover(tmp_path: Path, signatures: SignatureSet) -> None:
    """The gap this slice closed in the CBOM: per-file paths say where a finding
    is, not what the scan claims to cover."""
    root = mixed_tree(tmp_path / "bin")
    rendered = render_tree(root, signatures)
    assert root.as_posix() in rendered


def test_detectors_and_min_confidence_reach_the_cover(mixed_report: str) -> None:
    """A scan run with one detector looks exactly like a clean one otherwise."""
    assert "imports,constants,heuristics" in mixed_report
    assert "Min confidence" in mixed_report


# --- UI-2: a foreign CBOM renders, degraded -------------------------------


FOREIGN = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "other-tool"}]}},
        "components": [
            {"type": "file", "bom-ref": "f1", "name": "vendor.exe"},
            {
                "type": "cryptographic-asset",
                "bom-ref": "a1",
                "name": "RSA",
                "cryptoProperties": {"assetType": "algorithm"},
            },
        ],
        "dependencies": [{"ref": "f1", "dependsOn": ["a1"]}],
    }
)


def test_a_foreign_cbom_renders() -> None:
    rendered = report.render(FOREIGN)
    assert "vendor.exe" in rendered
    assert "RSA" in rendered
    assert "other-tool" in rendered


def test_foreign_missing_fields_degrade_rather_than_vanish() -> None:
    rendered = report.render(FOREIGN)
    assert "analysis coverage not recorded in this document" in rendered
    assert "no evidence recorded" in rendered
    assert "unknown" in rendered
    assert report.PLACEHOLDER in rendered


def test_a_document_that_is_not_an_object_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a CycloneDX document"):
        report.render("[]")


def test_an_empty_document_still_produces_a_report() -> None:
    """Nothing to say is not the same as failing to say it."""
    rendered = report.render('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')
    assert "No findings." in rendered
    assert report.CLAIM in rendered


# --- UI-3: the numbers equal what the document says ------------------------


def test_summary_counts_equal_the_document(tmp_path: Path, signatures: SignatureSet) -> None:
    root = mixed_tree(tmp_path / "bin")
    result = scan_tree(root, signatures, tool_version="0.1.0.test")
    document = json.loads(cbom.serialize(result, reproducible=True))
    rendered = report.render(cbom.serialize(result, reproducible=True))

    components = document["components"]
    files = [c for c in components if c["type"] == "file"]
    assets = [c for c in components if c["type"] == "cryptographic-asset"]
    vulnerable = [
        a
        for a in assets
        if a["cryptoProperties"].get("algorithmProperties", {}).get("nistQuantumSecurityLevel") == 0
    ]

    assert _metric(rendered, "Files scanned") == len(files)
    assert _metric(rendered, "Findings") == len(assets)
    assert _metric(rendered, "Quantum-vulnerable") == len(vulnerable)


def test_the_level_chart_totals_the_assets_that_have_a_level() -> None:
    """The chart is never the only source of a number: every bar is labelled
    with its exact count, and those counts have to add up."""
    document = {
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": f"a{i}",
                "name": "X",
                "cryptoProperties": {"algorithmProperties": {"nistQuantumSecurityLevel": level}},
            }
            for i, level in enumerate([0, 0, 1, 2, 2, 2])
        ]
    }
    rendered = report.render(json.dumps(document))
    counts = [int(n) for n in re.findall(r'class="level-count">(\d+)<', rendered)]
    assert counts == [2, 1, 3]
    assert _metric(rendered, "Quantum-vulnerable") == 2


def test_a_lone_category_still_gets_a_visible_bar() -> None:
    """Scaled against the largest count, not the total — otherwise one finding
    among two hundred is a bar nobody can see."""
    document = {
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": f"a{i}",
                "name": "X",
                "cryptoProperties": {"algorithmProperties": {"nistQuantumSecurityLevel": level}},
            }
            for i, level in enumerate([0] + [1] * 40)
        ]
    }
    widths = [float(w) for w in re.findall(r"width:([\d.]+)%", report.render(json.dumps(document)))]
    assert max(widths) == pytest.approx(100.0)
    assert min(widths) == pytest.approx(2.5)


# --- UI-5: vocabulary is verbatim ------------------------------------------


def test_status_strings_are_the_enum_verbatim(mixed_report: str) -> None:
    """Renaming a status to something friendlier breaks the reader's ability to
    cross-reference the CBOM, which is FR-13's whole mechanism."""
    for status in AnalysisStatus:
        assert status.value in report._STATUS_MEANING
    for friendly in ("Packed binary", "Not supported", "Failed", "Clean"):
        assert friendly not in mixed_report


def test_rendered_signature_ids_exist_in_the_signature_data(
    mixed_report: str, signatures: SignatureSet
) -> None:
    known = {s.id for s in signatures.constants} | {s.id for s in signatures.imports}
    known |= {s.id for s in signatures.strings} | {s.id for s in signatures.material}
    rendered = set(re.findall(r'class="signature">([a-z0-9-]+)<', mixed_report))
    assert rendered, "no evidence rows rendered, so this test proves nothing"
    assert rendered <= known, f"report invented signature ids: {sorted(rendered - known)}"


# --- UI-6: the palette is frozen -------------------------------------------


TOKENS = {
    "#ffffff",
    "#dfe3e8",
    "#14181d",
    "#414a55",
    "#6b7480",
    "#1b3a5c",
    "#eef2f6",
    "#a9b4c0",
    "#b00020",
    "#4a6f95",
    "#8ba6bf",
    "#c6d3df",
}


def test_no_colour_outside_the_frozen_token_table() -> None:
    """Design §7 is frozen and §11 puts colour on the escalate list. "Just this
    one accent" is how a frozen palette stops being frozen."""
    css = CSS.read_text(encoding="utf-8")
    literals = {value.lower() for value in re.findall(r"#[0-9a-fA-F]{3,8}\b", css)}
    assert literals <= TOKENS, f"unfrozen colours in report.css: {sorted(literals - TOKENS)}"


def test_every_token_is_defined_once_in_root() -> None:
    css = CSS.read_text(encoding="utf-8")
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    for token in TOKENS:
        assert token in root, f"{token} is used but not defined in :root"


def test_charts_force_background_printing() -> None:
    """Without this browsers strip background fills when printing and every bar
    comes out blank. The single rule that decides whether the report prints."""
    css = CSS.read_text(encoding="utf-8")
    assert css.count("print-color-adjust: exact") >= 3
    assert "-webkit-print-color-adjust: exact" in css


def test_print_rules_keep_findings_whole() -> None:
    css = CSS.read_text(encoding="utf-8")
    assert "break-inside: avoid" in css
    assert "break-after: avoid" in css
    assert "display: table-header-group" in css
    assert "@page" in css


# --- UI-7: scanned input is hostile ----------------------------------------


HOSTILE = '<img src=x onerror="alert(1)">&"\'.exe'


def test_a_hostile_filename_cannot_escape_into_markup(
    tmp_path: Path, signatures: SignatureSet
) -> None:
    """Filenames come off a scanned tree, so they are attacker-controlled
    strings landing in HTML. With no script element in the document, this is
    the entire attack surface."""
    try:
        (tmp_path / HOSTILE).write_bytes(minimal_pe())
    except OSError:  # pragma: no cover - filesystem refused the name
        pytest.skip("this filesystem will not take the hostile name")

    rendered = render_tree(tmp_path, signatures)
    assert "<img src=x" not in rendered
    assert "onerror=" not in rendered
    assert "&lt;img src=x onerror=" in rendered


def test_every_interpolated_field_is_escaped() -> None:
    """Windows will not create a file named `<img …>`, so the test above skips
    there and the injection point goes unchecked on half the CI matrix. This
    one drives the same code from the document instead, so it runs everywhere
    and covers the fields a filename never reaches."""
    payload = "</style><script>alert(1)</script>"
    document = {
        "metadata": {
            "tools": {"components": [{"name": payload, "version": payload}]},
            "properties": [
                {"name": "shorsighted:scan-root", "value": payload},
                {"name": "shorsighted:signature-version", "value": payload},
                {"name": "shorsighted:detectors-run", "value": payload},
            ],
        },
        "components": [
            {
                "type": "file",
                "bom-ref": "f1",
                "name": "x.exe",
                "hashes": [{"alg": "SHA-256", "content": payload}],
                "properties": [
                    {"name": "shorsighted:path", "value": payload},
                    {"name": "shorsighted:analysis", "value": payload},
                    {"name": "shorsighted:error-class", "value": payload},
                    {"name": "shorsighted:machine", "value": payload},
                ],
            },
            {
                "type": "cryptographic-asset",
                "bom-ref": "a1",
                "name": payload,
                "cryptoProperties": {"assetType": "algorithm"},
                "properties": [{"name": "shorsighted:confidence", "value": payload}],
                "evidence": {
                    "occurrences": [{"additionalContext": f"{payload}/{payload}: {payload}"}]
                },
            },
        ],
        "dependencies": [{"ref": "f1", "dependsOn": ["a1"]}],
    }
    rendered = report.render(json.dumps(document))
    assert "<script>" not in rendered
    assert "</style>" not in rendered.replace("</style>\n</head>", "")
    assert rendered.count("&lt;/style&gt;&lt;script&gt;") >= 10


def test_hostile_text_in_a_foreign_document_is_escaped() -> None:
    """The `render` path takes someone else's JSON, so every string in it is
    untrusted — not only the ones we would have produced."""
    document = {
        "components": [
            {"type": "file", "bom-ref": "f1", "name": "</style><script>alert(1)</script>"}
        ]
    }
    rendered = report.render(json.dumps(document))
    assert "<script>" not in rendered
    assert "&lt;/style&gt;&lt;script&gt;" in rendered


# --- UI-8: truncation drops filenames, never numbers -----------------------


def many_clean_files(count: int) -> str:
    document = {
        "metadata": {
            "properties": [{"name": "shorsighted:analysis", "value": "ok"}],
        },
        "components": [
            {
                "type": "file",
                "bom-ref": f"f{i}",
                "name": f"clean{i}.exe",
                "properties": [{"name": "shorsighted:analysis", "value": "ok"}],
            }
            for i in range(count)
        ],
    }
    return json.dumps(document)


def test_a_long_clean_list_collapses_but_keeps_its_count() -> None:
    rendered = report.render(many_clean_files(250), appendix_limit=200)
    assert "clean7.exe" not in rendered
    assert "250 files, not listed individually." in rendered
    assert "Above 200 files these are not listed individually" in rendered
    assert _metric(rendered, "Files scanned") == 250


def test_a_short_clean_list_is_printed(mixed_report: str) -> None:
    assert "clean.exe" in mixed_report
    assert "are listed in appendix A" in mixed_report


def test_the_omission_is_always_labelled() -> None:
    """FR-13 at the report layer: absence of a filename is not evidence of
    absence of cryptography, so a silent omission is not allowed."""
    rendered = report.render(many_clean_files(250), appendix_limit=200)
    assert "see the CBOM JSON for the complete file inventory" in rendered


def test_only_ok_files_with_no_findings_are_called_clean(mixed_report: str) -> None:
    """Design §4 amendment 1, literally. A managed assembly with no findings is
    unexamined, not clean; a packed one is uninformative. Either in the clean
    appendix would make the report lie."""
    appendix = mixed_report.split("Appendix A", 1)[1]
    assert "clean.exe" in appendix
    for unexamined in ("plugin.dll", "packed.exe", "broken.exe"):
        assert unexamined not in appendix


# --- reproducibility --------------------------------------------------------


def test_the_report_is_byte_identical_for_the_same_document(mixed_report: str) -> None:
    """NFR-6 reaches the HTML. It stops there: the PDF is a rendering, and
    depends on the browser, the fonts, and the print settings (design §8)."""
    assert report.render(FOREIGN) == report.render(FOREIGN)


def test_the_cbom_digest_is_over_the_bytes_the_reader_can_diff() -> None:
    import hashlib

    digest = hashlib.sha256(FOREIGN.encode("utf-8")).hexdigest()
    assert f"{digest[:4]}…{digest[-4:]}" in report.render(FOREIGN)


# --- helpers ----------------------------------------------------------------


def _metric(rendered: str, label: str) -> int:
    match = re.search(rf'{re.escape(label)}</div><div class="metric-value[^"]*">(\d+)<', rendered)
    assert match, f"metric {label!r} not found in the report"
    return int(match.group(1))


# --- review findings: the page must not contradict itself -------------------


def _asset(ref: str | None = None, level: int = 0) -> dict[str, object]:
    asset: dict[str, object] = {
        "type": "cryptographic-asset",
        "name": "RSA",
        "cryptoProperties": {"algorithmProperties": {"nistQuantumSecurityLevel": level}},
    }
    if ref:
        asset["bom-ref"] = ref
    return asset


def test_an_asset_with_no_bom_ref_is_still_a_finding() -> None:
    """`bom-ref` is optional in CycloneDX. Counting findings through the
    file join dropped these entirely — a foreign document could lose real
    assets and the report would look complete."""
    rendered = report.render(json.dumps({"components": [_asset()]}))
    assert _metric(rendered, "Findings") == 1
    assert _metric(rendered, "Quantum-vulnerable") == 1


def test_findings_and_quantum_vulnerable_count_the_same_set() -> None:
    """The defect this pair exists to catch: an asset no `dependencies` entry
    referenced was counted as quantum-vulnerable but not as a finding, so the
    summary printed 'Findings 0' directly above 'Quantum-vulnerable 1'."""
    document = {
        "components": [{"type": "file", "bom-ref": "f1", "name": "a.exe"}, _asset("a1")],
    }
    rendered = report.render(json.dumps(document))
    assert _metric(rendered, "Findings") == 1
    assert _metric(rendered, "Quantum-vulnerable") == 1


def test_a_finding_with_no_file_is_shown_not_silently_dropped() -> None:
    """It is counted in the summary, so it has to appear somewhere. A number on
    page 2 with nothing behind it in section 1 is the report contradicting
    itself."""
    rendered = report.render(json.dumps({"components": [_asset("a1")]}))
    assert "Findings not linked to a file in this document" in rendered
    assert "RSA" in rendered


def test_an_unrecognised_status_still_reaches_the_coverage_chart() -> None:
    """A status this build does not know about was dropped from both the bar
    and the table, leaving a coverage chart that covered half its files. The
    chart under-reported exactly where coverage was least understood."""
    document = {
        "components": [
            {
                "type": "file",
                "bom-ref": f"f{i}",
                "name": f"{i}.exe",
                "properties": [{"name": "shorsighted:analysis", "value": status}],
            }
            for i, status in enumerate(["ok", "degraded-future-thing"])
        ]
    }
    rendered = report.render(json.dumps(document))
    widths = [
        float(w)
        for w in re.findall(r'class="(?:swatch )?fill-[a-z-]+" style="width:([\d.]+)%', rendered)
    ]
    assert sum(widths) == pytest.approx(100.0), "the coverage bar must cover every file"
    assert "degraded-future-thing" in rendered
    assert "not a status this version records" in rendered


# --- layout: two shapes that silently collapse a column ----------------------


def test_a_spanning_header_never_leaves_its_columns_undeclared(mixed_report: str) -> None:
    """`table-layout: fixed` reads column widths from the *first* row.

    The finding tables open with a `colspan=3` file-identity cell, so that row
    declares nothing and the columns split evenly — which shrinks the asset
    column enough that the evidence table nested inside it has no room for a
    description, and every word breaks to one character per line. A `colgroup`
    outranks the first row and is the only thing standing between this layout
    and that collapse, so nothing may remove it.
    """
    tables = re.findall(r"<table[^>]*>(.*?)</table>", mixed_report, re.S)
    spanning = [t for t in tables if "colspan=" in t.split("<tbody>")[0]]
    assert spanning, "no spanning header rendered, so this test proves nothing"
    for table in spanning:
        assert "<colgroup>" in table, f"spanning header with undeclared columns: {table[:120]}"


def test_the_nested_evidence_table_sizes_in_percentages() -> None:
    """Pixel columns inside a nested table can total more than the cell holding
    them; percentages cannot. The overflow is not visible when it happens — the
    description column just stops being readable — so the fix has to be
    structural rather than a set of widths that happen to fit today."""
    css = CSS.read_text(encoding="utf-8")
    block = css[css.index(".evidence .detector") : css.index("/* --- footer")]
    assert "px" not in block, f"pixel widths inside the nested evidence table:\n{block}"


def test_the_level_chart_counts_every_finding(mixed_report: str) -> None:
    """The chart totals the metric printed above it, unstated levels included.

    CryptoAPI and CNG findings are a generic API, not an algorithm, so they
    carry no quantum level at all. Charting only the assets that have one drew
    no chart whatsoever for a scan whose findings were all imports - beside a
    "Findings" card reading 2.
    """
    counts = [int(n) for n in re.findall(r'class="level-count">(\d+)<', mixed_report)]
    assert sum(counts) == _metric(mixed_report, "Findings")


def test_a_finding_with_no_level_is_charted_as_unstated() -> None:
    document = {
        "components": [
            {"type": "cryptographic-asset", "bom-ref": "a1", "name": "CryptoAPI"},
            {
                "type": "cryptographic-asset",
                "bom-ref": "a2",
                "name": "RSA",
                "cryptoProperties": {"algorithmProperties": {"nistQuantumSecurityLevel": 0}},
            },
        ]
    }
    rendered = report.render(json.dumps(document))
    assert report._UNSTATED_LEVEL in rendered
    # The unstated bucket sorts last, after every numeric level.
    assert rendered.index("Level 0") < rendered.index(report._UNSTATED_LEVEL)
    counts = [int(n) for n in re.findall(r'class="level-count">(\d+)<', rendered)]
    assert counts == [1, 1]


def test_the_cover_carries_only_the_cover(mixed_report: str) -> None:
    """Title, what was scanned, how it was scanned, and the claim at the foot."""
    cover = mixed_report.split('class="sheet page-break cover"')[1].split("</div>")[0]
    assert report.TITLE in cover
    assert "Directory scanned" in cover
    assert report.CLAIM in cover
    assert "Summary" not in cover


def test_the_offset_column_is_absent_when_nothing_has_an_offset() -> None:
    """An import is a table entry, not a byte position, so import evidence has
    no offset. A boxed empty cell on every row reads as a value that failed to
    render rather than as one that was never there."""

    def document(context: str, **extra: object) -> str:
        return json.dumps(
            {
                "components": [
                    {
                        "type": "cryptographic-asset",
                        "bom-ref": "a1",
                        "name": "CryptoAPI",
                        "evidence": {
                            "occurrences": [
                                {"location": "x", "additionalContext": context, **extra}
                            ]
                        },
                    }
                ]
            }
        )

    imports_only = report.render(document("imports/capi-advapi32: imports CryptEncrypt"))
    assert 'class="offset"' not in imports_only

    with_offset = report.render(document("constants/aes-sbox-fwd: forward S-box", offset=1234))
    assert 'class="offset"' in with_offset
    assert "0x4D2" in with_offset


def test_a_detector_name_never_wraps() -> None:
    """`heuristics` broken across two lines as `heuristic` + `s` reads as a
    rendering fault, and the evidence table is where it happened."""
    css = CSS.read_text(encoding="utf-8")
    block = css[css.index(".evidence .detector") : css.index(".empty {")]
    assert block.count("white-space: nowrap") == 2, "detector and offset must both refuse to wrap"
