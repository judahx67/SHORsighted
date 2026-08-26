"""Signature loading and validation (FR-9, AC-6).

Two jobs here. First, the data we actually ship has to load — that is the test
that fails when someone fat-fingers a TOML file. Second, every way a
contributor can get it wrong has to produce a message that says what to fix,
because the whole promise of FR-9 is that adding an algorithm needs no Python,
and a promise like that survives exactly as long as its error messages do.
"""

import json
import shutil
from pathlib import Path

import pytest

from shorsighted.core.scanner import scan_paths
from shorsighted.output.cbom import serialize
from shorsighted.signatures.loader import DATA_DIR, load_signatures, signature_version
from shorsighted.signatures.schema import (
    SIGNATURE_CLASSES,
    ImportSignature,
    SignatureError,
    SignatureSet,
    StringSignature,
    parse_import_signature,
    parse_string_signature,
    validate_set,
)
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe

CONFIDENCE_TOML = """
[classes]
import-specific = 0.95
import-generic = 0.90
utf16-string = 0.70
[merge]
corroboration_bonus = 0.05
"""


def _write(tmp_path: Path, imports_toml: str, confidence: str = CONFIDENCE_TOML) -> Path:
    (tmp_path / "imports.toml").write_text(imports_toml, encoding="utf-8")
    (tmp_path / "confidence.toml").write_text(confidence, encoding="utf-8")
    return tmp_path


# --- the data we ship -----------------------------------------------------


def test_bundled_signatures_load() -> None:
    """The shipped data is valid. If this fails, the package is broken for
    everyone, so it runs on every PR (test-plan §7's signature fast path)."""
    signatures = load_signatures()
    assert signatures.imports
    assert signatures.strings
    assert signatures.version


def all_bundled() -> list[ImportSignature | StringSignature]:
    signatures = load_signatures()
    return [*signatures.imports, *signatures.strings]


def test_every_bundled_class_has_a_confidence_value() -> None:
    signatures = load_signatures()
    for signature in all_bundled():
        assert signature.signature_class in signatures.confidence


def test_bundled_quantum_levels_are_in_range() -> None:
    """FR-14: 0 for quantum-broken, 1-5 for NIST categories, or unset. A level
    of 6 would be meaningless and a negative one worse."""
    for signature in all_bundled():
        if signature.nist_quantum_level is not None:
            assert 0 <= signature.nist_quantum_level <= 5


def test_public_key_families_are_marked_quantum_broken() -> None:
    """The headline claim for the migration persona (D-1). If RSA ever stops
    reporting level 0, the tool has quietly failed at its actual job."""
    broken = {"RSA", "ECDSA", "ECDH", "DH", "DSA", "Ed25519", "X25519"}
    for signature in all_bundled():
        if signature.family in broken:
            assert signature.nist_quantum_level == 0, f"{signature.id} is not marked broken"


def test_signature_version_changes_with_content() -> None:
    """NFR-6 rests on this: a CBOM states which signatures produced it, so the
    version has to move whenever the data does."""
    before = signature_version(DATA_DIR)
    assert before == signature_version(DATA_DIR)
    assert before != signature_version(Path(__file__).parent)


def test_signature_version_ignores_directory_location(tmp_path: Path) -> None:
    """Content-addressed, not path-addressed: the same data in two places must
    version identically, or an editable install and a wheel would disagree."""
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        _write(tmp_path / name, MINIMAL_IMPORTS)
    assert signature_version(tmp_path / "a") == signature_version(tmp_path / "b")


MINIMAL_IMPORTS = """
[[signature]]
id = "x"
class = "import-specific"
dll = "libcrypto*.dll"
family = "AES"
symbols = ["AES_encrypt"]
"""


# --- what a contributor gets wrong ----------------------------------------


@pytest.mark.parametrize(
    ("body", "expected_message"),
    [
        pytest.param(
            '[[signature]]\nclass = "import-specific"\ndll = "a.dll"\n'
            'symbols = ["x"]\nfamily = "AES"',
            "missing required field 'id'",
            id="missing-id",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "wat"\ndll = "a.dll"\nsymbols = ["x"]',
            "unknown class 'wat'",
            id="unknown-class",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "unique-table"\ndll = "a.dll"\nsymbols = ["x"]',
            "not valid here",
            id="wrong-class-for-file",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "import-specific"\ndll = "a.dll"\nsymbols = []',
            "must not be empty",
            id="empty-symbols",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "import-specific"\ndll = "a.dll"\nsymbols = "one"',
            "must be a list of non-empty strings",
            id="symbols-not-a-list",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "import-specific"\ndll = "a.dll"\nsymbols = ["s"]',
            "must set 'family'",
            id="specific-without-family",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "import-generic"\ndll = "a.dll"\n'
            'symbols = ["s"]\nfamily = "F"',
            "must set both 'provides' and 'family'",
            id="generic-without-provides",
        ),
        pytest.param(
            '[[signature]]\nid = "x"\nclass = "import-specific"\ndll = "a.dll"\nsymbols = ["s"]\n'
            'family = "AES"\nnist_quantum_level = 9',
            "must be an integer 0-5",
            id="quantum-level-out-of-range",
        ),
        pytest.param(
            '[[signature]]\nid = 5\nclass = "import-specific"\ndll = "a.dll"\nsymbols = ["s"]',
            "field 'id' must be a non-empty string",
            id="id-wrong-type",
        ),
    ],
)
def test_malformed_signature_names_what_is_wrong(
    tmp_path: Path, body: str, expected_message: str
) -> None:
    _write(tmp_path, body)
    with pytest.raises(SignatureError) as exc:
        load_signatures(tmp_path)
    assert expected_message in str(exc.value)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    """Ids appear in every piece of evidence and in the eval report; two
    signatures sharing one would make findings impossible to trace back."""
    _write(tmp_path, MINIMAL_IMPORTS + MINIMAL_IMPORTS)
    with pytest.raises(SignatureError, match="duplicate signature id 'x'"):
        load_signatures(tmp_path)


def test_string_requiring_an_unknown_provider_is_rejected(tmp_path: Path) -> None:
    """A gate nothing can open means the signature never fires. That is always
    a typo, and catching it at load time beats wondering later why SM4 never
    shows up."""
    _write(
        tmp_path,
        MINIMAL_IMPORTS + '\n[[string]]\nid = "s"\nclass = "utf16-string"\nvalue = "AES"\n'
        'requires = ["cngg"]\nfamily = "AES"\n',
    )
    with pytest.raises(SignatureError, match="requires provider 'cngg'"):
        load_signatures(tmp_path)


def test_class_without_a_confidence_value_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, MINIMAL_IMPORTS, "[classes]\nimport-generic = 0.9\n")
    with pytest.raises(SignatureError, match=r"no value in confidence\.toml"):
        load_signatures(tmp_path)


def test_broken_toml_says_so(tmp_path: Path) -> None:
    _write(tmp_path, "[[signature]\nid = 'x'")
    with pytest.raises(SignatureError, match="not valid TOML"):
        load_signatures(tmp_path)


def test_missing_file_is_reported_by_name(tmp_path: Path) -> None:
    with pytest.raises(SignatureError, match="missing signature file"):
        load_signatures(tmp_path)


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        ("[classes]\n", "missing or empty [classes]"),
        ("[classes]\nimport-specific = 1.5\n", "must be a number in [0, 1]"),
        ('[classes]\nimport-specific = "high"\n', "must be a number in [0, 1]"),
        (
            "[classes]\nimport-specific = 0.9\n[merge]\ncorroboration_bonus = 3",
            "corroboration_bonus must be a number",
        ),
    ],
    ids=["empty", "out-of-range", "not-a-number", "bad-bonus"],
)
def test_malformed_confidence_is_rejected(tmp_path: Path, confidence: str, expected: str) -> None:
    _write(tmp_path, MINIMAL_IMPORTS, confidence)
    with pytest.raises(SignatureError) as exc:
        load_signatures(tmp_path)
    assert expected in str(exc.value)


# --- the shapes themselves ------------------------------------------------


def test_every_known_class_is_documented_in_shipped_confidence() -> None:
    """Slice 5 and 8 add classes to the enum before they add signatures using
    them. The confidence file has to keep up, or their first signature fails to
    load for a reason nobody will enjoy debugging."""
    shipped = load_signatures()
    assert set(shipped.confidence) >= SIGNATURE_CLASSES


def test_confidence_for_unknown_class_raises_rather_than_defaulting() -> None:
    """A missing class must not silently become 0.0 or 1.0 — either would be a
    fabricated number in someone's report."""
    with pytest.raises(KeyError):
        SignatureSet().confidence_for("import-specific")


def test_parse_helpers_reject_non_table_entries(tmp_path: Path) -> None:
    _write(tmp_path, 'signature = "not a table array"')
    with pytest.raises(SignatureError, match="must be an array of tables"):
        load_signatures(tmp_path)


def test_string_signature_requires_a_family() -> None:
    with pytest.raises(SignatureError, match="must set 'family'"):
        parse_string_signature(
            {"id": "s", "class": "utf16-string", "value": "AES", "requires": ["cng"]}, "test"
        )


def test_import_signature_round_trips_its_fields() -> None:
    signature = parse_import_signature(
        {
            "id": "openssl-aes",
            "class": "import-specific",
            "dll": "libcrypto*.dll",
            "symbols": ["AES_encrypt"],
            "family": "AES",
            "algorithm": "AES",
            "primitive": "block-cipher",
            "nist_quantum_level": 1,
            "description": "note",
        },
        "test",
    )
    assert signature.family == "AES"
    assert signature.nist_quantum_level == 1
    assert signature.symbols == ("AES_encrypt",)


def test_validate_set_accepts_an_empty_set() -> None:
    validate_set(SignatureSet())


# --- AC-6: the contributor path, end to end ---------------------------------

CONTRIBUTION = Path(__file__).parent / "fixtures" / "sm4-contribution.toml"


def test_the_shipped_signatures_do_not_know_sm4() -> None:
    """The control for the test below. If SM4 ever ships for real this fails,
    and the contributor test has to pick a different algorithm - otherwise it
    would pass without the contribution and prove nothing."""
    assert not [s for s in load_signatures().constants if s.family == "SM4"]


def test_a_data_only_contribution_is_detected_end_to_end(tmp_path: Path) -> None:
    """AC-6, whole. A contributor drops one TOML file into the signature
    directory and the algorithm turns up in the CBOM - no Python edited, which
    is the promise FR-9 makes and the reason detection knowledge is data.

    Deliberately the full pipeline rather than the detector alone: "detected"
    has to mean *in the document a user receives*, since a finding that never
    reaches the CBOM is not a detection from where they are standing.
    """
    root = tmp_path / "data"
    shutil.copytree(DATA_DIR, root)
    shutil.copy(CONTRIBUTION, root / "constants" / "sm4.toml")

    signatures = load_signatures(root)
    (sm4,) = [s for s in signatures.constants if s.family == "SM4"]
    assert signatures.version != load_signatures().version, (
        "the signature version is content-addressed; adding data must move it (NFR-6)"
    )

    binary = tmp_path / "uses-sm4.exe"
    binary.write_bytes(
        build_pe(
            sections=(
                SectionSpec(".text", b"\x90" * 64, SCN_CODE),
                SectionSpec(".rdata", bytes(64) + sm4.patterns[0] + bytes(64)),
            ),
            imports=(("kernel32.dll", ("ExitProcess",)),),
        )
    )

    document = json.loads(
        serialize(scan_paths((binary,), signatures, tool_version="test"), reproducible=True)
    )
    components = {
        component["name"]: component
        for component in document["components"]
        if component.get("type") == "cryptographic-asset"
    }
    assert "SM4" in components, f"contributed signature not reported: {sorted(components)}"

    properties = components["SM4"]["cryptoProperties"]
    assert properties["assetType"] == "algorithm"
    assert properties["algorithmProperties"]["nistQuantumSecurityLevel"] == 1
    assert components["SM4"]["evidence"]["occurrences"], "a finding with no offset is not evidence"
