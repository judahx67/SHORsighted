"""Signature-file validation rules and the in-memory shapes they produce (FR-9).

Signature data is the contributor surface, which makes it the one input we
*expect* to be wrong: a first-time contributor adding SM4 will typo a class
name or reuse an id long before they write a subtly wrong S-box. So validation
here is loud and specific — every failure names the file, the signature, and
what was wrong with it — and it runs at load time, not at match time, so a bad
data file cannot survive to produce a bad finding.

This is the opposite posture from `pe/loader.py`, which collapses every failure
into one quiet error class. The difference is who is on the other end: there,
an attacker who must learn nothing; here, a contributor who must learn exactly
what to fix.
"""

from dataclasses import dataclass, field
from typing import Any

SIGNATURE_CLASSES = frozenset(
    {
        "import-specific",
        "import-generic",
        "utf16-string",
        "unique-table",
        "word-table",
        "der-structure",
        "entropy-region",
    }
)
"""Every confidence class the project recognises (design §4).

Classes are the unit of confidence calibration, so this set is deliberately
small: adding one means adding a measured precision number to confidence.toml,
not just a label.
"""

IMPORT_CLASSES = frozenset({"import-specific", "import-generic"})


class SignatureError(Exception):
    """A signature file is malformed.

    Raised at load time and never caught internally: shipping with broken
    signature data is a build failure, not a runtime condition to tolerate.
    """


@dataclass(frozen=True)
class ImportSignature:
    """A DLL-and-symbols rule from `imports.toml` (FR-6)."""

    id: str
    signature_class: str

    dll: str
    """Matched case-insensitively as an fnmatch glob, because import tables
    disagree about case and OpenSSL ships as `libcrypto-3-x64.dll`,
    `libcrypto-1_1.dll`, `libeay32.dll`, and more."""

    symbols: tuple[str, ...]
    """Any one match is a hit. Requiring all of them would miss binaries that
    link a subset of an API, which is most of them."""

    provides: str | None = None
    """For generic provider imports: a token like "cng" that UTF-16 string
    signatures can require. This is the mechanism behind design §4's
    import+string corroboration."""

    algorithm: str | None = None
    family: str | None = None
    primitive: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    nist_quantum_level: int | None = None
    description: str = ""


@dataclass(frozen=True)
class StringSignature:
    """A UTF-16LE literal from `imports.toml` (design §4).

    On Windows the CNG API takes its algorithm as a runtime wide string, so
    `BCryptEncrypt` proves only that *some* algorithm is in use. The name is in
    the binary as `L"AES"`; finding it is what turns "uses CNG" into "uses AES".
    """

    id: str
    signature_class: str
    value: str

    requires: tuple[str, ...]
    """Provider tokens that must ALSO be present in the file before this string
    may be reported. A bare UTF-16 "AES" appears in plenty of binaries that do
    no cryptography at all — a settings dialog, a log format string — so the
    gate is what keeps FR-6's precision target reachable."""

    algorithm: str | None = None
    family: str | None = None
    primitive: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    nist_quantum_level: int | None = None
    description: str = ""


@dataclass(frozen=True)
class SignatureSet:
    """Everything the detectors need, already validated."""

    imports: tuple[ImportSignature, ...] = ()
    strings: tuple[StringSignature, ...] = ()
    confidence: dict[str, float] = field(default_factory=dict)
    corroboration_bonus: float = 0.0

    version: str = ""
    """Digest of the data directory. NFR-6 requires that the same input, tool,
    and signature version reproduce a byte-identical CBOM, which means the CBOM
    has to be able to state which signatures produced it."""

    def confidence_for(self, signature_class: str) -> float:
        """Confidence is data (design §4): these numbers are measured precision
        per class, recalibrated whenever signatures change, so no detector is
        allowed to hardcode one."""
        return self.confidence[signature_class]


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise SignatureError(f"{where}: missing required field {key!r}")
    return mapping[key]


def _require_str(mapping: dict[str, Any], key: str, where: str) -> str:
    value = _require(mapping, key, where)
    if not isinstance(value, str) or not value:
        raise SignatureError(f"{where}: field {key!r} must be a non-empty string")
    return value


def _optional_str(mapping: dict[str, Any], key: str, where: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SignatureError(f"{where}: field {key!r} must be a non-empty string")
    return value


def _optional_level(mapping: dict[str, Any], where: str) -> int | None:
    value = mapping.get("nist_quantum_level")
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 5:
        raise SignatureError(
            f"{where}: nist_quantum_level must be an integer 0-5 "
            f"(0 = quantum-broken, 1-5 = NIST category), got {value!r}"
        )
    return value


def _string_list(
    mapping: dict[str, Any], key: str, where: str, *, required: bool
) -> tuple[str, ...]:
    value = mapping.get(key)
    if value is None:
        if required:
            raise SignatureError(f"{where}: missing required field {key!r}")
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise SignatureError(f"{where}: field {key!r} must be a list of non-empty strings")
    if required and not value:
        raise SignatureError(f"{where}: field {key!r} must not be empty")
    return tuple(value)


def _validate_class(raw: dict[str, Any], where: str, allowed: frozenset[str]) -> str:
    signature_class = _require_str(raw, "class", where)
    if signature_class not in SIGNATURE_CLASSES:
        known = ", ".join(sorted(SIGNATURE_CLASSES))
        raise SignatureError(f"{where}: unknown class {signature_class!r} (known classes: {known})")
    if signature_class not in allowed:
        expected = ", ".join(sorted(allowed))
        raise SignatureError(
            f"{where}: class {signature_class!r} is not valid here (expected: {expected})"
        )
    return signature_class


def parse_import_signature(raw: dict[str, Any], where: str) -> ImportSignature:
    signature_class = _validate_class(raw, where, IMPORT_CLASSES)
    signature = ImportSignature(
        id=_require_str(raw, "id", where),
        signature_class=signature_class,
        dll=_require_str(raw, "dll", where),
        symbols=_string_list(raw, "symbols", where, required=True),
        provides=_optional_str(raw, "provides", where),
        algorithm=_optional_str(raw, "algorithm", where),
        family=_optional_str(raw, "family", where),
        primitive=_optional_str(raw, "primitive", where),
        parameter_set=_optional_str(raw, "parameter_set", where),
        oid=_optional_str(raw, "oid", where),
        nist_quantum_level=_optional_level(raw, where),
        description=raw.get("description", ""),
    )

    # A finding with neither a family nor a provider token is unreportable: it
    # would name no asset and corroborate no string.
    if signature.signature_class == "import-specific" and not signature.family:
        raise SignatureError(f"{where}: an import-specific signature must set 'family'")
    if signature.signature_class == "import-generic" and not (
        signature.provides and signature.family
    ):
        raise SignatureError(
            f"{where}: an import-generic signature must set both 'provides' and 'family'"
        )
    return signature


def parse_string_signature(raw: dict[str, Any], where: str) -> StringSignature:
    signature = StringSignature(
        id=_require_str(raw, "id", where),
        signature_class=_validate_class(raw, where, frozenset({"utf16-string"})),
        value=_require_str(raw, "value", where),
        requires=_string_list(raw, "requires", where, required=True),
        algorithm=_optional_str(raw, "algorithm", where),
        family=_optional_str(raw, "family", where),
        primitive=_optional_str(raw, "primitive", where),
        parameter_set=_optional_str(raw, "parameter_set", where),
        oid=_optional_str(raw, "oid", where),
        nist_quantum_level=_optional_level(raw, where),
        description=raw.get("description", ""),
    )
    if not signature.family:
        raise SignatureError(f"{where}: a utf16-string signature must set 'family'")
    return signature


def validate_set(signature_set: SignatureSet) -> None:
    """Whole-set checks that no single signature can make on its own."""
    every: list[ImportSignature | StringSignature] = [
        *signature_set.imports,
        *signature_set.strings,
    ]

    seen: dict[str, str] = {}
    for signature in every:
        if signature.id in seen:
            raise SignatureError(
                f"duplicate signature id {signature.id!r} "
                f"(already used by a {seen[signature.id]} signature)"
            )
        seen[signature.id] = signature.signature_class

    # A string gated on a provider nothing supplies can never fire. That is
    # always a typo, and finding it at load time beats wondering later why a
    # signature never matches anything.
    provided = {sig.provides for sig in signature_set.imports if sig.provides}
    for string in signature_set.strings:
        for token in string.requires:
            if token not in provided:
                available = ", ".join(sorted(provided)) or "none"
                raise SignatureError(
                    f"string signature {string.id!r} requires provider {token!r}, "
                    f"which no import signature provides (available: {available})"
                )

    for signature in every:
        if signature.signature_class not in signature_set.confidence:
            raise SignatureError(
                f"signature {signature.id!r} uses class {signature.signature_class!r}, "
                f"which has no value in confidence.toml"
            )
