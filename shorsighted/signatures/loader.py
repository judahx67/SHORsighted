"""Parse and validate the bundled signature TOML at load time (FR-9, D-9).

TOML because `tomllib` is stdlib from 3.11, which keeps the runtime dependency
budget at `pefile` alone, and because it takes comments — a contributor adding a
constant needs somewhere to write down *which FIPS section it came from*, and a
format that cannot hold that turns reviewable data into magic numbers.
"""

import hashlib
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from shorsighted.signatures.schema import (
    ConstantSignature,
    SignatureError,
    SignatureSet,
    parse_constant_signature,
    parse_import_signature,
    parse_string_signature,
    validate_set,
)

DATA_DIR = Path(__file__).parent / "data"


def load_signatures(directory: Path | None = None) -> SignatureSet:
    """Load, validate, and version the signature data.

    Raises `SignatureError` on anything malformed. There is no partial-success
    mode on purpose: a half-loaded signature set would silently lower recall,
    and a scanner that quietly finds less is worse than one that refuses to run.
    """
    root = DATA_DIR if directory is None else directory

    confidence, corroboration_bonus = _load_confidence(root / "confidence.toml")

    imports_path = root / "imports.toml"
    document = _read_toml(imports_path)
    import_signatures = tuple(
        parse_import_signature(raw, f"{imports_path.name}[signature #{index + 1}]")
        for index, raw in enumerate(_table_array(document, "signature", imports_path))
    )
    string_signatures = tuple(
        parse_string_signature(raw, f"{imports_path.name}[string #{index + 1}]")
        for index, raw in enumerate(_table_array(document, "string", imports_path))
    )

    signature_set = SignatureSet(
        imports=import_signatures,
        strings=string_signatures,
        constants=_load_constants(root),
        confidence=confidence,
        corroboration_bonus=corroboration_bonus,
        version=signature_version(root),
    )
    validate_set(signature_set)
    return signature_set


def signature_version(directory: Path) -> str:
    """A short digest over every signature file in the directory.

    Content-addressed rather than a hand-maintained version number, because a
    hand-maintained one drifts the first time somebody edits a constant without
    bumping it — and NFR-6's reproducibility claim rests on this being exact.
    """
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*.toml")):
        digest.update(path.relative_to(directory).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError as exc:
        raise SignatureError(f"missing signature file: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SignatureError(f"{path.name}: not valid TOML - {exc}") from exc


def _table_array(document: dict[str, Any], key: str, path: Path) -> Iterable[dict[str, Any]]:
    entries = document.get(key, [])
    if not isinstance(entries, list):
        raise SignatureError(f"{path.name}: '{key}' must be an array of tables ([[{key}]])")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SignatureError(f"{path.name}: every '{key}' entry must be a table")
    return entries


def _load_confidence(path: Path) -> tuple[dict[str, float], float]:
    document = _read_toml(path)

    classes = document.get("classes")
    if not isinstance(classes, dict) or not classes:
        raise SignatureError(f"{path.name}: missing or empty [classes] table")

    confidence: dict[str, float] = {}
    for name, value in classes.items():
        if not isinstance(value, int | float) or isinstance(value, bool) or not 0.0 <= value <= 1.0:
            raise SignatureError(f"{path.name}: confidence for {name!r} must be a number in [0, 1]")
        confidence[name] = float(value)

    merge = document.get("merge", {})
    if not isinstance(merge, dict):
        raise SignatureError(f"{path.name}: [merge] must be a table")
    bonus = merge.get("corroboration_bonus", 0.0)
    if not isinstance(bonus, int | float) or isinstance(bonus, bool) or not 0.0 <= bonus <= 1.0:
        raise SignatureError(f"{path.name}: corroboration_bonus must be a number in [0, 1]")

    return confidence, float(bonus)


def _load_constants(root: Path) -> tuple[ConstantSignature, ...]:
    """Load every `constants/*.toml` plus `confusables.toml`.

    Sorted by filename so the load order - and therefore the order findings come
    back in - does not depend on how the filesystem feels today (NFR-6).

    Missing files are not an error here: `constants/` is absent in the minimal
    signature directories tests build, and a deployment that ships only import
    signatures is a smaller tool rather than a broken one.
    """
    paths = sorted((root / "constants").glob("*.toml"))
    confusables = root / "confusables.toml"
    if confusables.is_file():
        paths.append(confusables)

    signatures: list[ConstantSignature] = []
    for path in paths:
        document = _read_toml(path)
        signatures.extend(
            parse_constant_signature(raw, f"{path.name}[signature #{index + 1}]")
            for index, raw in enumerate(_table_array(document, "signature", path))
        )
    return tuple(signatures)
