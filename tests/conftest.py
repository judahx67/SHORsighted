"""Shared fixtures, chiefly the CycloneDX schema validator.

The vendored schema under `tests/schema/` is the official CycloneDX 1.6
publication, unmodified. It is test data rather than package data: nothing at
runtime needs it, and shipping a spec we do not own inside our wheel would be a
licensing question we can avoid entirely by keeping it here.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMA_DIR = Path(__file__).parent / "schema"


@pytest.fixture(scope="session")
def cyclonedx_validator() -> Draft7Validator:
    """A validator for CycloneDX 1.6, with its sibling schemas resolved locally.

    The spec's `$ref`s point at `spdx.schema.json` and `jsf-0.82.schema.json` by
    bare filename, so both are registered under the names the document uses.
    Resolving them offline matters: AC-5 has to hold in CI without reaching the
    network, or the gate is only as reliable as cyclonedx.org's uptime.
    """
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents, default_specification=DRAFT7)
        resources.append((path.name, resource))
        if "$id" in contents:
            resources.append((contents["$id"], resource))

    registry = Registry().with_resources(resources)
    root = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    return Draft7Validator(root, registry=registry)


@pytest.fixture(scope="session")
def assert_valid_cbom(
    cyclonedx_validator: Draft7Validator,
) -> Callable[[dict[str, Any]], None]:
    """Fail with the schema's own message, not a bare boolean.

    AC-5 says every CBOM the suite produces validates. A conformance failure
    that only said "invalid" would send someone hunting through 260 KB of
    schema, so the error names the path and the rule that rejected it.
    """

    def check(document: dict[str, Any]) -> None:
        errors = sorted(cyclonedx_validator.iter_errors(document), key=lambda e: list(e.path))
        if errors:
            detail = "\n".join(
                f"  at {'/'.join(str(p) for p in error.path) or '<root>'}: {error.message}"
                for error in errors[:5]
            )
            pytest.fail(f"CBOM failed CycloneDX 1.6 validation:\n{detail}")

    return check
