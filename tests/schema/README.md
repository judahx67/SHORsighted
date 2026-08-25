# Vendored CycloneDX schema

Unmodified copies of the official CycloneDX specification schemas, fetched from
<https://github.com/CycloneDX/specification/tree/master/schema>:

| File | Purpose |
|---|---|
| `bom-1.6.schema.json` | The 1.6 BOM schema every emitted CBOM is validated against (AC-5) |
| `spdx.schema.json` | Referenced by the BOM schema for license expressions |
| `jsf-0.82.schema.json` | Referenced by the BOM schema for signatures |

These are **test data, not package data**. Nothing at runtime reads them, and
keeping a spec we do not own out of the wheel avoids a licensing question we
have no need to answer.

They are vendored rather than fetched at test time on purpose: AC-5 has to hold
in CI without network access, or the conformance gate is only as reliable as
cyclonedx.org's uptime.

To update, replace the files from the upstream repository and run the suite.
`tests/conftest.py` resolves the cross-references locally by registering each
file under both its `$id` and its bare filename.
