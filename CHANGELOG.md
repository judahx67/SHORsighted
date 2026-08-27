# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

`release.yml` reads the `## [x.y.z]` section for the version being tagged and
uses it verbatim as the GitHub release notes. A tag with no matching section
fails the release, on the grounds that a release nobody wrote notes for is a
release nobody reviewed.

Two things are part of the compatibility promise and belong in **Changed** with
a migration note whenever they move:

- **The CBOM.** The CycloneDX 1.6 document is the contract. Its shape,
  the `shorsighted:*` property names, and the meaning of every value are what
  downstream tooling parses.
- **Exit codes.** `0` clean, `1` the scan never started, `2` the scan ran and
  at least one file could not be read.

Everything else — the `text` output, the HTML report's markup and stylesheet,
every private module — carries no stability guarantee and may change in a patch
release.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-28

First release. Scans compiled Windows PE binaries and emits a CycloneDX 1.6
cryptographic bill of materials, for the case existing CBOM tooling cannot
reach: a binary you did not build and have no source for.

### Added

- **Three detectors**, each a pure function over a parsed PE.
  - `imports` reads the import table. CNG and CryptoAPI imports are generic —
    `BCryptEncrypt` proves "uses CNG", not "uses AES" — so an import is
    corroborated against UTF-16LE algorithm strings before it claims a
    specific algorithm.
  - `constants` finds algorithm tables in the bytes: AES S-boxes, SHA round
    constants, and the rest of `signatures/data/`. This is what sees
    statically linked cryptography, which is invisible to import analysis and
    to every existing CBOM tool.
  - `heuristics` finds embedded DER certificates and key material, and reports
    that it exists and where — never its bytes.
- **CycloneDX 1.6 output.** Every document shape CI can produce is validated
  against the vendored official schema, so conformance is a gate rather than a
  claim. `--reproducible` omits the serial number and timestamp for
  byte-identical output.
- **Printable evidence report.** `--format html` on a scan, or `shorsighted
  render <cbom.json>` to render a CycloneDX document from any tool. Prints to
  PDF from the browser, so it adds no runtime dependency and no rendering
  engine. Cover, summary with charts, then per-finding evidence carrying the
  detector, signature id and file offset that produced it.
- **Detection knowledge lives in `signatures/data/*.toml`, never in Python.**
  A new algorithm is a data contribution with no code change, and CI enforces
  that every signature ships with a fixture exercising it.
- **Calibrated confidence.** Values are measured per-class precision over a
  corpus compiled from pinned sources, published in
  [`eval/report.md`](eval/report.md) and re-checked in CI, so a signature
  change cannot quietly invalidate the numbers the tool prints.
- **Scan metadata in the CBOM**: `shorsighted:scan-root`,
  `shorsighted:detectors-run`, `shorsighted:min-confidence`. Without them a
  scan run with `--detectors imports --min-confidence 0.9` and a full scan
  produce identical-looking emptiness.
- `--format text` for humans, `--detectors` to select, `--min-confidence` to
  filter, `--timeout` per file, `--appendix-limit` for the report's clean-file
  list.
- **Release pipeline.** Tag-triggered build behind the same gate a pull request
  runs plus the corpus evaluation, signed build provenance attestation, PyPI
  Trusted Publishing behind an approval environment, and checksums on the
  GitHub release.

### Known limits

Read [`LIMITATIONS.md`](LIMITATIONS.md) before trusting a clean report. In
short: packed binaries give reduced coverage, .NET assemblies are not analysed
in v0.1, the high-entropy heuristic measured 0.038 precision and ships
disabled, and the corpus is built rather than collected — it shows that real
compilers emit recognisable tables, not what a shipping OpenSSL build looks
like.

Findings are evidence of presence, never proof of use. No findings means none
were detected, with caveats attached — never that a binary is free of
cryptography.

[Unreleased]: https://github.com/judahx67/SHORsighted/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/judahx67/SHORsighted/releases/tag/v0.1.0
