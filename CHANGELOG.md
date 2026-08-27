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

### Added

- Printable evidence report: `--format html` on a scan, or `shorsighted render
  <cbom.json>` to render a CycloneDX document produced by any tool. Prints to
  PDF from the browser, no new runtime dependency.
- `shorsighted:scan-root`, `shorsighted:detectors-run` and
  `shorsighted:min-confidence` in the CBOM metadata. Without them a scan run
  with `--detectors imports --min-confidence 0.9` and a full scan produce
  identical-looking emptiness, which is the confusion FR-13 exists to prevent.
- `--appendix-limit`, capping how many clean filenames the report lists
  individually. Counts stay exact either way.
- Release pipeline: tag-triggered build, provenance attestation, PyPI Trusted
  Publishing behind an approval environment, and a GitHub release carrying
  checksums.

### Changed

- All GitHub Actions are pinned to commit SHAs rather than moving tags.

## [0.1.0] - unreleased

The first release. Nothing is published yet; this section exists so the release
workflow has something to read the day a `v0.1.0` tag is cut.

### Added

- Three detectors — imports, constants, heuristics — over statically parsed PE
  files. No sample is ever executed or emulated.
- CycloneDX 1.6 CBOM output, validated against the vendored official schema in
  CI on every emitted document shape.
- Detection knowledge lives entirely in `signatures/data/*.toml`. A new
  algorithm is a data contribution with no Python change.
- Confidence values calibrated as measured per-class precision over a corpus
  built from pinned sources, published in `eval/report.md`.
- `--format text` for humans, `--reproducible` for byte-identical output.

[Unreleased]: https://github.com/judahx67/SHORsighted/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/judahx67/SHORsighted/releases/tag/v0.1.0
