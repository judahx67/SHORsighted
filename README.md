# SHORsighted

[![CI](https://github.com/judahx67/SHORsighted/actions/workflows/ci.yml/badge.svg)](https://github.com/judahx67/SHORsighted/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

> *Your binaries are Shor-sighted.*

A CBOM scanner for **compiled Windows PE binaries**. It reads EXE/DLL/SYS files as bytes, detects evidence of
cryptographic algorithms and material, and emits a **CycloneDX 1.6** Cryptographic Bill of Materials.

Existing CBOM tooling reads source code. A great deal of real-world cryptography ships as statically linked
OpenSSL inside software nobody has the source to — invisible to every source-level scanner. That gap is the
point of this tool.

## Status: pre-alpha, slice 6 of 12 🌱

Point it at a PE file and it emits a CycloneDX 1.6 CBOM naming the algorithms it
finds, with evidence, offsets, and NIST quantum levels. Two detectors run: the
import table, and **the constant tables** — so statically linked cryptography,
which imports nothing and is invisible to every source-reading CBOM tool, is
detected too. Every document the test suite produces is validated against the
official 1.6 schema in CI.

```console
$ shorsighted app.exe                      # CycloneDX 1.6 JSON (the contract)
$ shorsighted app.exe --format text        # summary table, no stability guarantee
$ shorsighted app.exe --min-confidence 0.9    # high-precision findings only
$ shorsighted app.exe --reproducible -o bom.json
```

**What it cannot do yet:** scan directories (slice 7), find embedded
certificates (slice 8), detect packed or .NET binaries as such (slice 7). DES and the
PQC constant tables are not shipped — see `tools/derive_constants.py` for why.
The confidence numbers you see are uncalibrated placeholders until slice 10.

Planning docs (`01requirements.md` … `05roadmap.md`) are the source of truth;
`04implementationhandoff.md` holds the build order.

## What it will promise

- Evidence, not vibes — every finding carries its detector, signature id, and file offset, so you can check it.
- **Honest absence.** No findings means "none detected", with caveats attached (packed? managed? errored?).
  Never "no cryptography present".
- Published per-detector precision and recall on a labelled corpus, plus a candid list of what defeats it.
- It never executes, emulates, or modifies what it scans, and it never lifts key material into the output.

## License

Apache-2.0.
