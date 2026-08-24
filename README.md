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

## Status: pre-alpha, slice 3 of 12 🌱

The import detector works. Point it at a PE and it will name the algorithms it can
see from the import table, with evidence and NIST quantum levels.

**What it cannot do yet:** statically linked cryptography (the constant detector,
slice 5 — and the whole reason this project exists), CycloneDX JSON output
(slice 4), directory scanning (slice 7), embedded certificates (slice 8). The
confidence numbers you see are uncalibrated placeholders until slice 10. Planning docs (`01requirements.md` … `05roadmap.md`) are the source
of truth; `04implementationhandoff.md` holds the build order.

## What it will promise

- Evidence, not vibes — every finding carries its detector, signature id, and file offset, so you can check it.
- **Honest absence.** No findings means "none detected", with caveats attached (packed? managed? errored?).
  Never "no cryptography present".
- Published per-detector precision and recall on a labelled corpus, plus a candid list of what defeats it.
- It never executes, emulates, or modifies what it scans, and it never lifts key material into the output.

## License

Apache-2.0.
