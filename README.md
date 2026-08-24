# SHORsighted

> *Your binaries are Shor-sighted.*

A CBOM scanner for **compiled Windows PE binaries**. It reads EXE/DLL/SYS files as bytes, detects evidence of
cryptographic algorithms and material, and emits a **CycloneDX 1.6** Cryptographic Bill of Materials.

Existing CBOM tooling reads source code. A great deal of real-world cryptography ships as statically linked
OpenSSL inside software nobody has the source to — invisible to every source-level scanner. That gap is the
point of this tool.

## Status: pre-alpha, slice 1 of 12 🌱

The skeleton and CI exist. No detection yet. Planning docs (`01requirements.md` … `05roadmap.md`) are the source
of truth; `04implementationhandoff.md` holds the build order.

## What it will promise

- Evidence, not vibes — every finding carries its detector, signature id, and file offset, so you can check it.
- **Honest absence.** No findings means "none detected", with caveats attached (packed? managed? errored?).
  Never "no cryptography present".
- Published per-detector precision and recall on a labelled corpus, plus a candid list of what defeats it.
- It never executes, emulates, or modifies what it scans, and it never lifts key material into the output.

## License

Apache-2.0.
