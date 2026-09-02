# Roadmap

Effort-gated, not date-gated. This is a solo, part-time project; versions ship
when their exit criteria are met, and the exit criteria are measurable on
purpose. Nothing below has a date attached and nothing below is a promise.

The order changes when the issues say it should. If something here matters to
you, saying so in an issue is how it moves up.

## Standing rules

- **SemVer with 0.x semantics.** Until 1.0, minor releases may break the CLI
  (noted in the CHANGELOG); patch releases are fixes and signature data. The
  CBOM content contract — component shapes, `shorsighted:*` property names,
  exit codes — is frozen within a minor version.
- **Signature data is release cargo.** A signature change re-runs the eval and
  re-calibrates `confidence.toml` in the same pull request, and may never
  regress corpus precision below the published floors.
- **The eval is the changelog's conscience.** Every minor release publishes an
  updated `eval/report.md`. A feature that cannot show its effect on precision
  and recall — or argue why it has none — does not merge.
- One supported minor at a time before 1.0. No backports.

## v0.1 — shipped

Import, constant and heuristic detectors; recursive PE scanning; CycloneDX 1.6
validated against the official schema in CI; a corpus of 104 binaries from 26
sources with published per-detector precision and recall; `LIMITATIONS.md`.

What the corpus changed that the plan did not predict is written up in
[`eval/report.md`](eval/report.md) — including one real false positive it
found, and one heuristic that measured 0.038 precision and now ships disabled.

## v0.2 — "See through the CLR"

Close the biggest gap v0.1 ships with, and pay the debts measurement found.

- **.NET/CLR metadata detector.** Parse CLR metadata tables for
  `System.Security.Cryptography.*`, BouncyCastle and NSec references. Managed
  binaries currently produce `unsupported-managed` and nothing else. AOT-compiled
  .NET stays constants territory and will be documented as such.
- **Curve parameters in limb order.** Bignum libraries store curve constants in
  machine-word limbs, and every one of them is invisible to the curve
  signatures today. `corpus/src/defeat_p256_limbs.c` measures the gap now.
  This is the highest-value item in `LIMITATIONS.md` and among the cheapest.
- **Post-quantum constants** (ML-KEM, ML-DSA). Embarrassing to be missing from a
  tool named after Shor.
- **A structural suppressor for IEEE-754 constant runs**, which is what would
  let the entropy heuristic ship enabled again. Runs of doubles buried it at
  0.038 precision, and they have a recognisable shape.
- Per-signature confidence overrides, where calibration shows a class is too coarse.

**Exit:** the managed corpus slice at ≥ 0.95 precision on the CLR detector, no
regression elsewhere, throughput requirement met or renegotiated in writing.

*Dropped from this version:* an Aho-Corasick optional extra. The v0.1 benchmark
measured 277 MB/s against a 25 MB/s requirement, so there was nothing to buy.

## v0.3 — "Read the code, not just the bytes"

The fourth detector: light disassembly (capstone, as an optional extra — the
core install stays dependency-free). AES-NI, SHA-NI, `PCLMULQDQ`, and
crypto-idiom recognition over a curated signature set — deliberately not a
general-purpose code analyzer. This catches hardware-accelerated cryptography
that has no tables and imports nothing, the largest slice of the v0.1 defeat
set. x86 focus; ARM64EC deferred.

**Exit:** the defeat set's NI-only samples now detected, the new detector's
scan-time cost measured and published, and `shorsighted` still installing and
running with zero native dependencies.

## v0.4 — "Other people's problems"

Whichever of these demand has actually materialised, in this default order:

- **ELF support** — the likeliest request. The architecture already isolates
  PE-ness behind `pe/`; this is the version that proves it, so it budgets
  refactor time rather than pretending none is needed.
- Archive and installer traversal (zip, MSI), with the zip-slip hardening and
  nesting limits that made it a deferral rather than a feature in v0.1.
- SARIF or VEX side-output, or CBOM merge across scans — only if a real
  consumer asks. A person, not a hypothetical.

## v1.0 — "Boring, in the good way"

Not a feature release. A stability promise, with gates that are all measurable:

- CBOM output contract and CLI flags frozen; breaking either means 2.0.
- Six months without shipping a corpus-precision regression.
- At least three external contributors have landed signatures through the
  data-only path without maintainer hand-holding. That is the proof the
  contributor surface works, and nothing else substitutes for it.
- Fuzz corpus of ≥ 100k mutants clean; `SECURITY.md` has handled a real report
  end to end, or twelve months have passed with none.
- Entry-point detector plugins either shipped with a supply-chain policy or
  formally rejected.

## Parking lot

Revisited every release, committed to by none: Mach-O; UEFI and firmware blobs;
ARM64 disassembly; protocol-level inference (a TLS stack as an
`assetType: protocol`); YARA export of the signature set; a `--diff` mode for
CBOM drift between two builds of the same binary (plausibly the most useful
thing on this list, and the one that most needs a design doc first); a GUI —
almost certainly never, the CBOM is the interface.
