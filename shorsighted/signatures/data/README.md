# Signature data ♡

**This directory is the contributor surface. No Python here, ever.**

Every symbol→algorithm mapping, constant byte pattern, and structural marker lives in `.toml` files under this
directory (FR-9). Adding an algorithm means adding data plus a test fixture — never editing a detector.

If you find yourself about to write a byte pattern inside a `.py` file: stop, it belongs here. (◕‿◕)

Format and per-file layout are specified in `02design.md` §4. Files arrive with their slices:

- `imports.toml` — slice 3
- `constants/*.toml`, `confusables.toml` — slice 5
- `material.toml` — slice 8
- `confidence.toml` — placeholder in slice 3, calibrated against the corpus in slice 10
