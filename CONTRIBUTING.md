# Contributing

```
python -m venv .venv && . .venv/bin/activate     # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
```

Four gates run on every pull request, across Linux and Windows on Python
3.11–3.14. Run them before pushing; they are the same commands CI runs.

```
ruff check . && ruff format --check .   # lint
mypy                                    # --strict, from slice 1, never "typed later"
lint-imports                            # the layering contract in .importlinter
pytest --cov                            # >= 90% line, 80% branch; detectors >= 90%
```

## Adding a signature

This is the contribution the project is shaped around, and it needs **no Python
at all**. Detection knowledge lives in `shorsighted/signatures/data/*.toml`; a
byte pattern inside a `.py` file is a bug (FR-9).

1. Add the entry to the right TOML file. Comment where the constant came from —
   a spec section, a page number, an RFC. The next person needs to check your
   work without trusting you.
2. Add a fixture that exercises it in `tests/fixtures/build.py`, and a test that
   asserts it is detected. CI fails a signature with no fixture (AC-6).
3. Run `python -m eval.run` and commit the regenerated `eval/report.md`. New
   signatures move measured precision, and confidence values *are* measured
   precision — a signature that ships without recalibration makes every
   confidence number in the tool a little bit false.

[`tests/fixtures/sm4-contribution.toml`](tests/fixtures/sm4-contribution.toml)
is a worked example: a complete algorithm added as data only.

**Verify your constants before you write them down.** The SM4 fixture's S-box
was checked by encrypting the standard test vector first, and that check caught
a transcription error. A wrong constant produces a signature that matches
nothing and a test that proves it matches nothing.

## Rules that are easy to break without reading the design docs

- **Never commit a real-world binary.** Not as a fixture, not as a test case,
  not in a bug report. Fixtures are synthesized by `tests/fixtures/build.py`;
  corpus samples are compiled from pinned sources with `zig cc`. A repository
  full of crypto-bearing executables trips antivirus on contributors' machines
  and cannot be re-verified on a clean one.
- **Never execute or emulate a sample** (NFR-7). Static byte analysis only.
- **Never extract key material.** Report that it exists and where. A CBOM
  carrying key bytes is a leak (non-goal 9).
- **The runtime dependency budget is `pefile` and nothing else.** Adding one
  needs a written justification in `02design.md`'s trade-off table first, and
  it is an escalation rather than a pull request.
- **Detectors never import each other, and never import `output/`.**
  Corroboration belongs in `core/merge.py`. The evaluation reports per-detector
  precision and recall, and merging inside a detector destroys that measurement
  (D-13).
- **Claims stay honest** (FR-13). A finding is evidence of presence, never proof
  of use. No findings means none were detected, with caveats attached — never
  that a binary is free of cryptography.

## Pull requests

Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`,
`style:`. Say what changed and why it was wrong before; the diff already says
what the code does now.

One reviewable changeset per pull request, each ending with a working CLI.

Changing the report's layout or stylesheet? Nothing in CI opens a browser, so
walk [`docs/print-check.md`](docs/print-check.md) in Chrome and Firefox and
record the result in the pull request. That checklist exists because a bug it
would have caught shipped without it.

## Releasing

Maintainers only, and it needs one-time setup: a PyPI Trusted Publisher for
`shorsighted` pointing at this repository and the `release.yml` workflow, plus a
`pypi` environment here with required reviewers.

1. Bump `__version__` in `shorsighted/__init__.py`. That is the single source —
   `pyproject.toml` reads it.
2. Move the `## [Unreleased]` entries into a `## [x.y.z]` section. The workflow
   uses that section verbatim as the release notes and fails if it is missing.
3. Tag `vx.y.z` and push it.

`release.yml` then re-runs the full gate and the corpus evaluation, refuses to
proceed if the tag and `__version__` disagree or the version is a pre-release,
builds, checks the sdist installs and still detects, attests provenance, waits
for approval on the `pypi` environment, publishes, and cuts the GitHub release
with checksums attached.

Run it with `workflow_dispatch` first if you want everything except the publish.
