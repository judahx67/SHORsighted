## What changed, and what was wrong before

<!-- The diff says what the code does now. Say why it needed to. -->

## Checks

<!-- Delete what does not apply. -->

- [ ] `ruff check . && ruff format --check .`, `mypy`, `lint-imports`, `pytest --cov` all pass locally
- [ ] Conventional Commit subject (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`, `style:`)

**Signature data only?** Then the Signatures workflow is your fast answer, and:

- [ ] Every new signature cites where its constant came from, in a comment
- [ ] `python -m eval.run` re-run and `eval/report.md` + `confidence.toml` committed here
      — confidence values *are* measured precision, so a signature that ships without
      recalibration makes every confidence number in the tool slightly false

**Touched the HTML report's markup or stylesheet?** Nothing in CI opens a browser:

- [ ] Walked `docs/print-check.md` in Chrome and Firefox, result recorded below

**Claims stay honest** (FR-13) — a finding is evidence of presence, never proof of use:

- [ ] No new claim overstates what the bytes prove
- [ ] No key material, no real-world binaries, nothing executed or emulated
