# Test suite

Every fixture is synthesized in memory by `fixtures/build.py`. **No real binary
is fetched, committed, or scanned anywhere in this suite** — a test that needed
one would be a test nobody could rerun on a clean machine, and a repo full of
crypto-bearing executables trips antivirus on contributors' machines.

```
pytest                      # everything (includes a 200-mutant fuzz subset)
SHORSIGHTED_FUZZ=full pytest tests/test_fuzz.py   # the full 2,000-mutant sweep
pytest --cov                # with the coverage gate (>= 90% line, 80% branch)
pytest tests/test_merge.py  # one file
pytest -k corroborat        # by name
```

Two generated artefacts are committed and regenerate deliberately, never
automatically — the point of both is that a change has to be reviewed by a
person before it lands:

```
python -m tools.derive_constants   # signature tables in shorsighted/signatures/data/
python -m tests.regenerate_golden  # tests/golden/cng-sample.cbom.json
```

## Traceability

Which test holds each acceptance criterion up (`01requirements.md` §6).

| AC | Claim | Where it is checked |
|---|---|---|
| **AC-1** | CNG binary → AES, SHA-256, RSA with correct quantum levels and import evidence | `test_detector_imports.py::test_ac1_shape_reports_correct_quantum_levels`, `test_cli.py::test_a_synthetic_cng_binary_reports_its_algorithms` |
| **AC-2** | Statically linked binary with no crypto imports → AES and SHA-256 via constants | `test_detector_constants.py::test_a_binary_with_no_crypto_imports_still_reports_aes`, `test_cli.py::test_a_statically_linked_binary_is_detected` |
| **AC-3** | Embedded DER certificate → `certificate` asset with offset evidence | `test_detector_heuristics.py::test_a_der_certificate_is_found`, `::test_the_certificate_offset_points_at_the_structure` |
| **AC-4** | Mixed tree completes, .NET marked unsupported, malformed errored, exit 2 | `test_traits_and_walk.py::test_a_mixed_tree_scan_reports_every_category`, `test_cli.py::test_a_directory_with_a_broken_file_exits_two` |
| **AC-5** | Every emitted CBOM validates against the official CycloneDX 1.6 schema in CI | `test_output_cbom.py::test_every_document_shape_validates` (12 shapes × 2 modes), `::test_a_real_scan_produces_a_valid_cbom`, `test_cli.py::test_cli_json_validates_against_the_schema` |
| **AC-6** | A new algorithm added purely as signature data is detected with zero Python changes | Partly: `test_signatures.py` covers the data path and its validation. The end-to-end contributor test (add SM4, no code change) lands with the corpus in slice 10. |
| **AC-7** | Published evaluation report meeting the NFR-5 targets | **Not met.** Slice 10. |
| **NFR-2** | Survives malformed input without crash or hang; per-file timeout | `test_fuzz.py` — 200 mutants per PR across 9 mutation kinds, 2,000 nightly |
| **AC-8** | `mypy --strict`, `ruff`, tests pass on Linux and Windows; wheel installs | `.github/workflows/ci.yml` — 8 matrix legs plus a clean-env wheel install |

## What the suite deliberately does not prove

- **Confidence numbers.** Every value in `confidence.toml` is a placeholder.
  They are *defined* as measured precision per class on a corpus that does not
  exist yet (slice 10), so no test asserts they are correct — only that they are
  read from data rather than hardcoded.
- **Real-world recall.** Synthetic fixtures show a detector works on a table
  placed where the test put it. Whether real compilers emit those tables in
  recognisable form is a corpus question, and until it is answered the recall
  numbers in NFR-5 are unclaimed.
- **Packing thresholds.** `pe/traits.py` uses heuristic cutoffs with no ground
  truth behind them. The tests pin the behaviour at those values; they do not
  argue the values are right.
