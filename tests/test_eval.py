"""The corpus and the eval harness (test-plan §4-5, AC-7).

These run without a compiler. The corpus itself needs `zig cc` and lives in
CI's nightly and release jobs, but the parts that can go quietly wrong on an
ordinary PR - a label that names a source nobody wrote, a defeat sample with no
explanation, arithmetic that flatters - are checked here on every commit.

The calibration arithmetic gets the most attention. It decides every confidence
value the tool prints, and a bug in it would be invisible: the numbers would
still look plausible.
"""

import tomllib
from pathlib import Path

import pytest

from corpus import build as corpus_build
from eval.run import (
    CEILING,
    FLOOR,
    Counts,
    Row,
    calibrated_confidence,
    load_labels,
    score,
    wilson_lower_bound,
)
from shorsighted.signatures.loader import load_signatures

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


# --- the corpus describes itself consistently --------------------------------


def test_every_label_names_a_source_that_exists() -> None:
    labels, _ = load_labels()
    sources = {path.stem for path in (CORPUS / "src").glob("*.c")}
    missing = set(labels) - sources
    assert not missing, f"labels.toml names sources that do not exist: {sorted(missing)}"


def test_every_source_is_labelled() -> None:
    """An unlabelled sample would be built, scanned, and silently excluded from
    every number in the report."""
    labels, _ = load_labels()
    sources = {path.stem for path in (CORPUS / "src").glob("*.c")}
    unlabelled = sources - set(labels)
    assert not unlabelled, f"corpus/src has unlabelled sources: {sorted(unlabelled)}"


def test_defeat_samples_explain_themselves() -> None:
    """A defeat sample's note is printed verbatim in the report and quoted in
    LIMITATIONS.md. One without a note is a miss nobody can act on."""
    labels, _ = load_labels()
    for label in labels.values():
        if label.kind == "defeat":
            assert label.truth, (
                f"{label.source}: a defeat sample with no ground truth proves nothing"
            )
            assert label.note, f"{label.source}: defeat samples must say why"


def test_negative_samples_claim_nothing() -> None:
    labels, _ = load_labels()
    for label in labels.values():
        if label.kind == "negative":
            assert not label.truth
            assert not label.expect


def test_sample_kinds_are_the_three_we_report_on() -> None:
    labels, _ = load_labels()
    assert {label.kind for label in labels.values()} <= {"positive", "negative", "defeat"}


def test_expected_detectors_are_real_detectors() -> None:
    """A typo in labels.toml would otherwise show up as a detector that
    mysteriously finds nothing."""
    labels, _ = load_labels()
    known = {"imports", "constants", "heuristics"}
    for label in labels.values():
        tables = [label.expect, *label.expect_by_config.values()]
        for table in tables:
            unknown = set(table) - known
            assert not unknown, f"{label.source}: unknown detector(s) {sorted(unknown)}"


def test_every_shipped_class_has_a_confidence() -> None:
    signatures = load_signatures()
    for group in (
        signatures.imports,
        signatures.strings,
        signatures.constants,
        signatures.material,
    ):
        for signature in group:
            assert signature.signature_class in signatures.confidence


# --- the arithmetic that decides every confidence value ----------------------


def test_wilson_bound_never_reaches_one() -> None:
    """The hard rule this whole scheme exists to enforce: a perfect score on a
    finite corpus is not certainty about a binary we did not build."""
    for trials in (1, 10, 100, 10_000):
        assert wilson_lower_bound(trials, trials) < 1.0


def test_more_samples_earn_more_confidence() -> None:
    """A clean 100/100 must outrank a clean 10/10. If it did not, there would be
    no arithmetic reason to grow the corpus."""
    bounds = [wilson_lower_bound(n, n) for n in (5, 10, 50, 100, 500)]
    assert bounds == sorted(bounds)
    assert bounds[0] < bounds[-1]


def test_a_perfect_small_sample_is_not_flattered() -> None:
    """20/20 is a point estimate of 1.000 and the bound reads it as far less."""
    assert wilson_lower_bound(20, 20) == pytest.approx(0.839, abs=0.005)


def test_bound_falls_when_false_positives_appear() -> None:
    assert wilson_lower_bound(90, 100) < wilson_lower_bound(100, 100)
    assert wilson_lower_bound(4, 104) < 0.1


def test_no_evidence_is_not_confidence() -> None:
    assert wilson_lower_bound(0, 0) == 0.0


def test_calibration_is_clamped_and_bucketed() -> None:
    assert calibrated_confidence(1000, 1000) == pytest.approx(CEILING)
    assert calibrated_confidence(0, 1000) == pytest.approx(FLOOR)
    for successes, trials in ((7, 11), (4, 104), (50, 50), (3, 5)):
        value = calibrated_confidence(successes, trials)
        assert FLOOR <= value <= CEILING
        assert value * 100 % 5 == pytest.approx(0, abs=1e-6)


def test_shipped_confidence_stays_inside_the_calibrated_range() -> None:
    """Nothing may ship above the ceiling, whatever the corpus says. Catches a
    hand-edit of confidence.toml that skipped the calibration."""
    signatures = load_signatures()
    for name, value in signatures.confidence.items():
        assert FLOOR <= value <= CEILING, f"{name} ships at {value}"


# --- precision and recall are counted the way the report claims --------------


def row(reported: dict[str, set[str]], truth: set[str], expected: dict[str, set[str]]) -> Row:
    return Row(
        binary="sample-x64-O2.exe",
        source="sample",
        config="x64-O2",
        kind="positive",
        reported=reported,
        truth=truth,
        expected=expected,
    )


def test_a_family_not_in_ground_truth_is_a_false_positive() -> None:
    rows = [row({"imports": {"AES", "DH"}}, {"AES"}, {"imports": {"AES"}})]
    per_detector, overall, _ = score(rows)
    assert per_detector["imports"].tp == 1
    assert per_detector["imports"].fp == 1
    assert overall.precision == pytest.approx(0.5)


def test_a_defeat_drags_overall_recall_down() -> None:
    """The property the report's headline depends on. If a defeat sample could
    be excluded from recall, the number would be worthless."""
    rows = [row({"constants": set()}, {"AES"}, {})]
    _, overall, _ = score(rows)
    assert overall.tp == 0
    assert overall.fn == 1
    assert overall.recall == pytest.approx(0.0)


def test_finding_more_than_expected_is_not_punished() -> None:
    """A detector that finds something real we did not expect has done its job,
    not made a mistake."""
    rows = [row({"constants": {"AES", "SHA-2"}}, {"AES", "SHA-2"}, {"constants": {"AES"}})]
    per_detector, overall, _ = score(rows)
    assert per_detector["constants"].fp == 0
    assert overall.precision == pytest.approx(1.0)


def test_toolchain_families_are_ground_truth_not_noise() -> None:
    """Cryptography the compiler linked in is really in the binary, so reporting
    it is correct. Counting it as a false positive would punish the tool for
    being right."""
    _, toolchain = load_labels()
    assert toolchain, "labels.toml should record what the toolchain contributes"
    for config, families in toolchain.items():
        assert families, f"{config}: an empty toolchain entry says nothing"


def test_counts_report_none_rather_than_zero_when_there_is_nothing_to_divide() -> None:
    """0/0 is not a precision of 0.0, and printing it as one would understate
    every class the corpus does not exercise."""
    assert Counts().precision is None
    assert Counts().recall is None


# --- the build script's generated headers ------------------------------------


def test_c_array_round_trips() -> None:
    data = bytes(range(256))
    emitted = corpus_build.c_array("SAMPLE", data)
    values = [
        int(token, 16) for token in emitted.split("{")[1].split("}")[0].replace(",", " ").split()
    ]
    assert bytes(values) == data


def test_material_referenced_by_the_corpus_is_committed() -> None:
    """The samples embed real DER and PEM. If these went missing the corpus
    would still build - with the blobs silently absent."""
    for name in ("cert.pem", "cert.der", "key.pem", "rsa-key.pem", "rsa-key.der"):
        assert (CORPUS / "material" / name).is_file()


def test_the_committed_certificate_is_a_der_certificate() -> None:
    """Guards the sample that has no banner to fall back on: if this file were
    ever replaced with something that is not DER, embedded_der_cert would
    quietly become a negative sample."""
    header = (CORPUS / "material" / "cert.der").read_bytes()[:4]
    assert header[0] == 0x30 and header[1] == 0x82


def test_labels_toml_parses_as_the_report_expects() -> None:
    raw = tomllib.loads((CORPUS / "labels.toml").read_text(encoding="utf-8"))
    assert raw["sample"], "no samples"
    for entry in raw["sample"]:
        assert {"source", "kind", "truth"} <= set(entry)
