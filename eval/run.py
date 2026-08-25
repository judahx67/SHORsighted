"""Evaluate the detectors against the labelled corpus (test-plan §5, AC-7).

    python -m eval.run                 # writes eval/report.md
    python -m eval.run --print         # and prints it
    python -m eval.run --check         # fail if confidence.toml has drifted

Two numbers matter and they are computed against different things.

**Precision** asks: of the families a detector reported, how many are genuinely
in the binary? Ground truth is `truth` in labels.toml, which includes what the
build toolchain linked in whether the program asked for it or not - because
those bytes really are there, and FR-13 says a finding means evidence of
presence.

**Recall** is reported twice, deliberately. Per-detector recall is measured
against `expect`, which is what that detector should currently find. Overall
recall is measured against `truth` across all detectors, so the defeat set drags
it down exactly as much as it should. A headline recall that quietly excludes
the samples designed to defeat us would be the one dishonest number in this
project, and there is no version of this file that prints it.

Detectors are run one at a time rather than filtered out of a merged result.
Merging promotes confidence when detectors corroborate each other (D-13), which
would make a per-detector number a measurement of the merge stage.
"""

import argparse
import collections
import math
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from shorsighted.core.model import ScannedFile
from shorsighted.core.scanner import BUILTIN_DETECTORS, scan_file
from shorsighted.detectors.base import Detector
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import SignatureSet

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
BUILD = CORPUS / "build"
LABELS = CORPUS / "labels.toml"
REPORT = ROOT / "eval" / "report.md"

BUCKET = 0.05
"""Confidence is rounded to this. Reporting a calibrated 0.9166... would imply a
resolution twenty-six samples cannot support (test-plan §5)."""

CEILING = 0.95
"""The highest confidence any class may be assigned. A class that scored 50/50
did not earn 1.00: the tool is reasoning about a binary it did not build, and
the merge stage caps corroborated findings at 0.99 for the same reason."""

FLOOR = 0.05
"""The lowest. A finding reported at 0.00 reads as unset rather than as
measured, and that distinction matters more than the two hundredths do."""

Z = 1.96
"""95% normal quantile, for the Wilson interval below."""


def wilson_lower_bound(successes: int, trials: int) -> float:
    """Lower bound of the 95% Wilson score interval.

    Calibration uses this rather than the raw ratio, and the difference is the
    difference between an honest number and a flattering one. Twenty true
    positives out of twenty is a point estimate of 1.000, which would have this
    tool claim certainty about a binary it did not build; the Wilson bound reads
    the same evidence as 0.84, because twenty samples cannot support more.

    Small corpora are penalised automatically, which is the right incentive for
    a corpus this size: the way to ship a higher number is to measure more
    binaries, not to round the ones you have.
    """
    if trials == 0:
        return 0.0
    ratio = successes / trials
    denominator = 1 + Z**2 / trials
    centre = (ratio + Z**2 / (2 * trials)) / denominator
    margin = Z * math.sqrt(ratio * (1 - ratio) / trials + Z**2 / (4 * trials**2)) / denominator
    return max(0.0, centre - margin)


def calibrated_confidence(successes: int, trials: int) -> float:
    """The value that ships: a Wilson bound, bucketed and clamped."""
    bound = round(wilson_lower_bound(successes, trials) / BUCKET) * BUCKET
    return min(CEILING, max(FLOOR, bound))


@dataclass
class Label:
    source: str
    kind: str
    truth: set[str]
    expect: dict[str, set[str]]
    expect_by_config: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    note: str = ""

    def expected(self, config: str) -> dict[str, set[str]]:
        return self.expect_by_config.get(config, self.expect)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        total = self.tp + self.fp
        return self.tp / total if total else None

    @property
    def recall(self) -> float | None:
        total = self.tp + self.fn
        return self.tp / total if total else None


def load_labels() -> tuple[dict[str, Label], dict[str, set[str]]]:
    raw = tomllib.loads(LABELS.read_text(encoding="utf-8"))
    toolchain = {config: set(families) for config, families in raw.get("toolchain", {}).items()}
    labels = {}
    for entry in raw["sample"]:
        labels[entry["source"]] = Label(
            source=entry["source"],
            kind=entry["kind"],
            truth=set(entry["truth"]),
            expect={d: set(f) for d, f in entry.get("expect", {}).items()},
            expect_by_config={
                config: {d: set(f) for d, f in table.items()}
                for config, table in entry.get("expect_by_config", {}).items()
            },
            note=entry.get("note", "").strip(),
        )
    return labels, toolchain


def families_of(scanned: ScannedFile) -> set[str]:
    return {finding.family for finding in scanned.findings if finding.family}


def classes_of(scanned: ScannedFile) -> dict[str, set[str]]:
    """Signature class -> families reported under it, for calibration.

    Read off the evidence rather than the finding, because one finding can carry
    evidence from several signatures and the class is a property of the
    signature that matched.
    """
    by_class: dict[str, set[str]] = collections.defaultdict(set)
    for finding in scanned.findings:
        for evidence in finding.evidence:
            by_class[evidence.signature_id].add(finding.family or "")
    return by_class


@dataclass
class Row:
    binary: str
    source: str
    config: str
    kind: str
    reported: dict[str, set[str]]
    truth: set[str]
    expected: dict[str, set[str]]


def evaluate(signatures: SignatureSet) -> tuple[list[Row], dict[str, list[tuple[str, str]]]]:
    """Scan every corpus binary once per detector."""
    labels, toolchain = load_labels()
    detectors: dict[str, Detector] = {d.name: d for d in BUILTIN_DETECTORS}

    rows: list[Row] = []
    class_hits: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)

    for path in sorted(BUILD.glob("*.exe")):
        source, arch, opt = path.stem.rsplit("-", 2)
        config = f"{arch}-{opt}"
        label = labels.get(source)
        if label is None:
            raise SystemExit(f"{path.name}: no label for source {source!r} in labels.toml")

        truth = label.truth | toolchain.get(config, set())
        reported = {}
        for name, detector in detectors.items():
            scanned = scan_file(path, signatures, detectors=[detector], timeout=0)
            reported[name] = families_of(scanned)
            for signature_id, families in classes_of(scanned).items():
                for family in families:
                    class_hits[signature_id].append((path.name, "TP" if family in truth else "FP"))

        rows.append(
            Row(
                binary=path.name,
                source=source,
                config=config,
                kind=label.kind,
                reported=reported,
                truth=truth,
                expected=label.expected(config),
            )
        )
    return rows, class_hits


def score(rows: list[Row]) -> tuple[dict[str, Counts], Counts, dict[str, dict[str, Counts]]]:
    per_detector: dict[str, Counts] = collections.defaultdict(Counts)
    per_family: dict[str, dict[str, Counts]] = collections.defaultdict(
        lambda: collections.defaultdict(Counts)
    )
    overall = Counts()

    for row in rows:
        for detector, reported in row.reported.items():
            expected = row.expected.get(detector, set())
            counts = per_detector[detector]
            counts.tp += len(reported & row.truth)
            counts.fp += len(reported - row.truth)
            counts.fn += len(expected - reported)
            for family in reported & row.truth:
                per_family[detector][family].tp += 1
            for family in reported - row.truth:
                per_family[detector][family].fp += 1
            for family in expected - reported:
                per_family[detector][family].fn += 1

        found = set().union(*row.reported.values()) if row.reported else set()
        overall.tp += len(found & row.truth)
        overall.fp += len(found - row.truth)
        overall.fn += len(row.truth - found)

    return dict(per_detector), overall, {d: dict(f) for d, f in per_family.items()}


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def fraction(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator}" if denominator else "0/0"


def render(
    rows: list[Row],
    per_detector: dict[str, Counts],
    overall: Counts,
    per_family: dict[str, dict[str, Counts]],
    signatures: SignatureSet,
) -> str:
    labels, toolchain = load_labels()
    configs = sorted({row.config for row in rows})
    lines: list[str] = []
    add = lines.append

    add("# Evaluation report")
    add("")
    add(
        f"{len(rows)} binaries, {len({r.source for r in rows})} sources, "
        f"{len(configs)} build configurations ({', '.join(configs)})."
    )
    add(f"Signature set `{signatures.version}`.")
    add("")
    add(
        "Generated by `python -m eval.run`. Every sample is compiled from "
        "`corpus/src/` by `corpus/build.py`; nothing here was collected from the "
        "wild, and no number below was rounded in our favour."
    )
    add("")

    add("## Headline")
    add("")
    add("| | TP | FP | FN | Precision | Recall |")
    add("|---|---|---|---|---|---|")
    add(
        f"| All detectors, all samples | {overall.tp} | {overall.fp} | {overall.fn} "
        f"| {pct(overall.precision)} | {pct(overall.recall)} |"
    )
    add("")
    add(
        "Recall here counts the defeat set, which is the point of having one. "
        "Per-detector recall below is measured against what each detector is "
        "expected to find, so the two numbers answer different questions and "
        "neither is the flattering one dressed up as the other."
    )
    add("")

    add("## Per detector")
    add("")
    add("| Detector | TP | FP | FN | Precision | Recall |")
    add("|---|---|---|---|---|---|")
    for name in sorted(per_detector):
        counts = per_detector[name]
        add(
            f"| {name} | {counts.tp} | {counts.fp} | {counts.fn} "
            f"| {pct(counts.precision)} | {pct(counts.recall)} |"
        )
    add("")

    add("## Per family")
    add("")
    for name in sorted(per_family):
        add(f"### {name}")
        add("")
        add("| Family | TP | FP | FN | Precision |")
        add("|---|---|---|---|---|")
        for family in sorted(per_family[name]):
            counts = per_family[name][family]
            add(f"| {family} | {counts.tp} | {counts.fp} | {counts.fn} | {pct(counts.precision)} |")
        add("")

    add("## Defeat set")
    add("")
    add("Real cryptography we do not find, measured rather than omitted.")
    add("")
    add("| Sample | Present | Found | Why |")
    add("|---|---|---|---|")
    for source in sorted({row.source for row in rows if row.kind == "defeat"}):
        label = labels[source]
        sample_rows = [row for row in rows if row.source == source]
        found = sorted(
            {
                family
                for row in sample_rows
                for reported in row.reported.values()
                for family in reported & label.truth
            }
        )
        configs_found = sorted({row.config for row in sample_rows if _found_any(row, label.truth)})
        found_text = f"{', '.join(found)} ({', '.join(configs_found)})" if found else "nothing"
        why = " ".join(label.note.split())
        add(f"| `{source}` | {', '.join(sorted(label.truth))} | {found_text} | {why} |")
    add("")

    add("## Expectation misses")
    add("")
    misses = [
        (row, detector, expected - row.reported.get(detector, set()))
        for row in rows
        for detector, expected in row.expected.items()
        if expected - row.reported.get(detector, set())
    ]
    surprises = [
        (row, detector, reported - row.truth)
        for row in rows
        for detector, reported in row.reported.items()
        if reported - row.truth
    ]
    if not misses and not surprises:
        add("None. Every sample reported exactly what `labels.toml` expects.")
    else:
        add("| Binary | Detector | Expected but missing | Reported but not present |")
        add("|---|---|---|---|")
        keys = sorted({(row.binary, detector) for row, detector, _ in misses + surprises})
        for binary, detector in keys:
            missing = next(
                (
                    sorted(families)
                    for row, name, families in misses
                    if row.binary == binary and name == detector
                ),
                [],
            )
            extra = next(
                (
                    sorted(families)
                    for row, name, families in surprises
                    if row.binary == binary and name == detector
                ),
                [],
            )
            add(
                f"| `{binary}` | {detector} | {', '.join(missing) or '-'} "
                f"| {', '.join(extra) or '-'} |"
            )
    add("")

    add("## Toolchain-contributed cryptography")
    add("")
    if toolchain:
        add(
            "Cryptography the build toolchain links in whether the program asks "
            "for it or not. Confirmed by searching the built binaries for the "
            "literal bytes, not by scanning them."
        )
        add("")
        add("| Configuration | Families |")
        add("|---|---|")
        for config in sorted(toolchain):
            add(f"| {config} | {', '.join(sorted(toolchain[config]))} |")
        add("")
        add(
            "This is not noise to be labelled around. It is the argument for "
            "binary-level CBOMs in one line: the source of these programs never "
            "mentions ChaCha20, and the binaries contain it."
        )
    else:
        add("None recorded.")
    add("")

    add("## What this does not measure")
    add("")
    add(
        "- **The corpus is built, not collected.** Ground truth is exact and the "
        "distribution is ours. These numbers are optimistic for the wild, and "
        "no amount of sample count fixes that - only real binaries would."
    )
    add(
        "- **No real static OpenSSL, mbedTLS, or libsodium.** The static arm is "
        "reference implementations compiled in, which exercise the same tables "
        "but not the same code layout, inlining, or vectorised variants a real "
        "library ships. The import signatures for those libraries are therefore "
        "shipped untested against a real build."
    )
    add(
        "- **No packed samples.** UPX and friends need a packer in the build, "
        "which the corpus does not have. Packing is detected as a status "
        "(`degraded-packed`), and that path is unit-tested, but its effect on "
        "detection rate is not measured here."
    )
    add(
        "- **No PQC.** Nothing in the corpus contains ML-KEM or ML-DSA, and no "
        "signatures ship for them."
    )
    add(
        f"- **{len(rows)} binaries.** Small. Every table above reports exact "
        "counts for that reason: 19/20 and 950/1000 are not the same claim and "
        "a percentage hides which one you are reading."
    )
    add("")
    return "\n".join(lines) + "\n"


def _found_any(row: Row, families: set[str]) -> bool:
    return any(reported & families for reported in row.reported.values())


def calibrate(class_hits: dict[str, list[tuple[str, str]]], signatures: SignatureSet) -> str:
    """Measured precision per signature class, bucketed (test-plan §5).

    Confidence is *defined* as this number, which is why it lives in data. A
    class the corpus never exercised keeps its current value and is listed as
    uncalibrated rather than silently assigned one.
    """
    by_class = class_counts(class_hits, signatures)

    lines = [
        "| Class | TP | FP | Raw precision | Wilson 95% lower | Calibrated | Shipped |",
        "|---|---|---|---|---|---|---|",
    ]
    for signature_class in sorted(signatures.confidence):
        counts = by_class.get(signature_class)
        shipped = signatures.confidence[signature_class]
        if counts is None:
            lines.append(
                f"| `{signature_class}` | 0 | 0 | not exercised by the corpus "
                f"| - | - | {shipped:.2f} |"
            )
            continue
        trials = counts.tp + counts.fp
        calibrated = calibrated_confidence(counts.tp, trials)
        flag = "" if abs(calibrated - shipped) < 1e-9 else " **stale**"
        lines.append(
            f"| `{signature_class}` | {counts.tp} | {counts.fp} | {pct(counts.precision)} "
            f"| {wilson_lower_bound(counts.tp, trials):.3f} | {calibrated:.2f} "
            f"| {shipped:.2f}{flag} |"
        )
    return "\n".join(lines)


def class_counts(
    class_hits: dict[str, list[tuple[str, str]]],
    signatures: SignatureSet,
) -> dict[str, Counts]:
    by_class: dict[str, Counts] = collections.defaultdict(Counts)
    for signature_id, outcomes in class_hits.items():
        signature_class = _class_of(signature_id, signatures)
        if signature_class is None:
            continue
        for _, outcome in outcomes:
            if outcome == "TP":
                by_class[signature_class].tp += 1
            else:
                by_class[signature_class].fp += 1
    return dict(by_class)


def stale_classes(
    class_hits: dict[str, list[tuple[str, str]]],
    signatures: SignatureSet,
) -> list[tuple[str, float, float]]:
    """Classes whose shipped confidence no longer matches the corpus.

    Test-plan §5 asks for a CI check that data and measurement cannot drift
    apart. This is it: `--check` fails when a signature change moved a number
    and nobody re-ran the calibration.
    """
    stale = []
    for signature_class, counts in class_counts(class_hits, signatures).items():
        shipped = signatures.confidence.get(signature_class)
        if shipped is None:
            continue
        calibrated = calibrated_confidence(counts.tp, counts.tp + counts.fp)
        if abs(calibrated - shipped) >= 1e-9:
            stale.append((signature_class, shipped, calibrated))
    return sorted(stale)


def _class_of(signature_id: str, signatures: SignatureSet) -> str | None:
    for group in (
        signatures.imports,
        signatures.strings,
        signatures.constants,
        signatures.material,
    ):
        for signature in group:
            if signature.id == signature_id:
                return str(signature.signature_class)
    if signature_id == "entropy-region":
        return "entropy-region"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print", action="store_true", help="print the report as well as writing it"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if confidence.toml disagrees with the corpus",
    )
    parser.add_argument("--out", type=Path, default=REPORT)
    args = parser.parse_args(argv)

    if not BUILD.exists() or not any(BUILD.glob("*.exe")):
        raise SystemExit("no corpus binaries. Run `python -m corpus.build` first.")

    signatures = load_signatures()
    rows, class_hits = evaluate(signatures)
    per_detector, overall, per_family = score(rows)

    report = render(rows, per_detector, overall, per_family, signatures)
    report += "\n## Confidence calibration\n\n"
    report += (
        "Confidence is defined as the measured precision of a signature class on "
        "this corpus, and shipped as the lower bound of its 95% Wilson interval, "
        "bucketed to 0.05 (test-plan §5). The bound rather than the ratio: a "
        "class that scored 20/20 has a point estimate of 1.000 and has not "
        "earned it, and a corpus this size should be told so by the arithmetic "
        "rather than by a footnote.\n\n"
        "`shorsighted/signatures/data/confidence.toml` carries these values. "
        "`python -m eval.run --check` fails when they drift.\n\n"
    )
    report += calibrate(class_hits, signatures) + "\n"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"wrote {args.out}")
    if args.print:
        print()
        print(report)

    if args.check:
        stale = stale_classes(class_hits, signatures)
        if stale:
            print("\nconfidence.toml is stale:")
            for signature_class, shipped, calibrated in stale:
                print(f"  {signature_class}: ships {shipped:.2f}, corpus says {calibrated:.2f}")
            print("\nUpdate confidence.toml and commit it with this report.")
            return 1
        print("confidence.toml matches the corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
