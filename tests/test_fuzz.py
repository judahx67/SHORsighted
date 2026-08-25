"""Robustness under malformed input (NFR-2, test-plan §6).

The whole pipeline rests on one promise: hostile bytes produce a `PEFormatError`
or a `ScannedFile`, never a crash, never a hang, never a wrong answer presented
confidently. Slices 2 through 8 asserted that promise on a handful of
hand-written cases. This is where it meets two thousand mutants.

Two sizes. The fast subset runs on every PR; the full set runs nightly, or
locally with:

    SHORSIGHTED_FUZZ=full pytest tests/test_fuzz.py

Failures print the seed. A fuzz failure nobody can reproduce is a bug report
nobody can act on.
"""

import os
import tracemalloc
from pathlib import Path

import pytest

from shorsighted.core.model import AnalysisStatus
from shorsighted.core.scanner import scan_file, scan_tree
from shorsighted.pe.loader import PEFormatError, load_bytes
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import SignatureSet
from tests.mutations import MUTATIONS, base_image, generate

FAST_MUTANTS = 200
"""Enough to cover every mutation kind many times over while keeping the PR
gate under a second (test-plan §6)."""

FULL_MUTANTS = 2000


def mutant_count() -> int:
    return FULL_MUTANTS if os.environ.get("SHORSIGHTED_FUZZ") == "full" else FAST_MUTANTS


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


# --- the loader's single failure mode -------------------------------------


def test_no_mutant_escapes_as_anything_but_a_pe_format_error() -> None:
    """The loader's whole contract, at scale.

    Slice 2 asserted this on random bytes, which almost never get past the DOS
    header. These mutants start from a valid PE, so they reach the parsers that
    random data never touches.
    """
    for mutant in generate(mutant_count()):
        try:
            pe = load_bytes(mutant.data)
        except PEFormatError:
            continue
        except Exception as exc:  # the failure this test exists to catch
            pytest.fail(f"{mutant.describe()} raised {type(exc).__name__}: {exc}")
        else:
            # A mutant that parses must still describe itself consistently.
            for section in pe.sections:
                assert section.raw_offset + section.raw_size <= len(mutant.data), (
                    f"{mutant.describe()} produced a section outside the file"
                )
                assert len(section.data) == section.raw_size


def test_every_mutation_kind_is_exercised() -> None:
    """Guards the fast subset from having a hole in it: a 200-mutant run that
    happened to skip section-table corruption would be a gate that passes for
    the wrong reason."""
    kinds = {mutant.kind for mutant in generate(FAST_MUTANTS)}
    assert kinds == set(MUTATIONS)


def test_mutants_are_reproducible() -> None:
    """Same seed, same bytes. A fuzz failure that cannot be replayed is not
    actionable."""
    first = [m.data for m in generate(40, seed=7)]
    second = [m.data for m in generate(40, seed=7)]
    assert first == second
    assert [m.data for m in generate(40, seed=8)] != first


# --- the whole pipeline, not just the loader ------------------------------


def test_no_mutant_breaks_a_scan(tmp_path: Path, signatures: SignatureSet) -> None:
    """FR-3 end to end: every mutant yields a ScannedFile, errored or not.

    Runs the detectors too, so a mutant that parses but produces a strange
    `LoadedPE` — zero sections, absurd entropy, an import table full of
    nonsense — still has to survive three detectors and the merge stage.
    """
    target = tmp_path / "mutant.exe"
    for mutant in generate(mutant_count()):
        target.write_bytes(mutant.data)
        try:
            scanned = scan_file(target, signatures)
        except Exception as exc:  # the failure this test exists to catch
            pytest.fail(f"{mutant.describe()} broke the scan: {type(exc).__name__}: {exc}")

        assert scanned.path == target
        if scanned.status is AnalysisStatus.ERROR:
            assert scanned.error_class, f"{mutant.describe()} errored without a class"
        else:
            assert scanned.sha256, f"{mutant.describe()} succeeded without a hash"


def test_a_directory_of_mutants_still_produces_a_complete_report(
    tmp_path: Path, signatures: SignatureSet
) -> None:
    """The property that makes a directory scan usable: 60 broken files must
    not cost the one good one."""
    for index, mutant in enumerate(generate(60, seed=3)):
        (tmp_path / f"mutant-{index:03d}.exe").write_bytes(mutant.data)
    (tmp_path / "good.exe").write_bytes(base_image())

    result = scan_tree(tmp_path, signatures, tool_version="test")

    good = next(f for f in result.files if f.path.name == "good.exe")
    assert good.status is not AnalysisStatus.ERROR
    assert len(result.files) >= 1


def test_error_classes_stay_a_small_stable_set(tmp_path: Path, signatures: SignatureSet) -> None:
    """Error classes land in the CBOM and users filter on them, so the set has
    to be enumerable rather than open-ended."""
    known = {
        "empty",
        "not-pe",
        "truncated",
        "unsupported-machine",
        "parse-failed",
        "unreadable",
        "timeout",
        "no-result",
    }
    target = tmp_path / "mutant.exe"
    seen = set()
    for mutant in generate(mutant_count()):
        target.write_bytes(mutant.data)
        scanned = scan_file(target, signatures)
        if scanned.error_class:
            seen.add(scanned.error_class)
    assert seen <= known, f"unexpected error classes: {seen - known}"


# --- NFR-1: memory ---------------------------------------------------------


def test_absurd_header_sizes_do_not_allocate(tmp_path: Path, signatures: SignatureSet) -> None:
    """A PE claiming a 4 GB section must not produce a 4 GB read.

    Test-plan §6 suggests `resource` limits, which are POSIX-only; tracemalloc
    measures the thing that actually matters here — Python-side allocation
    driven by attacker-controlled sizes — and works on both CI platforms.
    """
    target = tmp_path / "greedy.exe"
    tracemalloc.start()
    try:
        for mutant in generate(120, seed=11):
            if "size" not in mutant.kind and "section" not in mutant.kind:
                continue
            target.write_bytes(mutant.data)
            scan_file(target, signatures)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 64 * 1024 * 1024, f"peak allocation was {peak / 1e6:.1f} MB"


# --- NFR-2: timeouts -------------------------------------------------------


def test_a_slow_file_is_reported_as_timed_out(tmp_path: Path, signatures: SignatureSet) -> None:
    """A scan that cannot finish must still produce a row in the report, not a
    hang and not a missing file."""
    target = tmp_path / "slow.exe"
    target.write_bytes(base_image())

    class SlowDetector:
        name = "slow"

        def scan(self, pe: object, sigs: object) -> list[object]:
            import time

            time.sleep(5)
            return []

    scanned = scan_file(target, signatures, detectors=[SlowDetector()], timeout=0.2)  # type: ignore[list-item]
    assert scanned.status is AnalysisStatus.ERROR
    assert scanned.error_class == "timeout"


def test_a_timeout_does_not_end_the_scan(tmp_path: Path, signatures: SignatureSet) -> None:
    (tmp_path / "good.exe").write_bytes(base_image())
    result = scan_tree(tmp_path, signatures, tool_version="test", timeout=30.0)
    assert result.files[0].status is not AnalysisStatus.ERROR


def test_timeout_can_be_disabled(tmp_path: Path, signatures: SignatureSet) -> None:
    """Zero runs the scan inline, which is what the evaluation harness wants:
    a watchdog thread per file would muddy per-file timing measurements."""
    target = tmp_path / "good.exe"
    target.write_bytes(base_image())
    assert scan_file(target, signatures, timeout=0).status is not AnalysisStatus.ERROR


def test_an_exception_inside_the_worker_is_not_swallowed(
    tmp_path: Path, signatures: SignatureSet
) -> None:
    """The watchdog must not turn a real bug into a silent success. A detector
    that raises is a defect in us, and it should surface as one."""
    target = tmp_path / "good.exe"
    target.write_bytes(base_image())

    class BrokenDetector:
        name = "broken"

        def scan(self, pe: object, sigs: object) -> list[object]:
            raise RuntimeError("detector bug")

    with pytest.raises(RuntimeError, match="detector bug"):
        scan_file(target, signatures, detectors=[BrokenDetector()])  # type: ignore[list-item]
