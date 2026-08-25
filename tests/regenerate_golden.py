"""Regenerate the committed golden CBOM.

    python -m tests.regenerate_golden

Deliberately a separate command rather than an `--update` flag on the test run.
A golden file that regenerates itself whenever it disagrees with the code is not
a test, it is a transcript — the whole value is that a change to the output
shape has to be looked at and approved by a person before it lands.
"""

import tempfile
from dataclasses import replace
from pathlib import Path

from shorsighted.core.scanner import scan_paths
from shorsighted.output import cbom
from shorsighted.signatures.loader import load_signatures
from tests.test_output_cbom import CNG_IMAGE, GOLDEN


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "cng-sample.exe"
        target.write_bytes(CNG_IMAGE)
        result = scan_paths([target], load_signatures(), tool_version="0.1.0.test")

    stable = replace(
        result,
        files=tuple(replace(f, path=Path("fixtures/cng-sample.exe")) for f in result.files),
    )
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(cbom.serialize(stable, reproducible=True), encoding="utf-8", newline="\n")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
