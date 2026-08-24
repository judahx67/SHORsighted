"""Slice 1 smoke test: the CLI wiring works end to end.

Tiny on purpose. It exists so that "CI is green" means something before any
feature code lands.
"""

import subprocess
import sys

import pytest

from shorsighted import __version__
from shorsighted.cli import main


def test_version_flag_prints_version_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_args_exits_zero() -> None:
    assert main([]) == 0


def test_module_entry_point_runs() -> None:
    """`python -m shorsighted` must work, not just the console script."""
    result = subprocess.run(
        [sys.executable, "-m", "shorsighted", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout
