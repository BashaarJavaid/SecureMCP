"""--diff-policy / --html on scripts/verify_audit_chain.py (item 19): pure file
diffing of revision snapshots — no database, chain verification stays the default."""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT = str(Path(__file__).parent.parent.parent / "scripts" / "verify_audit_chain.py")


def run_diff(
    revisions_dir: Path, *args: str, cwd: Path | None = None
) -> "subprocess.CompletedProcess[str]":
    env = dict(os.environ, POLICY_REVISIONS_DIR=str(revisions_dir))
    return subprocess.run(
        [sys.executable, SCRIPT, *args], capture_output=True, text=True, env=env, cwd=cwd
    )


def write_revisions(tmp_path: Path) -> Path:
    (tmp_path / "v1.yaml").write_text("version: 1\nidentities: []\n")
    (tmp_path / "v2.yaml").write_text("version: 2\nidentities: []\nrisk:\n  protected_repos: []\n")
    return tmp_path


def test_terminal_diff(tmp_path: Path) -> None:
    result = run_diff(write_revisions(tmp_path), "--diff-policy", "v1", "v2")
    assert result.returncode == 0, result.stderr
    assert "--- v1" in result.stdout and "+++ v2" in result.stdout
    assert "-version: 1" in result.stdout
    assert "+version: 2" in result.stdout


def test_bare_numbers_accepted(tmp_path: Path) -> None:
    result = run_diff(write_revisions(tmp_path), "--diff-policy", "1", "2")
    assert result.returncode == 0
    assert "+version: 2" in result.stdout


def test_html_diff_writes_side_by_side_page(tmp_path: Path) -> None:
    result = run_diff(
        write_revisions(tmp_path), "--diff-policy", "v1", "v2", "--html", cwd=tmp_path
    )
    assert result.returncode == 0, result.stderr
    out = tmp_path / "policy-diff-v1-v2.html"
    assert out.exists()
    html = out.read_text()
    # difflib.HtmlDiff side-by-side markup: the changed digit sits in a highlight span.
    assert "<table" in html and "version:&nbsp;" in html and 'class="diff_chg"' in html


def test_missing_revision_fails(tmp_path: Path) -> None:
    result = run_diff(write_revisions(tmp_path), "--diff-policy", "v1", "v9")
    assert result.returncode == 1
    assert "no revision snapshot" in result.stdout


def test_html_without_diff_policy_is_an_error(tmp_path: Path) -> None:
    result = run_diff(tmp_path, "--html")
    assert result.returncode == 2  # argparse error
    assert "--html requires --diff-policy" in result.stderr
