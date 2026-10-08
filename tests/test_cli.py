"""End-to-end runs of the CLI on the committed corpus."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run([sys.executable, "-m", "sbomcheck", *args], cwd=ROOT, capture_output=True, text=True)


def test_conform_reports_every_field():
    proc = run("conform", "corpus/koa/sboms/trivy.cdx.json", "--json")
    assert proc.returncode == 0
    report = json.loads(proc.stdout)
    assert len(report["fields"]) == 13
    assert report["fields"]["component_hash"]["failures"][0]["path"].startswith("$.components[")


def test_conform_strict_exits_nonzero_on_failure():
    assert run("conform", "corpus/koa/sboms/syft.spdx.json", "--strict").returncode == 1


def test_diff_against_lockfile():
    proc = run("diff", "corpus/koa/sboms/cyclonedx-npm.cdx.json", "corpus/koa/src/package-lock.json",
               "--fail-on-unexplained")
    assert proc.returncode == 0, proc.stderr
    assert "[dev_test_dependency_included]" in proc.stdout


def test_evaluate_corpus_has_no_unexplained_mismatches(tmp_path):
    proc = run("evaluate", "--corpus", "corpus", "--out", str(tmp_path), "--fail-on-unexplained")
    assert proc.returncode == 0, proc.stderr
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["repositories"] == 20
    assert summary["unexplained_mismatches"] == 0
    assert summary["sboms_evaluated"] >= 80
    assert (tmp_path / "report.md").exists() and (tmp_path / "mismatches.csv").exists()


DATA = ROOT / "data" / "built"


@pytest.mark.skipif(not (DATA / "model.pkl.gz").exists(), reason="needs `python3 -m cpeinfer evaluate` data")
def test_cpeinfer_resolve_and_sbom_gaps(tmp_path):
    out = subprocess.run([sys.executable, "-m", "cpeinfer", "resolve", "CVE-2025-27152", "--json"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    configs = json.loads(out)[0]["configurations"]
    assert configs[0]["criteria"].startswith("cpe:2.3:a:axios:axios:")
    assert configs[0]["cpeMatch"] == [{"versionEndExcluding": "1.8.2"}]
    subprocess.run([sys.executable, "-m", "cpeinfer", "sbom-gaps", "--corpus", "corpus", "--out", str(tmp_path)], cwd=ROOT,
                   check=True, capture_output=True)
    assert (tmp_path / "sbom_gaps.csv").exists() and (tmp_path / "sbom_gaps.md").exists()
