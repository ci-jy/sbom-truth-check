"""Command line: ``sbomcheck conform``, ``sbomcheck diff`` and ``sbomcheck evaluate``."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from . import conformance, diff as diffmod, lockfiles, sbom as sbommod


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def cmd_conform(args) -> int:
    report = conformance.check(args.sbom)
    if args.json:
        print(json.dumps(report.as_dict(), indent=1))
    else:
        print(f"{args.sbom}: {report.format} {report.spec_version}")
        for name, r in report.results.items():
            status = "PASS" if r.passed else "FAIL"
            print(f"  {status}  {name:<26} {len(r.failures)}/{r.checked} locations failing")
            for path, reason in r.failures[: args.max_failures]:
                print(f"          {path}: {reason}")
            if len(r.failures) > args.max_failures:
                print(f"          ... {len(r.failures) - args.max_failures} more")
        print("CONFORMANT" if report.passed else "NOT CONFORMANT")
    return 1 if args.strict and not report.passed else 0


def cmd_diff(args) -> int:
    doc = sbommod.load(args.sbom)
    lock = Path(args.lockfile)
    if lock.name == "poetry.lock" and args.pyproject:
        truth = lockfiles.resolve_poetry(lock, args.pyproject)
    elif args.pom:
        truth = lockfiles.resolve_maven_tree(lock, args.pom)
    else:
        truth = lockfiles.resolve(lock)
    result = diffmod.diff(doc, truth)
    if args.json:
        print(json.dumps(result.as_dict(), indent=1))
        return 1 if args.fail_on_unexplained and result.cause_counts()[diffmod.UNEXPLAINED] else 0
    print(f"{args.sbom} vs {args.lockfile} ({truth.ecosystem}, {len(truth.runtime_keys())} shipped packages)")
    for part in ("components", "edges"):
        for split, pr in getattr(result, part).items():
            print(f"  {part:<10} {split:<10} precision {_pct(pr.precision):>6}  recall {_pct(pr.recall):>6}"
                  f"  (matched {pr.tp}, reported {pr.reported}, expected {pr.expected})")
    grouped = defaultdict(list)
    for m in result.mismatches:
        grouped[m.cause].append(m)
    print(f"  {len(result.mismatches)} mismatches")
    for cause, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        print(f"  [{cause}] {len(items)}")
        for m in items[: args.max_failures]:
            print(f"      {m.kind}: {m.subject}" + (f"  ({m.detail})" if m.detail else ""))
        if len(items) > args.max_failures:
            print(f"      ... {len(items) - args.max_failures} more")
    return 1 if args.fail_on_unexplained and grouped.get(diffmod.UNEXPLAINED) else 0


def cmd_evaluate(args) -> int:
    from .evaluate import evaluate

    summary = evaluate(Path(args.corpus), Path(args.out))
    print(f"evaluated {summary['sboms_evaluated']} SBOMs from {summary['repositories']} repositories")
    for key, t in summary["tools"].items():
        print(f"  {key:<26} components P {_pct(t['components.all']['precision']):>6} "
              f"R {_pct(t['components.all']['recall']):>6} | edges P {_pct(t['edges.all']['precision']):>6} "
              f"R {_pct(t['edges.all']['recall']):>6}")
    print(f"mismatches: {summary['mismatches_total']}, unexplained: {summary['unexplained_mismatches']}")
    print(f"report written to {Path(args.out) / 'report.md'}")
    if args.fail_on_unexplained and summary["unexplained_mismatches"]:
        print("FAIL: unexplained mismatches remain", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sbomcheck", description="Check SBOMs against CISA minimum "
                                     "elements and against the dependency graph in the lockfile.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("conform", help="per-field CISA minimum-element verdict for one SBOM")
    p.add_argument("sbom")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit 1 when any field fails")
    p.add_argument("--max-failures", type=int, default=3, help="failing locations printed per field")
    p.set_defaults(func=cmd_conform)

    p = sub.add_parser("diff", help="compare an SBOM with lockfile ground truth")
    p.add_argument("sbom")
    p.add_argument("lockfile", help="package-lock.json, poetry.lock, mvn dependency:tree output, or a directory")
    p.add_argument("--pyproject", help="pyproject.toml for a poetry.lock (default: next to the lockfile)")
    p.add_argument("--pom", help="pom.xml for a Maven tree (default: next to the tree file)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--max-failures", type=int, default=5, help="mismatches printed per cause")
    p.add_argument("--fail-on-unexplained", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("evaluate", help="evaluate every SBOM in a corpus directory")
    p.add_argument("--corpus", default="corpus")
    p.add_argument("--out", default="results")
    p.add_argument("--fail-on-unexplained", action="store_true")
    p.set_defaults(func=cmd_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)
