"""Command line: ``cpeinfer build``, ``cpeinfer evaluate``, ``cpeinfer resolve`` and ``cpeinfer sbom-gaps``."""

from __future__ import annotations

import argparse
import gzip
import json
import pickle
import subprocess
import sys
from pathlib import Path

from . import data as datamod


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def ensure_built(data: Path, years: list[int]) -> None:
    built = data / "built"
    if (built / "cves.jsonl.gz").exists() and (built / "dictionary.json.gz").exists():
        return
    if not (data / "nvd" / "nvdcpe-2.0.tar.gz").exists() or not (data / "cvelistV5").exists():
        script = Path(__file__).resolve().parent.parent / "scripts" / "fetch_cve_data.sh"
        print(f"downloading inputs with {script.name} ...", file=sys.stderr)
        subprocess.run([str(script), *map(str, years)], check=True, env={**__import__("os").environ,
                                                                            "CPEINFER_DATA": str(data)})
    datamod.build(data, years)


def load_model(data: Path):
    path = data / "built" / "model.pkl.gz"
    if not path.exists():
        sys.exit(f"{path} not found: run `python3 -m cpeinfer evaluate` first")
    with gzip.open(path, "rb") as f:
        return pickle.load(f)


def cmd_build(args) -> int:
    ensure_built(Path(args.data), args.years)
    return 0


def cmd_evaluate(args) -> int:
    from .evaluate import evaluate

    data = Path(args.data)
    ensure_built(data, sorted({*args.train_years, args.test_year}))
    s = evaluate(args.train_years, args.test_year, args.min_precision, args.margin, data, Path(args.out))
    t, b = s["test"], s["baseline"]
    print(f"test {s['test_year']} ({s['counts']['test']} enriched CVEs), threshold {s['threshold']:.2f}")
    for field in ("vendor", "vendor_product", "version_range"):
        print(f"  {field:<15} resolver P {_pct(t[field]['precision']):>6} R {_pct(t[field]['recall']):>6} | "
              f"baseline P {_pct(b[field]['precision']):>6} R {_pct(b[field]['recall']):>6}")
    print(f"  recall at baseline precision: {_pct(s['recall_at_baseline_precision'])} "
          f"vs baseline {_pct(b['vendor_product']['recall'])}")
    u = s["unenriched"]
    print(f"unenriched CVEs given a CPE: {u['covered']} of {u['total']}")
    print(f"report written to {Path(args.out) / 'report.md'}")
    rc = 0
    if not s["meets_min_precision"]:
        print(f"FAIL: vendor:product precision below {args.min_precision:.0%}", file=sys.stderr)
        rc = 1
    if args.must_beat_baseline and not s["beats_baseline"]:
        print("FAIL: recall does not beat the string-match baseline at equal precision", file=sys.stderr)
        rc = 1
    return rc


def _load_records(sources: list[str], data: Path) -> list[dict]:
    ids, records = set(), []
    for src in sources:
        p = Path(src)
        files = sorted(p.rglob("CVE-*.json")) if p.is_dir() else [p] if p.exists() else []
        if not files:
            ids.add(src.upper())
        for fp in files:
            rec = json.loads(fp.read_text())
            cna = rec.get("containers", {}).get("cna", {})
            records.append({"id": rec["cveMetadata"]["cveId"], "cna": rec["cveMetadata"].get("assignerShortName", ""),
                            "affected": cna.get("affected") or []})
    if ids:
        records += [r for r in datamod.load_cves(data) if r["id"] in ids]
    return records


def cmd_resolve(args) -> int:
    from . import resolver as R
    from .evaluate import translate

    data = Path(args.data)
    model = load_model(data)
    dictionary = R.Dictionary(datamod.load_dictionary(data))
    out = []
    for rec in _load_records(args.cves, data):
        configs = []
        for e in rec["affected"]:
            cands = R.candidates(e, rec["cna"], model["alias"], dictionary)
            if not cands:
                continue
            probs = model["scorer"].predict(R.Scorer.matrix(cands))
            k = int(probs.argmax())
            vp, p = cands[k].vp, float(probs[k])
            part = dictionary.vps.get(vp, ["a"])[0]
            ranges = translate(e)
            configs.append({"cna_vendor": e.get("vendor"), "cna_product": e.get("product"),
                            "criteria": f"cpe:2.3:{part}:{vp}:*:*:*:*:*:*:*:*", "confidence": round(p, 3),
                            "decision": "propose" if p >= model["threshold"] else "abstain",
                            "cpeMatch": None if ranges is None else [r.as_cpe_match() for r in ranges]})
        out.append({"id": rec["id"], "configurations": configs})
    if args.json:
        print(json.dumps(out, indent=1))
        return 0
    for r in out:
        print(r["id"])
        if not r["configurations"]:
            print("  abstain: no candidate CPE")
        for c in r["configurations"]:
            rng = "versions untranslatable" if c["cpeMatch"] is None else json.dumps(c["cpeMatch"])
            print(f"  {c['decision']:<8} {c['confidence']:.2f}  {c['criteria']}  {rng}"
                  f"   <- {c['cna_vendor']} / {c['cna_product']}")
    return 0


def cmd_sbom_gaps(args) -> int:
    from . import gaps as G
    from . import resolver as R

    data = Path(args.data)
    model = load_model(data)
    dictionary = R.Dictionary(datamod.load_dictionary(data), cutoff=model["cutoff"])
    index = G.Index(data / "built" / "resolved.jsonl.gz", model["threshold"])
    paths = [Path(p) for p in args.sbom]
    if args.corpus:
        paths += G.corpus_sboms(Path(args.corpus))
    gaps, stats = G.sbom_gaps(paths, model, dictionary, index)
    G.write(gaps, stats, Path(args.out))
    for g in gaps[: args.max_rows]:
        print(f"{g.purl}@{g.version:<12} {g.cve:<16} {g.cpe:<45} {g.confidence:.2f}  {g.nvd_status}: {g.reason}")
    if len(gaps) > args.max_rows:
        print(f"... {len(gaps) - args.max_rows} more")
    print(f"{len(paths)} SBOMs, {stats['components']} components: {stats['cve_hits']} CVE hits, "
          f"{len(gaps)} missed by CPE-only matching (written to {Path(args.out) / 'sbom_gaps.md'})")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cpeinfer", description="Propose NVD CPE configurations for CVEs "
                                     "from their CNA affected blocks, or abstain.")
    parser.add_argument("--data", default=str(datamod.DATA_DIR), help="data directory (default: data)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build", help="download (if needed) and compact the CVE, NVD and CPE dictionary inputs")
    p.add_argument("--years", type=int, nargs="+", default=[2023, 2024, 2025])
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("evaluate", help="time-split evaluation against NIST-enriched CVEs")
    p.add_argument("--train-years", type=int, nargs="+", default=[2023, 2024])
    p.add_argument("--test-year", type=int, default=2025)
    p.add_argument("--min-precision", type=float, default=0.95)
    p.add_argument("--margin", type=float, default=0.01, help="extra precision required on validation")
    p.add_argument("--out", default="results/cpeinfer")
    p.add_argument("--must-beat-baseline", action="store_true")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("resolve", help="proposed CPE configurations for CVE JSON 5 files, directories or CVE IDs")
    p.add_argument("cves", nargs="+")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("sbom-gaps", help="CVE hits for SBOM components that CPE-only matching misses")
    p.add_argument("sbom", nargs="*")
    p.add_argument("--corpus", help="SBOM Truth Check corpus directory (one SBOM per repository)")
    p.add_argument("--out", default="results/cpeinfer")
    p.add_argument("--max-rows", type=int, default=20)
    p.set_defaults(func=cmd_sbom_gaps)

    args = parser.parse_args(argv)
    return args.func(args)
