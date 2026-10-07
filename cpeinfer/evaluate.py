"""Time-split evaluation: alias model and scorer from the training years, metrics on the held-out year.

Splits (by CNA ``datePublished``; the CPE dictionary is cut at the same dates):

* alias fit   training years before 1 July of the last training year
* validation  1 July - 31 December of the last training year: the scorer is fitted here
              (5-fold cross-fitted probabilities choose the abstention threshold)
* test        the test year, scored with aliases re-learned from all training years
"""

from __future__ import annotations

import gzip
import json
import pickle
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from . import data as datamod
from . import resolver as R
from . import versions as vmod

THRESHOLDS = [round(x, 2) for x in np.arange(0.05, 1.0, 0.01)]


def enriched(rec: dict) -> bool:
    return rec["nvd_status"] in datamod.ENRICHED and bool(rec["truth"]) and bool(rec["affected"])


def unenriched(rec: dict) -> bool:
    return not rec["truth"] and rec["nvd_status"] in datamod.UNENRICHED and bool(rec["affected"])


def translate(entry: dict):
    try:
        return vmod.translate(entry.get("versions") or [], entry.get("defaultStatus"))
    except Exception:
        return None


def truth_ranges(items: list[dict]) -> list[vmod.Range]:
    return [vmod.Range.from_cpe_match(m, m.get("version", "*")) for m in items]


def score_records(records, alias, dictionary, scorer=None):
    """-> rows (cve, entry index, candidate vp, features, label) and per-entry candidate lists."""
    out = []
    for rec in records:
        truth = set(rec["truth"])
        for i, e in enumerate(rec["affected"]):
            cands = R.candidates(e, rec["cna"], alias, dictionary)
            if cands and scorer is not None:
                probs = scorer.predict(R.Scorer.matrix(cands))
                for c, p in zip(cands, probs):
                    c.prob = float(p)
            out.append((rec, i, e, cands, [c.vp in truth for c in cands]))
    return out


def predictions(scored) -> dict[str, dict[str, tuple[float, list | None]]]:
    """Top candidate per entry, merged per CVE: cve -> vp -> (probability, translated ranges)."""
    preds: dict[str, dict] = defaultdict(dict)
    for rec, _, e, cands, _ in scored:
        if not cands:
            continue
        best = max(cands, key=lambda c: c.prob)
        ranges = translate(e)
        cur = preds[rec["id"]].get(best.vp)
        if cur is None:
            preds[rec["id"]][best.vp] = (best.prob, ranges)
        else:
            merged = None if cur[1] is None or ranges is None else cur[1] + ranges
            preds[rec["id"]][best.vp] = (max(cur[0], best.prob), merged)
    return preds


def pair_table(records, preds) -> list[tuple]:
    """(cve, vp, probability, range overlap or None) per predicted pair; overlaps are computed once."""
    by_id = {r["id"]: r for r in records}
    rows = []
    for cve, vps in preds.items():
        for vp, (p, ranges) in vps.items():
            ov = None
            if vp in by_id[cve]["truth"] and ranges is not None:
                ov = vmod.range_overlap(ranges, truth_ranges(by_id[cve]["truth"][vp]))
            rows.append((cve, vp, p, ov))
    return rows


def metrics(records, preds, threshold: float, table=None) -> dict:
    truth_pairs = {(r["id"], vp) for r in records for vp in r["truth"]}
    truth_vendors = {(c, vp.split(":", 1)[0]) for c, vp in truth_pairs}
    pred_pairs, pred_vendors = set(), set()
    exact = overlaps = 0
    overlap_sum = 0.0
    for cve, vp, p, ov in (table if table is not None else pair_table(records, preds)):
        if p < threshold:
            continue
        pred_pairs.add((cve, vp))
        pred_vendors.add((cve, vp.split(":", 1)[0]))
        if ov is not None:
            overlaps += 1
            overlap_sum += ov
            exact += ov == 1.0
    tp, tpv = len(pred_pairs & truth_pairs), len(pred_vendors & truth_vendors)

    def pr(hit, pred, true):
        return {"precision": hit / pred if pred else None, "recall": hit / true if true else None,
                "predicted": pred, "correct": hit, "truth": true}

    return {"vendor": pr(tpv, len(pred_vendors), len(truth_vendors)),
            "vendor_product": pr(tp, len(pred_pairs), len(truth_pairs)),
            "version_range": pr(exact, len(pred_pairs), len(truth_pairs)),
            "version_overlap_mean": overlap_sum / overlaps if overlaps else None,
            "cves_with_prediction": len({c for c, _ in pred_pairs})}


def baseline_preds(records, dictionary):
    preds: dict[str, dict] = defaultdict(dict)
    for rec in records:
        for e in rec["affected"]:
            vp = R.baseline(e, dictionary)
            if vp:
                preds[rec["id"]][vp] = (1.0, translate(e))
    return preds


def choose_threshold(records, preds, target: float) -> float:
    table = pair_table(records, preds)
    for t in THRESHOLDS:
        m = metrics(records, preds, t, table)["vendor_product"]
        if m["precision"] is not None and m["precision"] >= target:
            return t
    return THRESHOLDS[-1]


def calibration(scored) -> pd.DataFrame:
    rows = []
    for rec, _, e, cands, labels in scored:
        if cands:
            best = max(range(len(cands)), key=lambda k: cands[k].prob)
            rows.append((cands[best].prob, labels[best]))
    df = pd.DataFrame(rows, columns=["prob", "correct"])
    df["bin"] = pd.cut(df["prob"], np.linspace(0, 1, 11), include_lowest=True)
    return df.groupby("bin", observed=True).agg(n=("correct", "size"), mean_prob=("prob", "mean"),
                                                 accuracy=("correct", "mean")).reset_index()


def evaluate(train_years, test_year, min_precision=0.95, margin=0.01, data=datamod.DATA_DIR,
             out=Path("results/cpeinfer"), log=print) -> dict:
    data, out = Path(data), Path(out)
    raw_dict = datamod.load_dictionary(data)
    records = datamod.load_cves(data)
    year = lambda r: int(r["published"][:4]) if r["published"] else 0
    last = max(train_years)
    val_start, test_start = f"{last}-07-01", f"{test_year}-01-01"
    train = [r for r in records if year(r) in train_years and enriched(r)]
    fit = [r for r in train if r["published"] < val_start]
    val = [r for r in train if r["published"] >= val_start]
    test = [r for r in records if year(r) == test_year and enriched(r)]
    log(f"records: {len(records)}; enriched train {len(train)} (alias fit {len(fit)}, validation {len(val)}), "
        f"test {len(test)}")

    # stage 1: aliases before the validation window, scorer + threshold on it
    alias1 = R.AliasModel().fit(fit)
    dict1 = R.Dictionary(raw_dict, cutoff=val_start)
    scored_val = score_records(val, alias1, dict1)
    X = np.vstack([R.Scorer.matrix(c) for _, _, _, c, _ in scored_val if c])
    y = np.concatenate([np.array(l, float) for _, _, _, c, l in scored_val if c])
    groups = np.concatenate([[hash(rec["id"]) % 5] * len(c) for rec, _, _, c, _ in scored_val if c])
    oof = np.zeros(len(y))
    for k in range(5):
        m = groups == k
        oof[m] = R.Scorer().fit(X[~m], y[~m]).predict(X[m])
    pos = 0
    for _, _, _, cands, _ in scored_val:
        for c in cands:
            c.prob = float(oof[pos])
            pos += 1
    val_preds = predictions(scored_val)
    threshold = choose_threshold(val, val_preds, min_precision + margin)
    val_m = metrics(val, val_preds, threshold)
    calib = calibration(scored_val)
    scorer = R.Scorer().fit(X, y)
    log(f"validation: threshold {threshold:.2f} -> vendor:product precision "
        f"{val_m['vendor_product']['precision']:.3f} recall {val_m['vendor_product']['recall']:.3f}")

    # stage 2: aliases from all training years, dictionary as of the test start
    alias2 = R.AliasModel().fit(train)
    dict2 = R.Dictionary(raw_dict, cutoff=test_start)
    scored_test = score_records(test, alias2, dict2, scorer)
    test_preds = predictions(scored_test)
    base_preds = baseline_preds(test, dict2)
    base = metrics(test, base_preds, 0.5)
    table = pair_table(test, test_preds)
    ours = metrics(test, test_preds, threshold, table)
    curve = pd.DataFrame([{"threshold": t, **{f"{f}_{k}": metrics(test, test_preds, t, table)[f][k]
                                              for f in ("vendor", "vendor_product", "version_range")
                                              for k in ("precision", "recall")}} for t in THRESHOLDS])
    bp = base["vendor_product"]["precision"]
    at_equal = curve[curve["vendor_product_precision"] >= bp]["vendor_product_recall"].max()
    at_equal = float(at_equal) if not np.isnan(at_equal) else 0.0

    # coverage of CVEs NIST has not enriched, at the operating point
    pending = [r for r in records if unenriched(r)]
    scored_pending = score_records(pending, alias2, dict2, scorer)
    pending_preds = predictions(scored_pending)
    covered = {c for c, vps in pending_preds.items() if any(p >= threshold for p, _ in vps.values())}
    by_status, by_year = Counter(), Counter()
    cov_status, cov_year = Counter(), Counter()
    for r in pending:
        by_status[r["nvd_status"]] += 1
        by_year[year(r)] += 1
        if r["id"] in covered:
            cov_status[r["nvd_status"]] += 1
            cov_year[year(r)] += 1

    summary = {
        "train_years": list(train_years), "test_year": test_year, "min_precision": min_precision,
        "threshold": threshold, "validation": val_m, "test": ours, "baseline": base,
        "recall_at_baseline_precision": at_equal,
        "beats_baseline": at_equal > base["vendor_product"]["recall"],
        "meets_min_precision": (ours["vendor_product"]["precision"] or 0) >= min_precision,
        "counts": {"enriched_train": len(train), "validation": len(val), "test": len(test),
                   "dictionary_vps_at_test": len(dict2.vps), "renames": len(dict2.renames)},
        "unenriched": {"total": len(pending), "covered": len(covered),
                       "by_status": {s: [by_status[s], cov_status[s]] for s in sorted(by_status)},
                       "by_year": {str(y): [by_year[y], cov_year[y]] for y in sorted(by_year)}},
        "scorer_weights": dict(zip(R.FEATURES, map(float, scorer.w))),
    }
    write_report(out, summary, curve, calib)
    model_path = data / "built" / "model.pkl.gz"
    with gzip.open(model_path, "wb") as f:
        pickle.dump({"alias": alias2, "scorer": scorer, "threshold": threshold, "cutoff": test_start}, f)
    write_index(data, records, alias2, dict2, scorer)
    return summary


def write_index(data: Path, records, alias, dictionary, scorer) -> None:
    """Resolve every CVE once so ``sbom-gaps`` can look components up by vendor:product."""
    with gzip.open(data / "built" / "resolved.jsonl.gz", "wt", encoding="utf-8") as f:
        for rec in records:
            entries = []
            for e in rec["affected"]:
                cands = R.candidates(e, rec["cna"], alias, dictionary)
                if cands:
                    probs = scorer.predict(R.Scorer.matrix(cands))
                    k = int(np.argmax(probs))
                    vp, p = cands[k].vp, float(probs[k])
                else:
                    vp, p = None, 0.0
                ranges = translate(e)
                entries.append({"vp": vp, "prob": round(p, 4), "pkg": R.package_key(e),
                                "ranges": None if ranges is None else [r.as_cpe_match() for r in ranges]})
            f.write(json.dumps({"id": rec["id"], "nvd_status": rec["nvd_status"], "truth": rec["truth"],
                                "entries": entries}, separators=(",", ":")) + "\n")


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def write_report(out: Path, s: dict, curve: pd.DataFrame, calib: pd.DataFrame) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, m in (("resolver", s["test"]), ("string-match baseline", s["baseline"])):
        for field in ("vendor", "vendor_product", "version_range"):
            rows.append({"method": name, "field": field, **m[field]})
    table = pd.DataFrame(rows)
    table.to_csv(out / "metrics.csv", index=False)
    curve.to_csv(out / "precision_coverage.csv", index=False)
    calib.assign(bin=calib["bin"].astype(str)).to_csv(out / "calibration.csv", index=False)
    (out / "summary.json").write_text(json.dumps(s, indent=1) + "\n")
    t, b, u = s["test"], s["baseline"], s["unenriched"]
    lines = [
        "# cpeinfer evaluation", "",
        f"Train {s['train_years']} (validation = second half of {max(s['train_years'])}), "
        f"test {s['test_year']}: {s['counts']['test']} NIST-enriched CVEs with CNA affected blocks.",
        f"Threshold {s['threshold']:.2f}, chosen on validation for >= {s['min_precision']:.0%} vendor:product precision.", "",
        "| Field | Resolver precision | Resolver recall | Baseline precision | Baseline recall |",
        "|---|---|---|---|---|",
    ]
    for field in ("vendor", "vendor_product", "version_range"):
        lines.append(f"| {field} | {_pct(t[field]['precision'])} | {_pct(t[field]['recall'])} | "
                     f"{_pct(b[field]['precision'])} | {_pct(b[field]['recall'])} |")
    lines += ["",
              f"Mean range overlap (Jaccard) on correct vendor:product pairs: resolver "
              f"{_pct(t['version_overlap_mean'])}, baseline {_pct(b['version_overlap_mean'])}.",
              f"Resolver recall at the baseline's precision ({_pct(b['vendor_product']['precision'])}): "
              f"{_pct(s['recall_at_baseline_precision'])} vs baseline {_pct(b['vendor_product']['recall'])}.", "",
              "## Unenriched CVEs covered at the operating point", "",
              f"{u['covered']} of {u['total']} CVEs with CNA affected data and no NIST CPE configuration "
              "get at least one CPE.", "", "| NVD status | CVEs | covered |", "|---|---|---|"]
    for st, (n, c) in u["by_status"].items():
        lines.append(f"| {st} | {n} | {c} |")
    lines += ["", "| Published | CVEs | covered |", "|---|---|---|"]
    for y, (n, c) in u["by_year"].items():
        lines.append(f"| {y} | {n} | {c} |")
    lines += ["", "## Precision-coverage curve (test)", "",
              "| Threshold | vendor:product precision | recall | version-range precision | recall |",
              "|---|---|---|---|---|"]
    for _, r in curve.iloc[::10].iterrows():
        lines.append(f"| {r['threshold']:.2f} | {_pct(r['vendor_product_precision'])} | "
                     f"{_pct(r['vendor_product_recall'])} | {_pct(r['version_range_precision'])} | "
                     f"{_pct(r['version_range_recall'])} |")
    lines += ["", "## Calibration (validation, cross-fitted)", "", "| Probability bin | entries | mean probability | accuracy |",
              "|---|---|---|---|"]
    for _, r in calib.iterrows():
        lines.append(f"| {r['bin']} | {r['n']} | {r['mean_prob']:.2f} | {r['accuracy']:.2f} |")
    (out / "report.md").write_text("\n".join(lines) + "\n")
