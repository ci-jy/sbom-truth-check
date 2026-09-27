"""Corpus evaluation: conformance and ground-truth accuracy for every generated SBOM."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from . import conformance, diff as diffmod, lockfiles, sbom as sbommod

TOOLS = ["cyclonedx-npm", "cyclonedx-py", "syft", "trivy"]


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def evaluate(corpus: Path, out: Path) -> dict:
    corpus, out = Path(corpus), Path(out)
    repos = json.loads((corpus / "repos.json").read_text())
    out.mkdir(parents=True, exist_ok=True)

    per_sbom: list[dict] = []
    failures: list[dict] = []
    mismatch_rows: list[list] = []
    for repo in repos:
        base = corpus / repo["name"]
        truth = lockfiles.resolve(base / "src")
        for err in sorted((base / "sboms").glob("*.error.txt")):
            failures.append({"repo": repo["name"], "tool": err.name.split(".")[0],
                             "error": err.read_text().strip().splitlines()[-2:]})
        for path in sorted((base / "sboms").glob("*.json")):
            tool, fmt = path.name.split(".")[0], path.name.split(".")[1]
            doc = sbommod.load(path)
            conf = conformance.check(doc)
            d = diffmod.diff(doc, truth)
            per_sbom.append({
                "repo": repo["name"], "ecosystem": repo["ecosystem"], "tool": tool, "format": fmt,
                "file": str(path.relative_to(corpus)),
                "truth": {"runtime_components": len(truth.runtime_keys()),
                          "runtime_edges": len(truth.runtime_edges()),
                          "all_locked_components": len(truth.nodes)},
                "conformance": conf.as_dict(),
                "diff": {k: v for k, v in d.as_dict().items() if k != "mismatches"},
            })
            for m in d.mismatches:
                mismatch_rows.append([repo["name"], tool, fmt, m.kind, m.cause, m.subject, m.detail])

    summary = summarize(per_sbom, failures)
    (out / "per_sbom.json").write_text(json.dumps(per_sbom, indent=1) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    with open(out / "mismatches.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "tool", "format", "kind", "cause", "subject", "detail"])
        w.writerows(mismatch_rows)
    (out / "report.md").write_text(render_markdown(summary))
    return summary


def summarize(per_sbom: list[dict], failures: list[dict]) -> dict:
    acc: dict = defaultdict(lambda: defaultdict(Counter))
    fields: dict = defaultdict(lambda: defaultdict(Counter))
    causes: dict = defaultdict(Counter)
    for row in per_sbom:
        key = f"{row['tool']} ({row['format']})"
        for part in ("components", "edges"):
            for split, pr in row["diff"][part].items():
                acc[key][f"{part}.{split}"].update(tp=pr["tp"], reported=pr["reported"], expected=pr["expected"])
        acc[key]["sboms"]["n"] += 1
        acc[key]["sboms"]["with_graph"] += int(row["diff"]["has_dependency_graph"])
        for name, res in row["conformance"]["fields"].items():
            fields[key][name]["sboms"] += 1
            fields[key][name]["passed"] += int(res["passed"])
            fields[key][name]["checked"] += res["checked"]
            fields[key][name]["failed_locations"] += len(res["failures"])
        causes[key].update(row["diff"]["causes"])

    tools = {}
    for key in sorted(acc):
        entry = {"sboms": acc[key]["sboms"]["n"], "sboms_with_dependency_graph": acc[key]["sboms"]["with_graph"]}
        for metric, c in acc[key].items():
            if metric == "sboms":
                continue
            entry[metric] = {"tp": c["tp"], "reported": c["reported"], "expected": c["expected"],
                             "precision": _ratio(c["tp"], c["reported"]), "recall": _ratio(c["tp"], c["expected"])}
        entry["conformance"] = {
            name: {"sbom_pass_rate": _ratio(c["passed"], c["sboms"]),
                   "location_pass_rate": _ratio(c["checked"] - c["failed_locations"], c["checked"])}
            for name, c in fields[key].items()}
        entry["mismatch_causes"] = dict(causes[key].most_common())
        tools[key] = entry

    field_totals = Counter()
    field_passes = Counter()
    for row in per_sbom:
        for name, res in row["conformance"]["fields"].items():
            field_totals[name] += 1
            field_passes[name] += int(res["passed"])
    all_causes = Counter()
    for c in causes.values():
        all_causes.update(c)
    return {
        "sboms_evaluated": len(per_sbom),
        "repositories": len({r["repo"] for r in per_sbom} | {f["repo"] for f in failures}),
        "fully_conformant_sboms": sum(r["conformance"]["passed"] for r in per_sbom),
        "field_pass_rate": {f: _ratio(field_passes[f], field_totals[f]) for f in conformance.FIELDS},
        "mismatches_total": sum(all_causes.values()),
        "mismatch_causes": dict(all_causes.most_common()),
        "unexplained_mismatches": all_causes.get(diffmod.UNEXPLAINED, 0),
        "generator_failures": failures,
        "tools": tools,
    }


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def render_markdown(s: dict) -> str:
    lines = ["# SBOM Truth Check: corpus results", "",
             f"{s['sboms_evaluated']} SBOMs from {s['repositories']} repositories; "
             f"{s['fully_conformant_sboms']} fully conformant; "
             f"{s['mismatches_total']} mismatches against lockfile ground truth, "
             f"{s['unexplained_mismatches']} unexplained.", "",
             "## Accuracy against lockfile ground truth (micro-averaged)", "",
             "| Tool (format) | SBOMs | Component precision | Component recall | Edge precision | Edge recall "
             "| Transitive edge recall |",
             "|---|---|---|---|---|---|---|"]
    for key, t in s["tools"].items():
        lines.append(f"| {key} | {t['sboms']} | {_pct(t['components.all']['precision'])} | "
                     f"{_pct(t['components.all']['recall'])} | {_pct(t['edges.all']['precision'])} | "
                     f"{_pct(t['edges.all']['recall'])} | {_pct(t['edges.transitive']['recall'])} |")
    lines += ["", "## Direct vs transitive components", "",
              "| Tool (format) | Direct precision | Direct recall | Transitive precision | Transitive recall |",
              "|---|---|---|---|---|"]
    for key, t in s["tools"].items():
        lines.append(f"| {key} | {_pct(t['components.direct']['precision'])} | "
                     f"{_pct(t['components.direct']['recall'])} | {_pct(t['components.transitive']['precision'])} | "
                     f"{_pct(t['components.transitive']['recall'])} |")
    lines += ["", "## CISA minimum-element conformance (share of SBOMs passing each field)", "",
              "| Field | All SBOMs | " + " | ".join(s["tools"]) + " |",
              "|---|---|" + "---|" * len(s["tools"])]
    for f in conformance.FIELDS:
        cells = [_pct(t["conformance"][f]["sbom_pass_rate"]) for t in s["tools"].values()]
        lines.append(f"| {f} | {_pct(s['field_pass_rate'][f])} | " + " | ".join(cells) + " |")
    lines += ["", "## Mismatches per cause class", "", "| Cause | Count |", "|---|---|"]
    for cause in diffmod.CAUSES:
        lines.append(f"| {cause} | {s['mismatch_causes'].get(cause, 0)} |")
    lines += ["", "## Mismatch causes per tool", ""]
    for key, t in s["tools"].items():
        top = ", ".join(f"{c} {n}" for c, n in t["mismatch_causes"].items()) or "none"
        lines.append(f"- **{key}**: {top}")
    if s["generator_failures"]:
        lines += ["", "## Generator failures", "", "| Repository | Tool | Last error line |", "|---|---|---|"]
        for f in s["generator_failures"]:
            msg = (f["error"][-1] if f["error"] else "").replace("|", "\\|")
            lines.append(f"| {f['repo']} | {f['tool']} | `{msg.strip()}` |")
    return "\n".join(lines) + "\n"
