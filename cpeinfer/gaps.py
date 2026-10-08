"""SBOM link: join SBOM Truth Check's canonical PURLs to inferred CPEs and list CVE hits CPE-only matching misses.

A component hits a CVE when one of the CVE's CNA affected entries names the component (same
canonical package URL, or both resolve to the same ``vendor:product`` and the component's own
resolution clears the threshold) and the component's version falls inside the entry's translated range. The hit is *missed by
CPE-only matching* when NVD's CPE configurations would not flag it: the CVE was never enriched,
its configurations do not name the product, or their ranges exclude the version.
"""

from __future__ import annotations

import gzip
import json
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

from sbomcheck import purl as purlmod
from sbomcheck import sbom as sbommod

from . import resolver as R
from . import versions as vmod

COLLECTION = {"npm": "https://registry.npmjs.org", "pypi": "https://pypi.org", "maven": "https://repo.maven.apache.org/maven2",
              "gem": "https://rubygems.org", "cargo": "https://crates.io", "composer": "https://packagist.org",
              "nuget": "https://www.nuget.org", "golang": "https://pkg.go.dev"}
TOOL_PREFERENCE = ["trivy.cdx.json", "syft.cdx.json", "cyclonedx-npm.cdx.json", "cyclonedx-py.cdx.json"]


@dataclass
class Gap:
    sbom: str
    purl: str
    version: str
    cve: str
    cpe: str
    confidence: float
    matched_by: str
    nvd_status: str
    reason: str


def component_entry(p: purlmod.Purl) -> dict:
    """A CNA-style affected entry describing an SBOM component, so the resolver can map it to a CPE."""
    if p.type == "maven":
        pkg = f"{p.namespace}:{p.name}"
        vendor = (p.namespace or "").split(".")[-1]
    else:
        pkg = f"{p.namespace}/{p.name}" if p.namespace else p.name
        vendor = (p.namespace or p.name).lstrip("@")
    return {"vendor": vendor, "product": p.name, "packageName": pkg,
            "collectionURL": COLLECTION.get(p.type, ""), "packageURL": purlmod.Purl(p.type, p.namespace, p.name).to_string()}


class Index:
    def __init__(self, resolved_path: Path, threshold: float):
        self.by_vp: dict[str, list] = defaultdict(list)
        self.by_pkg: dict[str, list] = defaultdict(list)
        with gzip.open(resolved_path, "rt", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                for e in rec["entries"]:
                    if e["ranges"] is None:
                        continue
                    item = (rec, e)
                    if e["pkg"]:
                        self.by_pkg[e["pkg"]].append(item)
                    if e["vp"]:
                        self.by_vp[e["vp"]].append(item)


def cpe_only_flags(rec: dict, vp: str, version: str) -> tuple[bool, str]:
    if not rec["truth"]:
        return False, "no NVD CPE configuration"
    if vp not in rec["truth"]:
        return False, "NVD configuration does not name this product"
    ranges = [vmod.Range.from_cpe_match(m, m.get("version", "*")) for m in rec["truth"][vp]]
    if vmod.in_ranges(ranges, version):
        return True, ""
    return False, "NVD range excludes this version"


def sbom_gaps(sbom_paths, model: dict, dictionary: R.Dictionary, index: Index) -> tuple[list[Gap], dict]:
    gaps, stats = [], {"components": 0, "resolved": 0, "cve_hits": 0, "cpe_only_hits": 0}
    seen = set()
    for path in sbom_paths:
        doc = sbommod.load(path)
        for comp in doc.package_components:
            if not comp.purl:
                continue
            try:
                p = purlmod.canonicalize(comp.purl)
            except purlmod.PurlError:
                continue
            if not p.version:
                continue
            stats["components"] += 1
            entry = component_entry(p)
            cands = R.candidates(entry, "", model["alias"], dictionary)
            vp, conf = None, 0.0
            if cands:
                probs = model["scorer"].predict(R.Scorer.matrix(cands))
                k = int(probs.argmax())
                vp, conf = cands[k].vp, float(probs[k])
                stats["resolved"] += conf >= model["threshold"]
            pkg = purlmod.Purl(p.type, p.namespace, p.name).to_string()
            items = [(r, e, "purl") for r, e in index.by_pkg.get(pkg, [])]
            if vp and conf >= model["threshold"]:  # the component's own CPE must clear the threshold
                items += [(r, e, "cpe") for r, e in index.by_vp.get(vp, [])]
            for rec, e, how in items:
                key = (str(path), pkg, p.version, rec["id"])
                if key in seen:
                    continue
                ranges = [vmod.Range.from_cpe_match(m, m.get("version", "*")) for m in e["ranges"]]
                if not ranges or not vmod.in_ranges(ranges, p.version):
                    continue
                seen.add(key)
                stats["cve_hits"] += 1
                target = vp or e["vp"]
                flagged, reason = cpe_only_flags(rec, target, p.version) if target else (False, "no CPE")
                if flagged:
                    stats["cpe_only_hits"] += 1
                    continue
                gaps.append(Gap(str(path), pkg, p.version, rec["id"], f"cpe:2.3:a:{target}:{p.version}"
                                if target else "", round(max(conf, e["prob"]) if vp else e["prob"], 3), how,
                                rec["nvd_status"] or "not in NVD feed", reason))
    return gaps, stats


def corpus_sboms(corpus: Path) -> list[Path]:
    out = []
    for repo in sorted(p for p in corpus.iterdir() if (p / "sboms").is_dir()):
        for name in TOOL_PREFERENCE:
            if (repo / "sboms" / name).exists():
                out.append(repo / "sboms" / name)
                break
    return out


def write(gaps: list[Gap], stats: dict, out: Path) -> None:
    import pandas as pd

    out.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame([asdict(g) for g in gaps], columns=list(Gap.__dataclass_fields__))
    df.to_csv(out / "sbom_gaps.csv", index=False)
    lines = ["# SBOM gap list", "",
             f"{stats['components']} versioned components, {stats['resolved']} mapped to a CPE at the threshold; "
             f"{stats['cve_hits']} component-CVE hits from CNA data, {stats['cpe_only_hits']} of them also found by "
             f"NVD CPE matching, {len(gaps)} missed by CPE-only matching.", ""]
    if len(df):
        lines += ["| SBOM | Component | CVE | Inferred CPE | Confidence | NVD status | Why CPE-only matching misses it |",
                  "|---|---|---|---|---|---|---|"]
        for g in gaps:
            lines.append(f"| {Path(g.sbom).parent.parent.name} | {g.purl}@{g.version} | {g.cve} | `{g.cpe}` | "
                         f"{g.confidence:.2f} | {g.nvd_status} | {g.reason} |")
    (out / "sbom_gaps.md").write_text("\n".join(lines) + "\n")
