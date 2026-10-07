"""Stream the raw downloads into two compact files the resolver loads in seconds.

* ``cves.jsonl.gz``: one line per CVE with its CNA affected blocks, publication date and,
  when NIST enriched it, the ground-truth ``vendor:product -> ranges`` from the NVD configurations.
* ``dictionary.json.gz``: every NVD CPE Dictionary ``vendor:product`` with its part, the date
  it was first created, its listed versions, and the rename chain from deprecated names.

Raw inputs are read one record at a time (``ijson`` for the NVD feeds, one tar member at a
time for the CPE dictionary), so peak memory stays well below 2 GB.
"""

from __future__ import annotations

import gzip
import json
import os
import tarfile
from collections import defaultdict
from pathlib import Path

import ijson

DATA_DIR = Path(os.environ.get("CPEINFER_DATA", "data"))
ENRICHED = {"Analyzed", "Modified"}
UNENRICHED = {"Deferred", "Awaiting Analysis", "Undergoing Analysis", "Received", "Not Scheduled"}
AFFECTED_FIELDS = ("vendor", "product", "packageName", "collectionURL", "repo", "cpes",
                   "packageURL", "versions", "defaultStatus")


def unescape(field: str) -> str:
    return field.replace("\\", "")


def split_cpe(name: str) -> tuple[str, str, str, str]:
    """``cpe:2.3:a:vendor:product:version:...`` -> (part, vendor, product, version), honouring ``\\:`` escapes."""
    fields, cur, esc = [], [], False
    for ch in name:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    if len(fields) < 6 or fields[0] != "cpe" or fields[1] != "2.3":
        raise ValueError(f"not a CPE 2.3 name: {name!r}")
    return fields[2], unescape(fields[3]), unescape(fields[4]), unescape(fields[5])


def vp_of(name: str) -> str:
    _, vendor, product, _ = split_cpe(name)
    return f"{vendor}:{product}"


def nvd_truth(cve: dict) -> dict[str, list[dict]]:
    """``vendor:product -> [cpeMatch range dicts]`` over the vulnerable matches of the NVD configurations."""
    out: dict[str, list[dict]] = defaultdict(list)
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                part, vendor, product, version = split_cpe(m["criteria"])
                r = {k: m[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                       "versionEndIncluding", "versionEndExcluding") if k in m}
                if version not in ("*", "-", ""):
                    r = {"version": version}
                out[f"{vendor}:{product}"].append(r)
    return dict(out)


def iter_nvd(path: Path):
    with gzip.open(path, "rb") as f:
        for item in ijson.items(f, "vulnerabilities.item", use_float=True):
            yield item["cve"]


def iter_cna(repo: Path, year: int):
    for p in sorted((repo / "cves" / str(year)).rglob("CVE-*.json")):
        with open(p, encoding="utf-8") as f:
            rec = json.load(f)
        meta = rec.get("cveMetadata", {})
        if meta.get("state") != "PUBLISHED":
            continue
        cna = rec.get("containers", {}).get("cna", {})
        affected = []
        for a in cna.get("affected") or []:
            affected.append({k: a[k] for k in AFFECTED_FIELDS if a.get(k) not in (None, "", [])})
        yield {"id": meta["cveId"], "published": (meta.get("datePublished") or "")[:10],
               "cna": meta.get("assignerShortName", ""), "affected": affected}


def build_cves(data: Path, years: list[int], out: Path) -> int:
    nvd: dict[str, tuple[str, dict]] = {}
    for y in years:
        for cve in iter_nvd(data / "nvd" / f"nvdcve-2.0-{y}.json.gz"):
            status = cve.get("vulnStatus", "")
            if status == "Rejected":
                continue
            nvd[cve["id"]] = (status, nvd_truth(cve), (cve.get("published") or "")[:10])
    n = 0
    with gzip.open(out, "wt", encoding="utf-8") as f:
        for y in years:
            for rec in iter_cna(data / "cvelistV5", y):
                status, truth, nvd_pub = nvd.get(rec["id"], ("", {}, ""))
                rec["published"] = rec["published"] or nvd_pub
                rec["nvd_status"] = status
                rec["truth"] = truth
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                n += 1
    return n


def build_dictionary(tar_path: Path, out: Path) -> int:
    vps: dict[str, list] = {}
    deprecated_by: dict[str, set[str]] = defaultdict(set)
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            chunk = json.load(tar.extractfile(member))
            for prod in chunk.get("products", []):
                c = prod["cpe"]
                try:
                    part, vendor, product, version = split_cpe(c["cpeName"])
                except ValueError:
                    continue
                vp = f"{vendor}:{product}"
                created = (c.get("created") or "")[:10]
                cur = vps.setdefault(vp, [part, created, set(), True])
                if created and (not cur[1] or created < cur[1]):
                    cur[1] = created
                if version not in ("*", "-", ""):
                    cur[2].add(version)
                if c.get("deprecated"):
                    for d in c.get("deprecatedBy") or []:
                        try:
                            new = vp_of(d["cpeName"])
                        except (KeyError, ValueError):
                            continue
                        if new != vp:
                            deprecated_by[vp].add(new)
                else:
                    cur[3] = False  # at least one live entry
            del chunk
    renames = {}
    for vp, targets in deprecated_by.items():
        if len(targets) == 1 and vps.get(vp, [0, 0, 0, False])[3]:
            renames[vp] = next(iter(targets))
    payload = {"vps": {vp: [p, c, sorted(v)] for vp, (p, c, v, _) in vps.items()}, "renames": renames}
    with gzip.open(out, "wt", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
    return len(vps)


def build(data: Path = DATA_DIR, years: list[int] = (2023, 2024, 2025)) -> None:
    out_dir = data / "built"
    out_dir.mkdir(parents=True, exist_ok=True)
    n = build_dictionary(data / "nvd" / "nvdcpe-2.0.tar.gz", out_dir / "dictionary.json.gz")
    print(f"dictionary: {n} vendor:product pairs")
    n = build_cves(data, list(years), out_dir / "cves.jsonl.gz")
    print(f"cves: {n} published CNA records")


def load_cves(data: Path = DATA_DIR) -> list[dict]:
    with gzip.open(data / "built" / "cves.jsonl.gz", "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def load_dictionary(data: Path = DATA_DIR) -> dict:
    with gzip.open(data / "built" / "dictionary.json.gz", "rt", encoding="utf-8") as f:
        return json.load(f)
