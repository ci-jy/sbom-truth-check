"""Alias model, candidate generation and calibrated scoring: CNA affected entry -> NVD ``vendor:product``.

The alias model is learned only from CVEs NIST enriched inside the training window. Each CNA
affected entry is aligned with the NVD ``vendor:product`` it most resembles, and the model
counts how often each key (normalized vendor+product, product, package URL, vendor) mapped to
each CPE. Candidates come from those aliases, from CPEs the CNA itself listed, and from the
CPE dictionary (as of the cutoff date) by normalized tokens, with deprecated names followed to
their replacement. A logistic regression turns the candidate features into a probability.
"""

from __future__ import annotations

import math
import re
from functools import lru_cache
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np

from sbomcheck import purl as purlmod

from . import versions as vmod
from .data import split_cpe

STOP = {"inc", "ltd", "llc", "co", "corp", "corporation", "company", "gmbh", "ag", "sa", "the", "limited",
        "software", "technologies", "technology", "foundation", "project", "team", "org", "com", "systems"}

# collectionURL host -> PURL type
REGISTRIES = [
    ("npmjs", "npm"), ("pypi", "pypi"), ("maven", "maven"), ("rubygems", "gem"), ("crates.io", "cargo"),
    ("packagist", "composer"), ("nuget", "nuget"), ("pkg.go.dev", "golang"), ("proxy.golang", "golang"),
    ("hex.pm", "hex"), ("pub.dev", "pub"), ("cocoapods", "cocoapods"), ("wordpress.org/plugins", "wordpress-plugin"),
    ("wordpress.org/themes", "wordpress-theme"), ("github.com", "github"),
]


@lru_cache(maxsize=1_000_000)
def norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


@lru_cache(maxsize=1_000_000)
def tokens(s: str | None) -> frozenset[str]:
    return frozenset(t for t in norm(s).split("_") if t and t not in STOP)


def jaccard(a: frozenset, b: frozenset) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def package_key(entry: dict) -> str | None:
    """Version-less canonical PURL for an affected entry (from packageURL, collectionURL+packageName or repo)."""
    if entry.get("packageURL") and (key := purl_key(entry["packageURL"])):
        return key
    name, coll = entry.get("packageName"), (entry.get("collectionURL") or "").lower()
    if name and coll:
        for host, ptype in REGISTRIES:
            if host in coll:
                if ptype == "maven" and ":" in name:
                    g, a = name.split(":", 1)
                    text = f"pkg:maven/{g}/{a}"
                elif ptype in ("wordpress-plugin", "wordpress-theme"):
                    return f"pkg:generic/{ptype}/{name.lower()}"
                else:
                    text = f"pkg:{ptype}/{name}"
                return purl_key(text)
    repo = (entry.get("repo") or "").lower()
    m = re.match(r"https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", repo)
    if m:
        return f"pkg:github/{m.group(1)}/{m.group(2)}"
    return None


def purl_key(text: str) -> str | None:
    """SBOM Truth Check's canonical PURL without the version (``pkg:PyPI/Foo_Bar@1`` -> ``pkg:pypi/foo-bar``)."""
    try:
        return purlmod.package_key(text)
    except purlmod.PurlError:
        return None


def cna_cpe_vps(entry: dict) -> set[str]:
    out = set()
    for c in entry.get("cpes") or []:
        try:
            _, v, p, _ = split_cpe(c)
        except ValueError:
            continue
        if v not in ("*", "") and p not in ("*", ""):
            out.add(f"{v}:{p}")
    return out


def entry_keys(entry: dict, cna: str = "") -> list[tuple]:
    nv, np_ = norm(entry.get("vendor")), norm(entry.get("product"))
    keys = []
    if np_ and np_ not in ("n_a", "unspecified"):
        keys.append(("vp", nv, np_))
        keys.append(("p", np_))
        keys.append(("cp", cna, np_))
    if (pk := package_key(entry)):
        keys.append(("pkg", pk))
    return keys


def similarity(entry: dict, vp: str) -> float:
    v, p = vp.split(":", 1)
    et = tokens(entry.get("vendor")) | tokens(entry.get("product")) | tokens(entry.get("packageName"))
    return jaccard(et, tokens(v) | tokens(p)) + 0.5 * jaccard(tokens(entry.get("product")), tokens(p))


def align(rec: dict) -> list[tuple[dict, str]]:
    """Pair each CNA affected entry of an enriched CVE with the NVD vendor:product it describes."""
    truth = list(rec["truth"])
    entries = rec["affected"]
    if not truth or not entries:
        return []
    out = []
    for e in entries:
        hits = cna_cpe_vps(e) & set(truth)
        if hits:
            out.append((e, sorted(hits)[0]))
            continue
        if len(truth) == 1 and len(entries) == 1:
            out.append((e, truth[0]))
            continue
        best = max(truth, key=lambda vp: similarity(e, vp))
        if similarity(e, best) > 0:
            out.append((e, best))
    return out


class Dictionary:
    """The CPE dictionary as it stood at ``cutoff`` (entries created later are invisible)."""

    def __init__(self, raw: dict, cutoff: str | None = None):
        self.vps: dict[str, list] = {vp: v for vp, v in raw["vps"].items() if cutoff is None or (v[1] or "") < cutoff}
        self.renames = {a: b for a, b in raw["renames"].items() if a in self.vps}
        self.by_norm: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.by_product: dict[str, list[str]] = defaultdict(list)
        self.by_vendor: dict[str, list[str]] = defaultdict(list)
        self.vendor_tok: dict[str, set[str]] = defaultdict(set)
        self.product_tok: dict[tuple[str, str], list[str]] = defaultdict(list)  # (vendor, product token) -> vps
        for vp in self.vps:
            v, p = vp.split(":", 1)
            nv, np_ = norm(v), norm(p)
            self.by_norm[(nv, np_)].append(vp)
            self.by_product[np_].append(vp)
            self.by_vendor[nv].append(vp)
            for t in tokens(v):
                self.vendor_tok[t].add(nv)
            for t in tokens(p):
                self.product_tok[(nv, t)].append(vp)

    def current(self, vp: str) -> tuple[str, bool]:
        seen = {vp}
        renamed = False
        while vp in self.renames and self.renames[vp] not in seen:
            vp = self.renames[vp]
            seen.add(vp)
            renamed = True
        return vp, renamed


class AliasModel:
    def __init__(self):
        self.counts: dict[tuple, Counter] = defaultdict(Counter)
        self.vendor_counts: dict[str, Counter] = defaultdict(Counter)
        self.popularity: Counter = Counter()

    def fit(self, records) -> "AliasModel":
        for rec in records:
            for vp in rec["truth"]:
                self.popularity[vp] += 1
            for e, vp in align(rec):
                for k in entry_keys(e, rec["cna"]):
                    self.counts[k][vp] += 1
                nv = norm(e.get("vendor"))
                if nv:
                    self.vendor_counts[nv][vp.split(":", 1)[0]] += 1
        return self


FEATURES = ["bias", "alias_vp_share", "alias_vp_logc", "alias_p_share", "alias_cp_share", "alias_cp_logc",
            "alias_pkg_share", "alias_pkg_logc", "alias_vendor_share", "cna_cpe", "exact_norm", "vendor_sim",
            "product_sim", "product_exact", "in_dictionary", "renamed", "popularity", "n_candidates",
            "version_overlap", "dict_only"]


@dataclass
class Candidate:
    vp: str
    feats: dict = field(default_factory=dict)
    prob: float = 0.0


def _dict_overlap(dictionary: Dictionary, vp: str, ranges) -> float:
    entry = dictionary.vps.get(vp)
    if not entry or not entry[2] or ranges is None:
        return 0.0
    for v in entry[2][-100:]:
        try:
            if vmod.in_ranges(ranges, v):
                return 1.0
        except Exception:
            continue
    return -1.0


def candidates(entry: dict, cna: str, alias: AliasModel, dictionary: Dictionary) -> list[Candidate]:
    nv, np_ = norm(entry.get("vendor")), norm(entry.get("product"))
    cands: dict[str, Candidate] = {}

    def add(vp: str) -> Candidate:
        cur, renamed = dictionary.current(vp)
        c = cands.get(cur)
        if c is None:
            c = cands[cur] = Candidate(cur, {f: 0.0 for f in FEATURES})
        if renamed:
            c.feats["renamed"] = 1.0
        return c

    for k in entry_keys(entry, cna):
        counter = alias.counts.get(k)
        if not counter:
            continue
        total = sum(counter.values())
        name = {"vp": "alias_vp", "p": "alias_p", "cp": "alias_cp", "pkg": "alias_pkg"}[k[0]]
        for vp, c in counter.most_common(5):
            cand = add(vp)
            cand.feats[f"{name}_share"] = max(cand.feats[f"{name}_share"], c / total)
            if f"{name}_logc" in cand.feats:
                cand.feats[f"{name}_logc"] = max(cand.feats[f"{name}_logc"], math.log1p(c))
    for vp in cna_cpe_vps(entry):
        add(vp).feats["cna_cpe"] = 1.0
    dict_hits = list(dictionary.by_norm.get((nv, np_), []))
    for vp in dict_hits:
        add(vp).feats["exact_norm"] = 1.0
    if np_:
        vendors = {nv} if nv in dictionary.by_vendor else set()
        for vv in alias.vendor_counts.get(nv, {}):
            vendors.add(norm(vv))
        for t in tokens(entry.get("vendor")):
            if len(dictionary.vendor_tok.get(t, ())) <= 3:
                vendors |= dictionary.vendor_tok.get(t, set())
        pt = tokens(entry.get("product"))
        for v in vendors:
            near = {vp for t in pt for vp in dictionary.product_tok.get((v, t), ())}
            for vp in near:
                if jaccard(pt, tokens(vp.split(":", 1)[1])) >= 0.5:
                    add(vp)
        prods = dictionary.by_product.get(np_, [])
        if len(prods) <= 5:
            for vp in prods:
                add(vp)
    try:
        ranges = vmod.translate(entry.get("versions") or [], entry.get("defaultStatus"))
    except Exception:
        ranges = None
    n = len(cands)
    vshare = alias.vendor_counts.get(nv)
    vtotal = sum(vshare.values()) if vshare else 0
    for c in cands.values():
        v, p = c.vp.split(":", 1)
        f = c.feats
        f["bias"] = 1.0
        f["vendor_sim"] = jaccard(tokens(entry.get("vendor")), tokens(v))
        f["product_sim"] = jaccard(tokens(entry.get("product")) | tokens(entry.get("packageName")), tokens(p))
        f["product_exact"] = float(np_ == norm(p) and bool(np_))
        f["in_dictionary"] = float(c.vp in dictionary.vps)
        f["popularity"] = math.log1p(alias.popularity.get(c.vp, 0))
        f["n_candidates"] = math.log(n)
        f["alias_vendor_share"] = (vshare.get(v, 0) / vtotal) if vtotal else 0.0
        f["version_overlap"] = _dict_overlap(dictionary, c.vp, ranges)
        f["dict_only"] = float(not any(f[k] for k in ("alias_vp_share", "alias_p_share", "alias_cp_share",
                                                      "alias_pkg_share", "cna_cpe")))
    return list(cands.values())


class Scorer:
    """L2-regularized logistic regression fitted by Newton's method (IRLS)."""

    def __init__(self, l2: float = 1.0):
        self.l2 = l2
        self.w = np.zeros(len(FEATURES))

    @staticmethod
    def matrix(cands: list[Candidate]) -> np.ndarray:
        return np.array([[c.feats[f] for f in FEATURES] for c in cands], dtype=float).reshape(-1, len(FEATURES))

    def fit(self, X: np.ndarray, y: np.ndarray, iters: int = 25) -> "Scorer":
        w = np.zeros(X.shape[1])
        reg = self.l2 * np.eye(X.shape[1])
        reg[0, 0] = 0.0
        for _ in range(iters):
            p = 1 / (1 + np.exp(-np.clip(X @ w, -30, 30)))
            g = X.T @ (p - y) + reg @ w
            H = (X * (p * (1 - p))[:, None]).T @ X + reg + 1e-9 * np.eye(X.shape[1])
            step = np.linalg.solve(H, g)
            w -= step
            if np.abs(step).max() < 1e-6:
                break
        self.w = w
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return 1 / (1 + np.exp(-np.clip(X @ self.w, -30, 30)))


def baseline(entry: dict, dictionary: Dictionary) -> str | None:
    """Plain string match: lowercase vendor/product, spaces -> underscores, must exist in the dictionary."""
    v = (entry.get("vendor") or "").strip().lower().replace(" ", "_")
    p = (entry.get("product") or "").strip().lower().replace(" ", "_")
    vp = f"{v}:{p}"
    return vp if v and p and vp in dictionary.vps else None
