"""Graph diff of an SBOM against lockfile ground truth, with a named cause for every disagreement.

The reference set is what ships: every locked package outside dev/test scope, including optional and
platform-conditional ones. Components are compared by canonical PURL identity; edges by the canonical
identities of both ends, with the project itself (and the scanned directory/lockfile entries some tools
emit) mapped to ``ROOT``.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from . import purl as purls
from .lockfiles import ROOT, TruthGraph
from .sbom import Sbom

# Cause classes. Every mismatch gets exactly one; UNEXPLAINED is the residue the evaluation must not have.
DEV_DEPENDENCY = "dev_test_dependency_included"
OPTIONAL = "optional_or_platform_dependency"
BUNDLED = "bundled_vendored_package"
NAME_NORMALIZATION = "name_normalization_mismatch"
RANGE_VERSION = "range_instead_of_locked_version"
VERSION_MISMATCH = "different_locked_version"
MISSING_TRANSITIVE_EDGE = "missing_transitive_edge"
MISSING_DIRECT_EDGE = "missing_direct_edge"
MISSING_TRANSITIVE_DEP = "missing_transitive_dependency"
NO_GRAPH = "no_dependency_graph"
FLATTENED = "transitive_reported_as_direct"
AMBIGUOUS_EDGE = "edge_to_wrong_version"
INACTIVE_PROFILE = "inactive_build_profile_dependency"
DUPLICATE = "duplicate_component"
NO_IDENTIFIER = "component_without_purl"
UNEXPLAINED = "unexplained"

CAUSES = [DEV_DEPENDENCY, OPTIONAL, BUNDLED, NAME_NORMALIZATION, RANGE_VERSION, VERSION_MISMATCH,
          MISSING_TRANSITIVE_DEP, MISSING_TRANSITIVE_EDGE, MISSING_DIRECT_EDGE, NO_GRAPH, FLATTENED,
          AMBIGUOUS_EDGE, INACTIVE_PROFILE, DUPLICATE, NO_IDENTIFIER, UNEXPLAINED]

_UNRESOLVED_VERSION = re.compile(r"[\^~*<>=|$ {}]|^\s*$|(^|\.)[xX](\.|$)|latest|SNAPSHOT-RANGE")


def is_unresolved_version(version: str | None) -> bool:
    return version is None or bool(_UNRESOLVED_VERSION.search(version))


@dataclass
class Mismatch:
    kind: str  # missing_component, extra_component, missing_edge, extra_edge, normalized_component, ...
    cause: str
    subject: str  # identity or "parent -> child"
    detail: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "cause": self.cause, "subject": self.subject, "detail": self.detail}


@dataclass
class PR:
    tp: int = 0
    reported: int = 0
    expected: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / self.reported if self.reported else None

    @property
    def recall(self) -> float | None:
        return self.tp / self.expected if self.expected else None

    def as_dict(self) -> dict:
        return {"tp": self.tp, "reported": self.reported, "expected": self.expected,
                "precision": self.precision, "recall": self.recall}


@dataclass
class DiffResult:
    components: dict[str, PR] = field(default_factory=dict)  # all / direct / transitive
    edges: dict[str, PR] = field(default_factory=dict)
    has_graph: bool = False
    mismatches: list[Mismatch] = field(default_factory=list)

    def cause_counts(self) -> Counter:
        return Counter(m.cause for m in self.mismatches)

    def as_dict(self) -> dict:
        return {
            "components": {k: v.as_dict() for k, v in self.components.items()},
            "edges": {k: v.as_dict() for k, v in self.edges.items()},
            "has_dependency_graph": self.has_graph,
            "causes": dict(self.cause_counts()),
            "mismatches": [m.as_dict() for m in self.mismatches],
        }


def _safe_identity(text: str | None) -> str | None:
    try:
        return purls.identity(text) if text else None
    except purls.PurlError:
        return None


def diff(sbom: Sbom, truth: TruthGraph) -> DiffResult:
    res = DiffResult()
    out = res.mismatches
    runtime = truth.runtime_keys()
    direct = truth.direct_keys() & runtime
    by_package: dict[str, set[str]] = {}
    for key in truth.nodes:
        by_package.setdefault(purls.package_key(key), set()).add(key)

    # ---- map SBOM refs to canonical identities
    ref_key: dict[str, str] = {r: ROOT for r in sbom.root_refs}
    seen: Counter = Counter()
    for comp in sbom.package_components:
        key = _safe_identity(comp.purl)
        if key is None:
            out.append(Mismatch("extra_component", NO_IDENTIFIER, comp.name or comp.ref, comp.path))
            continue
        if purls.package_key(key) == truth.root_package_key:
            ref_key[comp.ref] = ROOT  # the project describing itself
            continue
        ref_key[comp.ref] = key
        seen[key] += 1
        if seen[key] == 2:
            out.append(Mismatch("duplicate_component", DUPLICATE, key, f"listed {comp.path} and earlier"))
        elif seen[key] > 2:
            out.append(Mismatch("duplicate_component", DUPLICATE, key, comp.path))
        node = truth.nodes.get(key)
        if node is not None and seen[key] == 1 and purls.raw_identity(comp.purl) != purls.raw_identity(node.purl):
            out.append(Mismatch("normalized_component", NAME_NORMALIZATION, key,
                                f"SBOM wrote {comp.purl!r}, lockfile gives {node.purl!r}"))
    reported = set(seen)
    reported_pkgs: dict[str, set[str]] = {}
    for key in reported:
        reported_pkgs.setdefault(purls.package_key(key), set()).add(key)

    # ---- components
    cause_of: dict[str, str] = {}  # identity -> cause, reused for the edges touching it
    for key in sorted(reported - runtime):
        node = truth.nodes.get(key)
        version = purls.canonicalize(key).version
        if node is not None and node.dev:
            cause = DEV_DEPENDENCY
        elif by_package.get(purls.package_key(key)):
            others = by_package[purls.package_key(key)]
            if is_unresolved_version(version):
                cause = RANGE_VERSION
            elif all(truth.nodes[o].dev for o in others):
                cause = DEV_DEPENDENCY  # a dev-only package, reported at another version
            else:
                cause = VERSION_MISMATCH
        elif purls.package_key(key) in truth.inactive:
            cause = INACTIVE_PROFILE
        else:
            cause = UNEXPLAINED
        cause_of[key] = cause
        out.append(Mismatch("extra_component", cause, key))
    for key in sorted(runtime - reported):
        node = truth.nodes[key]
        siblings = reported_pkgs.get(purls.package_key(key), set()) - runtime
        if node.bundled:
            cause = BUNDLED
        elif node.optional:
            cause = OPTIONAL
        elif siblings:
            cause = cause_of[sorted(siblings)[0]]  # same package reported with another version
        elif key not in direct:
            cause = MISSING_TRANSITIVE_DEP
        else:
            cause = UNEXPLAINED
        cause_of[key] = cause
        out.append(Mismatch("missing_component", cause, key))

    def pr(expected: set[str], got: set[str]) -> PR:
        return PR(len(expected & got), len(got), len(expected))

    reported_direct = {k for k in reported if k in direct or (k not in runtime and k in truth.direct_keys())}
    res.components = {
        "all": pr(runtime, reported),
        "direct": pr(direct, reported & direct),
        "transitive": pr(runtime - direct, reported & (runtime - direct)),
    }
    # precision of the split views counts only reported items that the truth places in that split
    res.components["direct"].reported = len(reported_direct)
    res.components["transitive"].reported = len(reported - reported_direct)

    # ---- edges
    sbom_edges = set()
    for parent_ref, child_ref in sbom.edges:
        p, c = ref_key.get(parent_ref), ref_key.get(child_ref)
        if p is None or c is None or p == c or c == ROOT:
            continue
        sbom_edges.add((p, c))
    res.has_graph = bool(sbom_edges)
    truth_edges = truth.runtime_edges()
    all_truth_edges = set(truth.edges)

    for p, c in sorted(sbom_edges - truth_edges):
        subject = f"{p} -> {c}"
        parent_node = truth.nodes.get(p)
        if c in cause_of:
            cause = cause_of[c]
        elif p in cause_of:
            cause = cause_of[p]
        elif (p, c) in all_truth_edges:
            cause = DEV_DEPENDENCY  # a locked edge used only in dev scope
        elif parent_node is not None and truth.nodes[c].name in parent_node.extras:
            cause = OPTIONAL  # the parent's optional extras, not a locked dependency
        elif purls.package_key(c) in {purls.package_key(x) for (pp, x) in all_truth_edges if pp == p}:
            cause = AMBIGUOUS_EDGE
        elif p == ROOT and c in runtime:
            cause = FLATTENED
        elif p != ROOT and c in runtime and _reachable(truth, p, c):
            cause = FLATTENED  # an indirect dependency drawn as a direct one of an ancestor
        else:
            cause = UNEXPLAINED
        out.append(Mismatch("extra_edge", cause, subject))

    for p, c in sorted(truth_edges - sbom_edges):
        subject = f"{p} -> {c}"
        if c in cause_of:
            cause = cause_of[c]
        elif p in cause_of:
            cause = cause_of[p]
        elif not res.has_graph:
            cause = NO_GRAPH
        elif truth.edges[(p, c)]:
            cause = OPTIONAL
        elif p == ROOT:
            cause = MISSING_DIRECT_EDGE
        else:
            cause = MISSING_TRANSITIVE_EDGE
        out.append(Mismatch("missing_edge", cause, subject))

    direct_truth = {e for e in truth_edges if e[0] == ROOT}
    res.edges = {
        "all": pr(truth_edges, sbom_edges),
        "direct": pr(direct_truth, {e for e in sbom_edges if e[0] == ROOT}),
        "transitive": pr(truth_edges - direct_truth, {e for e in sbom_edges if e[0] != ROOT}),
    }
    return res


def _reachable(truth: TruthGraph, start: str, goal: str) -> bool:
    children: dict[str, list[str]] = {}
    for p, c in truth.edges:
        children.setdefault(p, []).append(c)
    stack, seen = [start], {start}
    while stack:
        cur = stack.pop()
        for nxt in children.get(cur, []):
            if nxt == goal:
                return True
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False
