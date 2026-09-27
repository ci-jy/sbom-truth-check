"""Field-by-field conformance to CISA's updated SBOM minimum elements.

Each check returns a pass/fail verdict plus the JSON path of every failing location, so an analyst can
open the vendor document and see exactly which component lacks which element.

Document-level elements: SBOM Author, Timestamp, Tool Name, Generation Context.
Component-level elements: Component Name, Component Version, Software Identifiers, Component Producer,
Component Hash (value *and* algorithm), License.
Graph elements: Dependency Relationship (every component's dependencies are stated) and transitive
completeness (every component is reachable from the primary component through stated edges).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sbom import CDX_SUPPORTED, SPDX_SUPPORTED, Sbom, load

FIELDS = [
    "format_version",
    "sbom_author",
    "timestamp",
    "tool_name",
    "generation_context",
    "component_name",
    "component_version",
    "software_identifier",
    "component_producer",
    "component_hash",
    "license",
    "dependency_relationships",
    "transitive_completeness",
]

HASH_LENGTHS = {  # hex digits per algorithm
    "MD5": 32, "SHA-1": 40, "SHA1": 40, "SHA-256": 64, "SHA256": 64, "SHA-384": 96, "SHA384": 96,
    "SHA-512": 128, "SHA512": 128, "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128,
    "BLAKE2B-256": 64, "BLAKE2B-384": 96, "BLAKE2B-512": 128, "BLAKE3": 64,
    "SHA224": 56, "SHA-224": 56,
}
LIFECYCLE_WORDS = ("design", "pre-build", "source", "build", "post-build", "analyzed", "deployed", "runtime")
_ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$")
_NOASSERT = {"", "NOASSERTION", "NONE", None}


@dataclass
class FieldResult:
    field: str
    passed: bool
    checked: int = 0  # number of places inspected (1 for document fields, N for components)
    failures: list[tuple[str, str]] = field(default_factory=list)  # (json path, reason)

    def as_dict(self) -> dict:
        return {"field": self.field, "passed": self.passed, "checked": self.checked,
                "failures": [{"path": p, "reason": r} for p, r in self.failures]}


@dataclass
class ConformanceReport:
    format: str
    spec_version: str
    results: dict[str, FieldResult]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results.values())

    def as_dict(self) -> dict:
        return {"format": self.format, "spec_version": self.spec_version, "passed": self.passed,
                "fields": {k: v.as_dict() for k, v in self.results.items()}}


class _Collector:
    def __init__(self):
        self.results = {f: FieldResult(f, True) for f in FIELDS}

    def check(self, name: str, ok: bool, path: str, reason: str) -> None:
        r = self.results[name]
        r.checked += 1
        if not ok:
            r.passed = False
            r.failures.append((path, reason))


def _valid_hash(alg: str | None, content: str | None) -> str | None:
    """Return None when the hash is usable, else the reason it is not."""
    if not alg:
        return "hash has no algorithm"
    if not content:
        return "hash has no value"
    want = HASH_LENGTHS.get(alg.upper())
    if want is None:
        return f"unknown hash algorithm {alg!r}"
    if not re.fullmatch(r"[0-9a-fA-F]+", content) or len(content) != want:
        return f"{alg} value is not {want} hex digits"
    return None


# --------------------------------------------------------------------------- CycloneDX


def _cdx_tools(meta: dict) -> list[str]:
    tools = meta.get("tools")
    if isinstance(tools, list):  # 1.4 style
        return [t.get("name") for t in tools if t.get("name")]
    if isinstance(tools, dict):  # 1.5+ style
        items = (tools.get("components") or []) + (tools.get("services") or [])
        return [t.get("name") for t in items if t.get("name")]
    return []


def _cdx_producer(comp: dict) -> bool:
    for key in ("supplier", "manufacturer"):
        if (comp.get(key) or {}).get("name"):
            return True
    if comp.get("publisher") or comp.get("author"):
        return True
    return any(a.get("name") for a in comp.get("authors") or [])


def _cdx_hashes(comp: dict) -> list[dict]:
    hashes = list(comp.get("hashes") or [])
    for ref in comp.get("externalReferences") or []:
        if ref.get("type") == "distribution":
            hashes.extend(ref.get("hashes") or [])
    return hashes


def _cdx_license(comp: dict) -> bool:
    for entry in comp.get("licenses") or []:
        if entry.get("expression"):
            return True
        lic = entry.get("license") or {}
        if lic.get("id") or lic.get("name"):
            return True
    return False


def _check_cyclonedx(sbom: Sbom, c: _Collector) -> None:
    data = sbom.data
    meta = data.get("metadata") or {}
    c.check("format_version", sbom.spec_version in CDX_SUPPORTED, "$.specVersion",
            f"CycloneDX {sbom.spec_version or '?'} is not 1.5/1.6/1.7")
    has_author = any(a.get("name") or a.get("email") for a in meta.get("authors") or []) or bool(
        (meta.get("manufacturer") or {}).get("name") or (meta.get("manufacture") or {}).get("name"))
    c.check("sbom_author", has_author, "$.metadata.authors", "no SBOM author (metadata.authors/manufacturer)")
    ts = meta.get("timestamp")
    c.check("timestamp", bool(ts and _ISO8601.match(ts)), "$.metadata.timestamp",
            "missing" if not ts else f"not ISO 8601: {ts!r}")
    c.check("tool_name", bool(_cdx_tools(meta)), "$.metadata.tools", "no generating tool named")
    phases = [lc.get("phase") or lc.get("name") for lc in meta.get("lifecycles") or []]
    c.check("generation_context", any(phases), "$.metadata.lifecycles", "no lifecycle phase (generation context)")

    comps = {comp.path: comp for comp in sbom.package_components}
    raw = {}

    def walk(items, path):
        for i, item in enumerate(items or []):
            raw[f"{path}[{i}]"] = item
            walk(item.get("components"), f"{path}[{i}].components")

    walk(data.get("components"), "$.components")
    for path, comp in comps.items():
        item = raw[path]
        c.check("component_name", bool(item.get("name")), f"{path}.name", "missing")
        c.check("component_version", bool(item.get("version")), f"{path}.version", "missing")
        c.check("software_identifier", bool(item.get("purl") or item.get("cpe") or item.get("swid")),
                f"{path}.purl", "no purl, cpe or swid")
        c.check("component_producer", _cdx_producer(item), f"{path}.supplier", "no supplier/manufacturer/author")
        hashes = _cdx_hashes(item)
        reasons = [_valid_hash(h.get("alg"), h.get("content")) for h in hashes]
        ok = any(r is None for r in reasons)
        c.check("component_hash", ok, f"{path}.hashes",
                "no hash" if not hashes else "; ".join(r for r in reasons if r))
        c.check("license", _cdx_license(item), f"{path}.licenses", "no license id, name or expression")
    _check_graph(sbom, c, lambda comp: comp.path)


# --------------------------------------------------------------------------- SPDX


def _check_spdx(sbom: Sbom, c: _Collector) -> None:
    data = sbom.data
    info = data.get("creationInfo") or {}
    creators = info.get("creators") or []
    c.check("format_version", sbom.spec_version in SPDX_SUPPORTED, "$.spdxVersion",
            f"{sbom.spec_version or '?'} is not SPDX-2.3")
    c.check("sbom_author", any(x.startswith(("Person:", "Organization:")) for x in creators),
            "$.creationInfo.creators", "no Person: or Organization: creator")
    ts = info.get("created")
    c.check("timestamp", bool(ts and _ISO8601.match(ts)), "$.creationInfo.created",
            "missing" if not ts else f"not ISO 8601: {ts!r}")
    c.check("tool_name", any(x.startswith("Tool:") for x in creators), "$.creationInfo.creators",
            "no Tool: creator")
    comment = (info.get("comment") or "").lower()
    c.check("generation_context", any(w in comment for w in LIFECYCLE_WORDS), "$.creationInfo.comment",
            "SPDX 2.3 has no lifecycle field and creationInfo.comment names no generation phase")

    for comp in sbom.package_components:
        item = data["packages"][int(comp.path.split("[")[1].rstrip("]"))]
        path = comp.path
        c.check("component_name", bool(item.get("name")), f"{path}.name", "missing")
        c.check("component_version", item.get("versionInfo") not in _NOASSERT, f"{path}.versionInfo", "missing")
        refs = [e for e in item.get("externalRefs") or []
                if e.get("referenceType") in ("purl", "cpe23Type", "cpe22Type", "swid")]
        c.check("software_identifier", bool(refs), f"{path}.externalRefs", "no purl/cpe/swid reference")
        c.check("component_producer",
                item.get("supplier") not in _NOASSERT or item.get("originator") not in _NOASSERT,
                f"{path}.supplier", "supplier and originator are NOASSERTION or missing")
        sums = item.get("checksums") or []
        reasons = [_valid_hash(s.get("algorithm"), s.get("checksumValue")) for s in sums]
        c.check("component_hash", any(r is None for r in reasons), f"{path}.checksums",
                "no checksum" if not sums else "; ".join(r for r in reasons if r))
        lic_ok = item.get("licenseConcluded") not in _NOASSERT or item.get("licenseDeclared") not in _NOASSERT
        c.check("license", lic_ok, f"{path}.licenseDeclared", "licenseConcluded and licenseDeclared are NOASSERTION")
    _check_graph(sbom, c, lambda comp: comp.path)


# --------------------------------------------------------------------------- graph


def _check_graph(sbom: Sbom, c: _Collector, path_of) -> None:
    """Dependency relationships must be stated for every component and reach every component."""
    edges = {}
    for p, ch in sbom.edges:
        edges.setdefault(p, set()).add(ch)
    reach, stack = set(sbom.root_refs), list(sbom.root_refs)
    while stack:
        for nxt in edges.get(stack.pop(), ()):
            if nxt not in reach:
                reach.add(nxt)
                stack.append(nxt)
    # SPDX producers express "no dependencies" by omission, so for SPDX a leaf counts as declared
    declared = sbom.declared if sbom.format == "cyclonedx" else None
    for comp in sbom.package_components:
        if declared is not None:
            c.check("dependency_relationships", comp.ref in declared, path_of(comp),
                    f"no dependencies entry for ref {comp.ref!r}")
        c.check("transitive_completeness", comp.ref in reach, path_of(comp),
                "not reachable from the primary component through dependency edges")
    if declared is None:
        c.check("dependency_relationships", bool(sbom.edges), "$.relationships", "no DEPENDS_ON relationships")
    elif not sbom.package_components:
        c.check("dependency_relationships", True, "$.dependencies", "")
    if not sbom.package_components:
        c.check("transitive_completeness", True, "$", "")


def check(source) -> ConformanceReport:
    sbom = source if isinstance(source, Sbom) else load(source)
    c = _Collector()
    (_check_cyclonedx if sbom.format == "cyclonedx" else _check_spdx)(sbom, c)
    return ConformanceReport(sbom.format, sbom.spec_version, c.results)
