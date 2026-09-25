"""Load CycloneDX and SPDX JSON documents into one small graph model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

CDX_SUPPORTED = {"1.5", "1.6", "1.7"}
SPDX_SUPPORTED = {"SPDX-2.3"}


@dataclass
class Component:
    ref: str
    name: str | None
    version: str | None
    purl: str | None
    path: str  # JSON path of the component inside the document
    kind: str = "library"


@dataclass
class Sbom:
    format: str  # "cyclonedx" or "spdx"
    spec_version: str
    data: dict
    components: list[Component] = field(default_factory=list)
    root_refs: set[str] = field(default_factory=set)
    edges: set[tuple[str, str]] = field(default_factory=set)  # (parent ref, child ref)
    declared: set[str] = field(default_factory=set)  # refs whose dependency list is stated

    @property
    def package_components(self) -> list[Component]:
        """Components that describe packages (not the analyzed directory or lockfile itself)."""
        return [c for c in self.components if c.ref not in self.root_refs]


class SbomError(ValueError):
    pass


def detect_format(data: dict) -> str:
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if str(data.get("spdxVersion", "")).startswith("SPDX-"):
        return "spdx"
    raise SbomError("document is neither CycloneDX JSON nor SPDX JSON")


def load(source: str | Path | dict) -> Sbom:
    data = source if isinstance(source, dict) else json.loads(Path(source).read_text())
    fmt = detect_format(data)
    return _load_cyclonedx(data) if fmt == "cyclonedx" else _load_spdx(data)


def _walk_cdx(components: list, path: str):
    for i, comp in enumerate(components or []):
        here = f"{path}[{i}]"
        yield here, comp
        yield from _walk_cdx(comp.get("components"), f"{here}.components")


def _load_cyclonedx(data: dict) -> Sbom:
    sbom = Sbom("cyclonedx", str(data.get("specVersion", "")), data)
    meta_comp = (data.get("metadata") or {}).get("component") or {}
    if meta_comp.get("bom-ref"):
        sbom.root_refs.add(meta_comp["bom-ref"])
    for path, comp in _walk_cdx(data.get("components"), "$.components"):
        ref = comp.get("bom-ref") or path
        c = Component(ref, comp.get("name"), comp.get("version"), comp.get("purl"), path, comp.get("type", "library"))
        sbom.components.append(c)
        # entries for the scanned directory or lockfile carry no package identity
        if not c.purl and c.kind in ("application", "file"):
            sbom.root_refs.add(ref)
    for dep in data.get("dependencies") or []:
        ref = dep.get("ref")
        if ref is None:
            continue
        sbom.declared.add(ref)
        for child in dep.get("dependsOn") or []:
            sbom.edges.add((ref, child))
    return sbom


def spdx_purl(pkg: dict) -> str | None:
    for ext in pkg.get("externalRefs") or []:
        if ext.get("referenceType") == "purl":
            return ext.get("referenceLocator")
    return None


def _load_spdx(data: dict) -> Sbom:
    sbom = Sbom("spdx", str(data.get("spdxVersion", "")), data)
    doc_id = data.get("SPDXID", "SPDXRef-DOCUMENT")
    sbom.root_refs.add(doc_id)
    sbom.root_refs.update(data.get("documentDescribes") or [])
    for i, pkg in enumerate(data.get("packages") or []):
        ref = pkg.get("SPDXID") or f"$.packages[{i}]"
        purl = spdx_purl(pkg)
        purpose = str(pkg.get("primaryPackagePurpose", "")).upper()
        c = Component(ref, pkg.get("name"), pkg.get("versionInfo"), purl, f"$.packages[{i}]",
                      purpose.lower() or "library")
        sbom.components.append(c)
        if not purl and purpose in ("APPLICATION", "FILE", "SOURCE", ""):
            sbom.root_refs.add(ref)
    for rel in data.get("relationships") or []:
        a, b = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        kind = str(rel.get("relationshipType", ""))
        if kind == "DESCRIBES" and a == doc_id:
            sbom.root_refs.add(b)
        elif kind == "DESCRIBED_BY" and b == doc_id:
            sbom.root_refs.add(a)
        elif kind in ("DEPENDS_ON", "DEV_DEPENDS_ON", "OPTIONAL_DEPENDS_ON"):
            sbom.edges.add((a, b))
            sbom.declared.add(a)
        elif kind.endswith("DEPENDENCY_OF"):
            sbom.edges.add((b, a))
            sbom.declared.add(b)
    return sbom
