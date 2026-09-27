"""Build matching lockfile + fully conformant SBOMs from one random dependency graph."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from hypothesis import strategies as st

ROOT_NAME = "demo-app"


@dataclass
class Graph:
    names: list[str]  # npm package names, index = node id
    versions: list[str]
    edges: set[tuple[int, int]]  # (parent, child); parent -1 is the project root

    def children(self, parent: int) -> list[int]:
        return sorted(c for p, c in self.edges if p == parent)

    def purl(self, i: int) -> str:
        name = self.names[i]
        if name.startswith("@"):
            scope, base = name.split("/")
            return f"pkg:npm/%40{scope[1:]}/{base}@{self.versions[i]}"
        return f"pkg:npm/{name}@{self.versions[i]}"


_ident = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8)


@st.composite
def graphs(draw, min_nodes=3, max_nodes=8) -> Graph:
    n = draw(st.integers(min_nodes, max_nodes))
    bases = draw(st.lists(_ident, min_size=n, max_size=n, unique=True))
    names = []
    for base in bases:
        scoped = draw(st.booleans())
        names.append(f"@{draw(_ident)}/{base}" if scoped else base)
    versions = [f"{draw(st.integers(0, 9))}.{draw(st.integers(0, 20))}.{draw(st.integers(0, 9))}" for _ in names]
    edges = set()
    for i in range(n):  # every package hangs off the root or an earlier package, so the graph is a DAG
        parent = draw(st.integers(-1, i - 1))
        edges.add((parent, i))
    for _ in range(draw(st.integers(0, n))):
        a, b = draw(st.integers(0, n - 1)), draw(st.integers(0, n - 1))
        if a < b:
            edges.add((a, b))
    return Graph(names, versions, edges)


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


def package_lock(g: Graph) -> dict:
    root_deps = {g.names[c]: f"^{g.versions[c]}" for c in g.children(-1)}
    packages = {"": {"name": ROOT_NAME, "version": "1.0.0", "dependencies": root_deps}}
    for i, name in enumerate(g.names):
        entry = {"version": g.versions[i], "resolved": f"https://registry.npmjs.org/{name}/-/x.tgz",
                 "license": "MIT"}
        deps = {g.names[c]: g.versions[c] for c in g.children(i)}
        if deps:
            entry["dependencies"] = deps
        packages[f"node_modules/{name}"] = entry
    return {"name": ROOT_NAME, "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": packages}


def cyclonedx(g: Graph) -> dict:
    comps = []
    for i, name in enumerate(g.names):
        comps.append({
            "type": "library", "bom-ref": f"ref-{i}", "name": name, "version": g.versions[i],
            "purl": g.purl(i), "supplier": {"name": f"{name} maintainers"},
            "hashes": [{"alg": "SHA-512", "content": sha512(name)}],
            "licenses": [{"license": {"id": "MIT"}}],
        })
    deps = [{"ref": "root", "dependsOn": [f"ref-{c}" for c in g.children(-1)]}]
    deps += [{"ref": f"ref-{i}", "dependsOn": [f"ref-{c}" for c in g.children(i)]} for i in range(len(g.names))]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": "2026-01-15T10:00:00Z", "lifecycles": [{"phase": "build"}],
            "authors": [{"name": "Example Corp SBOM team"}],
            "tools": {"components": [{"type": "application", "name": "example-generator", "version": "1.0"}]},
            "component": {"type": "application", "bom-ref": "root", "name": ROOT_NAME, "version": "1.0.0",
                          "purl": f"pkg:npm/{ROOT_NAME}@1.0.0"},
        },
        "components": comps, "dependencies": deps,
    }


def spdx(g: Graph) -> dict:
    pkgs = [{"SPDXID": "SPDXRef-root", "name": ROOT_NAME, "versionInfo": "1.0.0", "supplier": "Organization: Example",
             "downloadLocation": "NOASSERTION", "licenseDeclared": "MIT",
             "checksums": [{"algorithm": "SHA512", "checksumValue": sha512(ROOT_NAME)}],
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                               "referenceLocator": f"pkg:npm/{ROOT_NAME}@1.0.0"}]}]
    for i, name in enumerate(g.names):
        pkgs.append({
            "SPDXID": f"SPDXRef-p{i}", "name": name, "versionInfo": g.versions[i],
            "supplier": f"Organization: {name} maintainers", "downloadLocation": "NOASSERTION",
            "licenseConcluded": "MIT", "licenseDeclared": "MIT",
            "checksums": [{"algorithm": "SHA512", "checksumValue": sha512(name)}],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": g.purl(i)}],
        })
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root",
             "relationshipType": "DESCRIBES"}]
    for p, c in sorted(g.edges):
        src = "SPDXRef-root" if p == -1 else f"SPDXRef-p{p}"
        rels.append({"spdxElementId": src, "relatedSpdxElement": f"SPDXRef-p{c}", "relationshipType": "DEPENDS_ON"})
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": ROOT_NAME, "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/spdx/demo-app",
        "creationInfo": {"created": "2026-01-15T10:00:00Z", "creators": ["Organization: Example Corp", "Tool: gen-1.0"],
                         "comment": "Generated at build time from the lockfile."},
        "packages": pkgs, "relationships": rels,
    }


def write_lock(tmp_path, g: Graph):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(package_lock(g)))
    return path
