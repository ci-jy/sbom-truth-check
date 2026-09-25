"""Independent ground truth: dependency graphs built straight from committed lockfiles.

No SBOM generator is involved. Each resolver returns a :class:`TruthGraph` whose nodes carry
the facts the mismatch classifier needs (dev/test scope, optional or platform-conditional,
bundled, the package's declared extras) and whose edges are the locked parent -> child links.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import purl as purls

ROOT = "ROOT"


@dataclass
class Node:
    key: str  # canonical identity (see purl.identity)
    purl: str  # PURL exactly as derived from the lockfile spelling
    name: str
    version: str
    dev: bool = False
    optional: bool = False  # optional / extra / platform-marker conditional
    bundled: bool = False
    extras: set[str] = field(default_factory=set)  # names reachable only through this package's extras


@dataclass
class TruthGraph:
    ecosystem: str
    root_name: str
    root_version: str | None
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[tuple[str, str], bool] = field(default_factory=dict)  # (parent, child) -> conditional
    # package keys declared by the manifest but outside the resolved build (e.g. Maven profiles)
    inactive: set[str] = field(default_factory=set)

    @property
    def root_package_key(self) -> str:
        return purls.package_key(_make_purl(self.ecosystem, self.root_name, None))

    def runtime_keys(self) -> set[str]:
        return {k for k, n in self.nodes.items() if not n.dev}

    def runtime_edges(self) -> set[tuple[str, str]]:
        live = self.runtime_keys()
        return {(p, c) for (p, c) in self.edges if c in live and (p == ROOT or p in live)}

    def direct_keys(self) -> set[str]:
        return {c for (p, c) in self.edges if p == ROOT}

    def add_edge(self, parent: str, child: str, conditional: bool = False) -> None:
        if parent == child:
            return
        prior = self.edges.get((parent, child))
        self.edges[(parent, child)] = conditional if prior is None else (prior and conditional)


def _make_purl(ecosystem: str, name: str, version: str | None) -> str:
    if ecosystem == "npm":
        ns, _, base = name.rpartition("/")
        return purls.Purl("npm", ns or None, base, version).to_string()
    if ecosystem == "pypi":
        return purls.Purl("pypi", None, name, version).to_string()
    group, _, artifact = name.partition(":")
    return purls.Purl("maven", group, artifact, version).to_string()


def _node(ecosystem: str, name: str, version: str | None, **flags) -> Node:
    raw = _make_purl(ecosystem, name, version)
    return Node(purls.identity(raw), raw, name, version or "", **flags)


# --------------------------------------------------------------------------- npm


def resolve_npm(lockfile: str | Path) -> TruthGraph:
    """npm package-lock.json lockfileVersion 2 or 3 (the ``packages`` map)."""
    data = json.loads(Path(lockfile).read_text())
    packages = data.get("packages")
    if not packages:
        raise ValueError(f"{lockfile}: only lockfileVersion 2/3 (with a 'packages' map) is supported")
    root = packages.get("", {})
    g = TruthGraph("npm", root.get("name") or data.get("name") or "", root.get("version") or data.get("version"))

    path_key: dict[str, str] = {}
    for path, entry in packages.items():
        if not path or "node_modules/" not in path:
            continue
        if entry.get("link"):  # file:/workspace package: its facts live on the link target
            entry = packages.get(entry.get("resolved", ""), {})
        name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
        version = entry.get("version")
        node = _node("npm", name, version,
                     dev=bool(entry.get("dev") or entry.get("devOptional")),
                     optional=bool(entry.get("optional")),
                     bundled=bool(entry.get("inBundle")))
        prior = g.nodes.get(node.key)
        if prior:  # same name@version installed at several paths: one component
            prior.dev = prior.dev and node.dev
            prior.optional = prior.optional and node.optional
            prior.bundled = prior.bundled and node.bundled
        else:
            g.nodes[node.key] = node
        path_key[path] = node.key

    def locate(from_path: str, dep: str) -> str | None:
        base = from_path
        while True:
            candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if candidate in path_key:
                return path_key[candidate]
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    for path, entry in packages.items():
        if path and path not in path_key:
            continue
        parent = ROOT if not path else path_key[path]
        peer_meta = entry.get("peerDependenciesMeta") or {}
        groups = [("dependencies", False), ("optionalDependencies", True), ("peerDependencies", None)]
        if not path:
            groups.append(("devDependencies", False))
        for section, conditional in groups:
            for dep in entry.get(section) or {}:
                child = locate(path, dep)
                if child is None:
                    continue  # optional/peer dependency that is not installed for this platform
                cond = bool(peer_meta.get(dep, {}).get("optional")) if conditional is None else conditional
                g.add_edge(parent, child, cond)
    return g


# --------------------------------------------------------------------------- poetry

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(requirement: str) -> str:
    m = _REQ_NAME.match(requirement)
    return purls.pep503_name(m.group(1)) if m else ""


def _poetry_dep_conditional(spec) -> bool:
    if isinstance(spec, list):
        return True  # multiple-constraint dependency: one per python/platform marker
    if isinstance(spec, dict):
        return bool(spec.get("markers") or spec.get("optional") or spec.get("python") or spec.get("platform"))
    return False


def resolve_poetry(lockfile: str | Path, pyproject: str | Path | None = None) -> TruthGraph:
    """poetry.lock (lock-version 1.x or 2.x) plus the project's pyproject.toml for direct dependencies."""
    lock = tomllib.loads(Path(lockfile).read_text())
    pyproject = Path(pyproject) if pyproject else Path(lockfile).with_name("pyproject.toml")
    project = tomllib.loads(pyproject.read_text()) if pyproject.exists() else {}
    pep621 = project.get("project") or {}
    tool = (project.get("tool") or {}).get("poetry") or {}
    g = TruthGraph("pypi", pep621.get("name") or tool.get("name") or "", pep621.get("version") or tool.get("version"))

    by_name: dict[str, Node] = {}
    raw_pkgs = lock.get("package") or []
    for pkg in raw_pkgs:
        groups = pkg.get("groups")
        if groups is not None:
            dev = "main" not in groups
        else:
            dev = pkg.get("category", "main") != "main"
        optional = bool(pkg.get("optional")) or bool(pkg.get("markers"))
        node = _node("pypi", pkg["name"], str(pkg["version"]), dev=dev, optional=optional)
        for reqs in (pkg.get("extras") or {}).values():
            node.extras.update(_req_name(r) for r in reqs)
        by_name[purls.pep503_name(pkg["name"])] = node
        g.nodes[node.key] = node

    # direct dependencies: main (PEP 621 + tool.poetry), extras, and dev groups
    direct: list[tuple[str, bool]] = []
    for req in pep621.get("dependencies") or []:
        direct.append((_req_name(req), ";" in req))
    for reqs in (pep621.get("optional-dependencies") or {}).values():
        direct.extend((_req_name(r), True) for r in reqs)
    for name, spec in (tool.get("dependencies") or {}).items():
        if name.lower() != "python":
            direct.append((purls.pep503_name(name), _poetry_dep_conditional(spec)))
    dev_specs = dict(tool.get("dev-dependencies") or {})
    for grp in (tool.get("group") or {}).values():
        dev_specs.update(grp.get("dependencies") or {})
    for reqs in (project.get("dependency-groups") or {}).values():
        dev_specs.update({_req_name(r): "*" for r in reqs if isinstance(r, str)})
    direct.extend((purls.pep503_name(n), _poetry_dep_conditional(s)) for n, s in dev_specs.items())
    for name, cond in direct:
        if name in by_name:
            g.add_edge(ROOT, by_name[name].key, cond)

    for pkg in raw_pkgs:
        parent = by_name[purls.pep503_name(pkg["name"])]
        for dep, spec in (pkg.get("dependencies") or {}).items():
            child = by_name.get(purls.pep503_name(dep))
            if child:
                g.add_edge(parent.key, child.key, _poetry_dep_conditional(spec))
    return g


# --------------------------------------------------------------------------- maven

SHIPPED_SCOPES = {"compile", "runtime"}


def _pom_inactive_declarations(pom: Path) -> set[str]:
    """groupId:artifactId pairs declared in <profiles> or plugin configuration of a pom.xml."""
    import xml.etree.ElementTree as ET

    root = ET.parse(pom).getroot()
    ns = {"m": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    found = set()
    scopes = root.findall(f".//{q('profile')}", ns) + root.findall(f".//{q('plugin')}", ns)
    for scope in scopes:
        for dep in scope.iter():
            if dep.tag.split("}")[-1] not in ("dependency", "path"):
                continue
            group = dep.find(q("groupId"), ns)
            artifact = dep.find(q("artifactId"), ns)
            if group is not None and artifact is not None and group.text and artifact.text:
                found.add(purls.package_key(purls.Purl("maven", group.text.strip(), artifact.text.strip())))
    return found


def resolve_maven_tree(tree_file: str | Path, pom: str | Path | None = None) -> TruthGraph:
    """Text output of ``mvn dependency:tree`` (default format, one module).

    When the module's pom.xml is available, dependencies it declares only inside profiles or plugin
    configuration are recorded as ``inactive``: they are not part of the default build's graph.
    """
    lines = [ln.rstrip("\n") for ln in Path(tree_file).read_text().splitlines() if ln.strip()]
    lines = [re.sub(r"^\[INFO\] ", "", ln) for ln in lines]
    root_parts = lines[0].split(":")
    g = TruthGraph("maven", f"{root_parts[0]}:{root_parts[1]}", root_parts[-1])
    stack: list[str] = [ROOT]
    for line in lines[1:]:
        m = re.match(r"^((?:[| ]  )*)[+\\]- (\S+)(.*)$", line)
        if not m:
            continue
        depth = len(m.group(1)) // 3 + 1
        parts = m.group(2).split(":")
        # group:artifact:type[:classifier]:version:scope
        group, artifact, version, scope = parts[0], parts[1], parts[-2], parts[-1]
        classifier = parts[3] if len(parts) == 6 else None
        raw = purls.Purl("maven", group, artifact, version,
                         (("classifier", classifier),) if classifier else ()).to_string()
        node = Node(purls.identity(raw), raw, f"{group}:{artifact}", version,
                    dev=scope not in SHIPPED_SCOPES, optional="(optional)" in m.group(3))
        prior = g.nodes.get(node.key)
        if prior:
            prior.dev = prior.dev and node.dev
            prior.optional = prior.optional and node.optional
        else:
            g.nodes[node.key] = node
        del stack[depth:]
        g.add_edge(stack[-1], node.key, node.optional)
        stack.append(node.key)
    pom = Path(pom) if pom else Path(tree_file).with_name("pom.xml")
    if pom.exists():
        resolved = {purls.package_key(k) for k in g.nodes}
        g.inactive = _pom_inactive_declarations(pom) - resolved
    return g


def resolve(path: str | Path) -> TruthGraph:
    """Pick the resolver from the lockfile name."""
    path = Path(path)
    if path.is_dir():
        for candidate in ("package-lock.json", "poetry.lock", "dependency-tree.txt"):
            if (path / candidate).exists():
                return resolve(path / candidate)
        raise ValueError(f"{path}: no package-lock.json, poetry.lock or dependency-tree.txt found")
    if path.name.endswith("package-lock.json") or path.name == "npm-shrinkwrap.json":
        return resolve_npm(path)
    if path.name.endswith("poetry.lock"):
        return resolve_poetry(path)
    return resolve_maven_tree(path)
