"""Ground-truth resolvers on small hand-written lockfiles."""

import json

from sbomcheck import diff, lockfiles, sbom
from sbomcheck.lockfiles import ROOT


def test_npm_nested_resolution_scopes_and_flags(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1"}, "devDependencies": {"t": "^1"},
             "optionalDependencies": {"fsevents": "^2"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2"}},
        "node_modules/b": {"version": "1.0.0", "dev": True},  # hoisted b@1 is NOT what a needs
        "node_modules/a/node_modules/b": {"version": "2.0.0", "dependencies": {"c": "*"}},
        "node_modules/c": {"version": "3.0.0", "inBundle": True},
        "node_modules/t": {"version": "1.0.0", "dev": True, "dependencies": {"b": "^1"}},
        "node_modules/fsevents": {"version": "2.3.3", "optional": True, "os": ["darwin"]},
        "node_modules/@local/fixture": {"resolved": "fixtures/local", "link": True},
        "fixtures/local": {"name": "@local/fixture", "dev": True},
    }}
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(lock))
    g = lockfiles.resolve(path)
    key = lambda n, v: lockfiles.purls.identity(f"pkg:npm/{n}@{v}")  # noqa: E731
    assert (key("a", "1.0.0"), key("b", "2.0.0")) in g.edges
    assert (key("a", "1.0.0"), key("b", "1.0.0")) not in g.edges
    assert (key("b", "2.0.0"), key("c", "3.0.0")) in g.edges
    assert g.nodes[key("t", "1.0.0")].dev and g.nodes[key("fsevents", "2.3.3")].optional
    assert g.nodes[key("c", "3.0.0")].bundled
    assert g.edges[(ROOT, key("fsevents", "2.3.3"))] is True  # conditional edge
    assert g.nodes["pkg:npm/%40local/fixture"].dev
    assert g.runtime_keys() == {key("a", "1.0.0"), key("b", "2.0.0"), key("c", "3.0.0"), key("fsevents", "2.3.3")}
    assert key("b", "1.0.0") not in g.runtime_keys()  # only the dev tool t uses b@1


def test_poetry_groups_markers_and_extras(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "0.1"\ndependencies = ["Requests>=2", "colorama ; sys_platform == \'win32\'"]\n'
        '[tool.poetry.group.dev.dependencies]\npytest = "^8"\n')
    (tmp_path / "poetry.lock").write_text('''
[[package]]
name = "requests"
version = "2.31.0"
optional = false
python-versions = ">=3.7"
groups = ["main"]
[package.dependencies]
urllib3 = ">=1.21.1"
[package.extras]
socks = ["PySocks (>=1.5.6)"]

[[package]]
name = "urllib3"
version = "2.0.7"
optional = false
python-versions = ">=3.7"
groups = ["main", "dev"]

[[package]]
name = "colorama"
version = "0.4.6"
optional = false
python-versions = "*"
groups = ["main"]
markers = "sys_platform == \\"win32\\""

[[package]]
name = "pytest"
version = "8.0.0"
optional = false
python-versions = ">=3.8"
groups = ["dev"]

[metadata]
lock-version = "2.1"
''')
    g = lockfiles.resolve(tmp_path)
    assert {n.name: (n.dev, n.optional) for n in g.nodes.values()} == {
        "requests": (False, False), "urllib3": (False, False), "colorama": (False, True), "pytest": (True, False)}
    assert g.nodes["pkg:pypi/requests@2.31"].extras == {"pysocks"}
    assert g.direct_keys() == {"pkg:pypi/requests@2.31", "pkg:pypi/colorama@0.4.6", "pkg:pypi/pytest@8"}
    assert g.edges[(ROOT, "pkg:pypi/colorama@0.4.6")] is True


def test_maven_tree_scopes_optional_and_profiles(tmp_path):
    (tmp_path / "dependency-tree.txt").write_text(
        "org.example:app:jar:1.0\n"
        "+- org.slf4j:slf4j-api:jar:2.0.9:compile\n"
        "+- com.google.guava:guava:jar:33.0.0-jre:compile\n"
        "|  +- com.google.guava:failureaccess:jar:1.0.2:compile\n"
        "|  \\- org.checkerframework:checker-qual:jar:3.41.0:compile (optional)\n"
        "+- io.netty:netty-tcnative:jar:linux-x86_64:2.0.61.Final:runtime\n"
        "\\- org.junit.jupiter:junit-jupiter:jar:5.10.0:test\n")
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><profiles><profile><id>bench</id><dependencies>'
        '<dependency><groupId>org.openjdk.jmh</groupId><artifactId>jmh-core</artifactId></dependency>'
        '</dependencies></profile></profiles></project>')
    g = lockfiles.resolve(tmp_path)
    assert g.root_name == "org.example:app"
    assert ("pkg:maven/com.google.guava/guava@33.0.0-jre",
            "pkg:maven/com.google.guava/failureaccess@1.0.2") in g.edges
    assert g.nodes["pkg:maven/org.checkerframework/checker-qual@3.41.0"].optional
    assert "pkg:maven/io.netty/netty-tcnative@2.0.61.Final?classifier=linux-x86_64" in g.nodes
    assert g.nodes["pkg:maven/org.junit.jupiter/junit-jupiter@5.10.0"].dev
    assert g.inactive == {"pkg:maven/org.openjdk.jmh/jmh-core"}


def test_classifier_names_each_kind_of_disagreement(tmp_path):
    (tmp_path / "dependency-tree.txt").write_text(
        "org.example:app:jar:1.0\n"
        "+- com.google.guava:guava:jar:33.0.0-jre:compile\n"
        "|  \\- com.google.guava:failureaccess:jar:1.0.2:compile\n"
        "+- org.slf4j:slf4j-api:jar:2.0.9:compile\n"
        "\\- org.junit.jupiter:junit-jupiter:jar:5.10.0:test\n")
    (tmp_path / "pom.xml").write_text(
        "<project><profiles><profile><dependencies><dependency><groupId>org.openjdk.jmh</groupId>"
        "<artifactId>jmh-core</artifactId></dependency></dependencies></profile></profiles></project>")
    truth = lockfiles.resolve(tmp_path)
    comps = {
        "g": "pkg:maven/com.google.guava/guava@33.0.0-jre",
        "f": "pkg:maven/com.google.guava/failureaccess@1.0.2",
        "s": "pkg:maven/org.slf4j/slf4j-api@${slf4j.version}",  # unresolved property
        "j": "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.0",  # test scope
        "m": "pkg:maven/org.openjdk.jmh/jmh-core@1.37",  # profile-only
    }
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"type": "application", "bom-ref": "root", "name": "app"}},
           "components": [{"type": "library", "bom-ref": r, "name": r, "version": "1", "purl": p}
                          for r, p in comps.items()],
           "dependencies": [{"ref": "root", "dependsOn": ["g", "f", "s", "j", "m"]}]}
    result = diff.diff(sbom.load(doc), truth)
    causes = {(m.kind, m.subject.split("/")[-1]): m.cause for m in result.mismatches}
    assert causes == {
        ("extra_component", "slf4j-api@%24%7Bslf4j.version%7D"): diff.RANGE_VERSION,
        ("extra_component", "junit-jupiter@5.10.0"): diff.DEV_DEPENDENCY,
        ("extra_component", "jmh-core@1.37"): diff.INACTIVE_PROFILE,
        ("missing_component", "slf4j-api@2.0.9"): diff.RANGE_VERSION,
        ("extra_edge", "failureaccess@1.0.2"): diff.FLATTENED,
        ("extra_edge", "slf4j-api@%24%7Bslf4j.version%7D"): diff.RANGE_VERSION,
        ("extra_edge", "junit-jupiter@5.10.0"): diff.DEV_DEPENDENCY,
        ("extra_edge", "jmh-core@1.37"): diff.INACTIVE_PROFILE,
        ("missing_edge", "slf4j-api@2.0.9"): diff.RANGE_VERSION,
        ("missing_edge", "failureaccess@1.0.2"): diff.MISSING_TRANSITIVE_EDGE,
    }
    assert diff.UNEXPLAINED not in result.cause_counts()
