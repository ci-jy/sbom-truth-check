"""Planted-error tests: mutate a valid SBOM and require the checker to flag exactly the planted defect."""

import copy

from hypothesis import given, settings, strategies as st

from sbomcheck import conformance, diff, lockfiles, sbom
from synth import cyclonedx, graphs, package_lock, spdx

SETTINGS = settings(max_examples=60, deadline=None)


def failing_fields(report):
    return {name: r.failures for name, r in report.results.items() if not r.passed}


@SETTINGS
@given(graphs())
def test_unmutated_sboms_are_conformant_and_exact(g):
    truth = lockfiles.resolve_npm(package_lock(g))
    for doc in (cyclonedx(g), spdx(g)):
        assert failing_fields(conformance.check(doc)) == {}
        result = diff.diff(sbom.load(doc), truth)
        assert result.mismatches == []
        assert result.components["all"].precision == result.components["all"].recall == 1.0
        assert result.edges["all"].precision == result.edges["all"].recall == 1.0


@SETTINGS
@given(graphs(), st.data())
def test_dropped_hash_is_flagged_at_its_path(g, data):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    del doc["components"][i]["hashes"]
    assert failing_fields(conformance.check(doc)) == {
        "component_hash": [(f"$.components[{i}].hashes", "no hash")]}

    doc = spdx(g)
    del doc["packages"][i + 1]["checksums"]  # packages[0] is the root
    assert failing_fields(conformance.check(doc)) == {
        "component_hash": [(f"$.packages[{i + 1}].checksums", "no checksum")]}


@SETTINGS
@given(graphs(), st.data(), st.sampled_from(["SHA-1", "MD5", "SHA-256"]))
def test_hash_with_wrong_algorithm_length_is_flagged(g, data, alg):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    doc["components"][i]["hashes"][0]["alg"] = alg  # a SHA-512 value labelled as another algorithm
    fails = failing_fields(conformance.check(doc))
    assert list(fails) == ["component_hash"]
    assert [p for p, _ in fails["component_hash"]] == [f"$.components[{i}].hashes"]


@SETTINGS
@given(graphs(), st.data())
def test_stripped_license_is_flagged_at_its_path(g, data):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    del doc["components"][i]["licenses"]
    assert failing_fields(conformance.check(doc)) == {
        "license": [(f"$.components[{i}].licenses", "no license id, name or expression")]}

    doc = spdx(g)
    doc["packages"][i + 1]["licenseConcluded"] = "NOASSERTION"
    doc["packages"][i + 1]["licenseDeclared"] = "NOASSERTION"
    assert set(failing_fields(conformance.check(doc))) == {"license"}


@SETTINGS
@given(graphs(), st.data())
def test_removed_producer_and_author_are_flagged(g, data):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    del doc["components"][i]["supplier"]
    del doc["metadata"]["authors"]
    fails = failing_fields(conformance.check(doc))
    assert fails == {"component_producer": [(f"$.components[{i}].supplier", "no supplier/manufacturer/author")],
                     "sbom_author": [("$.metadata.authors", "no SBOM author (metadata.authors/manufacturer)")]}


@SETTINGS
@given(graphs(min_nodes=3), st.data())
def test_removed_transitive_edge_is_the_only_mismatch(g, data):
    transitive = sorted(e for e in g.edges if e[0] != -1)
    if not transitive:
        return
    p, c = data.draw(st.sampled_from(transitive))
    truth = lockfiles.resolve_npm(package_lock(g))
    doc = cyclonedx(g)
    entry = next(d for d in doc["dependencies"] if d["ref"] == f"ref-{p}")
    entry["dependsOn"].remove(f"ref-{c}")
    result = diff.diff(sbom.load(doc), truth)
    assert [(m.kind, m.cause, m.subject) for m in result.mismatches] == [
        ("missing_edge", diff.MISSING_TRANSITIVE_EDGE, f"{lockfiles.purls.identity(g.purl(p))} -> "
                                                       f"{lockfiles.purls.identity(g.purl(c))}")]
    assert result.components["all"].recall == 1.0
    assert result.edges["transitive"].recall < 1.0

    # the same edge removed from SPDX relationships
    doc = spdx(g)
    doc["relationships"] = [r for r in doc["relationships"]
                            if (r["spdxElementId"], r["relatedSpdxElement"]) != (f"SPDXRef-p{p}", f"SPDXRef-p{c}")]
    result = diff.diff(sbom.load(doc), truth)
    assert [(m.kind, m.cause) for m in result.mismatches] == [("missing_edge", diff.MISSING_TRANSITIVE_EDGE)]


@SETTINGS
@given(graphs(), st.data())
def test_unreachable_component_fails_transitive_completeness(g, data):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    for entry in doc["dependencies"]:
        entry["dependsOn"] = [r for r in entry["dependsOn"] if r != f"ref-{i}"]
    fails = failing_fields(conformance.check(doc))
    assert set(fails) == {"transitive_completeness"}
    assert (f"$.components[{i}]", "not reachable from the primary component through dependency edges") in \
        fails["transitive_completeness"]


@SETTINGS
@given(graphs(), st.data(), st.sampled_from(["type", "scope"]))
def test_purl_case_change_is_only_a_normalization_mismatch(g, data, where):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    purl = doc["components"][i]["purl"]
    if where == "scope" and "%40" in purl:
        scope = purl.split("%40", 1)[1].split("/", 1)[0]
        doc["components"][i]["purl"] = purl.replace(f"%40{scope}/", f"%40{scope.upper()}/", 1)
    else:
        doc["components"][i]["purl"] = purl.replace("pkg:npm/", "pkg:NPM/", 1)
    result = diff.diff(sbom.load(doc), lockfiles.resolve_npm(package_lock(g)))
    assert [(m.kind, m.cause) for m in result.mismatches] == [("normalized_component", diff.NAME_NORMALIZATION)]
    assert result.components["all"].precision == result.components["all"].recall == 1.0
    assert result.edges["all"].recall == 1.0


@SETTINGS
@given(graphs(), st.data())
def test_duplicate_component_is_flagged_once(g, data):
    i = data.draw(st.integers(0, len(g.names) - 1))
    doc = cyclonedx(g)
    dup = copy.deepcopy(doc["components"][i])
    dup["bom-ref"] = "dup"
    doc["components"].append(dup)
    doc["dependencies"].append({"ref": "dup", "dependsOn": []})
    result = diff.diff(sbom.load(doc), lockfiles.resolve_npm(package_lock(g)))
    assert [(m.kind, m.cause) for m in result.mismatches] == [("duplicate_component", diff.DUPLICATE)]


# ---------------------------------------------------------------- PyPI and Maven identity mutations

def _pypi_case(tmp_path, names):
    lock = "\n".join(
        f'[[package]]\nname = "{n}"\nversion = "1.0"\noptional = false\npython-versions = "*"\ngroups = ["main"]\n'
        for n in names)
    (tmp_path / "poetry.lock").write_text(lock + '\n[metadata]\nlock-version = "2.1"\n')
    deps = ", ".join(f'"{n}"' for n in names)
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "app"\nversion = "0.1"\ndependencies = [{deps}]\n')
    return lockfiles.resolve_poetry(tmp_path / "poetry.lock")


def _bom(purls_):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"type": "application", "bom-ref": "root", "name": "app"}},
            "components": [{"type": "library", "bom-ref": f"c{i}", "name": "x", "version": "1", "purl": p}
                           for i, p in enumerate(purls_)],
            "dependencies": [{"ref": "root", "dependsOn": [f"c{i}" for i in range(len(purls_))]}]}


@settings(max_examples=40, deadline=None)
@given(st.lists(st.from_regex(r"[a-z]{2,6}([-_.][a-z]{2,6})?", fullmatch=True), min_size=1, max_size=5,
                unique_by=lambda n: lockfiles.purls.pep503_name(n)), st.data())
def test_pypi_name_spelling_is_normalized(names, data):
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        truth = _pypi_case(Path(tmp), names)
    i = data.draw(st.integers(0, len(names) - 1))
    spelled = [f"pkg:pypi/{n}@1.0" for n in names]
    respelled = names[i].upper().replace("-", "_").replace(".", "_")
    if respelled == lockfiles.purls.pep503_name(names[i]):
        return
    spelled[i] = f"pkg:pypi/{respelled}@1.0.0"  # PEP 503 name variant and PEP 440 version variant
    result = diff.diff(sbom.load(_bom(spelled)), truth)
    assert [(m.kind, m.cause) for m in result.mismatches] == [("normalized_component", diff.NAME_NORMALIZATION)]
    assert result.components["all"].precision == result.components["all"].recall == 1.0


@settings(max_examples=40, deadline=None)
@given(st.sampled_from(["?type=jar", "?Type=jar", "?repository_url=https%3A%2F%2Frepo1.maven.org"]))
def test_maven_qualifier_variants_compare_equal(tmp_path_factory, suffix):
    tmp = tmp_path_factory.mktemp("mvn")
    (tmp / "dependency-tree.txt").write_text(
        "com.example:app:jar:1.0\n+- org.slf4j:slf4j-api:jar:2.0.9:compile\n"
        "\\- com.google.guava:guava:jar:33.0.0-jre:compile\n   \\- com.google.guava:failureaccess:jar:1.0.2:compile\n")
    truth = lockfiles.resolve_maven_tree(tmp / "dependency-tree.txt")
    purl_list = ["pkg:maven/org.slf4j/slf4j-api@2.0.9" + suffix, "pkg:maven/com.google.guava/guava@33.0.0-jre",
                 "pkg:maven/com.google.guava/failureaccess@1.0.2"]
    doc = _bom(purl_list)
    doc["dependencies"] = [{"ref": "root", "dependsOn": ["c0", "c1"]}, {"ref": "c1", "dependsOn": ["c2"]}]
    result = diff.diff(sbom.load(doc), truth)
    expected = [] if suffix.startswith("?repository_url") else [("normalized_component", diff.NAME_NORMALIZATION)]
    assert [(m.kind, m.cause) for m in result.mismatches] == expected
    assert result.edges["all"].precision == result.edges["all"].recall == 1.0
