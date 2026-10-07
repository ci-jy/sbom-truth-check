"""Planted alias cases: synthetic history with known CNA-name -> CPE aliases the resolver must recover."""

import numpy as np
from hypothesis import given, settings, strategies as st

from cpeinfer import resolver as R
from cpeinfer.data import nvd_truth, split_cpe
from cpeinfer.gaps import component_entry
from sbomcheck import purl as purlmod

RAW_DICT = {
    "vps": {
        "apache:tomcat": ["a", "2008-01-01", ["9.0.1", "10.1.0"]],
        "jenkins:script_security": ["a", "2015-01-01", ["1.0"]],
        "axios:axios": ["a", "2019-01-01", ["0.21.0"]],
        "old_vendor:widget": ["a", "2010-01-01", []],
        "new_vendor:widget": ["a", "2020-01-01", []],
        "later:product": ["a", "2026-02-01", []],
        "microsoft:windows_10": ["o", "2015-01-01", []],
    },
    "renames": {"old_vendor:widget": "new_vendor:widget"},
}


def rec(cid, entries, truth, cna="cna"):
    return {"id": cid, "cna": cna, "published": "2024-01-01", "nvd_status": "Analyzed",
            "affected": entries, "truth": {vp: [{}] for vp in truth}}


def test_cpe_names_split_with_escapes():
    assert split_cpe("cpe:2.3:a:vendor\\:x:prod\\!:1.0:*:*:*:*:*:*:*") == ("a", "vendor:x", "prod!", "1.0")
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*", "versionEndExcluding": "1.8.2"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}]}
    assert nvd_truth(cve) == {"axios:axios": [{"versionEndExcluding": "1.8.2"}]}


def test_dictionary_cutoff_hides_later_entries_and_follows_renames():
    d = R.Dictionary(RAW_DICT, cutoff="2025-01-01")
    assert "later:product" not in d.vps
    assert d.current("old_vendor:widget") == ("new_vendor:widget", True)


def test_package_keys_reuse_sbom_canonicalization():
    assert R.package_key({"packageName": "Foo_Bar", "collectionURL": "https://pypi.org/simple"}) == "pkg:pypi/foo-bar"
    assert R.package_key({"packageName": "org.jenkins-ci.plugins:script-security",
                          "collectionURL": "https://repo.jenkins-ci.org/releases"}) is None
    assert R.package_key({"repo": "https://github.com/Axios/axios.git"}) == "pkg:github/axios/axios"
    p = purlmod.canonicalize("pkg:npm/axios@1.6.0")
    assert R.package_key(component_entry(p)) == "pkg:npm/axios"


words = st.text(alphabet="abcdefghij", min_size=4, max_size=8)


@settings(max_examples=40, deadline=None)
@given(words, words, st.integers(2, 6))
def test_planted_vendor_alias_is_learned(cna_vendor, cna_product, n):
    """A CNA that always writes ``<cna_vendor> / <cna_product>`` for jenkins:script_security."""
    history = [rec(f"CVE-2024-{i}", [{"vendor": cna_vendor, "product": cna_product}], ["jenkins:script_security"])
               for i in range(n)]
    alias = R.AliasModel().fit(history)
    d = R.Dictionary(RAW_DICT)
    cands = R.candidates({"vendor": cna_vendor, "product": cna_product}, "cna", alias, d)
    top = max(cands, key=lambda c: (c.feats["alias_vp_share"], c.feats["alias_vp_logc"]))
    assert top.vp == "jenkins:script_security" and top.feats["alias_vp_share"] == 1.0


def test_planted_package_alias_and_rename_chain():
    history = [rec("CVE-2024-1", [{"vendor": "someone", "product": "w", "packageName": "widget",
                                   "collectionURL": "https://registry.npmjs.org"}], ["old_vendor:widget"])]
    alias = R.AliasModel().fit(history)
    d = R.Dictionary(RAW_DICT)
    # new CVE: different free-text names, same npm package -> learned alias, then the rename is followed
    cands = R.candidates({"vendor": "x", "product": "y", "packageName": "widget",
                          "collectionURL": "https://registry.npmjs.org/"}, "other", alias, d)
    hit = {c.vp: c for c in cands}["new_vendor:widget"]
    assert hit.feats["alias_pkg_share"] == 1.0 and hit.feats["renamed"] == 1.0


def test_alignment_uses_cna_cpes_then_similarity():
    r = rec("CVE-2024-9", [{"vendor": "Apache Software Foundation", "product": "Apache Tomcat"},
                           {"vendor": "Axios", "product": "axios", "cpes": ["cpe:2.3:a:axios:axios:*:*:*:*:*:*:*:*"]}],
            ["apache:tomcat", "axios:axios"])
    assert {e["product"]: vp for e, vp in R.align(r)} == {"Apache Tomcat": "apache:tomcat", "axios": "axios:axios"}


def test_dictionary_candidates_and_baseline():
    d = R.Dictionary(RAW_DICT)
    alias = R.AliasModel()
    entry = {"vendor": "The Apache Software Foundation", "product": "Apache Tomcat",
             "versions": [{"version": "9.0.0", "lessThan": "9.0.5", "status": "affected"}]}
    by_vp = {c.vp: c for c in R.candidates(entry, "apache", alias, d)}
    assert "apache:tomcat" in by_vp and by_vp["apache:tomcat"].feats["version_overlap"] == 1.0
    assert R.baseline(entry, d) is None  # "the_apache_software_foundation:apache_tomcat" is not a CPE
    assert R.baseline({"vendor": "Axios", "product": "axios"}, d) == "axios:axios"


def test_scorer_separates_planted_signal():
    rng = np.random.default_rng(0)
    X = np.c_[np.ones(400), rng.normal(size=(400, len(R.FEATURES) - 1))]
    y = (X[:, 1] + 0.1 * rng.normal(size=400) > 0).astype(float)
    s = R.Scorer().fit(X, y)
    assert ((s.predict(X) > 0.5) == y).mean() > 0.95
