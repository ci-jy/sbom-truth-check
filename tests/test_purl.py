"""Hand-worked PURL canonicalization cases."""

import pytest

from sbomcheck.purl import canonicalize, identity, parse, pep440_version, pep503_name, raw_identity

EQUAL = [
    # PyPI: PEP 503 names, PEP 440 versions, type case
    ("pkg:pypi/Django@4.2.1", "pkg:pypi/django@4.2.1"),
    ("pkg:pypi/typing_extensions@4.9.0", "pkg:pypi/typing-extensions@4.9.0"),
    ("pkg:pypi/zope.interface@6.1", "pkg:pypi/zope-interface@6.1"),
    ("pkg:pypi/Foo__Bar-.baz@1.0", "pkg:pypi/foo-bar-baz@1.0"),
    ("pkg:PyPI/requests@2.31.0", "pkg:pypi/requests@2.31.0"),
    ("pkg:pypi/pkg@1.0.0-RC1", "pkg:pypi/pkg@1.0.0rc1"),
    ("pkg:pypi/pkg@1.0-alpha.2", "pkg:pypi/pkg@1.0a2"),
    ("pkg:pypi/pkg@1.0-1", "pkg:pypi/pkg@1.0.post1"),
    ("pkg:pypi/pkg@v2.0.dev3", "pkg:pypi/pkg@2.0.dev3"),
    ("pkg:pypi/pkg@01.002", "pkg:pypi/pkg@1.2"),
    ("pkg:pypi/pkg@2.0.0", "pkg:pypi/pkg@2"),
    ("pkg:pypi/pkg@1.0.0-RC1", "pkg:pypi/pkg@1rc1"),
    # npm: scope encoding and case, leading v
    ("pkg:npm/%40Babel/core@7.23.0", "pkg:npm/%40babel/core@7.23.0"),
    ("pkg:npm/@babel/core@7.23.0", "pkg:npm/%40babel/core@7.23.0"),
    ("pkg:npm/babel/core@7.23.0", "pkg:npm/%40babel/core@7.23.0"),
    ("pkg:npm/lodash@v4.17.21", "pkg:npm/lodash@4.17.21"),
    ("pkg:NPM/lodash@4.17.21", "pkg:npm/lodash@4.17.21"),
    # qualifiers: order, key case, empty values, non-identity metadata, Maven default type
    ("pkg:maven/org.x/a@1?type=jar", "pkg:maven/org.x/a@1"),
    ("pkg:maven/org.x/a@1?Classifier=sources&type=jar", "pkg:maven/org.x/a@1?classifier=sources"),
    ("pkg:maven/org.x/a@1?type=pom&classifier=x", "pkg:maven/org.x/a@1?classifier=x&type=pom"),
    ("pkg:npm/lodash@4.17.21?repository_url=https://r.example", "pkg:npm/lodash@4.17.21"),
    ("pkg:pypi/six@1.16.0?package-id=abc123", "pkg:pypi/six@1.16.0"),
    ("pkg:npm/lodash@4.17.21?vcs_url=", "pkg:npm/lodash@4.17.21"),
    ("pkg:npm/lodash@4.17.21#lib/fp", "pkg:npm/lodash@4.17.21"),
]

DIFFERENT = [
    ("pkg:npm/JSONStream@1.3.5", "pkg:npm/jsonstream@1.3.5"),  # the npm registry is case-sensitive
    ("pkg:maven/org.X/a@1", "pkg:maven/org.x/a@1"),  # Maven coordinates are case-sensitive
    ("pkg:maven/org.x/a@1?classifier=sources", "pkg:maven/org.x/a@1"),
    ("pkg:maven/org.x/a@1?type=pom", "pkg:maven/org.x/a@1"),
    ("pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.31.1"),
    ("pkg:pypi/requests@2.31.0", "pkg:npm/requests@2.31.0"),
    ("pkg:npm/%40types/node@20.0.0", "pkg:npm/node@20.0.0"),
]


@pytest.mark.parametrize("a,b", EQUAL)
def test_equivalent_purls_share_identity(a, b):
    assert identity(a) == identity(b)


@pytest.mark.parametrize("a,b", DIFFERENT)
def test_distinct_purls_stay_distinct(a, b):
    assert identity(a) != identity(b)


def test_parse_splits_all_parts():
    p = parse("pkg:maven/org.apache.commons/commons-lang3@3.14.0?type=jar&classifier=sources#sub/dir")
    assert (p.type, p.namespace, p.name, p.version) == ("maven", "org.apache.commons", "commons-lang3", "3.14.0")
    assert p.qualifiers == (("type", "jar"), ("classifier", "sources"))
    assert p.subpath == "sub/dir"


def test_scoped_npm_without_version_keeps_scope():
    assert canonicalize("pkg:npm/%40types/node").to_string() == "pkg:npm/%40types/node"


def test_canonical_string_is_stable():
    assert identity("pkg:PYPI/Typing_Extensions@4.9.0") == "pkg:pypi/typing-extensions@4.9"
    assert identity("pkg:pypi/six@1.16.0") == "pkg:pypi/six@1.16"
    assert identity("pkg:npm/@Angular/Core@17.0.0") == "pkg:npm/%40angular/Core@17.0.0"


def test_raw_identity_keeps_spelling():
    assert raw_identity("pkg:pypi/Django@4.2") != raw_identity("pkg:pypi/django@4.2")
    assert raw_identity("pkg:pypi/django@4.2?package-id=1") == raw_identity("pkg:pypi/django@4.2")


@pytest.mark.parametrize("name,expected", [("Friendly-Bard", "friendly-bard"), ("FRIENDLY_BARD", "friendly-bard"),
                                           ("friendly.bard", "friendly-bard"), ("Friendly--._Bard", "friendly-bard")])
def test_pep503_examples(name, expected):
    assert pep503_name(name) == expected


@pytest.mark.parametrize("version,expected", [("1.0.0", "1.0.0"), ("1.0RC1", "1.0rc1"), ("1.0c1", "1.0rc1"),
                                              ("1.0-post2", "1.0.post2"), ("1.0+Ubuntu-1", "1.0+ubuntu.1"),
                                              ("0!1.0", "1.0"), ("not a version", "not a version")])
def test_pep440_examples(version, expected):
    assert pep440_version(version) == expected
