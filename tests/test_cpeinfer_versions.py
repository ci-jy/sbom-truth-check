"""Version-range translation: CNA ``versions`` semantics must agree with the translated cpeMatch ranges.

The reference is a brute-force evaluation of the CNA rules (``status_of``) at concrete versions;
the translation must flag exactly the same versions, over generated version lists.
"""

from hypothesis import given, settings, strategies as st

from cpeinfer.versions import Range, Version, range_overlap, same_ranges, status_of, translate

nums = st.integers(0, 4)
release = st.tuples(nums, nums, nums).map(lambda t: ".".join(map(str, t)))
pre = st.sampled_from(["", "-alpha", "-beta.1", "-rc1", "-rc2"])
version = st.builds(lambda r, p: r + p, release, pre)
branch = st.tuples(nums, nums).map(lambda t: f"{t[0]}.{t[1]}.*")
status = st.sampled_from(["affected", "unaffected"])


@st.composite
def entry(draw):
    kind = draw(st.sampled_from(["single", "lt", "lte", "branch", "open", "changes"]))
    s = draw(status)
    if kind == "single":
        return {"version": draw(version), "status": s}
    start = draw(st.one_of(version, st.just("0")))
    if kind == "lt":
        return {"version": start, "lessThan": draw(version), "status": s, "versionType": "semver"}
    if kind == "lte":
        return {"version": start, "lessThanOrEqual": draw(version), "status": s}
    if kind == "branch":
        return {"version": start, "lessThanOrEqual": draw(branch), "status": s}
    if kind == "open":
        return {"version": start, "lessThan": "*", "status": s}
    changes = [{"at": draw(version), "status": draw(status)} for _ in range(draw(st.integers(1, 2)))]
    return {"version": start, "lessThan": draw(version), "status": s, "changes": changes}


probe_versions = [f"{a}.{b}.{c}{p}" for a in range(6) for b in range(6) for c in range(6)
                  for p in ("", "-rc1")][::3] + ["0.0.1", "4.20", "5.0.0-alpha", "9.9.9", "100"]


@settings(max_examples=300, deadline=None)
@given(st.lists(entry(), min_size=1, max_size=4), st.sampled_from(["affected", "unaffected", "unknown"]))
def test_translation_matches_brute_force(entries, default):
    ranges = translate(entries, default)
    for v in probe_versions:
        expected = status_of(entries, default, v) == "affected"
        got = any(r.contains(v) for r in ranges)
        assert got == expected, (v, entries, default, ranges)


@settings(max_examples=200, deadline=None)
@given(st.lists(entry(), min_size=1, max_size=4))
def test_translated_ranges_round_trip_through_cpe_match(entries):
    ranges = translate(entries, "unaffected")
    back = [Range.from_cpe_match(r.as_cpe_match(), r.as_cpe_match().get("version", "*")) for r in ranges]
    assert same_ranges(ranges, back) or not ranges
    for v in probe_versions:
        assert any(r.contains(v) for r in ranges) == any(r.contains(v) for r in back)


@given(st.lists(version, min_size=2, max_size=6))
def test_version_order_is_total_and_consistent(vs):
    ordered = sorted(map(Version, vs))
    for a, b in zip(ordered, ordered[1:]):
        assert a <= b and not b < a


def test_hand_worked_orderings():
    assert Version("1.0.0-rc1") < Version("1.0") == Version("1.0.0") < Version("1.0.1")
    assert Version("1.9") < Version("1.10") and Version("v2.3") > Version("2.2.99")
    assert Version("2.0.0-alpha.9") < Version("2.0.0-beta.2") < Version("2.0.0")
    assert Version("4.19.300") < Version("4.19.*") < Version("4.20")


def test_typical_cna_shapes():
    # GitHub advisory style: everything below the fix
    assert [r.as_cpe_match() for r in translate([{"version": "< 1.8.2", "status": "affected"}], "unaffected")] == [
        {"versionEndExcluding": "1.8.2"}]
    assert [r.as_cpe_match() for r in translate([{"version": ">= 2.0.0, <= 2.4.1", "status": "affected"}])] == [
        {"versionStartIncluding": "2.0.0", "versionEndIncluding": "2.4.1"}]
    assert [r.as_cpe_match() for r in translate(
        [{"version": "0", "lessThan": "1.8.2", "status": "affected", "versionType": "semver"}], "unaffected")] == [
        {"versionEndExcluding": "1.8.2"}]
    # Linux kernel style: affected from 4.19, fixed on stable branches
    kernel = [{"version": "4.19", "status": "affected"},
              {"version": "0", "lessThan": "4.19", "status": "unaffected"},
              {"version": "5.4.10", "lessThanOrEqual": "5.4.*", "status": "unaffected"},
              {"version": "6.1", "lessThanOrEqual": "*", "status": "unaffected"}]
    assert [r.as_cpe_match() for r in translate(kernel, "affected")] == [
        {"versionStartIncluding": "4.19", "versionEndExcluding": "5.4.10"},
        {"versionStartIncluding": "5.5", "versionEndExcluding": "6.1"}]
    # inclusive upper bound and a single version
    assert [r.as_cpe_match() for r in translate(
        [{"version": "2.0", "lessThanOrEqual": "2.3.1", "status": "affected"},
         {"version": "3.0.0", "status": "affected"}], "unaffected")] == [
        {"versionStartIncluding": "2.0", "versionEndIncluding": "2.3.1"}, {"version": "3.0.0"}]


def test_range_overlap_scores():
    a = translate([{"version": "1.0", "lessThan": "2.0", "status": "affected"}], "unaffected")
    assert range_overlap(a, a) == 1.0
    b = [Range("1.5", True, "2.0", False)]
    assert 0 < range_overlap(a, b) < 1
    assert range_overlap(a, [Range("3.0", True, "4.0", False)]) == 0.0
