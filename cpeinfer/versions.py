"""Version ordering and translation of CNA ``versions`` lists into NVD cpeMatch ranges.

CVE JSON 5.x describes affected versions as a list of entries::

    {"version": "1.2.0", "lessThan": "1.4.3", "status": "affected", "versionType": "semver",
     "changes": [{"at": "1.3.0", "status": "unaffected"}]}

plus a ``defaultStatus`` for versions no entry mentions. NVD expresses the same set as a union
of cpeMatch ranges (``versionStartIncluding``/``versionStartExcluding``/``versionEndIncluding``/
``versionEndExcluding``) or single versions. Translation works on the sorted boundary points:
between two consecutive boundaries every entry either covers the whole gap or none of it, so
the status of each point and each open gap fixes the affected set exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

# Strings CNAs use for "no bound" / "every version".
UNBOUNDED = {"", "*", "0", "-", "all", "unspecified", "n/a", "na", "unknown", "all versions"}
PRE_RELEASE = {"dev": 0, "snapshot": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "m": 3, "milestone": 3,
               "pre": 4, "preview": 4, "c": 5, "rc": 5, "cr": 5, "ea": 4}
_TOKEN = re.compile(r"\d+|[a-z]+|\*")
_PREFIX = re.compile(r"^(?:v|version|release|rel|r)[\s._-]?(?=\d)", re.I)
# Comparison classes: pre-release word < end of version < other word < number < wildcard.
_PRE, _END, _WORD, _NUM, _STAR = 0, 1, 2, 3, 4
NEG_INF, POS_INF = (), ((9, 0, ""),)  # keys below / above every version


@total_ordering
@dataclass(frozen=True)
class Version:
    """A version string with a generic total order (semver, PEP 440-like and dotted vendor versions).

    Numbers compare numerically, pre-release words (alpha, beta, rc, ...) sort before the
    release, other words after it, trailing ``.0`` components are ignored (``1.2 == 1.2.0``),
    and ``*`` is greater than any component (``4.19.*`` bounds the whole 4.19 branch).
    """

    raw: str

    @property
    def key(self) -> tuple:
        return version_key(self.raw)

    def __eq__(self, other):
        return isinstance(other, Version) and self.key == other.key

    def __hash__(self):
        return hash(self.key)

    def __lt__(self, other):
        return self.key < other.key

    def __repr__(self):
        return f"Version({self.raw!r})"


def version_key(raw: str) -> tuple:
    text = _PREFIX.sub("", raw.strip().lower())
    text = text.split("+", 1)[0]  # semver build metadata does not take part in ordering
    out = []
    for tok in _TOKEN.findall(text):
        if tok == "*":
            out.append((_STAR, 0, ""))
            break
        if tok.isdigit():
            out.append((_NUM, int(tok), ""))
        elif tok in PRE_RELEASE:
            out.append((_PRE, PRE_RELEASE[tok], ""))
        else:
            out.append((_WORD, 0, tok))
    i = next((n for n, t in enumerate(out) if t[0] != _NUM), len(out))
    release, rest = out[:i], out[i:]
    while release and release[-1] == (_NUM, 0, "") and not (rest and rest[0][0] == _STAR):  # 1.2.0 == 1.2
        release.pop()
    out = release + rest
    out.append((_END, 0, ""))
    return tuple(out)


def is_unbounded(v: str | None) -> bool:
    return v is None or v.strip().lower() in UNBOUNDED


def comparable(v: str | None) -> bool:
    """True when ``v`` looks like an orderable version (not a git hash or free text)."""
    if v is None:
        return False
    s = v.strip()
    if re.fullmatch(r"[0-9a-f]{12,40}", s.lower()) and not s.isdigit():
        return False
    return bool(re.search(r"\d", s)) and len(s) <= 40 and " " not in s.strip()


# ---------------------------------------------------------------------------------------------
# CNA semantics


@dataclass(frozen=True)
class Entry:
    """One normalized CNA ``versions`` entry. ``end`` is None for a single version."""

    start: Version | None  # None = from the beginning
    end: Version | None
    end_inclusive: bool
    status: str
    changes: tuple[tuple[Version, str], ...] = ()
    single: bool = False


class Untranslatable(ValueError):
    pass


_CONSTRAINT = re.compile(r"^(<=|>=|<|>|=)\s*")


def _parse_constraint(text: str, status: str) -> Entry:
    """GitHub-advisory style ``">= 1.0.0, < 1.8.2"`` in the ``version`` field."""
    start, end, incl, exact = None, None, False, None
    for clause in text.split(","):
        clause = clause.strip()
        m = _CONSTRAINT.match(clause)
        if not m:
            raise Untranslatable(f"constraint {text!r}")
        op, val = m.group(1), clause[m.end():].strip()
        if not comparable(val):
            raise Untranslatable(f"constraint {text!r}")
        if op in ("<", "<="):
            end, incl = Version(val), op == "<="
        elif op == ">=":
            start = Version(val)
        elif op == "=":
            exact = Version(val)
        else:  # ">" (exclusive start) is rare in CNA data and left untranslated
            raise Untranslatable(f"constraint {text!r}")
    if exact is not None:
        return Entry(exact, exact, True, status, single=True)
    return Entry(start, end, incl, status)


def parse_entries(versions: list[dict]) -> list[Entry]:
    entries = []
    for v in versions or []:
        status = v.get("status", "unknown")
        ver = v.get("version")
        lt, lte = v.get("lessThan"), v.get("lessThanOrEqual")
        if ver and lt is None and lte is None and _CONSTRAINT.match(ver.strip()):
            entries.append(_parse_constraint(ver, status))
            continue
        if lt is None and lte is None:
            if is_unbounded(ver):
                # "version": "*" / "unspecified" with no bound means "every version"
                entries.append(Entry(None, None, False, status))
                continue
            if not comparable(ver):
                raise Untranslatable(f"version {ver!r}")
            entries.append(Entry(Version(ver), Version(ver), True, status, single=True))
            continue
        bound = lt if lt is not None else lte
        start = None if is_unbounded(ver) else Version(ver)
        if start is not None and not comparable(ver):
            raise Untranslatable(f"version {ver!r}")
        if bound.strip() == "*":
            end, incl = None, False
        else:
            if not comparable(bound):
                raise Untranslatable(f"bound {bound!r}")
            end, incl = Version(bound), lt is None
        changes = []
        for ch in v.get("changes") or []:
            if not comparable(ch.get("at")):
                raise Untranslatable(f"change at {ch.get('at')!r}")
            changes.append((Version(ch["at"]), ch.get("status", "unknown")))
        entries.append(Entry(start, end, incl, status, tuple(sorted(changes, key=lambda c: c[0].key))))
    return entries


def _entry_status(e: Entry, lo: tuple, hi: tuple | None) -> str | None:
    """Status ``e`` assigns to the point ``lo`` (hi is None) or the open gap (lo, hi); None if it does not cover it.

    ``lo``/``hi`` are version keys; ``()`` stands for minus infinity and ``(9,)`` for plus infinity.
    """
    s = e.start.key if e.start else NEG_INF
    if lo < s:
        return None
    if hi is None:  # a point
        if e.end is not None and (lo > e.end.key or (lo == e.end.key and not e.end_inclusive)):
            return None
    elif e.end is not None and hi > e.end.key:  # an open gap: covered iff start <= lo and hi <= end
        return None
    status = e.status
    for at, st in e.changes:  # a change at version c holds from c (and the gap after it) onwards
        if at.key <= lo:
            status = st
    return status


def segment_status(entries: list[Entry], default: str, lo: tuple, hi: tuple | None) -> str:
    """Resolved status of a point or gap: an explicit ``unaffected`` wins over ``affected``."""
    found = {st for e in entries if (st := _entry_status(e, lo, hi)) is not None}
    if "unaffected" in found:
        return "unaffected"
    if "affected" in found:
        return "affected"
    return default


def status_of(versions: list[dict], default_status: str, version: str) -> str:
    """Reference semantics: status of one concrete version (used by the brute-force tests)."""
    entries = parse_entries(versions)
    return segment_status(entries, default_status or "unknown", version_key(version), None)


# ---------------------------------------------------------------------------------------------
# Translation to cpeMatch ranges

@dataclass(frozen=True)
class Range:
    """One NVD cpeMatch range. A single version has start == end and both inclusive."""

    start: str | None = None
    start_inclusive: bool = True
    end: str | None = None
    end_inclusive: bool = False

    def contains(self, version: str) -> bool:
        k = version_key(version)
        if self.start is not None:
            s = version_key(self.start)
            if k < s or (k == s and not self.start_inclusive):
                return False
        if self.end is not None:
            e = version_key(self.end)
            if k > e or (k == e and not self.end_inclusive):
                return False
        return True

    def as_cpe_match(self) -> dict:
        if self.start is not None and self.start == self.end:
            return {"version": self.start}
        out = {}
        if self.start is not None:
            out["versionStartIncluding" if self.start_inclusive else "versionStartExcluding"] = self.start
        if self.end is not None:
            out["versionEndIncluding" if self.end_inclusive else "versionEndExcluding"] = self.end
        return out

    @classmethod
    def from_cpe_match(cls, m: dict, criteria_version: str = "*") -> "Range":
        if criteria_version not in ("*", "-", ""):
            return cls(criteria_version, True, criteria_version, True)
        start, si = m.get("versionStartIncluding"), True
        if start is None and m.get("versionStartExcluding") is not None:
            start, si = m["versionStartExcluding"], False
        end, ei = m.get("versionEndExcluding"), False
        if end is None and m.get("versionEndIncluding") is not None:
            end, ei = m["versionEndIncluding"], True
        return cls(start, si, end, ei)


def _star_to_exclusive(v: Version) -> str:
    """``4.19.*`` as an upper bound becomes the exclusive bound ``4.20``."""
    head = v.raw.strip().rstrip("*").rstrip(".-_")
    parts = head.split(".")
    if parts and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    raise Untranslatable(f"wildcard bound {v.raw!r}")


def translate(versions: list[dict], default_status: str | None = "unknown") -> list[Range]:
    """Translate a CNA ``versions`` list into the minimal list of affected cpeMatch ranges."""
    entries = parse_entries(versions)
    default = default_status or "unknown"
    points: dict[tuple, Version] = {}
    for e in entries:
        for v in (e.start, e.end, *(c[0] for c in e.changes)):
            if v is not None:
                points.setdefault(v.key, v)
    keys = sorted(points)
    # segments in order: gap(-inf, k0), point k0, gap(k0, k1), ..., point kn, gap(kn, +inf)
    segs: list[tuple[tuple, tuple | None]] = []
    prev = NEG_INF
    for k in keys:
        segs.append((prev, k))
        segs.append((k, None))
        prev = k
    segs.append((prev, POS_INF))
    affected = [segment_status(entries, default, lo, hi) == "affected" for lo, hi in segs]

    ranges: list[Range] = []
    i = 0
    while i < len(segs):
        if not affected[i]:
            i += 1
            continue
        j = i
        while j + 1 < len(segs) and affected[j + 1]:
            j += 1
        lo, hi = segs[i]
        if hi is None:
            start, si = points[lo], True
        elif lo == NEG_INF:
            start, si = None, True
        else:
            start, si = points[lo], False
        lo2, hi2 = segs[j]
        if hi2 is None:
            end, ei = points[lo2], True
        elif hi2 == POS_INF:
            end, ei = None, False
        else:
            end, ei = points[hi2], False
        start_s = start.raw if start else None
        end_s = end.raw if end else None
        if start is not None and "*" in start.raw:  # after "4.19.*" means from 4.20 on
            start_s, si = _star_to_exclusive(start), True
        if end is not None and "*" in end.raw:
            end_s, ei = _star_to_exclusive(end), False
        ranges.append(Range(start_s, si, end_s, ei))
        i = j + 1
    return ranges


def in_ranges(ranges: list[Range], version: str) -> bool:
    return any(r.contains(version) for r in ranges)


def range_overlap(a: list[Range], b: list[Range]) -> float:
    """Jaccard agreement of two range sets over the segments their boundaries induce (1.0 = same set)."""
    pts: dict[tuple, str] = {}
    for r in (*a, *b):
        for v in (r.start, r.end):
            if v is not None:
                pts.setdefault(version_key(v), v)
    keys = sorted(pts)
    if not keys:
        return 1.0 if bool(a) == bool(b) else 0.0
    probes: list[tuple] = []
    prev = NEG_INF
    for k in keys:
        probes.append((prev, k))
        probes.append((k, None))
        prev = k
    probes.append((prev, POS_INF))

    def covers(r: Range, lo, hi) -> bool:
        s = version_key(r.start) if r.start is not None else NEG_INF
        e = version_key(r.end) if r.end is not None else POS_INF
        if hi is None:
            return (lo > s or (lo == s and r.start_inclusive)) and (lo < e or (lo == e and r.end_inclusive))
        return s <= lo and hi <= e

    inter = union = 0
    for lo, hi in probes:
        x = any(covers(r, lo, hi) for r in a)
        y = any(covers(r, lo, hi) for r in b)
        inter += x and y
        union += x or y
    return inter / union if union else 1.0


def same_ranges(a: list[Range], b: list[Range]) -> bool:
    return range_overlap(a, b) == 1.0 and bool(a) == bool(b)
