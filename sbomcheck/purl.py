"""Package URL parsing and per-ecosystem canonicalization.

Two PURLs that name the same artifact must compare equal after canonicalization:

* type is case-insensitive (``pkg:PyPI/...`` == ``pkg:pypi/...``)
* PyPI names follow PEP 503 (lowercase, runs of ``-``, ``_`` and ``.`` collapse to ``-``)
  and versions follow PEP 440 normalization and zero padding (``1.0.0-RC1`` == ``1.0rc1``)
* npm scopes are lowercase and always carry the ``@``; package names keep their case,
  because the npm registry treats ``JSONStream`` and ``jsonstream`` as different packages
* Maven groupId/artifactId are case-sensitive; ``type=jar`` is the default and is dropped
* qualifier keys are lowercased and sorted, empty values are dropped, and only qualifiers
  that change the artifact (``classifier``, non-default ``type``) take part in identity
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

# Qualifiers that change which artifact is meant; everything else (repository_url,
# download_url, checksums, tool-specific ids such as syft's package-id) is metadata.
IDENTITY_QUALIFIERS = {"classifier", "type"}
DEFAULT_QUALIFIERS = {"maven": {"type": "jar"}}


class PurlError(ValueError):
    pass


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None = None
    qualifiers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    subpath: str | None = None

    def to_string(self) -> str:
        parts = [f"pkg:{self.type}/"]
        if self.namespace:
            parts.append("/".join(quote(seg, safe="") for seg in self.namespace.split("/")) + "/")
        parts.append(quote(self.name, safe=""))
        if self.version:
            parts.append("@" + quote(self.version, safe="+"))
        if self.qualifiers:
            parts.append("?" + "&".join(f"{k}={quote(v, safe='/:')}" for k, v in self.qualifiers))
        if self.subpath:
            parts.append("#" + self.subpath)
        return "".join(parts)

    __str__ = to_string


def parse(text: str) -> Purl:
    """Parse a PURL string without normalizing it."""
    if not text or not text.startswith("pkg:"):
        raise PurlError(f"not a package URL: {text!r}")
    rest = text[4:].lstrip("/")
    subpath = None
    if "#" in rest:
        rest, subpath = rest.split("#", 1)
        subpath = subpath.strip("/") or None
    qualifiers: list[tuple[str, str]] = []
    if "?" in rest:
        rest, query = rest.split("?", 1)
        for pair in query.split("&"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            qualifiers.append((key, unquote(value)))
    if "/" not in rest:
        raise PurlError(f"package URL has no name: {text!r}")
    ptype, rest = rest.split("/", 1)
    rest = rest.strip("/")
    version = None
    # the version separator is the last '@' that is not the leading '@' of an npm scope
    at = rest.rfind("@")
    if at > 0 and rest[at - 1] != "/":
        rest, version = rest[:at], unquote(rest[at + 1:])
    segments = [unquote(s) for s in rest.split("/") if s]
    if not segments:
        raise PurlError(f"package URL has no name: {text!r}")
    namespace = "/".join(segments[:-1]) or None
    return Purl(ptype, namespace, segments[-1], version or None, tuple(qualifiers), subpath)


def pep503_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_PEP440 = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$",
    re.IGNORECASE,
)
_PRE = {"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}


def pep440_version(version: str) -> str:
    """Normalize a PEP 440 version string; return it unchanged when it is not PEP 440."""
    m = _PEP440.match(version)
    if not m:
        return version
    out = ""
    if m["epoch"] and int(m["epoch"]) != 0:
        out += f"{int(m['epoch'])}!"
    out += ".".join(str(int(p)) for p in m["release"].split("."))
    if m["pre_l"]:
        out += _PRE[m["pre_l"].lower()] + str(int(m["pre_n"] or 0))
    if m["post_n1"] or m["post_l"]:
        out += ".post" + str(int(m["post_n1"] or m["post_n2"] or 0))
    if m["dev_l"]:
        out += ".dev" + str(int(m["dev_n"] or 0))
    if m["local"]:
        out += "+" + re.sub(r"[-_]", ".", m["local"].lower())
    return out


def pep440_identity(version: str) -> str:
    """PEP 440 normalized version with trailing zero release segments removed (1.0.0 == 1.0 == 1)."""
    norm = pep440_version(version)
    m = re.match(r"^((?:\d+!)?)(\d+(?:\.\d+)*)(.*)$", norm)
    if not m or norm == version and not _PEP440.match(version):
        return norm
    release = m.group(2).split(".")
    while len(release) > 1 and release[-1] == "0":
        release.pop()
    return m.group(1) + ".".join(release) + m.group(3)


def canonicalize(p: Purl | str) -> Purl:
    """Return the canonical form of a PURL (see module docstring for the rules)."""
    if isinstance(p, str):
        p = parse(p)
    ptype = p.type.lower()
    namespace, name, version = p.namespace, p.name, p.version
    if ptype == "pypi":
        namespace = None
        name = pep503_name(name)
        version = pep440_identity(version) if version else None
    elif ptype == "npm":
        if namespace:
            namespace = "@" + namespace.lstrip("@").lower()
        if version and version[:1] in "vV" and version[1:2].isdigit():
            version = version[1:]
    elif ptype in ("github", "bitbucket", "golang"):
        namespace = namespace.lower() if namespace else None
        if ptype != "golang":
            name = name.lower()
    defaults = DEFAULT_QUALIFIERS.get(ptype, {})
    quals = {}
    for key, value in p.qualifiers:
        key = key.lower()
        if value and defaults.get(key) != value:
            quals[key] = value
    return Purl(ptype, namespace or None, name, version or None, tuple(sorted(quals.items())), None)


def identity(p: Purl | str) -> str:
    """Canonical comparison key: type/namespace/name@version plus identity qualifiers only."""
    c = canonicalize(p)
    quals = tuple((k, v) for k, v in c.qualifiers if k in IDENTITY_QUALIFIERS)
    return Purl(c.type, c.namespace, c.name, c.version, quals).to_string()


def package_key(p: Purl | str) -> str:
    """Canonical key without the version: used to pair up version disagreements."""
    c = canonicalize(p)
    return Purl(c.type, c.namespace, c.name).to_string()


def raw_identity(p: Purl | str) -> str:
    """Identity of a PURL as written (no normalization beyond dropping non-identity qualifiers)."""
    if isinstance(p, str):
        p = parse(p)
    quals = tuple((k, v) for k, v in p.qualifiers if k.lower() in IDENTITY_QUALIFIERS)
    return Purl(p.type, p.namespace, p.name, p.version, quals).to_string()
