"""Loose semantic version parsing and range checks."""

from __future__ import annotations

import re

_VERSION = re.compile(r"^\s*v?(\d+(?:\.\d+)*)(?:[-+.]?([0-9A-Za-z][0-9A-Za-z.-]*))?\s*$")


def parse_version(text: str) -> tuple | None:
    """Sortable key for ``text`` ('3.5.0', 'v1.8.2', '4.0.0-beta.2').

    Pre-releases sort before the release. Returns None when unparsable.
    """
    m = _VERSION.match(text or "")
    if not m:
        return None
    nums = [int(p) for p in m.group(1).split(".")]
    nums += [0] * (3 - len(nums))
    pre = m.group(2)
    tail = (1, "") if not pre else (0, pre.lower())
    return (tuple(nums), tail)


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1. Raises ValueError for unparsable input."""
    ka, kb = parse_version(a), parse_version(b)
    if ka is None or kb is None:
        raise ValueError(f"cannot compare {a!r} and {b!r}")
    na, nb = ka[0], kb[0]
    width = max(len(na), len(nb))
    na += (0,) * (width - len(na))
    nb += (0,) * (width - len(nb))
    ka, kb = (na, ka[1]), (nb, kb[1])
    return (ka > kb) - (ka < kb)


def in_range(version: str, introduced: str | None = None, fixed: str | None = None) -> bool:
    """True when ``introduced <= version < fixed`` (missing bounds are open)."""
    if parse_version(version) is None:
        return False
    if introduced and compare_versions(version, introduced) < 0:
        return False
    if fixed and compare_versions(version, fixed) >= 0:
        return False
    return True
