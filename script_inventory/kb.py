"""Bundled data: known script hosts and library advisories."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from .versions import in_range


def _load(name: str) -> dict:
    text = resources.files("script_inventory").joinpath("data", name).read_text(encoding="utf-8")
    return json.loads(text)


@lru_cache(maxsize=None)
def vendor_table() -> dict[str, dict]:
    return {k.lower(): v for k, v in _load("vendors.json")["hosts"].items()}


def lookup_vendor(host: str, table: dict[str, dict] | None = None) -> dict | None:
    """Vendor entry for ``host`` (exact host or any parent domain, longest key wins)."""
    table = vendor_table() if table is None else table
    host = (host or "").rstrip(".").lower()
    labels = host.split(".")
    for i in range(len(labels)):
        entry = table.get(".".join(labels[i:]))
        if entry is not None:
            return entry
    return None


@dataclass(frozen=True)
class Advisory:
    library: str
    id: str
    kind: str
    summary: str
    affected: tuple = ()
    references: tuple = field(default=())

    def matches(self, version: str) -> bool:
        return any(in_range(version, r.get("introduced"), r.get("fixed")) for r in self.affected)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "references": list(self.references),
        }


@lru_cache(maxsize=None)
def advisory_table() -> tuple[Advisory, ...]:
    out = []
    for a in _load("advisories.json")["advisories"]:
        out.append(
            Advisory(
                library=a["library"],
                id=a["id"],
                kind=a.get("kind", "vulnerability"),
                summary=a["summary"],
                affected=tuple(a.get("affected", ())),
                references=tuple(a.get("references", ())),
            )
        )
    return tuple(out)


def advisories_for(library: str, version: str | None, table=None) -> list[Advisory]:
    """Advisories that apply to ``library`` at ``version`` (none if version unknown)."""
    if not version:
        return []
    table = advisory_table() if table is None else table
    return [a for a in table if a.library == library and a.matches(version)]
