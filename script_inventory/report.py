"""Markdown and JSON rendering."""

from __future__ import annotations

import json

from . import __version__
from .analyze import PageReport, severity_rank


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _short(url: str, limit: int = 90) -> str:
    if len(url) <= limit:
        return url
    keep = (limit - 3) // 2
    return url[:keep] + "..." + url[-keep:]


def _size(n: int | None) -> str:
    return "-" if n is None else f"{n:,} B"


def _load(s) -> str:
    if s.inline and not s.module:
        return "-"
    if not s.in_dom:
        return "?"
    parts = [p for p, on in (("module", s.module), ("async", s.is_async), ("defer", s.defer),
                             ("nomodule", s.nomodule)) if on]
    return ", ".join(parts) or "blocking"


def _libs(s) -> str:
    return ", ".join(f"{l.name} {l.version or '?'}" for l in s.libraries) or "-"


def _sri(s) -> str:
    if s.inline:
        return "-"
    return s.sri


def count_at_or_above(pages: list[PageReport], threshold: str) -> int:
    if threshold == "none":
        return 0
    rank = severity_rank(threshold)
    return sum(1 for p in pages for f in p.findings if severity_rank(f.severity) >= rank)


def render_markdown(pages: list[PageReport], fail_on: str = "high") -> str:
    lines = ["# Script inventory", ""]
    for p in pages:
        lines.append(f"## {p.url}")
        lines.append("")
        if p.final_url != p.url:
            lines.append(f"Final URL: {p.final_url}  ")
        status = f"HTTP {p.status}" if p.status is not None else "no response"
        if p.error:
            lines.append(f"**Error:** {p.error} ({status})")
            lines.append("")
            if not p.scripts:
                continue
        first = sum(1 for s in p.scripts if s.party == "first")
        inline = sum(1 for s in p.scripts if s.inline)
        runtime = sum(1 for s in p.scripts if s.loaded_by == "runtime")
        total = sum(s.size or 0 for s in p.scripts)
        frames = len(p.frames.get("inspected", [])) - 1
        summary = (f"{status}. {len(p.scripts)} script(s): {first} first-party ({inline} inline), "
                   f"{len(p.scripts) - first} third-party; {runtime} added at runtime; {total:,} bytes of script")
        if frames > 0:
            summary += f"; {frames} same-origin iframe(s) inspected"
        skipped = len(p.frames.get("skipped_cross_origin", []))
        if skipped:
            summary += f"; {skipped} cross-origin iframe(s) not inspected"
        lines += [summary + ".", ""]

        lines += ["### Scripts", "",
                  "| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for i, s in enumerate(p.scripts, 1):
            name = "inline" if s.inline else _short(s.url)
            if not s.main_frame:
                name += " (iframe)"
            if not s.in_dom:
                name += " (network only)"
            lines.append("| " + " | ".join(_cell(c) for c in (
                i, name, s.party, s.vendor or "-", _size(s.size), _load(s), s.loaded_by, _sri(s),
                s.crossorigin if s.crossorigin is not None else "-", _libs(s))) + " |")
        lines.append("")

        lines += ["### Libraries", ""]
        if p.libraries:
            lines += ["| Library | Version | Found via | Advisories |", "|---|---|---|---|"]
            for lib in p.libraries:
                adv = ", ".join(f"[{a['id']}]({a['references'][0]})" if a["references"] else a["id"]
                                for a in lib.advisories) or "none known"
                lines.append(f"| {_cell(lib.name)} | {_cell(lib.version or '?')} | {', '.join(lib.via)} | {adv} |")
        else:
            lines.append("No known library detected.")
        lines.append("")

        lines += ["### Mixed content", ""]
        if p.mixed_content:
            for m in p.mixed_content:
                lines.append(f"- {'active' if m['active'] else 'passive'} ({m['element']}): {m['url']}")
        elif p.final_url.startswith("https:"):
            lines.append("None: no http: subresources.")
        else:
            lines.append("Not applicable: the page itself is not served over HTTPS.")
        lines.append("")

        inl = p.inline
        lines += ["### Inline scripts and CSP", "",
                  f"- Inline scripts: {inl.get('count', 0)} ({inl.get('with_nonce', 0)} with a nonce); "
                  f"elements with inline event handlers: {inl.get('event_handler_elements', 0)}; "
                  f"non-executed data blocks (JSON-LD etc.): {inl.get('data_blocks', 0)}",
                  f"- {inl.get('hint', '')}"]
        if inl.get("csp_script_src"):
            lines.append(f"- Script sources allowed by the CSP: `{inl['csp_script_src']}`")
        lines.append("")

        lines += ["### Findings", ""]
        if p.findings:
            for f in p.findings:
                where = f" `{_short(f.url, 120)}`" if f.url and f.url != p.url else ""
                refs = " " + " ".join(f"<{r}>" for r in f.references) if f.references else ""
                lines.append(f"- **{f.severity.upper()}** {f.kind}: {f.message}{where}{refs}")
        else:
            lines.append("None.")
        lines.append("")

    n = count_at_or_above(pages, fail_on)
    tail = f"{len(pages)} page(s); " + (
        f"{n} finding(s) at or above '{fail_on}'." if fail_on != "none" else "--fail-on none.")
    lines.append(tail)
    return "\n".join(lines) + "\n"


def render_json(pages: list[PageReport], fail_on: str = "high") -> str:
    doc = {
        "tool": "script-inventory",
        "version": __version__,
        "fail_on": fail_on,
        "findings_at_or_above": count_at_or_above(pages, fail_on),
        "pages": [p.to_dict() for p in pages],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
