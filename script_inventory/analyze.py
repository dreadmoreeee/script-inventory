"""Turn raw browser observations into a report with findings."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin

from . import detect, kb, sri
from .domains import host_of, registrable_domain

SEVERITIES = ("info", "low", "medium", "high", "critical")

# <script type> values that browsers execute as classic scripts.
JS_TYPES = {
    "", "text/javascript", "application/javascript", "application/ecmascript",
    "application/x-ecmascript", "application/x-javascript", "text/ecmascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2", "text/javascript1.3",
    "text/javascript1.4", "text/javascript1.5", "text/jscript", "text/livescript",
    "text/x-ecmascript", "text/x-javascript",
}
ACTIVE_TAGS = {"script", "iframe", "frame", "embed", "object", "stylesheet", "xhr", "fetch",
               "document", "websocket", "eventsource"}
# Chromium request failure codes worth spelling out.
FAILURE_REASONS = {
    "csp": "blocked by the page's Content-Security-Policy",
    "mixed-content": "blocked as mixed content",
    "net::ERR_BLOCKED_BY_CLIENT": "blocked by the browser",
}
TRUSTWORTHY_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def is_executable_type(type_attr: str | None) -> bool:
    t = (type_attr or "").strip().lower()
    return t in JS_TYPES or t == "module"


@dataclass
class Library:
    name: str
    version: str | None
    via: list[str] = field(default_factory=list)


@dataclass
class Script:
    url: str | None  # None for inline scripts
    frame_url: str = ""
    main_frame: bool = True
    party: str = "first"
    domain: str = ""
    vendor: str | None = None
    category: str | None = None
    size: int | None = None
    status: int | None = None
    type: str | None = None
    is_async: bool = False
    defer: bool = False
    module: bool = False
    nomodule: bool = False
    integrity: str | None = None
    sri: str = sri.ABSENT
    sri_detail: str = ""
    crossorigin: str | None = None
    nonce: bool = False
    in_dom: bool = True
    loaded_by: str = "unknown"  # html | runtime | unknown
    libraries: list[Library] = field(default_factory=list)
    sha256: str | None = None  # CSP hash source for inline scripts
    error: str | None = None

    @property
    def inline(self) -> bool:
        return self.url is None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["async"] = d.pop("is_async")
        d["url"] = self.url or "inline"
        d["inline"] = self.inline
        return d


@dataclass
class LibraryReport:
    name: str
    version: str | None
    via: list[str]
    scripts: list[str]
    advisories: list[dict]


@dataclass
class Finding:
    severity: str
    kind: str
    message: str
    url: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class PageReport:
    url: str
    final_url: str
    status: int | None
    error: str | None
    scripts: list[Script] = field(default_factory=list)
    libraries: list[LibraryReport] = field(default_factory=list)
    mixed_content: list[dict] = field(default_factory=list)
    inline: dict = field(default_factory=dict)
    frames: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scripts"] = [s.to_dict() for s in self.scripts]
        return d

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)


class _StaticScripts(HTMLParser):
    """Script srcs and inline bodies present in the HTML as served."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.srcs: list[str] = []
        self.inline: list[str] = []
        self._raw_srcs: list[str] = []
        self._in_script = False
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "base" and a.get("href") and self.base_url:
            self.base_url = urljoin(self.base_url, a["href"])
        elif tag == "script":
            if a.get("src"):
                self._raw_srcs.append(a["src"].strip())
            else:
                self._in_script = True
                self._text = []

    def handle_data(self, data):
        if self._in_script:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            self.inline.append("".join(self._text).strip())

    def close(self):
        super().close()
        self.srcs = [urljoin(self.base_url, s) for s in self._raw_srcs]


def static_scripts(html: str, url: str) -> tuple[set[str], set[str]]:
    p = _StaticScripts(url)
    p.feed(html)
    p.close()
    return set(p.srcs), set(p.inline)


def _csp_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _add_libs(script: Script, hits, via: str) -> None:
    for name, version in hits:
        for lib in script.libraries:
            if lib.name == name and (lib.version == version or version is None or lib.version is None):
                if lib.version is None and version:
                    lib.version = version
                if via not in lib.via:
                    lib.via.append(via)
                break
        else:
            script.libraries.append(Library(name, version, [via]))


def build_report(raw: dict) -> PageReport:
    page_url = raw.get("final_url") or raw["url"]
    page_site = registrable_domain(host_of(page_url))
    report = PageReport(url=raw["url"], final_url=page_url, status=raw.get("status"), error=raw.get("error"))

    static: dict[str, tuple[set[str], set[str]]] = {}
    for doc_url, html in (raw.get("documents") or {}).items():
        static[doc_url] = static_scripts(html, doc_url)

    net_by_url: dict[str, dict] = {}
    for n in raw.get("network") or []:
        for u in n.get("chain") or [n["url"]]:
            net_by_url.setdefault(u, n)
    used: set[int] = set()

    inline_count = with_nonce = handlers = js_urls = data_blocks = 0
    csp_meta: list[str] = []
    all_globals: list[tuple[dict, str]] = []

    for frame in raw.get("frames") or []:
        dom = frame.get("dom")
        if not dom:
            continue
        frame_url = frame.get("url") or dom.get("url") or ""
        main = bool(frame.get("main", True))
        handlers += dom.get("handlers", 0)
        js_urls += dom.get("jsUrls", 0)
        csp_meta += dom.get("cspMeta") or []
        all_globals.append((frame.get("globals") or {}, frame_url))
        known = static.get(urldefrag(frame_url)[0])
        for el in dom.get("scripts") or []:
            type_attr = el.get("type")
            if not is_executable_type(type_attr):
                data_blocks += 1
                continue
            s = Script(
                url=el.get("src"),
                frame_url=frame_url,
                main_frame=main,
                type=type_attr,
                is_async=bool(el.get("async")),
                defer=bool(el.get("defer")),
                module=(type_attr or "").strip().lower() == "module",
                nomodule=bool(el.get("nomodule")),
                integrity=el.get("integrity"),
                crossorigin=el.get("crossorigin"),
                nonce=bool(el.get("nonce")),
            )
            if s.url is None:
                text = el.get("text") or ""
                inline_count += 1
                with_nonce += s.nonce
                s.size = len(text.encode("utf-8"))
                s.sha256 = _csp_hash(text)
                s.domain = page_site
                if known is not None:
                    s.loaded_by = "html" if text.strip() in known[1] else "runtime"
                _add_libs(s, detect.from_body(text), "banner")
            else:
                n = net_by_url.get(s.url)
                if n is not None:
                    used.add(id(n))
                if known is not None:
                    s.loaded_by = "html" if s.url in known[0] else "runtime"
                _fill_from_network(s, n)
            report.scripts.append(s)

    for n in raw.get("network") or []:
        if id(n) in used:
            continue
        original = (n.get("chain") or [n["url"]])[-1]
        s = Script(url=original, frame_url=n.get("frame_url") or page_url, in_dom=False)
        s.main_frame = s.frame_url == page_url
        in_html = any(original in v[0] or n["url"] in v[0] for v in static.values())
        s.loaded_by = "html" if in_html else "runtime"
        _fill_from_network(s, n)
        report.scripts.append(s)

    for s in report.scripts:
        if s.url is None:
            s.party = "first"
            continue
        host = host_of(s.url)
        s.domain = registrable_domain(host)
        s.party = "first" if s.domain and s.domain == page_site else "third"
        vendor = kb.lookup_vendor(host)
        if vendor:
            s.vendor = vendor["vendor"]
            s.category = vendor.get("category")

    report.libraries = _aggregate_libraries(report.scripts, all_globals)
    report.mixed_content = find_mixed_content(page_url, raw.get("frames") or [], raw.get("requests") or [])

    headers = raw.get("headers") or {}
    csp = headers.get("content-security-policy")
    report.inline = {
        "count": inline_count,
        "with_nonce": with_nonce,
        "event_handler_elements": handlers,
        "javascript_urls": js_urls,
        "data_blocks": data_blocks,
        "csp_header": csp,
        "csp_meta": csp_meta,
        "csp_script_src": script_sources([csp, *csp_meta]),
        "hint": csp_hint(inline_count, with_nonce, handlers, js_urls, csp, csp_meta),
    }
    report.frames = {
        "inspected": [f.get("url") for f in raw.get("frames") or []],
        "skipped_cross_origin": list(raw.get("skipped_frames") or []),
    }
    report.findings = compute_findings(report)
    return report


def _fill_from_network(s: Script, n: dict | None) -> None:
    if n is None:
        s.sri, s.sri_detail = sri.check_integrity(s.integrity, None)
        if s.sri == sri.UNVERIFIED:
            s.sri_detail = "no response seen for this script"
        detect_hits = detect.from_url(s.url)
        _add_libs(s, detect_hits, "url")
        return
    body = n.get("body")
    s.status = n.get("status")
    if n.get("failed"):
        reason = n.get("body_error") or "request failed"
        s.error = FAILURE_REASONS.get(reason, reason)
    elif s.status is not None and s.status >= 400:
        s.error = f"HTTP {s.status}"
    if body is not None:
        s.size = len(body)
    s.sri, s.sri_detail = sri.check_integrity(s.integrity, body)
    if s.sri == sri.UNVERIFIED and n.get("body_error"):
        s.sri_detail = f"body not available: {n['body_error']}"
    for u in dict.fromkeys([s.url, n["url"]]):
        _add_libs(s, detect.from_url(u), "url")
    if body:
        _add_libs(s, detect.from_body(body.decode("utf-8", "replace")), "banner")


def _aggregate_libraries(scripts: list[Script], all_globals) -> list[LibraryReport]:
    agg: dict[tuple, LibraryReport] = {}
    order: list[tuple] = []

    def add(name, version, via, where):
        key = (name, version)
        if key not in agg:
            agg[key] = LibraryReport(name, version, [], [], [])
            order.append(key)
        lr = agg[key]
        for v in via:
            if v not in lr.via:
                lr.via.append(v)
        if where and where not in lr.scripts:
            lr.scripts.append(where)

    global_versions: dict[str, set[str]] = {}
    for globs, _frame in all_globals:
        for name, version in globs.items():
            global_versions.setdefault(name, set()).add(version)

    for s in scripts:
        for lib in s.libraries:
            if lib.version is None and len(global_versions.get(lib.name, ())) == 1:
                lib.version = next(iter(global_versions[lib.name]))
                lib.via.append("global")
            elif lib.version and lib.version in global_versions.get(lib.name, ()):
                if "global" not in lib.via:
                    lib.via.append("global")
            add(lib.name, lib.version, lib.via, s.url or "inline")

    for name, versions in global_versions.items():
        for version in sorted(versions):
            if (name, version) not in agg:
                add(name, version, ["global"], None)

    # Drop versionless entries when the same library is known with a version.
    out = []
    for key in order:
        lr = agg[key]
        if lr.version is None and any(k[0] == lr.name and k[1] for k in order):
            continue
        lr.advisories = [a.to_dict() for a in kb.advisories_for(lr.name, lr.version)]
        out.append(lr)
    return out


def find_mixed_content(page_url: str, frames: list[dict], requests: list[dict]) -> list[dict]:
    """http: subresources referenced or requested by an https page."""
    if not page_url.lower().startswith("https:"):
        return []
    out: dict[str, dict] = {}

    def consider(url: str, tag: str):
        if not url or not url.lower().startswith("http:"):
            return
        if host_of(url) in TRUSTWORTHY_HOSTS:
            return
        if url not in out:
            out[url] = {"url": url, "element": tag, "active": tag in ACTIVE_TAGS}

    for frame in frames:
        for r in (frame.get("dom") or {}).get("resources") or []:
            tag = r.get("tag", "")
            if tag == "link":
                rel = r.get("rel", "")
                tag = "stylesheet" if "stylesheet" in rel else ("script" if "modulepreload" in rel else "link")
            consider(r.get("url", ""), tag)
    for r in requests:
        rt = r.get("resource_type", "other")
        consider(r.get("url", ""), {"image": "img", "media": "video"}.get(rt, rt))
    return list(out.values())


_SCRIPT_SRC = re.compile(r"(?:^|;)\s*(script-src-elem|script-src|default-src)\s+([^;]*)", re.I)


def script_sources(policies: list[str | None]) -> str | None:
    """Effective script source list: script-src-elem, else script-src, else default-src."""
    sources = None
    for p in policies:
        if not p:
            continue
        found = {m.group(1).lower(): m.group(2).strip() for m in _SCRIPT_SRC.finditer(p)}
        sources = found.get("script-src-elem") or found.get("script-src") or found.get("default-src") or sources
    return sources


def csp_hint(inline: int, with_nonce: int, handlers: int, js_urls: int,
             csp_header: str | None, csp_meta: list[str] | None = None) -> str:
    """One-paragraph advice on what a strict CSP would need for this page."""
    policies = [p for p in [csp_header, *(csp_meta or [])] if p]
    parts = []
    if not policies:
        parts.append("No Content-Security-Policy.")
    else:
        sources = (script_sources(policies) or "").lower()
        if not sources:
            parts.append("CSP present without script-src or default-src (scripts unrestricted).")
        elif "'unsafe-inline'" in sources and not re.search(r"'(nonce-|sha(256|384|512)-|strict-dynamic)", sources):
            parts.append("CSP allows 'unsafe-inline' for scripts, which disables inline-script protection.")
        elif "'nonce-" in sources or "'sha" in sources or "'strict-dynamic'" in sources:
            parts.append("CSP uses nonces/hashes for scripts.")
        else:
            parts.append("CSP restricts scripts.")
    if inline == 0 and handlers == 0 and js_urls == 0:
        parts.append("No inline scripts or inline event handlers: a strict CSP needs no nonces or hashes for inline code.")
        return " ".join(parts)
    if inline:
        parts.append(
            f"{inline} inline script(s) ({with_nonce} with a nonce): a strict CSP without 'unsafe-inline' "
            "needs a nonce or a 'sha256-...' hash for each (hashes are in the JSON output)."
        )
    if handlers:
        parts.append(
            f"{handlers} element(s) use inline event handlers (onclick=...): nonces do not cover them; "
            "move them to addEventListener."
        )
    if js_urls:
        parts.append(f"{js_urls} javascript: link(s) are also blocked by a strict CSP.")
    return " ".join(parts)


def compute_findings(report: PageReport) -> list[Finding]:
    out: list[Finding] = []
    if report.error:
        out.append(Finding("info", "page-error", f"page did not load cleanly: {report.error}", report.url))
    for lib in report.libraries:
        label = f"{lib.name} {lib.version}"
        where = lib.scripts[0] if lib.scripts else "window global"
        for a in lib.advisories:
            if a["kind"] == "eol":
                out.append(Finding("medium", "eol-library", f"{label}: {a['summary']}", where, a["references"]))
            else:
                out.append(Finding("high", "vulnerable-library", f"{label}: {a['id']} {a['summary']}",
                                   where, a["references"]))
    for s in report.scripts:
        if s.inline:
            continue
        vendor = kb.lookup_vendor(host_of(s.url)) or {}
        if vendor.get("risk"):
            out.append(Finding("critical", "risky-host", f"{vendor['vendor']}: {vendor['risk']}", s.url,
                               list(vendor.get("references", []))))
        if s.sri == sri.INVALID:
            out.append(Finding("high", "sri-invalid",
                               f"integrity does not match the served file ({s.sri_detail}); the browser refuses to run it",
                               s.url))
        elif s.sri == sri.MALFORMED:
            out.append(Finding("low", "sri-malformed", s.sri_detail, s.url))
        if s.integrity and s.crossorigin is None and s.party == "third":
            out.append(Finding("medium", "sri-no-crossorigin",
                               "integrity on a cross-origin script without a crossorigin attribute: "
                               "the check cannot pass and the script is blocked", s.url))
        if s.sri == sri.ABSENT and s.party == "third" and vendor.get("cdn"):
            out.append(Finding("low", "sri-missing",
                               f"file from a public CDN ({vendor['vendor']}) without Subresource Integrity", s.url))
        if s.error:
            out.append(Finding("low", "script-error", f"script did not load: {s.error}", s.url))
    for m in report.mixed_content:
        kind = "active" if m["active"] else "passive"
        out.append(Finding("high" if m["active"] else "medium", "mixed-content",
                           f"{kind} mixed content ({m['element']}) over http: on an https page", m["url"]))
    inl = report.inline
    if inl.get("count") or inl.get("event_handler_elements"):
        out.append(Finding("info", "inline-scripts", inl.get("hint", "")))
    out.sort(key=lambda f: -severity_rank(f.severity))
    return out
