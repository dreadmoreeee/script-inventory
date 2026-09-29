import json

from script_inventory.analyze import build_report, csp_hint, find_mixed_content
from script_inventory.report import count_at_or_above, render_json, render_markdown
from script_inventory.sri import sri_hash

PAGE = "https://shop.example.com/"
JQ = b"/*! jQuery v3.4.1 | (c) JS Foundation */"
GTM = b"(function(){ /* tag manager */ })();"


def el(src=None, text=None, **kw):
    d = {"src": src, "type": None, "async": False, "defer": False, "nomodule": False,
         "integrity": None, "crossorigin": None, "nonce": False, "text": text}
    d.update(kw)
    return d


def raw_page(scripts, network, html="", resources=(), requests=(), globals_=None, headers=None, frames=None):
    main = {"url": PAGE, "main": True, "globals": globals_ or {},
            "dom": {"url": PAGE, "scripts": scripts, "resources": list(resources), "handlers": 0,
                    "jsUrls": 0, "cspMeta": []}}
    return {
        "url": PAGE, "final_url": PAGE, "status": 200, "error": None,
        "headers": headers or {}, "documents": {PAGE: html},
        "frames": [main] + list(frames or []), "skipped_frames": [],
        "network": network, "requests": list(requests),
    }


def net(url, body, status=200, chain=None):
    return {"url": url, "chain": chain or [url], "status": status, "frame_url": PAGE, "body": body,
            "body_error": None, "content_type": "application/javascript"}


def test_party_vendor_size_and_library():
    jq_url = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"
    gtm_url = "https://www.googletagmanager.com/gtag/js?id=G-1"
    own = "https://static.example.com/app.js"
    html = f'<script src="{jq_url}"></script><script src="{own}" defer></script>'
    r = build_report(raw_page(
        [el(jq_url), el(own, defer=True), el(gtm_url, **{"async": True})],
        [net(jq_url, JQ), net(own, b"x"), net(gtm_url, GTM)],
        html=html,
    ))
    by = {s.url: s for s in r.scripts}
    assert by[jq_url].party == "third" and by[jq_url].vendor == "cdnjs"
    assert by[own].party == "first" and by[own].domain == "example.com" and by[own].defer
    assert by[gtm_url].vendor == "Google Tag Manager" and by[gtm_url].is_async
    assert by[gtm_url].loaded_by == "runtime" and by[own].loaded_by == "html"
    assert by[jq_url].size == len(JQ)
    lib = by[jq_url].libraries[0]
    assert (lib.name, lib.version) == ("jquery", "3.4.1") and lib.via == ["url", "banner"]
    kinds = {(f.kind, f.url) for f in r.findings}
    assert ("vulnerable-library", jq_url) in kinds
    assert ("sri-missing", jq_url) in kinds  # public CDN without integrity
    assert not any(f.kind == "sri-missing" and f.url == gtm_url for f in r.findings)


def test_sri_statuses_and_crossorigin():
    good = "https://cdn.jsdelivr.net/npm/x@1.0.0/x.js"
    bad = "https://cdn.jsdelivr.net/npm/y@1.0.0/y.js"
    nocors = "https://cdn.jsdelivr.net/npm/z@1.0.0/z.js"
    r = build_report(raw_page(
        [el(good, integrity=sri_hash(b"g"), crossorigin="anonymous"),
         el(bad, integrity=sri_hash(b"other"), crossorigin="anonymous"),
         el(nocors, integrity=sri_hash(b"z"))],
        [net(good, b"g"), net(bad, b"b"), net(nocors, b"z")],
    ))
    by = {s.url: s for s in r.scripts}
    assert by[good].sri == "valid" and by[bad].sri == "invalid"
    kinds = {(f.kind, f.url, f.severity) for f in r.findings}
    assert ("sri-invalid", bad, "high") in kinds
    assert ("sri-no-crossorigin", nocors, "medium") in kinds


def test_redirected_script_is_matched_to_its_element():
    short = "https://unpkg.com/jquery"
    final = "https://unpkg.com/jquery@3.7.1/dist/jquery.js"
    r = build_report(raw_page([el(short)], [net(final, b"/*! jQuery v3.7.1 */", chain=[final, short])]))
    assert len(r.scripts) == 1
    s = r.scripts[0]
    assert s.size == len(b"/*! jQuery v3.7.1 */")
    assert [(l.name, l.version) for l in s.libraries] == [("jquery", "3.7.1")]
    assert r.libraries[0].advisories == []


def test_network_only_script_and_inline_hash():
    worker = "https://shop.example.com/sw-helper.js"
    r = build_report(raw_page([el(text="var a = 1;")], [net(worker, b"x")], html="<script>var a = 1;</script>"))
    inline = [s for s in r.scripts if s.inline][0]
    assert inline.loaded_by == "html" and inline.sha256.startswith("sha256-")
    extra = [s for s in r.scripts if not s.inline][0]
    assert extra.url == worker and not extra.in_dom and extra.loaded_by == "runtime"
    assert r.inline["count"] == 1


def test_data_blocks_are_not_counted_as_scripts():
    r = build_report(raw_page([el(text="{}", type="application/ld+json"), el(text="x()", type="module")], []))
    assert r.inline["count"] == 1 and r.inline["data_blocks"] == 1
    assert r.scripts[0].module


def test_global_fills_unknown_version_and_adds_global_only_library():
    url = "https://shop.example.com/js/jquery.min.js"
    r = build_report(raw_page([el(url)], [net(url, b"!function(){}")],
                              globals_={"jquery": "1.12.4", "moment": "2.29.4"}))
    libs = {(l.name, l.version): l for l in r.libraries}
    assert ("jquery", "1.12.4") in libs and "global" in libs[("jquery", "1.12.4")].via
    assert libs[("jquery", "1.12.4")].scripts == [url]
    assert ("moment", "2.29.4") in libs and libs[("moment", "2.29.4")].advisories == []
    assert ("jquery", None) not in libs


def test_eol_is_medium():
    r = build_report(raw_page([], [], globals_={"angularjs": "1.8.2"}))
    f = [f for f in r.findings if f.kind == "eol-library"][0]
    assert f.severity == "medium" and f.url == "window global"


def test_mixed_content():
    frames = [{"dom": {"resources": [
        {"tag": "script", "url": "http://cdn.example.net/a.js"},
        {"tag": "img", "url": "http://img.example.net/a.png"},
        {"tag": "link", "rel": "stylesheet", "url": "http://cdn.example.net/a.css"},
        {"tag": "img", "url": "https://img.example.net/ok.png"},
        {"tag": "img", "url": "http://localhost/dev.png"},
    ]}}]
    requests = [{"url": "http://api.example.net/x", "resource_type": "fetch"},
                {"url": "http://cdn.example.net/a.js", "resource_type": "script"}]
    mixed = find_mixed_content(PAGE, frames, requests)
    assert [(m["url"], m["active"]) for m in mixed] == [
        ("http://cdn.example.net/a.js", True),
        ("http://img.example.net/a.png", False),
        ("http://cdn.example.net/a.css", True),
        ("http://api.example.net/x", True),
    ]
    assert find_mixed_content("http://example.com/", frames, requests) == []


def test_mixed_content_findings_severity():
    r = build_report(raw_page([], [], resources=[{"tag": "img", "url": "http://x.example.net/a.png"},
                                                 {"tag": "iframe", "url": "http://x.example.net/f"}]))
    sev = {f.url: f.severity for f in r.findings if f.kind == "mixed-content"}
    assert sev == {"http://x.example.net/a.png": "medium", "http://x.example.net/f": "high"}


def test_risky_host_is_critical():
    url = "https://cdn.polyfill.io/v3/polyfill.min.js"
    r = build_report(raw_page([el(url)], [net(url, b"x")]))
    assert r.findings[0].severity == "critical" and r.findings[0].kind == "risky-host"


def test_csp_hint_variants():
    assert "No inline scripts" in csp_hint(0, 0, 0, 0, None)
    h = csp_hint(3, 1, 2, 1, None)
    assert "No Content-Security-Policy" in h and "3 inline script(s) (1 with a nonce)" in h
    assert "addEventListener" in h and "javascript:" in h
    assert "'unsafe-inline'" in csp_hint(1, 0, 0, 0, "default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert "nonces/hashes" in csp_hint(1, 1, 0, 0, "script-src 'nonce-abc' 'strict-dynamic'")
    assert "nonces/hashes" in csp_hint(1, 0, 0, 0, None, ["script-src 'sha256-xyz'"])


def test_render_markdown_and_json():
    url = "https://code.jquery.com/jquery-3.4.1.min.js"
    r = build_report(raw_page([el(url), el(text="x()")], [net(url, JQ)], headers={}))
    md = render_markdown([r], "high")
    assert "| jquery | 3.4.1 | url, banner |" in md
    assert "[CVE-2020-11022](https://nvd.nist.gov/vuln/detail/CVE-2020-11022)" in md
    assert "**HIGH** vulnerable-library" in md
    assert md.rstrip().endswith("finding(s) at or above 'high'.")
    doc = json.loads(render_json([r], "high"))
    page = doc["pages"][0]
    assert doc["findings_at_or_above"] == count_at_or_above([r], "high") > 0
    assert page["scripts"][0]["async"] is False and page["scripts"][1]["url"] == "inline"
    assert page["libraries"][0]["advisories"][0]["references"]


def test_thresholds():
    r = build_report(raw_page([], [], globals_={"vue": "2.7.16"}))
    assert count_at_or_above([r], "high") == 0
    assert count_at_or_above([r], "medium") == 1
    assert count_at_or_above([r], "none") == 0


def test_error_page_renders():
    raw = raw_page([], [])
    raw.update(status=None, error="net::ERR_NAME_NOT_RESOLVED", frames=[])
    r = build_report(raw)
    assert "**Error:** net::ERR_NAME_NOT_RESOLVED" in render_markdown([r])


def test_csp_blocked_script_is_reported():
    url = "https://static.cloudflareinsights.com/beacon.min.js"
    failed = {"url": url, "chain": [url], "status": None, "frame_url": None, "body": None,
              "body_error": "csp", "content_type": "", "failed": True}
    r = build_report(raw_page([el(url, integrity=sri_hash(b"b"), crossorigin="anonymous", type="module")],
                              [failed], headers={"content-security-policy": "script-src 'self'"}))
    s = r.scripts[0]
    assert s.vendor == "Cloudflare Web Analytics" and s.sri == "unverified"
    assert s.error == "blocked by the page's Content-Security-Policy"
    assert [(f.kind, f.severity) for f in r.findings] == [("script-error", "low")]
    assert r.inline["csp_script_src"] == "'self'"
    assert "`'self'`" in render_markdown([r])
