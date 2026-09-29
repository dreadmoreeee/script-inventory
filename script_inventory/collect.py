"""Load pages in headless Chromium and collect raw script data.

The collector only records what the browser saw; analysis happens in
``analyze.build_report`` so it can be tested without a browser.
"""

from __future__ import annotations

import time

from .detect import GLOBAL_PROBE_JS
from .domains import origin_of

DEFAULT_USER_AGENT = "script-inventory/1.0 (+https://github.com/dreadmoreeee/script-inventory)"
MAX_BODY = 10 * 1024 * 1024

# Evaluated in each inspected frame.
DOM_SCAN_JS = r"""
() => {
  const abs = (v) => { try { return new URL(v, document.baseURI).href; } catch (e) { return v; } };
  const scripts = [];
  for (const s of document.querySelectorAll('script')) {
    const src = s.getAttribute('src');
    scripts.push({
      src: src !== null ? abs(src) : null,
      type: s.getAttribute('type'),
      async: !!s.async,
      defer: !!s.defer,
      nomodule: s.hasAttribute('nomodule'),
      integrity: s.getAttribute('integrity'),
      crossorigin: s.getAttribute('crossorigin'),
      nonce: !!(s.nonce || s.getAttribute('nonce')),
      text: src === null ? s.textContent : null,
    });
  }
  const resources = [];
  const pick = [['script', 'src'], ['iframe', 'src'], ['frame', 'src'], ['img', 'src'],
                ['audio', 'src'], ['video', 'src'], ['source', 'src'], ['track', 'src'],
                ['embed', 'src'], ['object', 'data'], ['link', 'href']];
  for (const [tag, attr] of pick) {
    for (const el of document.querySelectorAll(tag + '[' + attr + ']')) {
      const rel = tag === 'link' ? (el.getAttribute('rel') || '').toLowerCase() : '';
      if (tag === 'link' && !/stylesheet|preload|modulepreload|icon/.test(rel)) continue;
      resources.push({tag: tag, rel: rel, url: abs(el.getAttribute(attr))});
    }
  }
  let handlers = 0;
  for (const el of document.querySelectorAll('*')) {
    for (const a of el.attributes) {
      if (a.name.startsWith('on')) { handlers++; break; }
    }
  }
  const jsUrls = document.querySelectorAll('a[href^="javascript:" i]').length;
  const cspMeta = [...document.querySelectorAll('meta[http-equiv]')]
    .filter((m) => (m.getAttribute('http-equiv') || '').toLowerCase() === 'content-security-policy')
    .map((m) => m.getAttribute('content') || '');
  return {url: location.href, scripts, resources, handlers, jsUrls, cspMeta};
}
"""


def _frame_inspectable(frame_url: str, page_origin: str) -> bool:
    if frame_url in ("about:blank", "about:srcdoc", ""):
        return True
    return origin_of(frame_url) == page_origin


def collect_page(context, url: str, timeout: float = 30.0, settle: float = 3.0) -> dict:
    """Load ``url`` in a new page of ``context`` and return raw observations."""
    raw: dict = {
        "url": url,
        "final_url": url,
        "status": None,
        "error": None,
        "headers": {},
        "documents": {},
        "frames": [],
        "skipped_frames": [],
        "network": [],
        "requests": [],
    }
    page = context.new_page()
    responses = []
    failures: dict[str, str] = {}

    page.on("response", lambda r: responses.append(r))
    page.on("request", lambda r: raw["requests"].append({"url": r.url, "resource_type": r.resource_type}))
    page.on(
        "requestfailed",
        lambda r: failures.__setitem__(r.url, r.failure or "failed") if r.resource_type == "script" else None,
    )
    try:
        try:
            main = page.goto(url, wait_until="load", timeout=timeout * 1000)
        except Exception as exc:  # navigation error, DNS, timeout
            raw["error"] = _short_error(exc)
            return raw
        if main is None:
            raw["error"] = "no response"
            return raw
        raw["status"] = main.status
        raw["final_url"] = page.url
        raw["headers"] = {k.lower(): v for k, v in main.headers.items()}
        if main.status >= 400:
            raw["error"] = f"HTTP {main.status}"
        if settle > 0:
            try:
                page.wait_for_load_state("networkidle", timeout=settle * 1000)
            except Exception:
                pass
            page.wait_for_timeout(min(500, settle * 1000))

        page_origin = origin_of(page.url)
        inspected = []
        for frame in page.frames:
            if frame is page.main_frame or _frame_inspectable(frame.url, page_origin):
                inspected.append(frame)
            else:
                raw["skipped_frames"].append(frame.url)
        for frame in inspected:
            entry = {"url": frame.url, "main": frame is page.main_frame, "dom": None, "globals": {}}
            try:
                entry["dom"] = frame.evaluate(DOM_SCAN_JS)
                entry["globals"] = frame.evaluate(GLOBAL_PROBE_JS)
            except Exception as exc:
                entry["error"] = _short_error(exc)
            raw["frames"].append(entry)
        inspected_urls = {f.url for f in inspected}

        for resp in responses:
            req = resp.request
            try:
                frame_url = resp.frame.url
            except Exception:
                frame_url = None
            if req.resource_type == "document":
                if frame_url in inspected_urls and resp.status < 300:
                    try:
                        raw["documents"][resp.url] = resp.text()
                    except Exception:
                        pass
                continue
            if req.resource_type != "script":
                continue
            if frame_url is not None and frame_url not in inspected_urls:
                continue
            chain = [resp.url]
            prev = req.redirected_from
            while prev is not None:
                chain.append(prev.url)
                prev = prev.redirected_from
            body, body_error = None, None
            try:
                body = resp.body()
                if len(body) > MAX_BODY:
                    body, body_error = None, f"body larger than {MAX_BODY} bytes"
            except Exception as exc:
                body_error = _short_error(exc)
            raw["network"].append(
                {
                    "url": resp.url,
                    "chain": chain,
                    "status": resp.status,
                    "frame_url": frame_url,
                    "body": body,
                    "body_error": body_error,
                    "content_type": resp.headers.get("content-type", ""),
                }
            )
        seen = {u for n in raw["network"] for u in n["chain"]}
        for failed_url, reason in failures.items():
            if failed_url not in seen:
                raw["network"].append(
                    {"url": failed_url, "chain": [failed_url], "status": None, "frame_url": None,
                     "body": None, "body_error": reason, "content_type": "", "failed": True}
                )
    finally:
        page.close()
    return raw


def _short_error(exc: Exception) -> str:
    text = str(exc).strip().splitlines()
    return (text[0] if text else exc.__class__.__name__)[:300]


def collect(urls, user_agent: str = DEFAULT_USER_AGENT, timeout: float = 30.0,
            settle: float = 3.0, delay: float = 1.0, headless: bool = True):
    """Yield one raw dict per URL. One browser, a fresh context per page."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        try:
            for i, url in enumerate(urls):
                if i and delay > 0:
                    time.sleep(delay)
                context = browser.new_context(user_agent=user_agent, service_workers="block")
                try:
                    yield collect_page(context, url, timeout=timeout, settle=settle)
                finally:
                    context.close()
        finally:
            browser.close()
