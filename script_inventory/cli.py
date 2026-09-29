"""Command line: python -m script_inventory URL [URL ...]"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlsplit

from . import __version__
from .analyze import SEVERITIES, build_report
from .collect import DEFAULT_USER_AGENT, collect
from .report import count_at_or_above, render_json, render_markdown

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="script-inventory",
        description="Inventory every script a page runs (headless Chromium): party, vendor, size, "
                    "SRI, libraries and known-vulnerable versions, mixed content, inline scripts.",
    )
    p.add_argument("urls", nargs="+", metavar="URL", help="http(s) page(s) to load")
    p.add_argument("--format", choices=("markdown", "json"), default="markdown")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report here instead of stdout")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="high",
                   help="exit 1 when a finding has this severity or worse (default: high)")
    p.add_argument("--timeout", type=float, default=30.0, help="page load timeout in seconds (default 30)")
    p.add_argument("--settle", type=float, default=3.0,
                   help="seconds to wait after load for runtime-injected scripts (default 3)")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between pages (default 1)")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    for url in args.urls:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            parser.error(f"not an http(s) URL: {url}")
    if args.timeout <= 0 or args.settle < 0 or args.delay < 0:
        parser.error("--timeout must be > 0; --settle and --delay must be >= 0")

    pages = []
    try:
        for raw in collect(args.urls, user_agent=args.user_agent, timeout=args.timeout,
                           settle=args.settle, delay=args.delay):
            pages.append(build_report(raw))
    except Exception as exc:  # browser missing or crashed
        print(f"script-inventory: browser error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    render = render_json if args.format == "json" else render_markdown
    text = render(pages, args.fail_on)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    for p in pages:
        if p.error:
            print(f"script-inventory: {p.url}: {p.error}", file=sys.stderr)
    if any(p.error for p in pages):
        return EXIT_ERROR
    return EXIT_FINDINGS if count_at_or_above(pages, args.fail_on) else EXIT_OK
