"""Registrable domain (eTLD+1) with a small built-in suffix list.

This is not the full Public Suffix List: it knows the common two-label
country suffixes (co.uk, com.au, on.ca, ...) and a few shared hosting
domains where every subdomain belongs to a different owner (github.io,
netlify.app, ...). Anything else is treated as a one-label suffix.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

MULTI_LABEL_SUFFIXES = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk net.uk ltd.uk plc.uk
    com.au net.au org.au edu.au gov.au
    co.nz org.nz net.nz govt.nz
    co.jp ne.jp or.jp ac.jp
    com.br net.br org.br gov.br
    com.mx org.mx gob.mx
    co.za org.za gov.za
    co.in net.in org.in gov.in
    com.cn net.cn org.cn gov.cn
    com.ar com.co com.pe com.tr com.sg com.hk com.tw com.my
    co.kr co.il co.id co.th
    ab.ca bc.ca mb.ca nb.ca nl.ca ns.ca nt.ca nu.ca on.ca pe.ca qc.ca sk.ca yk.ca gc.ca
    github.io gitlab.io netlify.app vercel.app pages.dev workers.dev
    herokuapp.com web.app firebaseapp.com appspot.com azurewebsites.net
    cloudfront.net blogspot.com onrender.com fly.dev
    """.split()
)


def host_of(url: str) -> str:
    """Lower-case host of a URL, without port or trailing dot."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def registrable_domain(host: str) -> str:
    """Return the registrable domain of ``host`` ('' for an empty host).

    IP addresses and single-label hosts (localhost) are returned unchanged.
    """
    host = host.rstrip(".").lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return host
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(n + 1):])
        if len(labels) == n and ".".join(labels) in MULTI_LABEL_SUFFIXES:
            return host
    return ".".join(labels[-2:])


def same_site(url_a: str, url_b: str) -> bool:
    """True when both URLs share a registrable domain."""
    a = registrable_domain(host_of(url_a))
    return bool(a) and a == registrable_domain(host_of(url_b))


def origin_of(url: str) -> str:
    """scheme://host[:port] of a URL ('' when it has no network origin)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc.lower()}"
