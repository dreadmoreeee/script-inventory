import pytest

from script_inventory.domains import host_of, origin_of, registrable_domain, same_site
from script_inventory.kb import lookup_vendor, vendor_table


@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.demarkstudio.ca", "demarkstudio.ca"),
        ("demo.demarkstudio.ca", "demarkstudio.ca"),
        ("demarkstudio.ca", "demarkstudio.ca"),
        ("shop.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("co.uk", "co.uk"),
        ("city.fredericton.nb.ca", "fredericton.nb.ca"),
        ("alice.github.io", "alice.github.io"),
        ("WWW.Example.COM.", "example.com"),
        ("localhost", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("", ""),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_same_site_and_origin():
    assert same_site("https://demarkstudio.ca/", "https://demo.demarkstudio.ca/x.js")
    assert not same_site("https://alice.github.io/", "https://bob.github.io/x.js")
    assert host_of("https://CDN.Example.com:8443/a.js") == "cdn.example.com"
    assert origin_of("https://Example.com:8443/a?b") == "https://example.com:8443"
    assert origin_of("about:blank") == ""


def test_vendor_lookup_longest_match():
    assert lookup_vendor("www.googletagmanager.com")["vendor"] == "Google Tag Manager"
    assert lookup_vendor("cdnjs.cloudflare.com")["vendor"] == "cdnjs"
    assert lookup_vendor("cdnjs.cloudflare.com")["cdn"] is True
    assert lookup_vendor("static.cloudflareinsights.com")["vendor"] == "Cloudflare Web Analytics"
    assert lookup_vendor("ajax.googleapis.com")["vendor"] == "Google Hosted Libraries"
    assert lookup_vendor("fonts.googleapis.com")["vendor"] == "Google APIs"
    assert lookup_vendor("js.stripe.com")["vendor"] == "Stripe"
    assert lookup_vendor("connect.facebook.net")["vendor"] == "Meta (Facebook)"
    assert lookup_vendor("static.hotjar.com")["vendor"] == "Hotjar"
    assert lookup_vendor("cdn.polyfill.io")["risk"]
    assert lookup_vendor("example.com") is None
    assert lookup_vendor("notstripe.com") is None


def test_vendor_table_is_well_formed():
    for host, entry in vendor_table().items():
        assert host == host.lower() and "." in host
        assert entry["vendor"] and entry["category"]
