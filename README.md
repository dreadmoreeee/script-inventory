# script-inventory

Every script a page **actually runs**, measured in headless Chromium: where it comes from, who owns it, how big it is, whether its Subresource Integrity hash really matches, and which library versions have known advisories.

```
python -m script_inventory https://example.com [more URLs] [--format json] [-o report.md] [--fail-on high]
```

Reading the HTML is not enough: tag managers, consent banners and chat widgets add scripts after load, iframes bring their own, and an `integrity=` attribute says nothing about whether the hash is right. This tool loads the page, watches the network and reads the DOM, then reports for each script:

- **URL or `inline`**, and whether it was in the HTML as served or **added at runtime**. Scripts in **same-origin iframes** are included; cross-origin iframes are listed but not inspected.
- **First or third party**, by registrable domain (`demo.demarkstudio.ca` and `demarkstudio.ca` are the same party), and the **vendor** for known hosts (Google Tag Manager, Google Analytics, cdnjs, jsDelivr, unpkg, Stripe, Cloudflare, Meta, Hotjar, HubSpot, ...), from a small bundled JSON file.
- **Size in bytes** of the body the browser received, and `async` / `defer` / `type=module` / `nomodule`.
- **SRI present and valid**: the sha256/384/512 digest of the fetched body is recomputed and compared with the `integrity` attribute (strongest algorithm wins, as in the W3C spec). The `crossorigin` attribute is shown, and integrity on a cross-origin script without `crossorigin` is flagged, because the browser blocks it.
- **Library and version** from the file name (`jquery-3.4.1.min.js`, `/npm/bootstrap@5.3.3/`, `/ajax/libs/lodash.js/4.17.15/`, `?ver=3.7.1`), banner comments (`/*! jQuery v3.4.1`), and globals probed in the page (`jQuery.fn.jquery`, `React.version`, `Vue.version`, `bootstrap.Tooltip.VERSION`, `_.VERSION`, `moment.version`, `angular.version.full`, ...).
- **Known advisories** from a small bundled table with source links: jQuery < 3.5.0 (CVE-2020-11022, CVE-2020-11023), < 3.4.0 (CVE-2019-11358), < 3.0.0 (CVE-2015-9251); Bootstrap < 3.4.1 and 4.0-4.3.0 (CVE-2019-8331); Lodash < 4.17.21 (CVE-2021-23337), < 4.17.12 (CVE-2019-10744); Moment 2.18.0-2.29.3 (CVE-2022-31129); end of life for AngularJS 1.x, Vue 2, Bootstrap 3 and 4.
- **Mixed content**: `http:` scripts, iframes, stylesheets, images and requests on an `https:` page (active or passive).
- **Inline scripts and CSP**: how many inline scripts and inline event handlers there are, what the current CSP allows, and what a strict CSP would need. The JSON output has the `'sha256-...'` hash of every inline script, ready to paste into a policy.

## Measured result

My three sites, with the default User-Agent `script-inventory/1.0 (+https://github.com/dreadmoreeee/script-inventory)`. Output trimmed where marked `[...]`; the full report is in [examples/demarkstudio-sites.md](examples/demarkstudio-sites.md) and the JSON for one page in [examples/riverside-pub.json](examples/riverside-pub.json).

```
$ python -m script_inventory https://demarkstudio.ca https://demo.demarkstudio.ca/riverside-pub/site https://marvin.demarkstudio.ca
# Script inventory

## https://demarkstudio.ca

Final URL: https://demarkstudio.ca/en/
HTTP 200. 10 script(s): 9 first-party (0 inline), 1 third-party; 0 added at runtime; 226,687 bytes of script.

### Scripts

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | https://demarkstudio.ca/static/vendor/gsap.min.js?v=fa1aeabc | first | - | 72,435 B | defer | html | absent | - | gsap 3.13.0 |
| 2 | https://demarkstudio.ca/static/vendor/ScrollTrigger.min.js?v=ecd3242f | first | - | 44,157 B | defer | html | absent | - | - |
| 3 | https://demarkstudio.ca/static/js/sitio.js?v=a856b994 | first | - | 19,865 B | defer | html | absent | - | - |
| 4 | https://demarkstudio.ca/static/js/hero.js?v=38ac7c85 | first | - | 14,385 B | defer | html | absent | - | - |
| 5 | https://demarkstudio.ca/static/js/movimiento.js?v=3b9a496e | first | - | 5,641 B | defer | html | absent | - | - |
| 6 | https://demarkstudio.ca/static/js/secciones.js?v=380cd57e | first | - | 24,255 B | defer | html | absent | - | - |
| 7 | https://demarkstudio.ca/static/js/transiciones.js?v=affc0013 | first | - | 9,690 B | defer | html | absent | - | - |
| 8 | https://demarkstudio.ca/static/js/widget.js?v=fda4fe2f | first | - | 4,726 B | defer | html | absent | - | - |
| 9 | https://static.cloudflareinsights.com/beaco...edd6df95cf4e85bb4c19e7a9bdbcba1788362987495 | third | Cloudflare Web Analytics | 30,294 B | module | html | valid | anonymous | - |
| 10 | https://demarkstudio.ca/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js (network only) | first | - | 1,239 B | ? | html | absent | - | - |

### Libraries

| Library | Version | Found via | Advisories |
|---|---|---|---|
| gsap | 3.13.0 | url, global | none known |

### Mixed content

None: no http: subresources.

### Inline scripts and CSP

- Inline scripts: 0 (0 with a nonce); elements with inline event handlers: 0; non-executed data blocks (JSON-LD etc.): 1
- CSP restricts scripts. No inline scripts or inline event handlers: a strict CSP needs no nonces or hashes for inline code.
- Script sources allowed by the CSP: `'self' https://static.cloudflareinsights.com`

### Findings

None.

## https://demo.demarkstudio.ca/riverside-pub/site

HTTP 200. 3 script(s): 2 first-party (0 inline), 1 third-party; 0 added at runtime; 21,104 bytes of script.

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | https://demo.demarkstudio.ca/static/js/sitio.js?v=a856b994 | first | - | 19,865 B | defer | html | absent | - | - |
| 2 | https://static.cloudflareinsights.com/beaco...edd6df95cf4e85bb4c19e7a9bdbcba1788362987495 | third | Cloudflare Web Analytics | - | module | html | unverified | anonymous | - |
| 3 | https://demo.demarkstudio.ca/cdn-cgi/script...dd728/cloudflare-static/email-decode.min.js (network only) | first | - | 1,239 B | ? | html | absent | - | - |
[...]
- Script sources allowed by the CSP: `'self'`

### Findings

- **LOW** script-error: script did not load: blocked by the page's Content-Security-Policy `https://static.cloudflareinsights.com/beacon.min.js/v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495`

## https://marvin.demarkstudio.ca

Final URL: https://marvin.demarkstudio.ca/
HTTP 200. 1 script(s): 0 first-party (0 inline), 1 third-party; 0 added at runtime; 0 bytes of script.

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | https://static.cloudflareinsights.com/beaco...edd6df95cf4e85bb4c19e7a9bdbcba1788362987495 | third | Cloudflare Web Analytics | - | module | html | unverified | anonymous | - |
[...]
- Script sources allowed by the CSP: `'none'`

### Findings

- **LOW** script-error: script did not load: blocked by the page's Content-Security-Policy `https://static.cloudflareinsights.com/beacon.min.js/v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495`

3 page(s); 0 finding(s) at or above 'high'.
$ echo $?
0

$ python -m pytest -q -p no:cacheprovider --import-mode=importlib script-inventory
........................................................................ [ 87%]
..........                                                               [100%]
82 passed in 10.37s
```

What it found, honestly: no vulnerable or end-of-life library, no invalid SRI and no mixed content on any of the three sites, and no inline scripts. The one real problem: Cloudflare adds its Web Analytics beacon to every page at the edge, but the CSP on the demo and portfolio sites (`script-src 'self'` and `'none'`) does not allow `static.cloudflareinsights.com`, so the beacon is blocked there and those two sites send no analytics. On demarkstudio.ca the CSP allows it and its SRI hash checks out. The `email-decode.min.js` script is also added by Cloudflare (email obfuscation); it removes its own tag after running (`e.parentNode.removeChild(e)`), which is why it shows up on the network only.

For what the vulnerable-library and SRI findings look like, [examples/local-fixture.md](examples/local-fixture.md) is the report for the local test page (fake jQuery 3.4.1, Lodash 4.17.20 and Moment 2.29.1 banners, one good and one tampered SRI hash, a script injected after load, a same-origin iframe).

## CLI

```
python -m script_inventory URL [URL ...] [--format markdown|json] [-o FILE]
                           [--fail-on info|low|medium|high|critical|none]
                           [--timeout 30] [--settle 3] [--delay 1] [--user-agent UA]
```

After `pip install .` the same command is available as `script-inventory`. Requires Chromium for Playwright (`python -m playwright install chromium`).

- `--settle`: seconds to wait after `load` (for network idle) so scripts injected at runtime are caught.
- `--delay`: pause between pages. Each URL is one page load in a fresh browser context; the tool never clicks, submits forms or follows links.

Exit codes for CI: **0** clean, **1** at least one finding at or above `--fail-on` (default `high`), **2** usage error, page that did not load (network error or HTTP 4xx/5xx) or browser failure.

| Severity | Finding |
|---|---|
| critical | script from a host known to have served malware (polyfill.io) |
| high | library version with a known vulnerability; SRI hash does not match; active mixed content (script, iframe, stylesheet, fetch) |
| medium | end-of-life library; passive mixed content (images, media); `integrity` on a cross-origin script without `crossorigin` |
| low | public-CDN file without SRI; malformed `integrity`; script that failed to load or was blocked |
| info | inline scripts and inline event handlers (CSP hint) |

## Limitations

- One page load per URL, no crawling and no interaction: scripts that only load after a click, a scroll or consent are not seen.
- The registrable domain uses a short built-in suffix list (common country suffixes such as `co.uk` and `nb.ca`, plus shared hosts like `github.io`), not the full Public Suffix List.
- Library detection covers popular libraries; bundled or renamed copies without a banner or global are not recognised. The advisory table is deliberately small and hand-checked: "none known" means "not in this table", not "safe". Use a full scanner (npm audit, OSV) on your source for complete coverage.
- A script blocked before it is fetched (by CSP, for example) cannot have its SRI verified; it is reported as `unverified`.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
