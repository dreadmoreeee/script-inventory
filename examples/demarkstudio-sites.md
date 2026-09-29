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

### Scripts

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | https://demo.demarkstudio.ca/static/js/sitio.js?v=a856b994 | first | - | 19,865 B | defer | html | absent | - | - |
| 2 | https://static.cloudflareinsights.com/beaco...edd6df95cf4e85bb4c19e7a9bdbcba1788362987495 | third | Cloudflare Web Analytics | - | module | html | unverified | anonymous | - |
| 3 | https://demo.demarkstudio.ca/cdn-cgi/script...dd728/cloudflare-static/email-decode.min.js (network only) | first | - | 1,239 B | ? | html | absent | - | - |

### Libraries

No known library detected.

### Mixed content

None: no http: subresources.

### Inline scripts and CSP

- Inline scripts: 0 (0 with a nonce); elements with inline event handlers: 0; non-executed data blocks (JSON-LD etc.): 0
- CSP restricts scripts. No inline scripts or inline event handlers: a strict CSP needs no nonces or hashes for inline code.
- Script sources allowed by the CSP: `'self'`

### Findings

- **LOW** script-error: script did not load: blocked by the page's Content-Security-Policy `https://static.cloudflareinsights.com/beacon.min.js/v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495`

## https://marvin.demarkstudio.ca

Final URL: https://marvin.demarkstudio.ca/  
HTTP 200. 1 script(s): 0 first-party (0 inline), 1 third-party; 0 added at runtime; 0 bytes of script.

### Scripts

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | https://static.cloudflareinsights.com/beaco...edd6df95cf4e85bb4c19e7a9bdbcba1788362987495 | third | Cloudflare Web Analytics | - | module | html | unverified | anonymous | - |

### Libraries

No known library detected.

### Mixed content

None: no http: subresources.

### Inline scripts and CSP

- Inline scripts: 0 (0 with a nonce); elements with inline event handlers: 0; non-executed data blocks (JSON-LD etc.): 1
- CSP restricts scripts. No inline scripts or inline event handlers: a strict CSP needs no nonces or hashes for inline code.
- Script sources allowed by the CSP: `'none'`

### Findings

- **LOW** script-error: script did not load: blocked by the page's Content-Security-Policy `https://static.cloudflareinsights.com/beacon.min.js/v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495`

3 page(s); 0 finding(s) at or above 'high'.
