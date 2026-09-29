# Script inventory

## http://127.0.0.1:PORT/

HTTP 200. 10 script(s): 9 first-party (2 inline), 1 third-party; 1 added at runtime; 658 bytes of script; 1 same-origin iframe(s) inspected.

### Scripts

| # | Script | Party | Vendor | Size | Load | Added | SRI | crossorigin | Library |
|---|---|---|---|---|---|---|---|---|---|
| 1 | http://127.0.0.1:PORT/js/jquery-3.4.1.min.js | first | - | 137 B | blocking | html | absent | - | jquery 3.4.1 |
| 2 | http://127.0.0.1:PORT/js/good.js | first | - | 26 B | blocking | html | valid | anonymous | - |
| 3 | http://127.0.0.1:PORT/js/bad.js | first | - | 25 B | blocking | html | invalid | anonymous | - |
| 4 | http://127.0.0.1:PORT/js/mod.js | first | - | 28 B | module | html | absent | - | - |
| 5 | http://127.0.0.1:PORT/js/app.js | first | - | 25 B | defer | html | absent | - | - |
| 6 | http://localhost:PORT/js/lodash.js | third | - | 154 B | async | html | absent | - | lodash 4.17.20 |
| 7 | inline | first | - | 21 B | - | html | - | - | - |
| 8 | http://127.0.0.1:PORT/js/injected.js | first | - | 30 B | async | runtime | absent | - | - |
| 9 | inline | first | - | 139 B | - | html | - | - | - |
| 10 | http://127.0.0.1:PORT/js/moment.js (iframe) | first | - | 73 B | blocking | html | absent | - | moment 2.29.1 |

### Libraries

| Library | Version | Found via | Advisories |
|---|---|---|---|
| jquery | 3.4.1 | url, banner, global | [CVE-2020-11022](https://nvd.nist.gov/vuln/detail/CVE-2020-11022), [CVE-2020-11023](https://nvd.nist.gov/vuln/detail/CVE-2020-11023) |
| lodash | 4.17.20 | url, banner, global | [CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337) |
| moment | 2.29.1 | url, banner, global | [CVE-2022-31129](https://nvd.nist.gov/vuln/detail/CVE-2022-31129) |

### Mixed content

Not applicable: the page itself is not served over HTTPS.

### Inline scripts and CSP

- Inline scripts: 2 (0 with a nonce); elements with inline event handlers: 1; non-executed data blocks (JSON-LD etc.): 1
- No Content-Security-Policy. 2 inline script(s) (0 with a nonce): a strict CSP without 'unsafe-inline' needs a nonce or a 'sha256-...' hash for each (hashes are in the JSON output). 1 element(s) use inline event handlers (onclick=...): nonces do not cover them; move them to addEventListener.

### Findings

- **HIGH** vulnerable-library: jquery 3.4.1: CVE-2020-11022 XSS: HTML from untrusted sources passed to DOM manipulation methods (.html(), .append(), ...) may run code even after sanitizing `http://127.0.0.1:PORT/js/jquery-3.4.1.min.js` <https://nvd.nist.gov/vuln/detail/CVE-2020-11022> <https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/>
- **HIGH** vulnerable-library: jquery 3.4.1: CVE-2020-11023 XSS: HTML containing <option> elements from untrusted sources passed to DOM manipulation methods may run code `http://127.0.0.1:PORT/js/jquery-3.4.1.min.js` <https://nvd.nist.gov/vuln/detail/CVE-2020-11023> <https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/>
- **HIGH** vulnerable-library: lodash 4.17.20: CVE-2021-23337 Command injection through the template function `http://localhost:PORT/js/lodash.js` <https://nvd.nist.gov/vuln/detail/CVE-2021-23337>
- **HIGH** vulnerable-library: moment 2.29.1: CVE-2022-31129 Inefficient RFC 2822 date parsing (ReDoS) on long user-supplied strings `http://127.0.0.1:PORT/js/moment.js` <https://nvd.nist.gov/vuln/detail/CVE-2022-31129> <https://github.com/moment/moment/security/advisories/GHSA-wc69-rhjr-hc9g>
- **HIGH** sri-invalid: integrity does not match the served file (body hashes to sha384-RH01Ocr0C6GE8OI7crb0s1TKIpNCZLvt8psOt2Zxt/SWnOQLpVPtf6fK5+9MjC4M); the browser refuses to run it `http://127.0.0.1:PORT/js/bad.js`
- **INFO** inline-scripts: No Content-Security-Policy. 2 inline script(s) (0 with a nonce): a strict CSP without 'unsafe-inline' needs a nonce or a 'sha256-...' hash for each (hashes are in the JSON output). 1 element(s) use inline event handlers (onclick=...): nonces do not cover them; move them to addEventListener.

1 page(s); 5 finding(s) at or above 'high'.
