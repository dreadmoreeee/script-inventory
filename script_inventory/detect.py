"""Library + version detection from script URLs, banner comments and page globals."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlsplit

# Package or file names -> canonical library name.
ALIASES = {
    "jquery": "jquery",
    "jquery-slim": "jquery",
    "jquery.slim": "jquery",
    "jquery-ui": "jquery-ui",
    "jqueryui": "jquery-ui",
    "jquery-ui-dist": "jquery-ui",
    "jquery-migrate": "jquery-migrate",
    "bootstrap": "bootstrap",
    "twitter-bootstrap": "bootstrap",
    "lodash": "lodash",
    "lodash.js": "lodash",
    "moment": "moment",
    "moment.js": "moment",
    "angular": "angularjs",
    "angular.js": "angularjs",
    "angularjs": "angularjs",
    "vue": "vue",
    "vue.js": "vue",
    "vue.global": "vue",
    "react": "react",
    "react-dom": "react-dom",
    "underscore": "underscore",
    "underscore.js": "underscore",
    "dompurify": "dompurify",
    "popper.js": "popper",
    "@popperjs/core": "popper",
    "handlebars": "handlebars",
    "handlebars.js": "handlebars",
    "d3": "d3",
    "swiper": "swiper",
    "gsap": "gsap",
    "alpinejs": "alpinejs",
    "htmx.org": "htmx",
}

_VER = r"v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)"

# /npm/pkg@1.2.3/ (jsDelivr), unpkg.com/pkg@1.2.3/, esm.sh/pkg@1.2.3
_AT_VERSION = re.compile(r"/(?:npm/)?((?:@[\w.-]+/)?[\w.-]+)@" + _VER + r"(?:/|$)")
# cdnjs and Google Hosted Libraries: /ajax/libs/<name>/<version>/
_AJAX_LIBS = re.compile(r"/ajax/libs/([\w.-]+)/" + _VER + r"/")
# code.jquery.com/ui/1.12.1/jquery-ui.min.js, bootstrapcdn /bootstrap/4.3.1/js/
_DIR_VERSION = re.compile(r"/(ui|bootstrap|twitter-bootstrap)/" + _VER + r"/")
# file names: jquery-3.4.1.min.js, jquery.3.4.1.js, moment-2.29.1.min.js
_FILE_VERSION = re.compile(r"^((?:[a-z]+[-.])*?[a-z]+)[-.@]" + _VER + r"(?:[.-](?:min|slim|slim\.min|bundle|bundle\.min|prod|production))*\.m?js$", re.I)
_FILE_PLAIN = re.compile(r"^([a-z][\w.-]*?)(?:[.-](?:min|slim|slim\.min|bundle|bundle\.min|prod|production))*\.m?js$", re.I)


def canonical(name: str) -> str | None:
    return ALIASES.get((name or "").lower())


def from_url(url: str) -> list[tuple[str, str | None]]:
    """Libraries named by a script URL, as ``(library, version or None)``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    path = unquote(parts.path)
    found: list[tuple[str, str | None]] = []

    def add(name, version):
        lib = canonical(name)
        if lib and (lib, version) not in found:
            found.append((lib, version))

    for m in _AT_VERSION.finditer(path):
        add(m.group(1), m.group(2))
    m = _AJAX_LIBS.search(path)
    if m:
        add(m.group(1), m.group(2))
    m = _DIR_VERSION.search(path)
    if m:
        add("jquery-ui" if m.group(1) == "ui" else m.group(1), m.group(2))
    if found:
        return found

    filename = path.rsplit("/", 1)[-1]
    m = _FILE_VERSION.match(filename)
    if m and canonical(m.group(1)):
        add(m.group(1), m.group(2))
        return found
    m = _FILE_PLAIN.match(filename)
    if m and canonical(m.group(1)):
        # WordPress style: /wp-includes/js/jquery/jquery.min.js?ver=3.7.1
        ver = (parse_qs(parts.query).get("ver") or [None])[0]
        if ver and not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", ver):
            ver = None
        add(m.group(1), ver)
    return found


# (library, banner regex with the version in group 1). Checked on the first 4 KiB.
_BANNERS = [
    ("jquery", re.compile(r"jQuery (?:JavaScript Library )?v" + _VER)),
    ("jquery-ui", re.compile(r"jQuery UI - v" + _VER)),
    ("jquery-migrate", re.compile(r"jQuery Migrate - v" + _VER)),
    ("bootstrap", re.compile(r"Bootstrap v" + _VER)),
    ("angularjs", re.compile(r"AngularJS v" + _VER)),
    ("vue", re.compile(r"Vue\.js v" + _VER)),
    ("dompurify", re.compile(r"DOMPurify " + _VER)),
    ("handlebars", re.compile(r"handlebars v" + _VER, re.I)),
    ("popper", re.compile(r"(?:@popperjs/core|Popper\.js) v" + _VER)),
    ("underscore", re.compile(r"Underscore\.js " + _VER + r"\s*$", re.M)),
]
_LODASH = re.compile(r"Lodash <https://lodash\.com/>|lodash\.com/license|\blodash\.com\b", re.I)
_LODASH_VERSION = re.compile(r"""VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]|=\s*"(\d+\.\d+\.\d+)"\s*[,;]""")
_MOMENT = re.compile(r"//! moment\.js")
_MOMENT_VERSION = re.compile(r"//! version : " + _VER + r"""|\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]""")
_REACT = re.compile(r"@license React(?: v(\d+\.\d+\.\d+))?\s*\*?\s*(react(?:-dom)?)\.", re.I)
_REACT_VERSION = re.compile(r"""\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]|ReactVersion\s*=\s*['"](\d+\.\d+\.\d+)['"]""")

HEAD_BYTES = 4096


def from_body(text: str) -> list[tuple[str, str | None]]:
    """Libraries identified by banner comments in a script body."""
    head = text[:HEAD_BYTES]
    found: list[tuple[str, str | None]] = []
    names = set()

    def add(lib, version):
        if lib not in names:
            names.add(lib)
            found.append((lib, version))

    if _LODASH.search(head):
        m = _LODASH_VERSION.search(text[:200_000])
        add("lodash", (m.group(1) or m.group(2)) if m else None)
        names.add("underscore")  # the lodash banner credits Underscore.js
    if _MOMENT.search(head):
        m = _MOMENT_VERSION.search(text[:200_000])
        add("moment", next((g for g in m.groups() if g), None) if m else None)
    m = _REACT.search(head)
    if m:
        version = m.group(1)
        if not version:
            v = _REACT_VERSION.search(text[:500_000])
            version = next((g for g in v.groups() if g), None) if v else None
        add(m.group(2).lower(), version)
    for lib, rx in _BANNERS:
        m = rx.search(head)
        if m:
            add(lib, m.group(1))
    return found


# Evaluated in each inspected frame. Returns {library: version} for set globals.
GLOBAL_PROBE_JS = r"""
() => {
  const out = {};
  const get = (name, f) => {
    try {
      const v = f();
      if (typeof v === 'string' && v) out[name] = v;
    } catch (e) {}
  };
  const w = window;
  get('jquery', () => w.jQuery.fn.jquery);
  get('jquery-ui', () => w.jQuery.ui.version);
  get('react', () => w.React.version);
  get('react-dom', () => w.ReactDOM.version);
  get('vue', () => w.Vue.version);
  get('bootstrap', () => w.bootstrap.Tooltip.VERSION);
  if (!out.bootstrap) get('bootstrap', () => w.jQuery.fn.tooltip.Constructor.VERSION);
  get(w._ && typeof w._.runInContext === 'function' ? 'lodash' : 'underscore', () => w._.VERSION);
  get('moment', () => w.moment.version);
  get('angularjs', () => w.angular.version.full);
  get('dompurify', () => w.DOMPurify.version);
  get('handlebars', () => w.Handlebars.VERSION);
  get('d3', () => w.d3.version);
  get('gsap', () => w.gsap.version);
  return out;
}
"""
