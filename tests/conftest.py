import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from script_inventory.sri import sri_hash  # noqa: E402

JQUERY = b"/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n" \
         b"window.jQuery = window.$ = {fn: {jquery: '3.4.1'}};\n"
GOOD = b"window.goodLoaded = true;\n"
BAD = b"window.badLoaded = true;\n"
MODULE = b"window.moduleLoaded = true;\n"
APP = b"window.appLoaded = true;\n"
INJECTED = b"window.injectedLoaded = true;\n"
MOMENT = b"//! moment.js\n//! version : 2.29.1\n;window.moment = {version: '2.29.1'};\n"
LODASH = (b"/**\n * @license\n * Lodash <https://lodash.com/>\n */\n"
          b";(function(){var VERSION = '4.17.20'; window._ = {VERSION: VERSION, runInContext: function(){}};})();\n")

INDEX = """<!doctype html>
<html><head><title>fixture</title>
<script src="/js/jquery-3.4.1.min.js"></script>
<script src="/js/good.js" integrity="{good}" crossorigin="anonymous"></script>
<script src="/js/bad.js" integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" crossorigin="anonymous"></script>
<script type="module" src="/js/mod.js"></script>
<script defer src="/js/app.js"></script>
<script src="http://localhost:{port}/js/lodash.js" async></script>
<script>window.inlineOne = 1;</script>
<script type="application/ld+json">{{"@context": "https://schema.org"}}</script>
</head><body>
<button onclick="void 0">x</button>
<iframe src="/frame.html"></iframe>
<script>
setTimeout(function () {{
  var s = document.createElement('script');
  s.src = '/js/injected.js';
  document.head.appendChild(s);
}}, 50);
</script>
</body></html>
"""

FRAME = b"""<!doctype html><html><head><script src="/js/moment.js"></script></head><body>frame</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        route = self.routes.get(path)
        if route is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ctype, body = route
        if callable(body):
            body = body(self.server.server_address[1])
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _routes():
    js = "application/javascript"
    return {
        "/": ("text/html; charset=utf-8",
              lambda port: INDEX.format(good=sri_hash(GOOD, "sha384"), port=port).encode("utf-8")),
        "/frame.html": ("text/html; charset=utf-8", FRAME),
        "/js/jquery-3.4.1.min.js": (js, JQUERY),
        "/js/good.js": (js, GOOD),
        "/js/bad.js": (js, BAD),
        "/js/mod.js": (js, MODULE),
        "/js/app.js": (js, APP),
        "/js/injected.js": (js, INJECTED),
        "/js/moment.js": (js, MOMENT),
        "/js/lodash.js": (js, LODASH),
        "/clean": ("text/html; charset=utf-8",
                   b"<!doctype html><title>clean</title><script src='/js/app.js'></script>"),
    }


@pytest.fixture(scope="session")
def site():
    handler = type("Handler", (_Handler,), {"routes": _routes()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
