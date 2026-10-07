"""A small web service on loopback, the target dast.yml is run against here.

A scan that can only pass proves nothing, so the server has modes that each
scan type must catch and modes it must pass:

    python3 fixture/dast/server.py --port 8080                serves the pages and the API with the security
                                                              headers a ZAP scan looks for, and escapes what it
                                                              echoes, so every scan type passes
    python3 fixture/dast/server.py --port 8080 --insecure     the same with none of the headers, so a baseline at
                                                              `fail-on: medium` must fail
    python3 fixture/dast/server.py --port 8080 --vulnerable   the headers stay, but /search echoes its `q`
                                                              parameter into the page unescaped: a reflected
                                                              cross-site scripting hole. The baseline's passive
                                                              rules cannot see it (nothing in the response
                                                              headers is wrong) and must pass; the full scan's
                                                              active rules must find it and fail at `high`

What is served:

    /                   a page linking to /about and /search?q=fixture
    /about              a second page
    /search?q=...       echoes q (escaped, or not with --vulnerable)
    /openapi.json       the OpenAPI 3 definition of the API below; also at fixture/dast/openapi.json
    /api/items          a JSON list
    /api/items/{id}     one item, or a JSON 404

Standard library only, bound to 127.0.0.1, and never reads anything off disk.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = b"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>fixture</title></head>
<body><h1>fixture</h1><p>A page for dast.yml to scan.</p>
<a href="/about">about</a> <a href="/search?q=fixture">search</a> <a href="/openapi.json">api</a></body>
</html>
"""

ABOUT = b"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>about</title></head>
<body><p>Nothing here either.</p><a href="/">home</a></body>
</html>
"""

SEARCH = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>search</title></head>
<body><p>You searched for: {q}</p><a href="/">home</a></body>
</html>
"""

NOT_FOUND = b"<!doctype html><html lang='en'><body>not found</body></html>"

ITEMS = {1: {"id": 1, "name": "one"}, 2: {"id": 2, "name": "two"}}

# The API the `api` scan type imports. `servers` names a host that does not exist on
# purpose: the workflow's -O override must redirect the scan to the loopback service.
OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "fixture", "version": "1.0.0", "description": "The API dast.yml's api scan is run against."},
    "servers": [{"url": "https://fixture.invalid"}],
    "paths": {
        "/api/items": {
            "get": {
                "operationId": "listItems",
                "summary": "List the items",
                "responses": {"200": {"description": "The items", "content": {"application/json": {}}}},
            }
        },
        "/api/items/{id}": {
            "get": {
                "operationId": "getItem",
                "summary": "One item",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {
                    "200": {"description": "The item", "content": {"application/json": {}}},
                    "404": {"description": "No such item", "content": {"application/json": {}}},
                },
            }
        },
    },
}

# What the baseline's passive rules ask a page to send.
SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}

ITEM = re.compile(r"^/api/items/([^/]+)$")


def make_handler(insecure: bool, vulnerable: bool) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "fixture"  # no Python or library version on the wire
        sys_version = ""

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            path = url.path
            if path == "/":
                self.reply(200, "text/html; charset=utf-8", PAGE)
            elif path == "/about":
                self.reply(200, "text/html; charset=utf-8", ABOUT)
            elif path == "/search":
                q = parse_qs(url.query).get("q", [""])[0]
                # --vulnerable is the hole the full scan exists to find: the raw query in the page.
                shown = q if vulnerable else html.escape(q)
                self.reply(200, "text/html; charset=utf-8", SEARCH.format(q=shown).encode())
            elif path == "/openapi.json":
                self.reply(200, "application/json", json.dumps(OPENAPI).encode())
            elif path == "/api/items":
                self.reply(200, "application/json", json.dumps(list(ITEMS.values())).encode())
            elif match := ITEM.match(path):
                item = ITEMS.get(int(match[1])) if match[1].isdigit() else None
                if item is None:
                    self.reply(404, "application/json", b'{"error": "no such item"}')
                else:
                    self.reply(200, "application/json", json.dumps(item).encode())
            else:
                self.reply(404, "text/html; charset=utf-8", NOT_FOUND)

        def reply(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if not insecure:
                for name, value in SECURE_HEADERS.items():
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--insecure", action="store_true", help="send none of the security headers")
    parser.add_argument("--vulnerable", action="store_true", help="echo /search?q= into the page unescaped")
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.insecure, args.vulnerable)).serve_forever()


if __name__ == "__main__":
    main()
