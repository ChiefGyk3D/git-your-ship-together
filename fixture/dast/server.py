"""A one-page web server on loopback, the target dast.yml is run against here.

Two modes, because a scan that can only pass proves nothing:

    python3 fixture/dast/server.py --port 8080              serves the page with the security headers a
                                                            ZAP baseline scan looks for, so the scan passes
    python3 fixture/dast/server.py --port 8080 --insecure   serves the same page with none of them, so a
                                                            `fail-on: medium` scan must fail

Standard library only, bound to 127.0.0.1, and never reads anything off disk.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>fixture</title></head>
<body><h1>fixture</h1><p>A page for dast.yml to scan.</p><a href="/about">about</a></body>
</html>
"""

ABOUT = b"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>about</title></head>
<body><p>Nothing here either.</p><a href="/">home</a></body>
</html>
"""

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


def make_handler(insecure: bool) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "fixture"  # no Python or library version on the wire
        sys_version = ""

        def do_GET(self) -> None:
            pages = {"/": PAGE, "/about": ABOUT}
            body = pages.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if not insecure:
                for name, value in SECURE_HEADERS.items():
                    self.send_header(name, value)
            body = body if body is not None else b"not found\n"
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
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.insecure)).serve_forever()


if __name__ == "__main__":
    main()
