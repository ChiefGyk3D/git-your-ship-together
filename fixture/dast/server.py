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
    python3 fixture/dast/server.py --port 8080 --login        a form login with throwaway credentials, and behind it
                                                              the same reflected cross-site scripting hole at
                                                              /account/search. The public pages stay escaped, so a
                                                              full scan with no login passes at `high`; only a scan
                                                              that signs in (a ZAP context file and a user,
                                                              fixture/dast/login.context and `throwaway`) reaches
                                                              the hole and fails

What is served:

    /                   a page linking to /about and /search?q=fixture
    /about              a second page
    /search?q=...       echoes q (escaped, or not with --vulnerable)
    /openapi.json       the OpenAPI 3 definition of the API below; also at fixture/dast/openapi.json
    /api/items          a JSON list
    /api/items/{id}     one item, or a JSON 404

With --login, also:

    /login              GET a form; POST username and password. A right pair sets a session cookie and redirects to
                        /account; a wrong one is a 401 and sets nothing
    /account            only with the session cookie, otherwise a redirect to /login. The page that links to the hole
    /account/search?q=  only with the session cookie; echoes q UNESCAPED

The credentials are the constants below, throwaway by construction: the server holds them in memory, reads
nothing from disk and is reachable only on loopback.

Standard library only, bound to 127.0.0.1, and never reads anything off disk.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# The login of --login. Throwaway: they open a fixture that holds nothing, on loopback, for one test run.
LOGIN_USER = "throwaway"
LOGIN_PASSWORD = "throwaway-password"
COOKIE = "fixture_session"

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

HOME_LOGIN_LINK = b'<a href="/login">sign in</a>'
HOME_ACCOUNT_LINK = b'<a href="/account">account</a>'

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>sign in</title></head>
<body><h1>Sign in</h1><p>{message}</p>
<form method="post" action="/login">
<label>Username <input name="username" type="text" autocomplete="off"></label>
<label>Password <input name="password" type="password" autocomplete="off"></label>
<button type="submit">Sign in</button></form><a href="/">home</a></body>
</html>
"""

ACCOUNT = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>account</title></head>
<body><h1>Account</h1><p>Signed in as {user}.</p>
<a href="/account/search?q=fixture">search your account</a> <a href="/">home</a></body>
</html>
"""

ACCOUNT_SEARCH = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>account search</title></head>
<body><p>You searched your account for: {q}</p><p>Signed in as {user}.</p><a href="/account">account</a></body>
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


def make_handler(insecure: bool, vulnerable: bool, login: bool = False) -> type[BaseHTTPRequestHandler]:
    sessions: set[str] = set()  # the cookies this process has issued; gone when it exits

    class Handler(BaseHTTPRequestHandler):
        server_version = "fixture"  # no Python or library version on the wire
        sys_version = ""

        def signed_in(self) -> bool:
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == COOKIE and value in sessions:
                    return True
            return False

        def redirect(self, location: str, cookie: str | None = None) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            if cookie:
                self.send_header("Set-Cookie", f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict")
            self.send_header("Content-Length", "0")
            self.send_secure_headers()
            self.end_headers()

        def do_POST(self) -> None:
            if not (login and urlsplit(self.path).path == "/login"):
                self.reply(404, "text/html; charset=utf-8", NOT_FOUND)
                return
            length = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(min(length, 4096)).decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            if secrets.compare_digest(user, LOGIN_USER) and secrets.compare_digest(password, LOGIN_PASSWORD):
                token = secrets.token_hex(16)
                sessions.add(token)
                self.redirect("/account", token)
            else:
                page = LOGIN_PAGE.format(message="Sign in failed.")
                self.reply(401, "text/html; charset=utf-8", page.encode())

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            path = url.path
            if login and path in ("/login", "/account", "/account/search"):
                self.login_routes(path, url.query)
            elif path == "/":
                page = PAGE
                if login:
                    link = HOME_ACCOUNT_LINK if self.signed_in() else HOME_LOGIN_LINK
                    page = PAGE.replace(b"</body>", link + b"</body>")
                self.reply(200, "text/html; charset=utf-8", page)
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

        def login_routes(self, path: str, query: str) -> None:
            if path == "/login":
                self.reply(200, "text/html; charset=utf-8", LOGIN_PAGE.format(message="").encode())
            elif not self.signed_in():
                self.redirect("/login")
            elif path == "/account":
                self.reply(200, "text/html; charset=utf-8", ACCOUNT.format(user=LOGIN_USER).encode())
            else:
                # The hole behind the login: the raw query in the page, whatever --vulnerable says.
                q = parse_qs(query).get("q", [""])[0]
                self.reply(200, "text/html; charset=utf-8", ACCOUNT_SEARCH.format(q=q, user=LOGIN_USER).encode())

        def send_secure_headers(self) -> None:
            if insecure:
                return
            for name, value in SECURE_HEADERS.items():
                # The login form posts to this origin; the rest of the fixture submits nothing.
                if login and name == "Content-Security-Policy":
                    value = value.replace("form-action 'none'", "form-action 'self'")
                self.send_header(name, value)

        def reply(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_secure_headers()
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
    parser.add_argument("--login", action="store_true", help="add a form login and, behind it, an unescaped echo")
    args = parser.parse_args()
    handler = make_handler(args.insecure, args.vulnerable, args.login)
    ThreadingHTTPServer(("127.0.0.1", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
