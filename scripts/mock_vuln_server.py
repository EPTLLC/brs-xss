#!/usr/bin/env python3

"""
Project: BRS-XSS - Mock Vulnerable Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 27 Dec 2025 12:00:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from aiohttp import web


async def handle_search(request: web.Request) -> web.Response:
    q = request.rel_url.query.get("q", "")
    # Intentionally reflect unsanitized
    body = f"<html><body><h1>Search</h1><div>Query: {q}</div></body></html>"
    return web.Response(text=body, content_type="text/html")


async def handle_index(request: web.Request) -> web.Response:
    page = request.rel_url.query.get("page", "home")
    body = f"<html><body><div>Page: {page}</div></body></html>"
    return web.Response(text=body, content_type="text/html")


async def handle_contact(request: web.Request) -> web.Response:
    name = request.rel_url.query.get("name", "")
    email = request.rel_url.query.get("email", "")
    body = f"<html><body><form>Name: {name} Email: {email}</form></body></html>"
    return web.Response(text=body, content_type="text/html")


# --- Acceptance Scenarios ---


async def handle_reflected_js(request: web.Request) -> web.Response:
    """Reflected XSS in JS string context"""
    q = request.rel_url.query.get("q", "default")
    body = f"""
    <html>
    <body>
    <h1>JS Context</h1>
    <script>
        var searchTerm = '{q}';
        console.log(searchTerm);
    </script>
    </body>
    </html>
    """
    return web.Response(text=body, content_type="text/html")


async def handle_reflected_attr(request: web.Request) -> web.Response:
    """Reflected XSS in HTML attribute context"""
    q = request.rel_url.query.get("q", "")
    body = f"""
    <html>
    <body>
    <h1>Attribute Context</h1>
    <input type="text" name="search" value="{q}">
    </body>
    </html>
    """
    return web.Response(text=body, content_type="text/html")


async def handle_dom_innerhtml(request: web.Request) -> web.Response:
    """DOM XSS: source -> innerHTML"""
    # Note: DOM XSS usually works client-side.
    # The server just serves the static page with the vulnerable JS.
    body = """
    <html>
    <body>
    <h1>DOM innerHTML</h1>
    <div id="output"></div>
    <script>
        const params = new URLSearchParams(window.location.search);
        const x = params.get('x');
        if (x) {
            document.getElementById('output').innerHTML = x;
        }
    </script>
    </body>
    </html>
    """
    return web.Response(text=body, content_type="text/html")


async def handle_dom_eval(request: web.Request) -> web.Response:
    """DOM XSS: source -> eval"""
    body = """
    <html>
    <body>
    <h1>DOM eval</h1>
    <script>
        const params = new URLSearchParams(window.location.search);
        const x = params.get('x');
        if (x) {
            eval(x);
        }
    </script>
    </body>
    </html>
    """
    return web.Response(text=body, content_type="text/html")


async def handle_dom_document_write(request: web.Request) -> web.Response:
    """DOM XSS: source -> document.write"""
    body = """
    <html>
    <body>
    <h1>DOM document.write</h1>
    <script>
        const params = new URLSearchParams(window.location.search);
        const x = params.get('x');
        if (x) {
            document.write(x);
        }
    </script>
    </body>
    </html>
    """
    return web.Response(text=body, content_type="text/html")


async def start_app() -> web.Application:
    app = web.Application()
    app.add_routes(
        [
            web.get("/", handle_index),
            web.get("/index.php", handle_index),
            web.get("/search", handle_search),
            web.get("/search.php", handle_search),
            web.get("/contact.php", handle_contact),
            # New routes for acceptance testing
            web.get("/reflected/js", handle_reflected_js),
            web.get("/reflected/attr", handle_reflected_attr),
            web.get("/dom/innerhtml", handle_dom_innerhtml),
            web.get("/dom/eval", handle_dom_eval),
            web.get("/dom/document_write", handle_dom_document_write),
        ]
    )
    return app


def main() -> None:
    # Changed port to 8009 to avoid conflict with default
    web.run_app(start_app(), host="127.0.0.1", port=8009)


if __name__ == "__main__":
    import sys

    # Support port via args for tests
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        web.run_app(start_app(), host="127.0.0.1", port=port)
    else:
        main()
