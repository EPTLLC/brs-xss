#!/usr/bin/env python3

"""
Project: BRS-XSS - Mock Vulnerable Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:36:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import asyncio
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


async def start_app() -> web.Application:
    app = web.Application()
    app.add_routes([
        web.get("/", handle_index),
        web.get("/index.php", handle_index),
        web.get("/search", handle_search),
        web.get("/search.php", handle_search),
        web.get("/contact.php", handle_contact),
    ])
    return app


def main() -> None:
    web.run_app(asyncio.run(start_app()), host="127.0.0.1", port=8008)


if __name__ == "__main__":
    main()
