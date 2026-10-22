"""MOCK Teams/Slack incoming webhook: accepts any POST on any path, logs the body, answers 200. Not a real chat service."""
import logging

from aiohttp import web

logging.basicConfig(level=logging.INFO, format="%(asctime)s MOCK-WEBHOOK %(message)s")
received: list[str] = []


async def hook(request: web.Request):
    body = await request.text()
    received.append(body)
    logging.info("POST %s %s", request.path, body)
    return web.Response(text="ok")


async def count(_):
    return web.json_response({"received": len(received), "last": received[-1] if received else None})

app = web.Application()
app.router.add_get("/_count", count)
app.router.add_post("/{tail:.*}", hook)
web.run_app(app, host="0.0.0.0", port=8080, print=None)
