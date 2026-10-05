"""LogUnify prototype: TCP listener -> pipeline queue -> ECS parser -> scorer -> webhook alerter.

Wire format: one record per line (newline-delimited), either NXLog `to_json()` Windows events or PostgreSQL / MySQL error-log text lines.
The listener is plain TCP on purpose: bind it to loopback and put the mutual-TLS stunnel in front of it.
"""
import asyncio
import json
import logging
import os
import time

import aiohttp

from alerts.notifier import notify
from engine.analyzer import analyze
from parsers.ecs_mapper import to_ecs

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

HOST = os.getenv("LOGUNIFY_LISTEN_HOST", "127.0.0.1")
PORT = int(os.getenv("LOGUNIFY_LISTEN_PORT", "5514"))
MAX_LINE = int(os.getenv("LOGUNIFY_MAX_LINE_BYTES", "65536"))
QUEUE_SIZE = int(os.getenv("LOGUNIFY_QUEUE_SIZE", "10000"))
DEFAULT_HOST = os.getenv("LOGUNIFY_DEFAULT_HOST_NAME") or None
DLQ_PATH = os.getenv("LOGUNIFY_DLQ_PATH", "dead_letter.jsonl")
OUT_PATH = os.getenv("LOGUNIFY_OUTPUT_PATH", "")                  # optional: append every normalised event as JSON lines

log = logging.getLogger("logunify")
STATS = {"received": 0, "parsed": 0, "dead_lettered": 0, "alerts_sent": 0, "oversize": 0}


class Pipeline:
    def __init__(self):
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.session: aiohttp.ClientSession | None = None
        self.redis = None
        self._worker: asyncio.Task | None = None

    async def start(self):
        self.session = aiohttp.ClientSession()
        url = os.getenv("LOGUNIFY_REDIS_URL", "")
        if url:
            try:
                import redis.asyncio as aioredis
                self.redis = aioredis.from_url(url, socket_connect_timeout=3)
                await self.redis.ping()
            except Exception as e:
                log.error("redis unavailable (%s): continuing without alert de-duplication", e)
                self.redis = None
        self._worker = asyncio.create_task(self._run())

    async def stop(self):
        await self.queue.join()
        self._worker.cancel()
        await self.session.close()
        if self.redis is not None:
            await self.redis.aclose()

    async def submit(self, raw: str):
        await self.queue.put(raw)                                 # blocks (back-pressure on the socket) when full: nothing is dropped

    async def _run(self):
        while True:
            raw = await self.queue.get()
            try:
                await self._process(raw)
            except Exception:
                log.exception("pipeline error; record dead-lettered")
                self._dead_letter(raw, "pipeline-error")
            finally:
                self.queue.task_done()

    async def _process(self, raw: str):
        ev = to_ecs(raw, DEFAULT_HOST)                            # event.original is set here from the untouched received line
        if ev is None:
            self._dead_letter(raw, "no-parser-matched")
            return
        STATS["parsed"] += 1
        analyze(ev)
        if OUT_PATH:
            with open(OUT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        if await notify(ev, self.session, self.redis):
            STATS["alerts_sent"] += 1

    @staticmethod
    def _dead_letter(raw: str, reason: str):
        STATS["dead_lettered"] += 1
        with open(DLQ_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "reason": reason, "event.original": raw}, ensure_ascii=False) + "\n")


async def handle_client(pipe: Pipeline, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    log.info("connection from %s", peer)
    try:
        while True:
            try:
                line = await reader.readuntil(b"\n")
            except asyncio.IncompleteReadError as e:
                line = e.partial                                  # final record without a trailing newline
                if not line:
                    break
            except (asyncio.LimitOverrunError, ValueError):
                STATS["oversize"] += 1
                log.error("line over %d bytes from %s: closing connection", MAX_LINE, peer)
                break
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if text.strip():
                STATS["received"] += 1
                await pipe.submit(text)
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def main():
    logging.basicConfig(level=os.getenv("LOGUNIFY_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    pipe = Pipeline()
    await pipe.start()
    server = await asyncio.start_server(lambda r, w: handle_client(pipe, r, w), HOST, PORT, limit=MAX_LINE)
    log.info("listening on %s (plain TCP: front it with mutual-TLS stunnel); threshold=%s", ", ".join(str(s.getsockname()) for s in server.sockets),
             os.getenv("LOGUNIFY_ALERT_SCORE_THRESHOLD", "0.80"))
    async with server:
        try:
            await server.serve_forever()
        finally:
            await pipe.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
