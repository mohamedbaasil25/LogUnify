import asyncio
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.pipeline.stream import StreamHub
from app.security import tokens
from tests.alert_helpers import run

LOG = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class LiveServer:
    """The real app on a real port in a thread: SSE needs a genuine socket and disconnect handling."""

    def __init__(self, **kw):
        base = dict(mock_enabled=False, alert_db_path=":memory:")
        base.update(kw)
        self.app = create_app(Settings(**base))
        self.port = _free_port()
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        end = time.time() + 15
        while not self.server.started and time.time() < end:
            time.sleep(0.05)
        assert self.server.started
        return self

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(10)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"


def read_events(resp, n, timeout=10):
    """Collect `n` (event, data) pairs from an httpx streaming response."""
    out, ev, end = [], None, time.time() + timeout
    for line in resp.iter_lines():
        if line.startswith("event:"):
            ev = line[6:].strip()
        elif line.startswith("data:") and ev:
            out.append((ev, json.loads(line[5:])))
            ev = None
            if len(out) >= n:
                break
        if time.time() > end:
            break
    return out


def test_logs_are_pushed_over_sse_and_filtered():
    with LiveServer() as s, httpx.Client(timeout=15) as c:
        with c.stream("GET", f"{s.url}/api/v1/stream/logs?format=syslog") as r:
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
            threading.Timer(0.5, lambda: httpx.post(f"{s.url}/api/v1/parse", json={"log": '{"message":"json log"}'})).start()
            threading.Timer(0.7, lambda: httpx.post(f"{s.url}/api/v1/parse", json={"log": LOG})).start()
            ev = read_events(r, 1)
        assert ev and ev[0][0] == "log" and ev[0][1]["logunify"]["source_format"] == "syslog"      # the JSON log was filtered out
        assert ev[0][1]["event"]["id"] and ev[0][1]["event"]["hash"]
        time.sleep(0.5)
        assert httpx.get(f"{s.url}/api/v1/stream/status").json()["subscribers"] == 0               # disconnect cleaned up


def test_stream_requires_a_token_when_auth_is_on():
    secret = "s" * 40
    with LiveServer(auth_mode="jwt", jwt_secret=secret, audit_db_path=":memory:") as s:
        assert httpx.get(f"{s.url}/api/v1/stream/logs").status_code == 401
        viewer = {"Authorization": "Bearer " + tokens.encode({"sub": "v", "exp": time.time() + 60, "roles": ["viewer"]}, secret)}
        assert httpx.get(f"{s.url}/api/v1/stream/logs", headers=viewer).status_code == 403         # raw logs: analyst+


def test_hub_slow_subscriber_loses_oldest_not_newest_and_threads_are_safe():
    async def go():
        hub = StreamHub()
        sub = hub.subscribe(maxsize=3)
        for i in range(10):
            hub.publish({"n": i})
        got = [sub.q.get_nowait()["n"] for _ in range(3)]
        assert got == [7, 8, 9] and sub.dropped == 7
        t = threading.Thread(target=lambda: hub.publish({"n": "from-thread"}))
        t.start()
        t.join()
        assert (await asyncio.wait_for(sub.q.get(), 2))["n"] == "from-thread"
        hub.unsubscribe(sub)
        hub.publish({"n": "nobody"})                                         # no subscribers: a no-op
        assert hub.subscribers == 0
    run(go())


def test_cors_is_off_by_default_and_never_wildcard(tmp_path):
    with TestClient(create_app(Settings(mock_enabled=False, alert_db_path=":memory:"))) as c:
        r = c.options("/api/v1/metrics", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        assert "access-control-allow-origin" not in r.headers
    with pytest.raises(ValueError):
        create_app(Settings(mock_enabled=False, alert_db_path=":memory:", cors_origins="*"))


def test_cors_allows_only_listed_origins():
    s = Settings(mock_enabled=False, alert_db_path=":memory:", cors_origins="https://soc.example.org")
    with TestClient(create_app(s)) as c:
        ok = c.options("/api/v1/metrics", headers={"Origin": "https://soc.example.org", "Access-Control-Request-Method": "GET",
                                                   "Access-Control-Request-Headers": "authorization"})
        assert ok.headers["access-control-allow-origin"] == "https://soc.example.org" and "access-control-allow-credentials" not in ok.headers
        bad = c.options("/api/v1/metrics", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        assert "access-control-allow-origin" not in bad.headers
        assert c.get("/api/v1/metrics", headers={"Origin": "https://evil.example"}).headers.get("access-control-allow-origin") is None
