import asyncio
import socket
import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.listeners.syslog import SyslogListener
from app.main import create_app
from app.pipeline.bus import InMemoryBus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from tests.alert_helpers import run

M3164 = b"<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2"
M5424 = b"<165>1 2026-09-30T10:00:00.003Z fw-01 appd 7 ID47 - request from 10.0.0.9 denied"


class Sink:
    def __init__(self, delay: float = 0.0):
        self.got: list[tuple[bytes, str | None]] = []
        self.delay = delay

    async def __call__(self, raw, hint):
        if self.delay:
            await asyncio.sleep(self.delay)
        self.got.append((raw, hint))
        return True


async def wait_for(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "condition not met in time"
        await asyncio.sleep(0.01)


async def listener(sink, **kw):
    kw.setdefault("udp_port", 0)
    kw.setdefault("tcp_port", 0)
    lst = SyslogListener(sink, **kw)
    await lst.start()
    return lst


async def tcp_send(port, data: bytes, close=True):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    if close:
        w.close()
        await w.wait_closed()
        return None
    return r, w


def udp_send(port, data: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, ("127.0.0.1", port))
    s.close()


def test_udp_3164_and_5424():
    async def go():
        sink = Sink()
        lst = await listener(sink, tcp_port=None)
        udp_send(lst.bound["udp"], M3164 + b"\n")
        udp_send(lst.bound["udp"], M5424)
        await wait_for(lambda: len(sink.got) == 2)
        await lst.stop()
        assert [g[0] for g in sink.got] == [M3164, M5424]
        assert lst.stats()["udp_received"] == 2
    run(go())


def test_tcp_newline_and_octet_counting_mixed():
    async def go():
        sink = Sink()
        lst = await listener(sink, udp_port=None)
        octet = str(len(M5424)).encode() + b" " + M5424
        await tcp_send(lst.bound["tcp"], M3164 + b"\r\n" + octet + M3164 + b"\n\n" + b"2026-09-30 10:00:00 plain text line\n" + b"42\n" + M3164)  # last: no trailing LF
        await wait_for(lambda: len(sink.got) == 6)
        await lst.stop()
        assert sink.got[0][0] == M3164 and sink.got[1][0] == M5424 and sink.got[2][0] == M3164
        assert sink.got[3][0] == b"2026-09-30 10:00:00 plain text line"     # digit-leading line is not mistaken for a length
        assert sink.got[4][0] == b"42" and sink.got[5][0] == M3164          # tail without LF still delivered
    run(go())


def test_tcp_message_split_across_packets():
    async def go():
        sink = Sink()
        lst = await listener(sink, udp_port=None)
        r, w = await tcp_send(lst.bound["tcp"], M3164[:20], close=False)
        await asyncio.sleep(0.05)
        w.write(M3164[20:] + b"\n")
        await w.drain()
        await wait_for(lambda: len(sink.got) == 1)
        w.close()
        await lst.stop()
        assert sink.got[0][0] == M3164
    run(go())


def test_oversize_and_bad_octet_count():
    async def go():
        sink = Sink()
        lst = await listener(sink, max_message_bytes=100)
        udp_send(lst.bound["udp"], b"<13>" + b"x" * 500)
        await tcp_send(lst.bound["tcp"], b"<13>" + b"y" * 500 + b"\n")      # line over the limit: connection closed
        await tcp_send(lst.bound["tcp"], b"9999 " + b"z" * 50)               # octet count over the limit
        await wait_for(lambda: lst.stats().get("oversize_dropped", 0) >= 3)
        await tcp_send(lst.bound["tcp"], M3164 + b"\n")                      # listener still healthy
        await wait_for(lambda: len(sink.got) == 1)
        await lst.stop()
        assert lst.stats()["framing_errors"] == 2
    run(go())


def test_udp_drops_when_queue_full_and_counts_it():
    async def go():
        sink = Sink(delay=0.2)
        lst = await listener(sink, tcp_port=None, queue_max=2)
        for _ in range(50):
            udp_send(lst.bound["udp"], M3164)
        await wait_for(lambda: lst.stats().get("queue_full_dropped", 0) > 0)
        await lst.stop(flush_timeout_s=2)
        st = lst.stats()
        assert st["udp_received"] + st["queue_full_dropped"] <= 50 and st["udp_received"] >= 1
    run(go())


def test_tcp_backpressure_loses_nothing():
    async def go():
        sink = Sink(delay=0.005)
        lst = await listener(sink, udp_port=None, queue_max=3)
        n = 60
        await tcp_send(lst.bound["tcp"], b"".join(M3164 + b"\n" for _ in range(n)))
        await wait_for(lambda: len(sink.got) == n, timeout=10)
        await lst.stop()
        assert lst.stats().get("queue_full_dropped", 0) == 0
    run(go())


def test_event_loop_stays_responsive_under_flood():
    async def go():
        sink = Sink()
        lst = await listener(sink, tcp_port=None)
        ticks, stop = [], False

        async def ticker():
            while not stop:
                t = time.monotonic()
                await asyncio.sleep(0.01)
                ticks.append(time.monotonic() - t)
        tk = asyncio.create_task(ticker())
        for _ in range(3000):
            udp_send(lst.bound["udp"], M3164)
            if _ % 200 == 0:
                await asyncio.sleep(0)
        await asyncio.sleep(0.3)
        stop = True
        await tk
        await lst.stop()
        assert max(ticks) < 0.5, max(ticks)
    run(go())


def test_connection_limit_and_idle_timeout():
    async def go():
        sink = Sink()
        lst = await listener(sink, udp_port=None, max_connections=1, idle_timeout_s=0.3)
        r1, w1 = await tcp_send(lst.bound["tcp"], b"", close=False)
        await wait_for(lambda: lst.stats()["tcp_connections"] == 1)
        r2, w2 = await tcp_send(lst.bound["tcp"], b"", close=False)
        await wait_for(lambda: lst.stats().get("connections_rejected", 0) == 1)
        await wait_for(lambda: lst.stats().get("idle_closed", 0) == 1, timeout=3)     # first one idles out
        for w in (w1, w2):
            w.close()
        await lst.stop()
    run(go())


def test_bind_failure_raises_and_cleans_up():
    async def go():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        lst = SyslogListener(Sink(), tcp_port=port)
        try:
            await lst.start()
            raise AssertionError("expected OSError")
        except OSError:
            pass
        finally:
            s.close()
    run(go())


def test_stop_flushes_queue():
    async def go():
        sink = Sink(delay=0.02)
        lst = await listener(sink, tcp_port=None)
        for _ in range(10):
            udp_send(lst.bound["udp"], M3164)
        await wait_for(lambda: lst.stats().get("udp_received", 0) == 10)
        await lst.stop()
        assert len(sink.got) == 10
    run(go())


def test_end_to_end_into_pipeline():
    """Real parser, real Pipeline: syslog over the wire becomes ECS with the right fields."""
    async def go():
        p = Pipeline(InMemoryBus(100), MetricsRegistry(), Settings(alert_db_path=":memory:", mock_enabled=False))
        await p.start()
        lst = await listener(p.submit, udp_port=None)
        await tcp_send(lst.bound["tcp"], M3164 + b"\n" + M5424 + b"\n" + b"<13>not really valid syslog?\n")
        await wait_for(lambda: p.metrics.processed == 2 and sum(p.metrics.dropped.values()) == 1)   # invalid line -> parse_error drop
        await lst.stop()
        await p.stop()
        docs = list(p.recent)
        assert any(d["host"]["name"] == "web-01" and d["source"]["ip"] == "185.220.101.4" for d in docs)
        assert any(d["host"]["name"] == "fw-01" for d in docs)
    run(go())


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_api_source_starts_and_stops_listener_and_reports_bind_error():
    port = free_port()
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        r = c.post("/api/v1/sources", json={"name": "fw-syslog", "type": "syslog", "protocol": "tcp", "port": port})
        assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["error"] is None
        sid = r.json()["id"]
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(M3164 + b"\n")
        s.close()
        deadline = time.time() + 3
        while c.get("/api/v1/metrics").json()["processed"] < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert c.get("/api/v1/metrics").json()["processed"] >= 1
        stats = c.get("/api/v1/sources/listeners").json()["items"]
        assert stats[0]["tcp_received"] == 1
        # same port again: registered, not active, with the reason
        r2 = c.post("/api/v1/sources", json={"name": "dup", "type": "syslog", "protocol": "tcp", "port": port})
        assert r2.status_code == 201 and r2.json()["status"] == "registered" and "could not bind" in r2.json()["error"]
        assert c.delete(f"/api/v1/sources/{sid}").status_code == 204
        s2 = socket.socket()
        s2.bind(("127.0.0.1", port))                 # port was released by the delete
        s2.close()


def test_settings_defined_listener():
    port = free_port()
    with TestClient(create_app(Settings(mock_enabled=False, syslog_udp_port=port))) as c:
        udp_send(port, M3164)
        deadline = time.time() + 3
        while c.get("/api/v1/metrics").json()["processed"] < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert c.get("/api/v1/metrics").json()["processed"] == 1
