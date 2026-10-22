import asyncio
import json
import os

import pytest
from aiohttp import web

from alerts.notifier import should_alert
from engine.analyzer import analyze
from parsers.ecs_mapper import to_ecs

W4625 = '{"EventID":4625,"Hostname":"WinServer-01","EventTime":"2026-10-01 17:30:00","TargetUserName":"admin","IpAddress":"203.0.113.9","LogonType":3}'
W4688 = ('{"EventID":4688,"Hostname":"WinServer-01","EventTime":"2026-10-01 17:31:00","SubjectUserName":"svc","NewProcessName":"C:\\\\Windows\\\\System32\\\\'
         'WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -EncodedCommand SQBFAFgA"}')
PG = '2026-10-01 12:00:00.123 UTC [1234] appuser@appdb FATAL:  password authentication failed for user "appuser"'
MY = "2026-10-01T12:00:00.123456Z 12 [Warning] [MY-010926] [Server] Access denied for user 'root'@'203.0.113.9' (using password: YES)"


def test_windows_fields_and_utc(monkeypatch):
    monkeypatch.setattr("parsers.ecs_mapper.SOURCE_TZ", __import__("zoneinfo").ZoneInfo("Asia/Kolkata"))
    ev = to_ecs(W4625)
    assert ev["event.original"] == W4625
    assert (ev["host.name"], ev["user.name"], ev["source.ip"]) == ("winserver-01", "admin", "203.0.113.9")
    assert ev["@timestamp"] == "2026-10-01T12:00:00+00:00"          # 17:30 IST -> 12:00 UTC


def test_db_logs():
    p = to_ecs(PG, "db-01")
    assert p["user.name"] == "appuser" and p["host.name"] == "db-01" and p["event.outcome"] == "failure" and p["@timestamp"].startswith("2026-10-01T12:00:00.123")
    m = to_ecs(MY, "db-02")
    assert m["user.name"] == "root" and m["source.ip"] == "203.0.113.9" and m["event.original"] == MY


def test_unknown_returns_none():
    assert to_ecs("garbage") is None and to_ecs('{"EventID":9999}') is None and to_ecs("{broken") is None


def test_scores_and_tags():
    assert analyze(to_ecs(W4625))["event.risk_score_norm"] == 0.5
    ev = analyze(to_ecs(W4688))
    assert ev["event.risk_score_norm"] == 0.85 and "T1059" in ev["threat.technique.id"]
    assert analyze(to_ecs(W4625))["threat.technique.id"] == ["T1110"]


def test_alert_rule_is_strictly_greater(monkeypatch):
    ev = analyze(to_ecs(W4688))
    monkeypatch.setenv("LOGUNIFY_ALERT_SCORE_THRESHOLD", "0.85")
    assert not should_alert(ev)                                     # equal is not enough
    monkeypatch.setenv("LOGUNIFY_ALERT_SCORE_THRESHOLD", "0.80")
    assert should_alert(ev)
    assert not should_alert(analyze(to_ecs(W4625)))                 # 0.5 and T1110 not critical


@pytest.mark.asyncio
async def test_end_to_end_tcp_to_webhook(tmp_path, monkeypatch):
    got = []

    async def hook(req):
        got.append(await req.json())
        return web.Response(text="ok")
    runner = web.AppRunner(web.Application())
    runner.app.router.add_post("/{t:.*}", hook)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    monkeypatch.setenv("LOGUNIFY_WEBHOOK_URL", f"http://127.0.0.1:{port}/x")
    monkeypatch.setenv("LOGUNIFY_REDIS_URL", "")
    import app as A
    monkeypatch.setattr(A, "DLQ_PATH", str(tmp_path / "dlq.jsonl"))
    pipe = A.Pipeline()
    await pipe.start()
    srv = await asyncio.start_server(lambda r, w: A.handle_client(pipe, r, w), "127.0.0.1", 0, limit=65536)
    p = srv.sockets[0].getsockname()[1]
    _, w = await asyncio.open_connection("127.0.0.1", p)
    w.write((W4625 + "\n" + W4688 + "\nnot a log\n" + PG).encode())     # last line has no newline
    await w.drain()
    w.close()
    await asyncio.sleep(0.3)
    await pipe.queue.join()
    srv.close()
    assert len(got) == 1 and "T1059" in got[0]["text"]
    assert got[0]["event"]["event.original"] == W4688
    dlq = [json.loads(x) for x in open(tmp_path / "dlq.jsonl")]
    assert [d["event.original"] for d in dlq] == ["not a log"]      # the unparsable line is kept, not lost
    await pipe.stop()
    await runner.cleanup()
