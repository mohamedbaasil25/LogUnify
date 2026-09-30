"""Shared fixtures for the alerting tests (plain module, imported by the test files)."""
import asyncio
import copy
import socketserver
import threading

from app.alerting.notifiers import DeliveryError


def deep_update(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v
    return base


def make_doc(**over) -> dict:
    """An ECS document as the pipeline would emit it for a high-scoring log-clearing event."""
    doc = {
        "@timestamp": "2026-09-30T09:15:00+00:00",
        "message": "Audit log cleared by user root on db-01 from 203.0.113.9",
        "host": {"name": "db-01"},
        "source": {"ip": "203.0.113.9"},
        "user": {"name": "root"},
        "event": {"id": "logunify.ecs:0:42", "original": "Audit log cleared by user root on db-01 from 203.0.113.9",
                  "dataset": "logunify.text"},
        "logunify": {"source_format": "text", "anomaly": {"score": 0.95, "model_ready": True},
                     "template": {"id": 5, "text": "Audit log cleared by user <*> on <*> from <IP>"},
                     "mitre": {"basis": "rule:log_clearing"}},
        "threat": {"framework": "MITRE ATT&CK", "technique": {"id": "T1070", "name": "Indicator Removal"},
                   "tactic": {"name": "Defense Evasion"}},
    }
    return deep_update(copy.deepcopy(doc), over)


def doc_for(host: str, **over) -> dict:
    """A distinct asset (distinct dedup key) per host."""
    return make_doc(host={"name": host}, event={"id": f"logunify.ecs:0:{abs(hash(host)) % 10_000}"}, **over)


class FakeClock:
    def __init__(self, t: float = 1_790_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeNotifier:
    def __init__(self, name: str = "fake", fail_first: int = 0, permanent: bool = False):
        self.name, self.label = name, name
        self.fail_first, self.permanent, self.down = fail_first, permanent, False
        self.calls, self.sent = 0, []

    async def send(self, msg) -> None:
        self.calls += 1
        if self.permanent:
            raise DeliveryError("permanent failure", retryable=False)
        if self.down or self.calls <= self.fail_first:
            raise DeliveryError("temporary failure", retryable=True)
        self.sent.append(msg)

    def kinds(self) -> list[str]:
        return [m.kind for m in self.sent]


def run(coro):
    return asyncio.run(coro)


NOW = 1_790_000_000.0


def make_alert(doc: dict | None = None, now: float = NOW):
    """A ready-made open Alert (for message / notifier tests that do not need a running manager)."""
    from app.alerting.models import Alert
    from app.alerting.rules import AlertRules
    doc = doc or make_doc()
    trig = AlertRules(0.9, "T1070", require_rule_basis=False).evaluate(doc)
    return Alert(id="ALR-20260930-deadbeef", dedup_key="k", status="open", created_at=now, due_at=now + 6 * 3600,
                 last_seen_at=now, occurrences=1, trigger=trig.as_dict(), doc=doc,
                 evidence={"record_sha256": "ab" * 32, "event_id": doc["event"]["id"]})


def make_message(kind: str = "incident.detected", now: float = NOW):
    from app.alerting.cert_in import OrgProfile, build_report
    from app.alerting.messages import build_message
    alert = make_alert(now=now)
    report = build_report(alert, OrgProfile(name="Acme Bank Ltd", poc_name="Asha Rao", poc_email="ciso@acme.example"), now=now)
    return build_message(kind, alert, report, now=now)


class FakeSMTP:
    """Minimal SMTP server (plaintext, no STARTTLS unless advertised) that records what real smtplib sends it."""

    def __init__(self, reject_rcpt: bool = False, temp_fail: bool = False, advertise_starttls: bool = False, port: int = 0):
        self.reject_rcpt, self.temp_fail, self.advertise_starttls = reject_rcpt, temp_fail, advertise_starttls
        self.messages: list[tuple[str, list[str], bytes]] = []
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                w, r = self.wfile, self.rfile
                w.write(b"220 fake ESMTP\r\n")
                mail_from, rcpts = "", []
                while True:
                    line = r.readline()
                    if not line:
                        return
                    cmd = line.decode("utf-8", "replace").strip()
                    up = cmd.upper()
                    if up.startswith(("EHLO", "HELO")):
                        w.write(b"250-fake\r\n" + (b"250-STARTTLS\r\n" if outer.advertise_starttls else b"") + b"250 8BITMIME\r\n")
                    elif up.startswith("MAIL FROM"):
                        if outer.temp_fail:
                            w.write(b"451 temporary local problem\r\n")
                        else:
                            mail_from = cmd.split(":", 1)[1].strip().strip("<>")
                            w.write(b"250 ok\r\n")
                    elif up.startswith("RCPT TO"):
                        if outer.reject_rcpt:
                            w.write(b"550 no such user\r\n")
                        else:
                            rcpts.append(cmd.split(":", 1)[1].strip().strip("<>"))
                            w.write(b"250 ok\r\n")
                    elif up == "DATA":
                        w.write(b"354 end with <CRLF>.<CRLF>\r\n")
                        chunks = []
                        while True:
                            part = r.readline()
                            if part == b".\r\n":
                                break
                            chunks.append(part[1:] if part.startswith(b"..") else part)
                        outer.messages.append((mail_from, list(rcpts), b"".join(chunks)))
                        w.write(b"250 queued\r\n")
                    elif up == "QUIT":
                        w.write(b"221 bye\r\n")
                        return
                    else:
                        w.write(b"250 ok\r\n")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server(("127.0.0.1", port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
