"""Local stand-in for your SOC webhook + mail server, to watch LogUnify alerts arrive during development.

    python scripts/dev_alert_sink.py --http-port 9911 --smtp-port 2525 --secret "<any-dev-secret>" --out ./alert-sink

    LOGUNIFY_ALERT_WEBHOOK_URL=http://127.0.0.1:9911/hook   LOGUNIFY_ALERT_WEBHOOK_SECRET=<same-dev-secret>
    LOGUNIFY_ALERT_SMTP_HOST=127.0.0.1 LOGUNIFY_ALERT_SMTP_PORT=2525 LOGUNIFY_ALERT_SMTP_SECURITY=none
    LOGUNIFY_ALERT_EMAIL_FROM=logunify@example.org LOGUNIFY_ALERT_EMAIL_TO=soc@example.org

The webhook side verifies the HMAC signature exactly as a real receiver should (see docs/ALERTING.md) and can fail its
first N requests with 503 to demonstrate retry/backoff. Everything received is written under --out.
"""
import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.alerting.messages import verify_signature  # noqa: E402
from tests.alert_helpers import FakeSMTP  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--http-port", type=int, default=9911)
    ap.add_argument("--smtp-port", type=int, default=2525)
    ap.add_argument("--secret", default="")
    ap.add_argument("--fail-first", type=int, default=0, help="answer the first N webhook calls with 503")
    ap.add_argument("--out", default="alert-sink")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    state = {"n": 0, "failed": 0}
    lock = threading.Lock()

    class Hook(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            sig_ok = (not a.secret) or verify_signature(a.secret, self.headers.get("X-LogUnify-Timestamp", ""), body,
                                                        self.headers.get("X-LogUnify-Signature", ""))
            with lock:
                if state["failed"] < a.fail_first:
                    state["failed"] += 1
                    print(f"[webhook] -> 503 (simulated outage {state['failed']}/{a.fail_first})", flush=True)
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                state["n"] += 1
                n = state["n"]
            payload = json.loads(body)
            (out / f"webhook-{n:03d}-{payload['event']}.json").write_bytes(body)
            print(f"[webhook] #{n} {payload['event']:<18} signature {'VALID' if sig_ok else 'INVALID'}  {payload['text'][:110]}", flush=True)
            code = 200 if sig_ok else 401
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

    http = ThreadingHTTPServer(("127.0.0.1", a.http_port), Hook)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    with FakeSMTP(port=a.smtp_port) as smtp:
        print(f"sink ready: webhook http://127.0.0.1:{a.http_port}/hook  smtp 127.0.0.1:{a.smtp_port}  out={out}", flush=True)
        seen = 0
        try:
            while True:
                threading.Event().wait(0.5)
                while seen < len(smtp.messages):
                    sender, rcpts, raw = smtp.messages[seen]
                    seen += 1
                    (out / f"mail-{seen:03d}.eml").write_bytes(raw)
                    subject = next((l for l in raw.decode("utf-8", "replace").splitlines() if l.lower().startswith("subject:")), "")
                    print(f"[smtp]    #{seen} to {rcpts}  {subject[:110]}", flush=True)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
