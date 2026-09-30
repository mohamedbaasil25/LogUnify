"""Protocol-faithful mock destinations for testing the forwarder without Elasticsearch / Splunk installed.

    python scripts/mock_receivers.py --es-port 9200 --hec-port 8088

Elasticsearch mock (POST /_bulk): gzip bodies, NDJSON action/doc pairs; data streams accept ONLY `create` and only
for `logs-logunify-*`; a repeated `_id` returns 409 version_conflict_engine_exception (like real ES).
Splunk HEC mock: Authorization `Splunk <token>`, gzip bodies of concatenated JSON events, `ackId` in every response
plus /services/collector/ack polling (indexer acknowledgement), health endpoint.
Control plane (either port): POST /_test/fail?target=es|hec&n=3  -> next n requests get 503;
GET /_test/state -> counts and samples;  POST /_test/reset.
NOT a substitute for the real products: it only checks the parts of their protocols the forwarder relies on.
"""
import argparse
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOCK = threading.Lock()
S = {"es_docs": {}, "es_conflicts": 0, "es_bulk_calls": 0, "es_rejected_actions": 0, "es_auth": set(),
     "hec_events": [], "hec_calls": 0, "hec_acks_polled": 0, "hec_next_ack": 1, "hec_channels": set(), "hec_bad_token": 0,
     "fail": {"es": 0, "hec": 0}, "hec_token": "test-hec-token"}


def body_of(h) -> bytes:
    raw = h.rfile.read(int(h.headers.get("Content-Length") or 0))
    return gzip.decompress(raw) if h.headers.get("Content-Encoding") == "gzip" else raw


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "es"

    def log_message(self, *a):
        pass

    def send_json(self, code: int, obj: dict, extra: dict | None = None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    # ---- control plane
    def control(self, u) -> bool:
        if not u.path.startswith("/_test/"):
            return False
        q = parse_qs(u.query)
        with LOCK:
            if u.path == "/_test/fail":
                S["fail"][q["target"][0]] = int(q.get("n", ["1"])[0])
                self.send_json(200, {"fail": S["fail"]})
            elif u.path == "/_test/reset":
                S["es_docs"].clear(); S["hec_events"].clear()
                S.update(es_conflicts=0, es_bulk_calls=0, es_rejected_actions=0, hec_calls=0, hec_acks_polled=0, hec_bad_token=0)
                S["fail"] = {"es": 0, "hec": 0}
                self.send_json(200, {"reset": True})
            else:
                self.send_json(200, {
                    "es_docs": len(S["es_docs"]), "es_conflicts": S["es_conflicts"], "es_bulk_calls": S["es_bulk_calls"],
                    "es_rejected_actions": S["es_rejected_actions"], "es_auth_values": sorted(S["es_auth"]),
                    "hec_events": len(S["hec_events"]), "hec_calls": S["hec_calls"], "hec_acks_polled": S["hec_acks_polled"],
                    "hec_channels": len(S["hec_channels"]), "hec_bad_token": S["hec_bad_token"],
                    "es_sample": list(S["es_docs"].values())[:1], "hec_sample": S["hec_events"][:1],
                    "es_ids": sorted(S["es_docs"]) if q.get("ids") else None,
                    "hec_event_ids": [e.get("event", {}).get("event", {}).get("id") for e in S["hec_events"]] if q.get("ids") else None})
        return True

    def do_GET(self):
        u = urlparse(self.path)
        if self.control(u):
            return
        if self.mode == "es":
            if u.path == "/":
                return self.send_json(200, {"name": "mock", "cluster_name": "mock-es", "version": {"number": "8.17.0"},
                                            "tagline": "You Know, for Search"}, {"X-Elastic-Product": "Elasticsearch"})
            if u.path.startswith("/_cluster/health"):
                return self.send_json(200, {"status": "green"}, {"X-Elastic-Product": "Elasticsearch"})
        elif u.path.startswith("/services/collector/health"):
            return self.send_json(200, {"text": "HEC is healthy", "code": 17})
        self.send_json(404, {"error": "not found"})

    do_HEAD = do_GET

    def do_POST(self):
        u = urlparse(self.path)
        if self.control(u):
            return
        body = body_of(self)
        (self.es if self.mode == "es" else self.hec)(u, body)

    # ---- Elasticsearch
    def es(self, u, body):
        if u.path != "/_bulk":
            return self.send_json(404, {"error": "not found"})
        with LOCK:
            S["es_bulk_calls"] += 1
            S["es_auth"].add(self.headers.get("Authorization", ""))
            if S["fail"]["es"] > 0:
                S["fail"]["es"] -= 1
                return self.send_json(503, {"error": {"type": "es_rejected_execution_exception"}})
            lines = [l for l in body.decode().split("\n") if l.strip()]
            items = []
            for i in range(0, len(lines) - 1, 2):
                action, meta = next(iter(json.loads(lines[i]).items()))
                doc = json.loads(lines[i + 1])
                idx, _id = meta.get("_index", ""), meta.get("_id")
                if action != "create" or not idx.startswith("logs-logunify-"):
                    S["es_rejected_actions"] += 1
                    items.append({action: {"_index": idx, "status": 400, "error": {"type": "illegal_argument_exception",
                                  "reason": "only op_type=create into logs-logunify-* data streams is allowed"}}})
                elif _id is not None and _id in S["es_docs"]:
                    S["es_conflicts"] += 1
                    items.append({"create": {"_index": idx, "_id": _id, "status": 409, "error": {
                        "type": "version_conflict_engine_exception",
                        "reason": f"[{_id}]: version conflict, document already exists (current version [1])"}}})
                else:
                    S["es_docs"][_id or f"auto-{len(S['es_docs'])}"] = {"_index": idx, "_source": doc}
                    items.append({"create": {"_index": idx, "_id": _id, "_version": 1, "result": "created", "status": 201}})
            errors = any(next(iter(it.values()))["status"] >= 300 for it in items)
        self.send_json(200, {"took": 1, "errors": errors, "items": items}, {"X-Elastic-Product": "Elasticsearch"})

    # ---- Splunk HEC
    def hec(self, u, body):
        if self.headers.get("Authorization") != f"Splunk {S['hec_token']}":
            with LOCK:
                S["hec_bad_token"] += 1
            return self.send_json(403, {"text": "Invalid token", "code": 4})
        if u.path == "/services/collector/ack":
            acks = json.loads(body).get("acks", [])
            with LOCK:
                S["hec_acks_polled"] += 1
            return self.send_json(200, {"acks": {str(a): True for a in acks}})
        if u.path not in ("/services/collector/event", "/services/collector"):
            return self.send_json(404, {"text": "Not found", "code": 404})
        with LOCK:
            S["hec_calls"] += 1
            if S["fail"]["hec"] > 0:
                S["fail"]["hec"] -= 1
                return self.send_json(503, {"text": "Server is busy", "code": 9})
            chan = self.headers.get("X-Splunk-Request-Channel")
            if chan:
                S["hec_channels"].add(chan)
            dec, text, pos, n = json.JSONDecoder(), body.decode(), 0, 0
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos >= len(text):
                    break
                obj, pos = dec.raw_decode(text, pos)
                S["hec_events"].append(obj)
                n += 1
            ack = S["hec_next_ack"]
            S["hec_next_ack"] += 1
        self.send_json(200, {"text": "Success", "code": 0, "ackId": ack})


def serve(port: int, mode: str) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), type("H", (Handler,), {"mode": mode}))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--es-port", type=int, default=9200)
    ap.add_argument("--hec-port", type=int, default=8088)
    ap.add_argument("--hec-token", default="test-hec-token")
    a = ap.parse_args()
    S["hec_token"] = a.hec_token
    serve(a.es_port, "es")
    serve(a.hec_port, "hec")
    print(f"mock ES on :{a.es_port}, mock Splunk HEC on :{a.hec_port}", flush=True)
    threading.Event().wait()
