"""Idempotently apply the LogUnify Elasticsearch lifecycle configuration (stdlib only).

    python elasticsearch/setup.py --url https://es.internal:9200 --auth "ApiKey <base64>" --repo s3
    python elasticsearch/setup.py --url http://localhost:9200 --repo fs --dry-run

Order matters: snapshot repository -> SLM policy (needs the repo) -> ILM policy (delete phase waits on the SLM policy)
-> index template (points at the ILM policy) -> data stream. Every step is a PUT, so re-running is safe.
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def steps(profile: str, repo: str, namespace: str, create_ds: bool):
    yield "snapshot repository", "PUT", "/_snapshot/logunify-archive", load(f"snapshot-repository-{repo}.json")
    yield "SLM policy", "PUT", "/_slm/policy/logunify-daily", load("slm-logunify-daily.json")
    ilm = "ilm-logunify-cert-in.json" if profile == "basic" else "ilm-logunify-cert-in-searchable.json"
    yield f"ILM policy ({profile})", "PUT", "/_ilm/policy/logunify-cert-in", load(ilm)
    yield "index template", "PUT", "/_index_template/logunify-ecs", load("index-template-logunify.json")
    if create_ds:
        yield "data stream", "PUT", f"/_data_stream/logs-logunify-{namespace}", None


def call(base: str, method: str, path: str, body: dict | None, auth: str | None, ctx) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--auth", help='Authorization header value, e.g. "ApiKey <base64>" (or set ES_AUTH_HEADER)')
    ap.add_argument("--profile", choices=["basic", "enterprise"], default="basic",
                    help="enterprise = searchable-snapshot cold/frozen tiers (needs that license)")
    ap.add_argument("--repo", choices=["s3", "fs"], default="s3")
    ap.add_argument("--namespace", default="prod")
    ap.add_argument("--create-data-stream", action="store_true")
    ap.add_argument("--ca-file", help="CA bundle for a private CA")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (local testing only)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    import os
    auth = a.auth or os.environ.get("ES_AUTH_HEADER")
    ctx = ssl.create_default_context(cafile=a.ca_file)
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

    failed = False
    for label, method, path, body in steps(a.profile, a.repo, a.namespace, a.create_data_stream):
        if a.dry_run:
            print(f"[dry-run] {method} {path}  ({label})")
            continue
        status, text = call(a.url.rstrip("/"), method, path, body, auth, ctx)
        ok = 200 <= status < 300
        print(f"{'OK  ' if ok else 'FAIL'} {status} {method} {path}  ({label})" + ("" if ok else f"\n     {text[:600]}"))
        failed |= not ok
        if not ok:
            break                                   # later steps depend on earlier ones
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
