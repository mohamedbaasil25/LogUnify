import copy
import hashlib
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.integrity.batcher import BatchBuilder
from app.integrity.cli import main as cli_main
from app.integrity.ledger import MockFabricLedger
from app.integrity.merkle import (LEAF_PREFIX, NODE_PREFIX, build_tree, canonical, hash_record,
                                  make_proof, merkle_root, verify_proof)
from app.main import create_app


def docs(n):
    return [{"@timestamp": f"2026-01-01T00:00:{i % 60:02d}+00:00", "message": f"event {i}",
             "source": {"ip": f"10.0.0.{i % 250}"}, "n": i} for i in range(n)]


def test_root_matches_manual_computation():
    a, b = docs(2)
    la, lb = (hashlib.sha256(b"\x00" + canonical(x)).digest() for x in (a, b))
    assert merkle_root([a, b]) == hashlib.sha256(b"\x01" + la + lb).hexdigest()


def test_key_order_does_not_change_hash():
    assert hash_record({"a": 1, "b": {"c": 2, "d": 3}}) == hash_record({"b": {"d": 3, "c": 2}, "a": 1})


@pytest.mark.parametrize("n", [1, 2, 3, 5, 7, 8, 100])
def test_every_proof_verifies(n):
    recs = docs(n)
    levels = build_tree([hash_record(r) for r in recs])
    root = levels[-1][0].hex()
    for i, r in enumerate(recs):
        assert verify_proof(r, make_proof(levels, i), root)


def test_tampering_is_detected():
    recs = docs(9)
    levels = build_tree([hash_record(r) for r in recs])
    root = levels[-1][0].hex()
    proof = make_proof(levels, 4)
    bad = copy.deepcopy(recs[4]); bad["source"]["ip"] = "6.6.6.6"
    assert not verify_proof(bad, proof, root)                                   # changed field
    assert not verify_proof(recs[4], make_proof(levels, 5), root)               # proof for another leaf
    assert not verify_proof(recs[4], proof, "0" * 64)                           # wrong root
    flipped = [{**s, "position": "right" if s["position"] == "left" else "left"} for s in proof]
    assert not verify_proof(recs[4], flipped, root)                             # swapped sides
    assert not verify_proof(recs[4], [{"hash": "zz", "position": "left"}], root)  # malformed proof
    extra = {"message": "injected"}
    assert not verify_proof(extra, proof, root)                                 # foreign record


def test_domain_separation_and_no_duplicate_ambiguity():
    r = docs(1)[0]
    assert hashlib.sha256(LEAF_PREFIX + canonical(r)).digest() != hashlib.sha256(NODE_PREFIX + canonical(r)).digest()
    a, b, c = docs(3)
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])                  # unpaired node is promoted, not duplicated


def test_empty_batch_rejected():
    with pytest.raises(ValueError):
        build_tree([])


def test_batcher_seals_at_size_and_partial():
    b = BatchBuilder(size=100)
    sealed = [b.add(d) for d in docs(250)]
    assert [x.count for x in sealed if x] == [100, 100]
    assert b.pending == 50
    part = b.seal_partial()
    assert part.count == 50 and part.id == "batch-000003" and b.pending == 0
    assert b.seal_partial() is None
    p = b.proof(part.id, 7)
    assert verify_proof(p["record"], p["proof"], part.root)


def test_batcher_bounds_memory():
    b = BatchBuilder(size=2, max_batches=3)
    for d in docs(20):
        b.add(d)
    assert len(b.list()) == 3 and b.get("batch-000001") is None


def test_mock_ledger_receipt_and_idempotence():
    led = MockFabricLedger()
    r1 = led.submit_anchor("batch-1", "ab" * 32)
    assert re.fullmatch(r"[0-9a-f]{64}", r1.tx_id) and r1.timestamp and r1.block_number == 1 and r1.mock
    assert led.submit_anchor("batch-1", "ab" * 32) is r1
    assert led.submit_anchor("batch-2", "cd" * 32).block_number == 2
    assert led.get_anchor(r1.tx_id) is r1 and led.get_anchor("nope") is None


def test_cli_prints_roots_and_verified_proof(capsys, tmp_path):
    f = tmp_path / "logs.ndjson"
    f.write_text("\n".join(json.dumps(d) for d in docs(250)), encoding="utf-8")
    assert cli_main([str(f), "--proof", "205"]) == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.strip().splitlines()]
    assert [x["records"] for x in lines if "batch" in x] == [100, 100, 50]
    assert next(x for x in lines if "proof_for_record" in x)["verified"] is True
    assert cli_main(["--mock", "30", "--batch-size", "10"]) == 0


# ---------------------------------------------------------------- API
@pytest.fixture
def client():
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        yield c


def ingest_batch(c, n=100):
    lines = [json.dumps({"timestamp": "2026-01-01T00:00:00Z", "host": f"h{i}", "message": f"m{i}", "src_ip": "8.8.8.8"})
             for i in range(n)]
    assert c.post("/api/v1/ingest", json={"logs": lines}).status_code == 202
    for _ in range(100):
        items = c.get("/api/v1/integrity/batches").json()["items"]
        if items:
            return items[0]
        time.sleep(0.05)
    raise AssertionError("batch never sealed")


def test_api_end_to_end(client):
    batch = ingest_batch(client)
    assert batch["count"] == 100 and batch["anchor"]["status"] == "VALID" and batch["anchor"]["mock"]
    assert client.get("/api/v1/metrics").json()["integrity"] == {"batches_sealed": 1, "batches_anchored": 1}
    tx = batch["anchor"]["tx_id"]
    assert client.get(f"/api/v1/integrity/anchors/{tx}").json()["merkle_root"] == batch["merkle_root"]

    p = client.get(f"/api/v1/integrity/batches/{batch['id']}/proof/37").json()
    body = {"record": p["record"], "proof": p["proof"], "merkle_root": p["merkle_root"], "batch_id": batch["id"]}
    r = client.post("/api/v1/integrity/verify", json=body).json()
    assert r["valid"] and r["anchored"] and r["anchor_root_matches"] and r["tx_id"] == tx

    tampered = copy.deepcopy(body); tampered["record"]["host"] = {"name": "evil"}
    r = client.post("/api/v1/integrity/verify", json=tampered).json()
    assert not r["valid"] and not r["proof_valid"]

    # attacker re-computes a self-consistent proof for a forged root: proof is valid, ledger anchor disagrees
    forged_rec = {"message": "forged"}
    forged_root = merkle_root([forged_rec])
    r = client.post("/api/v1/integrity/verify", json={"record": forged_rec, "proof": [], "merkle_root": forged_root,
                                                      "batch_id": batch["id"]}).json()
    assert r["proof_valid"] and r["anchored"] and not r["anchor_root_matches"] and not r["valid"]


def test_api_seal_anchor_and_errors():
    with TestClient(create_app(Settings(mock_enabled=False, integrity_auto_anchor=False))) as c:
        assert c.post("/api/v1/integrity/seal").status_code == 409
        c.post("/api/v1/ingest", json={"logs": ['{"message":"a"}', '{"message":"b"}', '{"message":"c"}']})
        for _ in range(100):
            if c.get("/api/v1/integrity/batches").json()["pending_records"] == 3:
                break
            time.sleep(0.05)
        b = c.post("/api/v1/integrity/seal").json()
        assert b["count"] == 3 and b["anchor"] is None
        a1 = c.post("/api/v1/integrity/anchor", json={"batch_id": b["id"]})
        a2 = c.post("/api/v1/integrity/anchor", json={"batch_id": b["id"]})
        assert a1.status_code == 201 and a1.json()["tx_id"] == a2.json()["tx_id"]
        assert c.post("/api/v1/integrity/anchor", json={"batch_id": "nope"}).status_code == 404
        assert c.get(f"/api/v1/integrity/batches/{b['id']}/proof/3").status_code == 404
        assert c.get("/api/v1/integrity/anchors/deadbeef").status_code == 404
        bad = {"record": {}, "proof": [{"hash": "xyz", "position": "left"}], "merkle_root": "0" * 64}
        assert c.post("/api/v1/integrity/verify", json=bad).status_code == 422


# ------------------------------------------------- hash-level + batch-level verification
def test_verify_by_leaf_hash_only(client):
    batch = ingest_batch(client)
    p = client.get(f"/api/v1/integrity/batches/{batch['id']}/proof/12").json()
    h = client.post("/api/v1/integrity/hash", json={"record": p["record"]}).json()
    assert h["leaf_hash"] == p["leaf_hash"] and h["canonical_json"].startswith("{")
    body = {"leaf_hash": p["leaf_hash"], "proof": p["proof"], "merkle_root": p["merkle_root"], "batch_id": batch["id"]}
    r = client.post("/api/v1/integrity/verify", json=body).json()
    assert r["valid"] and r["anchor_root_matches"]
    bad = {**body, "leaf_hash": "0" * 64}
    assert not client.post("/api/v1/integrity/verify", json=bad).json()["valid"]
    both = {**body, "record": p["record"]}
    assert client.post("/api/v1/integrity/verify", json=both).status_code == 422          # exactly one of the two
    assert client.post("/api/v1/integrity/verify", json={k: v for k, v in body.items() if k != "leaf_hash"}).status_code == 422


def all_records(c, batch):
    return [c.get(f"/api/v1/integrity/batches/{batch['id']}/proof/{i}").json()["record"] for i in range(batch["count"])]


def test_verify_batch_detects_tamper_missing_extra(client):
    batch = ingest_batch(client)
    recs = all_records(client, batch)
    ok = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": recs,
                                                             "expected_root": batch["merkle_root"]}).json()
    assert ok["valid"] and ok["anchored"] and ok["tampered_count"] == 0 and ok["computed_root"] == batch["merkle_root"]
    assert ok["checks"] == {"matches_batch_root": True, "matches_ledger_anchor": True, "matches_expected_root": True}

    t = copy.deepcopy(recs); t[3]["message"] = "edited"; t[77]["host"] = {"name": "evil"}
    r = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": t}).json()
    assert not r["valid"] and r["tampered_indexes"] == [3, 77] and not r["checks"]["matches_ledger_anchor"]

    r = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": recs[:90]}).json()
    assert not r["valid"] and r["missing_indexes"] == list(range(90, 100))
    r = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": recs + [{"x": 1}]}).json()
    assert not r["valid"] and r["extra_indexes"] == [100]
    r = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": list(reversed(recs))}).json()
    assert not r["valid"]                                                                 # order matters
    r = client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": recs,
                                                            "expected_root": "0" * 64}).json()
    assert not r["valid"] and r["checks"]["matches_expected_root"] is False
    assert client.post("/api/v1/integrity/verify-batch", json={"batch_id": "nope", "records": recs}).status_code == 404
    assert client.post("/api/v1/integrity/verify-batch", json={"batch_id": batch["id"], "records": []}).status_code == 422


def test_audit_detects_server_side_tampering():
    app = create_app(Settings(mock_enabled=False))
    with TestClient(app) as c:
        batch = ingest_batch(c)
        a = c.get(f"/api/v1/integrity/batches/{batch['id']}/audit").json()
        assert a["sealed_root_intact"] and a["ledger_root_matches"] and a["altered_indexes"] == []
        app.state.pipeline.batcher.get(batch["id"]).docs[9]["message"] = "rewritten after sealing"   # simulate DB tampering
        a = c.get(f"/api/v1/integrity/batches/{batch['id']}/audit").json()
        assert not a["sealed_root_intact"] and a["altered_indexes"] == [9] and a["ledger_root_matches"] is False
