import pytest

from app.config import Settings, acquire_slot

fcntl = pytest.importorskip("fcntl")          # Linux / macOS only (the container); skipped on Windows


def test_slots_are_leased_released_and_reused(tmp_path):
    d = str(tmp_path / "slots")
    a, fa = acquire_slot(d)
    b, fb = acquire_slot(d)
    assert (a, b) == ("w0", "w1")                       # two live replicas never share an id
    fa.close()                                          # replica 0 stops (or its container is re-created)
    c, fc = acquire_slot(d)
    assert c == "w0"                                    # ...and its successor gets the same identity back, so its stores are found
    for f in (fb, fc):
        f.close()


def test_worker_id_expands_in_paths(tmp_path):
    s = Settings(worker_id="w7", state_db_path="/data/{worker}/state.db", dlq_path="/data/{worker}/dlq.jsonl")
    assert s.state_db_path == "/data/w7/state.db" and s.dlq_path == "/data/w7/dlq.jsonl"
