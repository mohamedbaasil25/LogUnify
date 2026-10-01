"""Encrypted, append-only archive of RAW logs, keyed by event.id: the evidence behind every normalized document.

Why it exists: normalized documents carry `event.hash` = SHA-256 of the exact bytes received, but `event.original` is the
PII-REDACTED text. To prove what was really received (CERT-In evidence, an audit, a dispute) the unredacted bytes must exist
somewhere, and they must be protected like the sensitive data they are. So:
  * every record is zlib-compressed and AES-256-GCM encrypted (key from LOGUNIFY_RAW_ARCHIVE_KEY, event.id bound as authenticated
    data so a record cannot be swapped for another id); the SQLite index holds only ids, hashes and positions, never content;
  * with PII redaction on, the archive refuses to start without a key (plaintext only with an explicit opt-in);
  * records are appended to segment files that are never rewritten; retention deletes whole segments (crypto-shredding by
    deletion), and `get()` re-verifies the SHA-256 of what it decrypts against the index.
Writing is off the event loop: `put()` is a non-blocking queue push, a daemon thread appends + fsyncs in batches and updates the
index. If the queue is full the record is NOT archived and `dropped` counts it (alert on it). A crash can lose the records still in
the queue, and between the segment write and the index commit a record can be written but unindexed (get() then reports not found).
Key rotation is not implemented (re-encrypt by replaying segments). Keep the key out of the archive's backup.
"""
import base64
import hashlib
import logging
import os
import queue
import sqlite3
import struct
import threading
import time
import zlib
from pathlib import Path

from ..integrity.merkle import hash_record

log = logging.getLogger("logunify.archive")
_STOP = object()
_MAGIC_ENC, _MAGIC_PLAIN = b"E", b"P"


class ArchiveError(Exception):
    pass


def parse_key(b64: str) -> bytes:
    try:
        k = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise ArchiveError("LOGUNIFY_RAW_ARCHIVE_KEY must be base64") from e
    if len(k) != 32:
        raise ArchiveError("LOGUNIFY_RAW_ARCHIVE_KEY must decode to exactly 32 bytes (AES-256): "
                           "python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\"")
    return k


class RawArchive:
    def __init__(self, directory: str, key: bytes | None, segment_mb: int = 64, retention_days: int = 0,
                 queue_max: int = 200_000, require_key: bool = True):
        if key is None and require_key:
            raise ArchiveError("raw archive needs LOGUNIFY_RAW_ARCHIVE_KEY (or LOGUNIFY_RAW_ARCHIVE_ALLOW_PLAINTEXT=true)")
        self.dir, self.key = Path(directory), key
        self.segment_bytes, self.retention_days = segment_mb * 1024 * 1024, retention_days
        self.dir.mkdir(parents=True, exist_ok=True)
        self._aes = None
        if key is not None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aes = AESGCM(key)
        self._db = sqlite3.connect(str(self.dir / "index.db"), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS raw (event_id TEXT PRIMARY KEY, segment TEXT NOT NULL, off INTEGER NOT NULL, "
                         "len INTEGER NOT NULL, raw_sha256 TEXT NOT NULL, doc_sha256 TEXT, ts REAL NOT NULL)")
        self._db.commit()
        self._dblock = threading.Lock()
        self._q: queue.Queue = queue.Queue(maxsize=queue_max)
        self._seg: Path | None = None
        self._seg_size = 0
        self.c = {"archived": 0, "dropped": 0, "write_errors": 0, "purged_segments": 0}
        self._thread = threading.Thread(target=self._writer, name="raw-archive-writer", daemon=True)
        self._thread.start()
        self.purge_expired()

    @property
    def encrypted(self) -> bool:
        return self._aes is not None

    # ---- write path -------------------------------------------------------------------------------------------------
    def put(self, event_id: str, raw: bytes, doc: dict | None = None) -> bool:
        try:
            self._q.put_nowait((event_id, raw, doc))
            return True
        except queue.Full:
            self.c["dropped"] += 1
            if self.c["dropped"] in (1, 100) or self.c["dropped"] % 10_000 == 0:
                log.error("raw archive queue full: %d records NOT archived (the logs themselves were processed)", self.c["dropped"])
            return False

    def _encode(self, event_id: str, raw: bytes) -> bytes:
        body = zlib.compress(raw, 3)
        if self._aes is None:
            return _MAGIC_PLAIN + body
        nonce = os.urandom(12)
        return _MAGIC_ENC + nonce + self._aes.encrypt(nonce, body, event_id.encode())

    def _decode(self, event_id: str, blob: bytes) -> bytes:
        if blob[:1] == _MAGIC_PLAIN:
            return zlib.decompress(blob[1:])
        if blob[:1] != _MAGIC_ENC or self._aes is None:
            raise ArchiveError("record is encrypted but no key is configured (or the record is corrupt)")
        return zlib.decompress(self._aes.decrypt(blob[1:13], blob[13:], event_id.encode()))

    def _segment(self) -> Path:
        if self._seg is None or self._seg_size >= self.segment_bytes:
            self._seg = self.dir / f"seg-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{int(time.time() * 1000) % 100000:05d}.bin"
            self._seg_size = self._seg.stat().st_size if self._seg.exists() else 0
        return self._seg

    def _writer(self) -> None:
        while True:
            first = self._q.get()
            batch, stop = [first], first is _STOP
            while not stop and len(batch) < 500:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                stop = nxt is _STOP
                batch.append(nxt)
            recs = [b for b in batch if b is not _STOP]
            if recs:
                try:
                    self._append(recs)
                except Exception:
                    self.c["write_errors"] += len(recs)
                    log.exception("raw archive write failed for %d records", len(recs))
            for _ in batch:
                self._q.task_done()
            if stop:
                return

    def _append(self, recs: list) -> None:
        seg = self._segment()
        rows = []
        with open(seg, "ab") as f:
            pos = f.tell()
            for event_id, raw, doc in recs:
                blob = self._encode(event_id, raw)
                f.write(struct.pack(">I", len(blob)) + blob)
                rows.append((event_id, seg.name, pos + 4, len(blob), hashlib.sha256(raw).hexdigest(),
                             hash_record(doc).hex() if doc else None, time.time()))
                pos += 4 + len(blob)
            f.flush()
            os.fsync(f.fileno())
        self._seg_size = pos
        with self._dblock:
            self._db.executemany("INSERT OR REPLACE INTO raw VALUES (?,?,?,?,?,?,?)", rows)
            self._db.commit()
        self.c["archived"] += len(rows)

    # ---- read path --------------------------------------------------------------------------------------------------
    def flush(self, timeout_s: float = 10.0) -> None:
        end = time.monotonic() + timeout_s
        while self._q.unfinished_tasks and time.monotonic() < end:
            time.sleep(0.005)

    def lookup(self, event_id: str) -> dict | None:
        with self._dblock:
            row = self._db.execute("SELECT segment, off, len, raw_sha256, doc_sha256, ts FROM raw WHERE event_id=?", (event_id,)).fetchone()
        return dict(zip(("segment", "off", "len", "raw_sha256", "doc_sha256", "ts"), row)) if row else None

    def get(self, event_id: str) -> dict | None:
        """Decrypt and return the raw bytes with an integrity verdict, or None if unknown. Raises ArchiveError if the record
        cannot be read (missing/corrupt segment, wrong key): a missing-evidence situation must be loud, not 'not found'."""
        meta = self.lookup(event_id)
        if meta is None:
            return None
        path = self.dir / meta["segment"]
        if not path.exists():
            raise ArchiveError(f"segment {meta['segment']} is gone (retention purge or deletion)")
        with open(path, "rb") as f:
            f.seek(meta["off"])
            blob = f.read(meta["len"])
        try:
            raw = self._decode(event_id, blob)
        except Exception as e:
            raise ArchiveError(f"record cannot be decrypted/decompressed: {type(e).__name__}") from e
        digest = hashlib.sha256(raw).hexdigest()
        return {"raw": raw, "sha256": digest, "doc_sha256": meta["doc_sha256"], "stored_at": meta["ts"],
                "intact": digest == meta["raw_sha256"]}

    # ---- retention --------------------------------------------------------------------------------------------------
    def purge_expired(self) -> int:
        """Delete segments whose newest write is older than `retention_days` (0 = keep everything). Whole-segment deletion
        is what makes retention enforceable; index rows for the deleted segments are removed too."""
        if self.retention_days <= 0:
            return 0
        cutoff, n = time.time() - self.retention_days * 86400, 0
        for seg in self.dir.glob("seg-*.bin"):
            if seg != self._seg and seg.stat().st_mtime < cutoff:
                seg.unlink()
                with self._dblock:
                    self._db.execute("DELETE FROM raw WHERE segment=?", (seg.name,))
                    self._db.commit()
                n += 1
        self.c["purged_segments"] += n
        return n

    def stats(self) -> dict:
        with self._dblock:
            n = self._db.execute("SELECT COUNT(*) FROM raw").fetchone()[0]
        segs = list(self.dir.glob("seg-*.bin"))
        return {"encrypted": self.encrypted, "records_indexed": n, "segments": len(segs),
                "bytes": sum(s.stat().st_size for s in segs), "queued": self._q.qsize(),
                "retention_days": self.retention_days or None, **self.c}

    def close(self, timeout_s: float = 10.0) -> None:
        self._q.put(_STOP)
        self._thread.join(timeout_s)
        with self._dblock:
            self._db.close()
