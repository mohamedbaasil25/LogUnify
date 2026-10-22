"""Storage backends for the durable state: SQLite (aiosqlite, default) or PostgreSQL (asyncpg).

`StateStore` writes dialect-neutral SQL with `?` placeholders and `INSERT ... ON CONFLICT ... DO UPDATE` upserts (valid in both).
A backend owns ONE connection; the store serialises flushes with its own lock, so a single transaction is open at a time.

SQLite: one file per replica (`{worker}` in the path), as before. A corrupt file is moved aside by `open()` and recreated.
PostgreSQL: one database for all replicas, one SCHEMA per replica (`logunify_<worker>`), so replicas keep the same ownership
model as the per-replica files but share one server (one backup, one place to monitor, no per-replica volumes). A session-level
advisory lock on the schema makes two processes with the same worker id fail fast instead of overwriting each other.
"""
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

import aiosqlite

log = logging.getLogger("logunify.state")


class SchemaTooNew(RuntimeError):
    pass


class SqliteBackend:
    kind = "sqlite"

    def __init__(self, path: str):
        self.path = path
        self._db: aiosqlite.Connection | None = None

    def describe(self) -> str:
        return self.path

    async def open(self, schema: str, version: int) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            await self._connect(schema, version)
        except sqlite3.DatabaseError as e:                           # "file is not a database", malformed image ...
            if self.path == ":memory:":
                raise
            aside = f"{self.path}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}"
            log.error("state database unreadable (%s); moved to %s and starting empty", e, aside)
            await self.close()
            os.replace(self.path, aside)
            await self._connect(schema, version)

    async def _connect(self, schema: str, version: int) -> None:
        self._db = await aiosqlite.connect(self.path)
        if self.path != ":memory:":
            await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        async with self._db.execute("PRAGMA user_version") as cur:
            ver = (await cur.fetchone())[0]
        if ver > version:
            raise SchemaTooNew(f"state file has schema v{ver}, this build understands v{version}")
        await self._db.executescript(schema)
        await self._db.execute(f"PRAGMA user_version={version}")
        await self._db.commit()
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    async def close(self) -> None:
        if self._db is not None:
            try:
                await self._db.close()
            except Exception:
                pass
            self._db = None

    async def fetchall(self, sql: str, args: tuple = ()) -> list[tuple]:
        async with self._db.execute(sql, args) as cur:
            return [tuple(r) for r in await cur.fetchall()]

    async def execute(self, sql: str, args: tuple = ()) -> None:
        await self._db.execute(sql, args)

    async def executemany(self, sql: str, rows: list) -> None:
        await self._db.executemany(sql, rows)

    async def begin(self) -> None:
        pass                                                         # sqlite opens its transaction on the first write

    async def commit(self) -> None:
        await self._db.commit()

    async def rollback(self) -> None:
        await self._db.rollback()


def pg_schema_name(worker_id: str) -> str:
    """`w3` -> `logunify_w3`. Identifiers are restricted to [a-z0-9_] so the name is safe to interpolate into SQL."""
    return "logunify_" + (re.sub(r"[^a-z0-9_]", "_", (worker_id or "0").lower())[:40] or "0")


def _qmarks_to_dollars(sql: str) -> str:
    n = 0

    def sub(_m):
        nonlocal n
        n += 1
        return f"${n}"
    return re.sub(r"\?", sub, sql)


def _clean(v):
    """PostgreSQL text cannot hold NUL; log-derived strings (IOC values, descriptions) might."""
    return v.replace("\x00", "") if isinstance(v, str) else v


class PostgresBackend:
    kind = "postgres"

    def __init__(self, dsn: str, worker_id: str = "0", connect_timeout_s: float = 10.0):
        self.dsn, self.schema_name, self.timeout = dsn, pg_schema_name(worker_id), connect_timeout_s
        self._conn = None
        self._tx = None
        self._schema_sql = ""
        self._version = 0

    def describe(self) -> str:
        """DSN without the password (it can come from a secret): postgresql://user@host:port/db#schema"""
        m = re.match(r"^(\w+://)(?:([^:@/]*)(?::[^@]*)?@)?([^/?#]*)(/[^?#]*)?", self.dsn)
        if not m:
            return f"postgresql://?#{self.schema_name}"
        scheme, user, host, db = m.groups()
        return f"{scheme}{user + '@' if user else ''}{host}{db or ''}#{self.schema_name}"

    async def open(self, schema: str, version: int) -> None:
        self._schema_sql, self._version = schema, version
        await self._connect()

    async def _connect(self) -> None:
        import asyncpg
        conn = await asyncpg.connect(self.dsn, timeout=self.timeout, server_settings={"application_name": "logunify-state"})
        try:
            await conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema_name}"')
            await conn.execute(f'SET search_path TO "{self.schema_name}"')
            key = await conn.fetchval("SELECT hashtext($1)", self.schema_name)
            if not await conn.fetchval("SELECT pg_try_advisory_lock($1)", key):
                raise RuntimeError(f"state schema {self.schema_name} is owned by another running instance: "
                                   "give each replica a distinct LOGUNIFY_WORKER_ID")
            await conn.execute("CREATE TABLE IF NOT EXISTS schema_info (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)")
            row = await conn.fetchrow("SELECT version FROM schema_info WHERE id=1")
            if row and row["version"] > self._version:
                raise SchemaTooNew(f"state schema has v{row['version']}, this build understands v{self._version}")
            async with conn.transaction():
                for stmt in filter(None, (s.strip() for s in self._schema_sql.split(";"))):
                    await conn.execute(stmt)
                await conn.execute("INSERT INTO schema_info(id, version) VALUES (1, $1) "
                                   "ON CONFLICT (id) DO UPDATE SET version=excluded.version", self._version)
        except BaseException:
            await conn.close()
            raise
        self._conn = conn

    async def close(self) -> None:
        if self._conn is not None:
            try:
                await self._conn.close(timeout=5)
            except Exception:
                pass
            self._conn = None

    async def _ensure(self) -> None:
        if self._conn is None or self._conn.is_closed():             # connection lost (server restart, failover): reconnect
            self._conn = None
            await self._connect()

    async def fetchall(self, sql: str, args: tuple = ()) -> list[tuple]:
        await self._ensure()
        return [tuple(r) for r in await self._conn.fetch(_qmarks_to_dollars(sql), *map(_clean, args))]

    async def execute(self, sql: str, args: tuple = ()) -> None:
        await self._conn.execute(_qmarks_to_dollars(sql), *map(_clean, args))

    async def executemany(self, sql: str, rows: list) -> None:
        await self._conn.executemany(_qmarks_to_dollars(sql), [tuple(map(_clean, r)) for r in rows])

    async def begin(self) -> None:
        await self._ensure()
        self._tx = self._conn.transaction()
        await self._tx.start()

    async def commit(self) -> None:
        tx, self._tx = self._tx, None
        if tx:
            await tx.commit()

    async def rollback(self) -> None:
        tx, self._tx = self._tx, None
        if tx and self._conn is not None and not self._conn.is_closed():
            await tx.rollback()


def make_backend(db_path: str, database_url: str = "", worker_id: str = "0"):
    if database_url:
        if not re.match(r"^postgres(ql)?://", database_url):
            raise ValueError("LOGUNIFY_STATE_DATABASE_URL must start with postgresql://")
        return PostgresBackend(database_url, worker_id)
    return SqliteBackend(db_path)
