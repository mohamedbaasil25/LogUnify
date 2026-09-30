"""Asynchronous Syslog listener (UDP + TCP) that feeds the pipeline.

Division of labour: this module only receives and frames. RFC 3164 / RFC 5424 parsing stays in `parsers/syslog.py` and runs in
the pipeline's consumer, so there is one parser, and PII redaction, enrichment and metrics apply to syslog exactly as they do to
HTTP push. A listener hands each frame to `submit(raw, hint)` (normally `Pipeline.submit`, which enqueues on the bus).

Non-blocking design
  * Everything is asyncio I/O on the caller's event loop; nothing here blocks or does CPU-heavy work.
  * A bounded `asyncio.Queue` decouples the sockets from `submit`. UDP has no back-pressure, so a full queue DROPS the datagram
    (counted). TCP `await`s the put, which stops reading the socket and lets TCP flow control slow the sender: no loss.
  * The drain task only awaits `submit`; parsing cost is the pipeline's, as for every other input.

Framing
  UDP  one message per datagram (RFC 5426).
  TCP  per message, auto-detected from its first byte (RFC 6587):
       octet counting  `<len> <msg>`  (a digit run followed by a space), else
       non-transparent framing: a message ends at LF (a trailing CR is stripped).
       A line that merely starts with digits falls back to newline framing.

Limits (all counted, see `stats()`): max message bytes, max concurrent TCP connections, idle timeout per connection.
Not implemented: TLS (RFC 5425), so keep the default loopback bind or put a TLS terminator in front. Plain syslog is unauthenticated
and spoofable (UDP source addresses especially): treat its content as untrusted input.
Ports below 1024 (514) need elevated rights on Linux (CAP_NET_BIND_SERVICE); bind failures are raised from `start()`.
"""
import asyncio
import logging
from collections import Counter
from typing import Awaitable, Callable

log = logging.getLogger("logunify.syslog")
Submit = Callable[[bytes, str | None], Awaitable[bool]]


class _Framing(Exception):
    """Unrecoverable framing error on a TCP stream: the connection is closed."""


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "SyslogListener"):
        self.o = owner

    def datagram_received(self, data: bytes, addr) -> None:
        self.o._offer(data, udp=True)

    def error_received(self, exc: Exception) -> None:         # ICMP errors etc.; never fatal
        self.o.stats_c["udp_socket_errors"] += 1


class SyslogListener:
    def __init__(self, submit: Submit, host: str = "127.0.0.1", udp_port: int | None = None, tcp_port: int | None = None,
                 hint: str | None = None, queue_max: int = 10_000, max_message_bytes: int = 8192,
                 max_connections: int = 256, idle_timeout_s: float = 300.0, name: str = "syslog"):
        if udp_port is None and tcp_port is None:
            raise ValueError("enable at least one of udp_port / tcp_port")
        self.submit, self.host, self.hint, self.name = submit, host, hint, name
        self.udp_port, self.tcp_port = udp_port, tcp_port
        self.max_msg, self.max_conns, self.idle = max_message_bytes, max_connections, idle_timeout_s
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=queue_max)
        self.stats_c: Counter[str] = Counter()
        self._transport: asyncio.DatagramTransport | None = None
        self._server: asyncio.AbstractServer | None = None
        self._drain: asyncio.Task | None = None
        self._conns: set[asyncio.Task] = set()
        self.bound: dict[str, int] = {}          # actual ports (useful when 0 = ephemeral was requested)

    # ---- lifecycle ---------------------------------------------------------------------------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            if self.udp_port is not None:
                self._transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), local_addr=(self.host, self.udp_port))
                self.bound["udp"] = self._transport.get_extra_info("sockname")[1]
            if self.tcp_port is not None:
                self._server = await asyncio.start_server(self._on_connect, self.host, self.tcp_port,
                                                          limit=self.max_msg + 16)     # default reuse_address: True on POSIX, False on Windows (True there would allow port hijack)
                self.bound["tcp"] = self._server.sockets[0].getsockname()[1]
        except Exception:
            await self.stop()
            raise
        self._drain = asyncio.create_task(self._drain_loop(), name=f"{self.name}-drain")
        log.info("%s listening on %s %s", self.name, self.host, self.bound)

    async def stop(self, flush_timeout_s: float = 5.0) -> None:
        if self._server:
            self._server.close()                               # stop accepting; existing connections are cancelled below
        if self._transport:
            self._transport.close()
        for t in list(self._conns):
            t.cancel()
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)
        if self._drain:
            try:
                await asyncio.wait_for(self.queue.join(), flush_timeout_s)     # let queued messages reach the pipeline
            except asyncio.TimeoutError:
                log.warning("%s: %d queued messages not flushed at shutdown", self.name, self.queue.qsize())
            self._drain.cancel()
            await asyncio.gather(self._drain, return_exceptions=True)
        self._server = self._transport = self._drain = None

    def stats(self) -> dict:
        return {"name": self.name, "host": self.host, "ports": dict(self.bound), "queue_depth": self.queue.qsize(),
                "queue_max": self.queue.maxsize, "tcp_connections": len(self._conns), **self.stats_c}

    # ---- intake --------------------------------------------------------------------------------------------------
    def _offer(self, data: bytes, udp: bool) -> None:
        """Non-blocking enqueue used by UDP. Drops (and counts) when the queue is full: UDP cannot be back-pressured."""
        data = data.rstrip(b"\r\n\x00")
        if not data.strip():
            return
        if len(data) > self.max_msg:
            self.stats_c["oversize_dropped"] += 1
            return
        try:
            self.queue.put_nowait(data)
            self.stats_c["udp_received" if udp else "tcp_received"] += 1
        except asyncio.QueueFull:
            self.stats_c["queue_full_dropped"] += 1

    async def _drain_loop(self) -> None:
        while True:
            raw = await self.queue.get()
            try:
                if not await self.submit(raw, self.hint):
                    self.stats_c["pipeline_rejected"] += 1     # oversize / bus full: the pipeline already counted the drop reason
            except Exception:
                self.stats_c["submit_errors"] += 1
                log.exception("%s: submit failed; message dropped", self.name)
            finally:
                self.queue.task_done()

    # ---- TCP -----------------------------------------------------------------------------------------------------
    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._conns) >= self.max_conns:
            self.stats_c["connections_rejected"] += 1
            writer.close()
            return
        task = asyncio.current_task()
        self._conns.add(task)
        self.stats_c["connections_total"] += 1
        try:
            while True:
                frame = await self._read_frame(reader)
                if frame is None:
                    break
                if not frame.strip():
                    continue
                try:
                    await asyncio.wait_for(self.queue.put(frame), self.idle)   # blocks => TCP back-pressure on this sender
                    self.stats_c["tcp_received"] += 1
                except asyncio.TimeoutError:
                    self.stats_c["queue_full_dropped"] += 1
        except asyncio.TimeoutError:
            self.stats_c["idle_closed"] += 1
        except _Framing as e:
            self.stats_c["framing_errors"] += 1
            log.warning("%s: closing connection: %s", self.name, e)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._conns.discard(task)
            writer.close()

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes | None:
        """Next message, or None on clean EOF. Raises _Framing when the stream cannot be re-synchronised."""
        while True:
            first = await asyncio.wait_for(reader.read(1), self.idle)
            if not first:
                return None
            if first in (b"\n", b"\r", b"\x00"):                 # blank line / delimiter padding between messages
                continue
            break
        if first.isdigit():
            digits = first
            while True:
                c = await asyncio.wait_for(reader.readexactly(1), self.idle)
                if c == b" ":
                    n = int(digits)
                    if n == 0 or n > self.max_msg:
                        self.stats_c["oversize_dropped"] += 1
                        raise _Framing(f"octet-count {n} outside 1..{self.max_msg}")
                    return await asyncio.wait_for(reader.readexactly(n), self.idle)
                if c == b"\n":                                  # a short all-digit line, e.g. "42"
                    return digits
                if not c.isdigit() or len(digits) >= 5:
                    first = digits + c                          # not octet counting after all: a line that starts with digits
                    break
                digits += c
        try:
            rest = await asyncio.wait_for(reader.readuntil(b"\n"), self.idle)
        except asyncio.IncompleteReadError as e:                # EOF without a trailing newline: deliver the tail
            rest = e.partial
        except asyncio.LimitOverrunError:
            self.stats_c["oversize_dropped"] += 1
            raise _Framing(f"line longer than {self.max_msg} bytes") from None
        msg = (first + rest).rstrip(b"\r\n\x00")
        if len(msg) > self.max_msg:
            self.stats_c["oversize_dropped"] += 1
            return b""                                          # caller skips empty frames
        return msg
