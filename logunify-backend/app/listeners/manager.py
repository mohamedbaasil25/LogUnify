"""Owns the running syslog listeners: the optional settings-defined one plus one per registered syslog source."""
import logging

from .syslog import SyslogListener

log = logging.getLogger("logunify.listeners")


class ListenerManager:
    def __init__(self, pipeline_or_submit, settings):
        # accepts the Pipeline (preferred: gives batched submission) or a bare submit(raw, hint, **kw) coroutine function
        self._submit_many = getattr(pipeline_or_submit, "submit_many", None) or self._wrap(pipeline_or_submit)
        self._s = settings
        self._by_id: dict[str, SyslogListener] = {}

    def _make(self, name: str, udp: int | None, tcp: int | None, hint: str | None, source_id: str | None = None,
              tz: str | None = None) -> SyslogListener:
        s = self._s

        async def submit_many(raws: list[bytes], h: str | None) -> int:
            return await self._submit_many(raws, h, source_id=source_id, transport="syslog", tz=tz)

        async def submit_one(raw: bytes, h: str | None) -> bool:
            return await submit_many([raw], h) == 1

        return SyslogListener(submit_one, s.syslog_bind, udp, tcp, hint, s.syslog_queue_max, s.syslog_max_message_bytes,
                              s.syslog_max_connections, s.syslog_idle_timeout_s, name, submit_many=submit_many)

    @staticmethod
    def _wrap(submit):
        async def many(raws, hint, **kw):
            return sum([await submit(r, hint, **kw) for r in raws])
        return many

    async def start_default(self) -> None:
        s = self._s
        if s.syslog_udp_port is None and s.syslog_tcp_port is None:
            return
        try:
            lst = self._make("syslog-default", s.syslog_udp_port, s.syslog_tcp_port, None)
            await lst.start()
            self._by_id["default"] = lst
        except OSError as e:                      # e.g. port 514 needs privileges: the API must still come up
            log.error("syslog listener could not start on %s udp=%s tcp=%s: %s", s.syslog_bind, s.syslog_udp_port, s.syslog_tcp_port, e)

    async def start_source(self, src) -> None:
        """Bind the listener for a registered syslog source. Raises OSError (caller reports it) if the port is unavailable."""
        cfg = src.config
        udp = cfg["port"] if cfg["protocol"] == "udp" else None
        tcp = cfg["port"] if cfg["protocol"] == "tcp" else None
        lst = self._make(f"syslog-{src.id}", udp, tcp, None if src.format == "auto" else src.format, src.id, cfg.get("timezone"))
        await lst.start()
        self._by_id[src.id] = lst

    async def restore(self, registry) -> None:
        """After a restart: bind every restored syslog source again; the ones that cannot bind keep the reason."""
        for src in registry.list():
            if src.type != "syslog":
                continue
            try:
                await self.start_source(src)
                src.status, src.error = "active", None
            except OSError as e:
                src.error = f"could not bind {self._s.syslog_bind}:{src.config.get('port')}/{src.config.get('protocol')}: {e.strerror or e}"
                log.error("restored syslog source %s: %s", src.id, src.error)

    async def stop_source(self, sid: str) -> None:
        if (lst := self._by_id.pop(sid, None)):
            await lst.stop()

    async def stop_all(self) -> None:
        for sid in list(self._by_id):
            await self.stop_source(sid)

    def stats(self) -> list[dict]:
        return [{"source_id": sid, **lst.stats()} for sid, lst in self._by_id.items()]
