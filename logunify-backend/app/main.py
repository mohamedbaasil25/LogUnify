import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import forwarding as forwarding_api, state as state_api, alerts, audit as audit_api, compliance as compliance_api, health, integrity, intel, logs, metrics, sources, threatintel
from .sources import SourceRegistry
from .config import Settings, settings as default_settings
from .compliance import scheduler as compliance_scheduler
from .mock.generators import produce
from .listeners.manager import ListenerManager
from .state.store import StateStore
from .pipeline.bus import make_bus
from .pipeline.metrics import MetricsRegistry
from .pipeline.processor import Pipeline
from .security.audit import AuditLog
from .security.rbac import validate_settings


def create_app(settings: Settings = default_settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        pipeline = app.state.pipeline
        st = app.state.state
        if settings.state_enabled:
            await st.open()
            try:
                await st.load()                                    # before anything starts producing or serving
            except Exception:
                logging.getLogger("logunify.state").exception("restoring saved state failed; continuing with what loaded")
            await app.state.listeners.restore(app.state.sources)   # re-bind syslog sources that were registered before the restart
        await pipeline.start()
        mock = None
        if settings.mock_enabled:
            mock = asyncio.create_task(produce(pipeline.submit, settings.mock_rate))
        await app.state.listeners.start_default()
        st.start()
        report_task = None
        if settings.compliance_report_interval_hours > 0:
            report_task = asyncio.create_task(compliance_scheduler.run(settings, pipeline, app.state.audit))
        yield
        for t in (mock, report_task):
            if t:
                t.cancel()
        await app.state.listeners.stop_all()
        await pipeline.stop()
        await st.close()                                           # final flush, after the last log was processed

    app = FastAPI(title="LogUnify", version="0.1.0",
                  description="Universal log pre-processing: Syslog/JSON/CEF -> ECS", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    validate_settings(settings)
    app.state.settings = settings
    app.state.audit = AuditLog(settings.audit_db_path, settings.audit_hmac_key.get_secret_value() if settings.audit_hmac_key else None)
    app.state.metrics = MetricsRegistry()
    app.state.sources = SourceRegistry()
    app.state.pipeline = Pipeline(make_bus(settings), app.state.metrics, settings)
    p_ = app.state.pipeline
    app.state.state = StateStore(settings.state_db_path, settings.state_flush_interval_s, settings.state_persist_logs).attach(
        sources=app.state.sources, ti=p_.ti, batcher=p_.batcher, ledger=p_.ledger, recent=p_.recent, anomalies=p_.anomalies)
    app.state.listeners = ListenerManager(app.state.pipeline.submit, settings)
    for r in (health.router, metrics.router, logs.router, intel.router, integrity.router, sources.router, threatintel.router, alerts.router, audit_api.router, compliance_api.router, state_api.router, forwarding_api.router):
        app.include_router(r)
    return app


app = create_app()
