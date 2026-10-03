import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import (alerts, audit as audit_api, auth as auth_api, compliance as compliance_api, dlq as dlq_api, forwarding as forwarding_api, health,
                  integrity, intel, logs, metrics, parsers as parsers_api, sources, state as state_api, threatintel,
                  stream as stream_api, system as system_api, trace as trace_api)
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
from .security.oidc import Revocations, TokenVerifier
from .security.hardening import BodyLimitMiddleware, Hardening, RateLimitMiddleware, SecurityHeadersMiddleware
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
        if hasattr(hardening.rate, "close"):
            await hardening.rate.close()

    app = FastAPI(title="LogUnify", version=settings.version,
                  description="Universal log pre-processing: Syslog/JSON/CEF -> ECS", lifespan=lifespan,
                  docs_url="/docs" if settings.docs_enabled else None, redoc_url=None,
                  openapi_url="/openapi.json" if settings.docs_enabled else None)
    hardening = Hardening(settings)
    app.state.hardening = hardening
    app.add_middleware(RateLimitMiddleware, hardening=hardening)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if "*" in origins:
        raise ValueError("LOGUNIFY_CORS_ORIGINS must list explicit origins; a wildcard would let any website call this API from a browser")
    if origins:                                    # no credentials/cookies are used: bearer tokens only, so this stays narrow
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                           allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Source-Token"], max_age=600)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts_enabled)      # outermost: also on 413 / 429 / CORS replies
    validate_settings(settings)
    app.state.settings = settings
    app.state.verifier = TokenVerifier(settings)
    app.state.revocations = Revocations(settings.auth_db_path)
    app.state.audit = AuditLog(settings.audit_db_path, settings.audit_hmac_key.get_secret_value() if settings.audit_hmac_key else None)
    app.state.metrics = MetricsRegistry()
    app.state.sources = SourceRegistry()
    app.state.pipeline = Pipeline(make_bus(settings), app.state.metrics, settings)
    p_ = app.state.pipeline
    app.state.state = StateStore(
        settings.state_db_path, settings.state_flush_interval_s, settings.state_persist_logs,
        database_url=settings.state_database_url.get_secret_value() if settings.state_database_url else "",
        worker_id=settings.worker_id, persist_models=settings.state_persist_models, model_interval_s=settings.state_model_interval_s,
        hmac_key=((settings.state_hmac_key or settings.audit_hmac_key).get_secret_value().encode()
                  if (settings.state_hmac_key or settings.audit_hmac_key) else None),
    ).attach(sources=app.state.sources, ti=p_.ti, batcher=p_.batcher, ledger=p_.ledger, recent=p_.recent, anomalies=p_.anomalies,
             intel=p_.intel)
    app.state.listeners = ListenerManager(app.state.pipeline, settings)
    for r in (health.router, metrics.router, logs.router, intel.router, integrity.router, sources.router, threatintel.router,
              alerts.router, audit_api.router, compliance_api.router, state_api.router, forwarding_api.router, dlq_api.router,
              trace_api.router, parsers_api.router, stream_api.router, system_api.router, auth_api.router):
        app.include_router(r)
    return app


app = create_app()
