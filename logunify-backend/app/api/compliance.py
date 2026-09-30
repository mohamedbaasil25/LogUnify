"""Compliance API (admin only): retention proof, control mapping, auditor PDF."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from ..compliance import report
from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


def _build(request: Request, p: Pipeline):
    return report.build(request.app.state.settings, p, request.app.state.audit)


@router.get("/report", dependencies=[Depends(guard("admin", "compliance.report"))])
def get_report(request: Request, framework: str | None = None, p: Pipeline = Depends(get_pipeline)):
    """Full report as JSON; `framework` filters the control list (e.g. 'PCI-DSS 4.0'). Queries a live cluster if configured."""
    rep = _build(request, p)
    if framework:
        rep["controls"] = [c for c in rep["controls"] if c["framework"].lower() == framework.lower()]
    return rep


@router.get("/retention", dependencies=[Depends(guard("admin", "compliance.retention"))])
def retention(request: Request, p: Pipeline = Depends(get_pipeline)):
    return _build(request, p)["retention"]


@router.get("/report.pdf", dependencies=[Depends(guard("admin", "compliance.report_pdf"))])
def get_pdf(request: Request, p: Pipeline = Depends(get_pipeline)):
    rep = _build(request, p)
    return Response(report.render_pdf(rep), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="logunify-compliance-{rep["generated_at"][:10]}.pdf"',
                             "X-Report-SHA256": rep["report_sha256"]})
