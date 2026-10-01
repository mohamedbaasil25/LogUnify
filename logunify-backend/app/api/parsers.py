"""Parser registry API: which parsers (and versions) are loaded, and why a file failed to load."""
from fastapi import APIRouter, Depends

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/parsers", tags=["parsers"])


@router.get("", dependencies=[Depends(guard("viewer", "parsers.list", sample_s=60))])
def list_parsers(p: Pipeline = Depends(get_pipeline)):
    """Loaded parsers with versions. `errors` lists parser files / entry points that were skipped, with the reason."""
    return {"items": p.parsers.info(), "errors": list(p.parsers.errors)}
