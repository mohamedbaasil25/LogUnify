from fastapi import Request

from ..pipeline.metrics import MetricsRegistry
from ..pipeline.processor import Pipeline


def get_pipeline(request: Request) -> Pipeline:
    return request.app.state.pipeline


def get_metrics(request: Request) -> MetricsRegistry:
    return request.app.state.metrics
