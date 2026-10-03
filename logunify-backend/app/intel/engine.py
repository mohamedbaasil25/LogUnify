import math
from dataclasses import dataclass

from ..parsers.base import ParsedLog
from . import mitre
from .anomaly import AnomalyScorer
from .netutil import is_external
from .ecs_mapper import map_to_ecs
from .template_miner import TemplateMinerService


@dataclass
class Analysis:
    template_id: int
    template: str
    is_new_template: bool
    score: float
    model_ready: bool
    technique: str | None
    ecs_fields: dict          # fields added by parameter mapping (parser-provided fields are never overridden)


class LogIntelligence:
    """Drain3 template mining -> ECS parameter mapping -> Isolation Forest score -> MITRE tag."""

    def __init__(self, threshold: float = 0.7, warmup: int = 200, refit_every: int = 1000, window: int = 5000,
                 settle: int = 50):
        self.threshold = threshold
        self.settle = settle      # first N logs are not learned from: at startup every template is 'new'
        self.miner = TemplateMinerService()
        self.scorer = AnomalyScorer(warmup=warmup, refit_every=refit_every, window=window)
        self.anomalies = 0

    def export_state(self) -> dict[str, str]:
        """Learned state as text blobs: Drain3 templates (snapshot) and the Isolation Forest training window (JSON)."""
        import json
        return {"drain3": self.miner.export_state().decode("ascii"),
                "iforest_window": json.dumps(self.scorer.export_window(), separators=(",", ":"))}

    def import_state(self, blobs: dict[str, str]) -> dict:
        """Restore what `export_state` saved. The caller MUST have authenticated the blobs (Drain3's format is jsonpickle)."""
        import json
        out = {}
        if "drain3" in blobs:
            out["templates"] = self.miner.import_state(blobs["drain3"].encode("ascii"))
        if "iforest_window" in blobs:
            out["iforest_samples"] = len(rows := json.loads(blobs["iforest_window"]))
            out["model_ready"] = self.scorer.import_window(rows)
        return out

    def analyze(self, parsed: ParsedLog) -> Analysis:
        """Enrich `parsed.fields` in place (setdefault only) and return the analysis."""
        return self.analyze_many([parsed])[0]

    def analyze_many(self, parsed_list: list[ParsedLog], no_learn: list[bool] | None = None) -> list[Analysis]:
        """Same as `analyze`, for a batch: templates are mined in order (Drain3 is sequential by nature), then ALL logs are scored
        with one Isolation Forest call. Per-call overhead dominates single-row scoring, so this is several times faster per log."""
        staged = []
        for n, parsed in enumerate(parsed_list):
            skip = bool(no_learn and no_learn[n])               # synthetic / test source: scored and tagged, but it teaches the model nothing
            text = parsed.message or parsed.original
            mined = self.miner.peek(text) if skip else self.miner.mine(text)
            added = {k: v for k, v in map_to_ecs(mined).items() if k not in parsed.fields}
            parsed.fields.update(added)
            staged.append((parsed, text, mined, added, self._features(parsed, mined, len(text)), self.miner.total > self.settle and not skip))
        scores = self.scorer.score_many([s[4] for s in staged], [s[5] for s in staged])
        out = []
        for (parsed, text, mined, added, _feat, _learn), score in zip(staged, scores):
            tag = None
            f = parsed.fields
            f["logunify.template.id"] = mined.cluster_id
            f["logunify.template.text"] = mined.template
            f["logunify.anomaly.score"] = score
            f["logunify.anomaly.model_ready"] = self.scorer.ready
            if score > self.threshold:
                self.anomalies += 1
                t = mitre.tag(f, text)
                f.update(t)
                tag = t["threat.technique.id"]
            out.append(Analysis(mined.cluster_id, mined.template, mined.is_new, score, self.scorer.ready, tag, added))
        return out

    def _features(self, p: ParsedLog, m, msg_len: int) -> list[float]:
        f = p.fields
        share = m.cluster_size / max(self.miner.total, 1)     # how common is this template overall
        sev = f.get("event.severity")
        return [
            1.0 if m.is_new else 0.0,
            math.log10(share + 1e-6),
            float(sev if isinstance(sev, (int, float)) else 6),
            math.log1p(msg_len),
            float(len(m.params)),
            1.0 if f.get("event.outcome") == "failure" else 0.0,
            1.0 if _external(f.get("source.ip")) else 0.0,
        ]


_external = is_external      # kept for callers that imported the old private name
