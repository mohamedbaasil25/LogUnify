"""The alert trigger: anomaly score EXCEEDS the threshold AND the log matches a critical MITRE ATT&CK technique."""
from dataclasses import asdict, dataclass

from .validation import parse_techniques


@dataclass(frozen=True)
class Trigger:
    score: float
    threshold: float
    technique_id: str
    technique_name: str
    tactic: str
    basis: str              # "rule:<name>" (how the technique was chosen)
    critical_match: str     # the configured critical id that matched (exact, or the parent of a sub-technique)

    def as_dict(self) -> dict:
        return asdict(self)


def get(doc: dict, *path):
    cur = doc
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


class AlertRules:
    def __init__(self, threshold: float, critical: frozenset[str] | str, require_rule_basis: bool = True):
        if not 0.0 <= threshold < 1.0:
            raise ValueError("alert threshold must be in [0, 1)")
        self.threshold = threshold
        self.critical = parse_techniques(critical) if isinstance(critical, str) else frozenset(critical)
        self.require_rule_basis = require_rule_basis

    def evaluate(self, doc: dict) -> Trigger | None:
        score = get(doc, "logunify", "anomaly", "score")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or score <= self.threshold:
            return None                                              # "exceeds": strictly greater than
        if get(doc, "logunify", "anomaly", "model_ready") is False:
            return None                                              # a warming-up model's score is not evidence
        tid = get(doc, "threat", "technique", "id")
        if not isinstance(tid, str):
            return None
        tid = tid.strip().upper()
        basis = str(get(doc, "logunify", "mitre", "basis") or "unknown")
        if self.require_rule_basis and not basis.startswith("rule:"):
            return None                                              # the T1078 fallback tag is a placeholder, not a finding
        match = next((c for c in (tid, tid.split(".")[0]) if c in self.critical), None)
        if match is None:
            return None
        return Trigger(score=float(score), threshold=self.threshold, technique_id=tid,
                       technique_name=str(get(doc, "threat", "technique", "name") or ""),
                       tactic=str(get(doc, "threat", "tactic", "name") or ""), basis=basis, critical_match=match)
