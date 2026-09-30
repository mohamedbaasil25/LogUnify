"""Calibrate the alert threshold: how many alerts would each score threshold have produced?

    python scripts/alert_threshold_survey.py --logs 60000

Runs generated traffic through the real pipeline (Drain3 + Isolation Forest + MITRE rules) and counts, for each
candidate threshold, the events that would raise a CERT-In-clock alert: score above the threshold AND a rule-matched
critical technique. "Alerts" applies the same grouping as production (one per technique + asset during a burst of
activity), so the number is what an analyst would actually receive.

Mock traffic contains a small share of synthetic rare events; for a real decision replay a sample of YOUR logs
(adapt `feed()`), because score distributions depend entirely on your traffic.
"""
import argparse
import collections
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.alerting import cert_in  # noqa: E402
from app.alerting.defaults import DEFAULT_CRITICAL_TECHNIQUES  # noqa: E402
from app.alerting.rules import AlertRules  # noqa: E402
from app.config import Settings  # noqa: E402
from app.mock.generators import gen_log  # noqa: E402
from app.pipeline.bus import InMemoryBus  # noqa: E402
from app.pipeline.metrics import MetricsRegistry  # noqa: E402
from app.pipeline.processor import Pipeline  # noqa: E402


def feed(n: int, seed: int):
    random.seed(seed)
    for _ in range(n):
        yield gen_log(0.03)[0].encode()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", type=int, default=60000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--critical", default=DEFAULT_CRITICAL_TECHNIQUES, help="critical MITRE ids (CSV)")
    a = ap.parse_args()

    # alerting off inside the pipeline: we only need the enriched documents
    p = Pipeline(InMemoryBus(10), MetricsRegistry(), Settings(mock_enabled=False, alerting_enabled=False))
    docs = [d for raw in feed(a.logs, a.seed) if (d := p.process(raw))]
    scores = sorted(d["logunify"]["anomaly"]["score"] for d in docs)
    n = len(scores)
    print(f"{n:,} logs processed; score p50={scores[n // 2]:.2f} p99={scores[int(n * .99)]:.2f} p99.9={scores[int(n * .999)]:.2f} max={scores[-1]:.3f}")

    tagged = collections.Counter()
    for d in docs:
        t = (d.get("threat") or {}).get("technique")
        if t:
            tagged[(t["id"], d["logunify"]["mitre"]["basis"].split(":")[0], d["logunify"]["anomaly"]["score"] > 0.9)] += 1
    by_basis = collections.Counter()
    for (tid, basis, hi), c in tagged.items():
        by_basis[basis] += c
    print(f"tagged above the tagging threshold: {sum(by_basis.values())} ({dict(by_basis)}); "
          f"'default' = placeholder T1078 fallback, never alerts unless alert_require_rule_basis=false\n")

    print(f"{'threshold':>9} | {'events':>6} | {'alerts':>6} | techniques")
    for thr in (0.70, 0.75, 0.80, 0.85, 0.90):
        rules = AlertRules(thr, a.critical)
        hits = [(rules.evaluate(d), d) for d in docs]
        hits = [(t, d) for t, d in hits if t]
        groups = {(t.technique_id.split(".")[0], cert_in.asset_key(d)) for t, d in hits}
        techs = collections.Counter(t.technique_id for t, _ in hits)
        print(f"{thr:>9.2f} | {len(hits):>6} | {len(groups):>6} | {dict(techs)}")
    print("\nPick the lowest threshold whose alert volume your analysts can triage inside the 6-hour window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
