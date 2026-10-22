"""Heuristic risk scorer + MITRE ATT&CK tagger.

SIMULATION: this stands in for the Isolation Forest / Drain3 stage. The scores are fixed rule outputs, NOT learned from data and NOT calibrated.
"""
import re

_ENC_PS = re.compile(r"(?i)\bpowershell(?:\.exe)?\b.*?\s-(?:e|ec|enc|encodedcommand)\b")

# (technique, name) per rule
T1110 = ("T1110", "Brute Force")
T1059_001 = ("T1059.001", "Command and Scripting Interpreter: PowerShell")
T1059 = ("T1059", "Command and Scripting Interpreter")


def score_event(ev: dict) -> tuple[float, list[dict]]:
    """Returns (score in [0.0, 1.0], techniques[{id, name}])."""
    code = str(ev.get("event.code", ""))
    action = ev.get("event.action")
    score, techs = 0.05, []
    if code == "4625" or (action in ("authentication-failed", "access-denied") and ev.get("event.module") in ("postgresql", "mysql")):
        score, techs = 0.5, [T1110]
    elif code == "4688":
        cmd = ev.get("process.command_line", "") or ""
        if _ENC_PS.search(cmd):
            score, techs = 0.85, [T1059_001, T1059]
        else:
            score, techs = 0.2, [T1059]
    elif code == "4624":
        score = 0.1
    return max(0.0, min(1.0, score)), [{"id": i, "name": n} for i, n in techs]


def analyze(ev: dict) -> dict:
    score, techs = score_event(ev)
    ev["event.risk_score_norm"] = score                          # ECS field for a 0-1 risk score
    ev["logunify.score_method"] = "heuristic-simulation"
    if techs:
        ev["threat.technique.id"] = [t["id"] for t in techs]
        ev["threat.technique.name"] = [t["name"] for t in techs]
        ev["threat.framework"] = "MITRE ATT&CK"
    return ev
