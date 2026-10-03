"""Heuristic MITRE ATT&CK tagging. NOT a validated detection mapping.

Every log scoring above the anomaly threshold gets a technique. The first matching rule wins; each rule is a
conservative keyword / field heuristic and records its name, so downstream consumers (the alerting module) can tell a
rule-based match from the fallback:

    logunify.mitre.basis = "rule:<name>"   a rule matched
    logunify.mitre.basis = "default"       nothing matched; T1078 is only a placeholder (do NOT treat it as a finding)

Rules are deliberately few and explainable. They are a classification aid that only matters in combination with the
statistical anomaly score; replace them with real analytics before relying on the tags for decisions.
"""
import re
from dataclasses import dataclass
from typing import Callable

from .netutil import is_external

DEFAULT = ("T1078", "Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access")


@dataclass(frozen=True)
class Rule:
    name: str
    technique: tuple[str, str, str]                  # (technique id, name, tactic(s))
    matches: Callable[[dict, str], bool]             # (flat ECS fields, message text) -> bool


def _rx(pattern: str) -> Callable[[dict, str], bool]:
    rx = re.compile(pattern, re.I)
    return lambda fields, text: bool(rx.search(text))


def _auth(outcome: str, external_source: bool = False) -> Callable[[dict, str], bool]:
    def check(fields: dict, _text: str) -> bool:
        ok = fields.get("event.outcome") == outcome and "authentication" in ([cat] if isinstance((cat := fields.get("event.category")), str) else (cat or []))
        return ok and (is_external(fields.get("source.ip")) if external_source else ok)
    return check


def _win(codes: tuple[int, ...], also: Callable[[dict], bool] | None = None) -> Callable[[dict, str], bool]:
    """A Windows event-ID rule: keyed on the STRUCTURED `event.code`, so it works regardless of the OS display language or message text."""
    want = {str(c) for c in codes}

    def check(fields: dict, _text: str) -> bool:
        return fields.get("event.module") == "windows" and str(fields.get("event.code")) in want and (also is None or also(fields))
    return check


_PRIV_GROUP_NAME = re.compile(r"^(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|dnsadmins)$", re.I)
# well-known group SIDs: local Administrators / Account / Server / Backup Operators, and the domain's Domain / Schema / Enterprise Admins (RIDs 512/518/519)
_PRIV_GROUP_SID = re.compile(r"^(S-1-5-32-(544|548|549|551)|S-1-5-21-[\d-]+-(512|518|519))$")


def _privileged_group(f: dict) -> bool:
    return bool(_PRIV_GROUP_NAME.match(str(f.get("labels.target_name") or "").strip()) or _PRIV_GROUP_SID.match(str(f.get("labels.target_sid") or "").strip()))


RULES: list[Rule] = [
    # Windows, by event ID (see parsers/builtin/windows_security.yaml). First because structured fields beat keyword guesses.
    Rule("win_log_cleared", ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion"), _win((1102, 104))),
    Rule("win_privileged_group_add", ("T1098", "Account Manipulation", "Persistence, Privilege Escalation"), _win((4728, 4732, 4756), _privileged_group)),
    Rule("win_audit_policy_changed", ("T1562.002", "Impair Defenses: Disable Windows Event Logging", "Defense Evasion"), _win((4719,))),
    Rule("log_clearing", ("T1070", "Indicator Removal", "Defense Evasion"), _rx(
        r"\b(audit|event|security|system|auth|syslog)\s+logs?\s+(was\s+|were\s+|has\s+been\s+)?"
        r"(clear(ed)?|delet(ed)?|wip(ed)?|truncat(ed)?|purg(ed)?)\b|\bwevtutil(\.exe)?\s+cl\b|\bclear-eventlog\b|\bhistory\s+-c\b")),
    Rule("credential_dumping", ("T1003", "OS Credential Dumping", "Credential Access"), _rx(
        r"\bmimikatz\b|\bsekurlsa\b|\blsass(\.exe)?\b.{0,40}\b(dump|memory|minidump)\b|\bprocdump\b.{0,40}\blsass\b|\bntds\.dit\b")),
    Rule("ransomware", ("T1486", "Data Encrypted for Impact", "Impact"), _rx(
        r"\bransom\s*note\b|\bransomware\s+(detected|activity|behaviou?r|infection|payload|executed|blocked)\b"
        r"|\bfiles?\s+(have\s+been\s+|were\s+|are\s+)?encrypted\b")),
    Rule("shadow_copy_deletion", ("T1490", "Inhibit System Recovery", "Impact"), _rx(
        r"\bvssadmin(\.exe)?\s+delete\s+shadows\b|\bwbadmin\s+delete\s+(catalog|backup)\b|\bbcdedit\b.*\brecoveryenabled\s+no\b")),
    Rule("exfiltration", ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"), _rx(
        r"\bunexpected\s+outbound\s+transfer\b|\bexfiltrat\w*|\blarge\s+(outbound\s+)?(upload|transfer)\b")),
    Rule("web_exploit", ("T1190", "Exploit Public-Facing Application", "Initial Access"), _rx(
        r"\bsql\s*injection\b|\bunion\s+select\b|<script\b|\.\./\.\./|/etc/passwd\b|\$\{jndi:|\bremote\s+code\s+execution\b")),
    Rule("c2_beacon", ("T1071", "Application Layer Protocol", "Command and Control"), _rx(
        r"\bmalware\s+(callback|beacon)\b|\bc2\s+(server|channel|beacon|callback)\b|\bcommand[- ]and[- ]control\b|\bbeaconing\b")),
    Rule("command_exec", ("T1059", "Command and Scripting Interpreter", "Execution"), _rx(
        r"\breverse\s+shell\b|\bbash\s+-i\s+>&|\bnc(\.exe)?\s+\S*\s*-e\b|\bpowershell(\.exe)?\b.{0,80}\s-(enc|encodedcommand)\b")),
    Rule("privileged_group_add", ("T1098", "Account Manipulation", "Persistence, Privilege Escalation"), _rx(
        r"\badded\s+to\s+(the\s+)?(group\s+)?['\"]?(wheel|sudo|admin(istrators)?|root|domain\s+admins|docker)\b")),
    Rule("privilege_escalation", ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"), _rx(
        r"\bprivilege\s+escalation\b")),
    Rule("auth_failure", ("T1110", "Brute Force", "Credential Access"), _auth("failure")),
    Rule("external_login", ("T1078", "Valid Accounts", DEFAULT[2]), _auth("success", external_source=True)),
]


def tag(fields: dict, text: str = "") -> dict:
    """Flat ECS fields describing the technique for a high-scoring log, including how it was chosen."""
    for rule in RULES:
        if rule.matches(fields, text):
            tid, name, tactic = rule.technique
            basis = f"rule:{rule.name}"
            break
    else:
        (tid, name, tactic), basis = DEFAULT, "default"
    return {"threat.framework": "MITRE ATT&CK", "threat.technique.id": tid,
            "threat.technique.name": name, "threat.tactic.name": tactic,
            "logunify.mitre.basis": basis, "labels.mitre_placeholder": "true"}
