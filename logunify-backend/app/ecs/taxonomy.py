"""Unified event taxonomy: fills ECS `event.category`, `event.type`, `event.outcome` and `event.module` consistently across sources.

Parsers only extract what is literally in the log. This layer then applies defaults from small, auditable rule tables so that the
same kind of event looks the same whether it arrived as syslog, JSON or CEF, which is what makes one query / one dashboard work
across sources. Rules never override a value a parser or a declarative mapping already set. They are HEURISTICS: a rule says "a
log from sshd is an authentication event", not that it was proven to be one. Extend the tables (or give a source's own parser the
fields) rather than editing code paths.
"""
CATEGORIES = {"api", "authentication", "configuration", "database", "driver", "email", "file", "host", "iam", "intrusion_detection",
              "library", "malware", "network", "package", "process", "registry", "session", "threat", "vulnerability", "web"}
TYPES = {"access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "end", "error", "group", "indicator",
         "info", "installation", "protocol", "start", "user"}
OUTCOMES = {"success", "failure", "unknown"}
KINDS = {"alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"}

_OUTCOME_SYNONYMS = {
    "success": "success", "succeeded": "success", "successful": "success", "ok": "success", "allow": "success", "allowed": "success",
    "permit": "success", "permitted": "success", "accepted": "success", "pass": "success", "passed": "success",
    "failure": "failure", "failed": "failure", "fail": "failure", "error": "failure", "deny": "failure", "denied": "failure",
    "drop": "failure", "dropped": "failure", "block": "failure", "blocked": "failure", "reject": "failure", "rejected": "failure",
    "unknown": "unknown",
}

# syslog facility -> default category (only where the facility itself is informative)
_FACILITY = {"auth": "authentication", "authpriv": "authentication", "cron": "process", "kern": "host", "mail": "email"}
# program name -> category (matched on the syslog tag / process.name, lower-cased)
_PROGRAM = {"sshd": "authentication", "login": "authentication", "su": "authentication", "sudo": "authentication",
            "passwd": "authentication", "polkitd": "authentication", "cron": "process", "crond": "process", "anacron": "process",
            "systemd": "process", "kernel": "host", "postfix": "email", "sendmail": "email", "dovecot": "email",
            "nginx": "web", "httpd": "web", "apache2": "web", "named": "network", "dhclient": "network"}
_END_WORDS = ("session closed", "disconnected", "logout", "logged out", "connection closed")


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def has_category(fields: dict, name: str) -> bool:
    return name in _as_list(fields.get("event.category"))


def _set_default(f: dict, key: str, value) -> None:
    if f.get(key) in (None, "", []):
        f[key] = value


def categorize(f: dict, parser: str = "") -> None:
    """Normalise and complete the event taxonomy of `f` (dotted fields) in place."""
    # 1. normalise what the parser already set: category/type are arrays, outcome is one of success/failure/unknown
    for k in ("event.category", "event.type"):
        if k in f and f[k] is not None:
            f[k] = [str(x).lower() for x in _as_list(f[k])]
    if (o := f.get("event.outcome")) is not None:
        f["event.outcome"] = _OUTCOME_SYNONYMS.get(str(o).strip().lower(), "unknown")

    if "event.outcome" not in f and str(f.get("event.action") or "").strip().lower() in _OUTCOME_SYNONYMS:
        f["event.outcome"] = _OUTCOME_SYNONYMS[str(f["event.action"]).strip().lower()]      # firewall-style action=blocked/allowed

    cats = _as_list(f.get("event.category"))
    msg = str(f.get("message") or "").lower()
    program = str(f.get("process.name") or "").lower()

    # 2. category defaults
    if not cats:
        if (fac := f.get("log.syslog.facility.name")) in _FACILITY:
            cats = [_FACILITY[fac]]
        if program in _PROGRAM:                             # the program is more specific than the facility
            cats = [_PROGRAM[program]]
        if not cats and ("http.response.status_code" in f or "http.request.method" in f):
            cats = ["web"]
        if not cats and "source.ip" in f and "destination.ip" in f:
            cats = ["network"]
        if not cats and "file.name" in f:
            cats = ["file"]
        if cats:
            f["event.category"] = cats

    # 3. type + outcome defaults per category
    if "web" in cats:
        _set_default(f, "event.type", ["access"])
        code = f.get("http.response.status_code")
        if "event.outcome" not in f and isinstance(code, (int, str)) and str(code).isdigit():
            f["event.outcome"] = "success" if int(code) < 400 else "failure"
    elif "authentication" in cats:
        if any(w in msg for w in _END_WORDS):
            _set_default(f, "event.type", ["end"])
        elif f.get("event.outcome") in ("success", "failure"):
            _set_default(f, "event.type", ["start"])
        else:
            _set_default(f, "event.type", ["info"])
    elif "network" in cats:
        _set_default(f, "event.type", ["connection"])
    elif cats:
        _set_default(f, "event.type", ["info"])

    # 4. module: which parser / integration produced this
    if parser:
        _set_default(f, "event.module", parser)
