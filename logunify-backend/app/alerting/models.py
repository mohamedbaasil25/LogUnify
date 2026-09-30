import json
from dataclasses import asdict, dataclass, field

STATUSES = ("open", "acknowledged", "reported", "closed")
ACTIVE = ("open", "acknowledged")                 # the CERT-In clock is running, nothing has been reported yet
NOT_CLOSED = ("open", "acknowledged", "reported")
RESOLUTIONS = ("false_positive", "not_reportable", "resolved")
REPORT_CHANNELS = ("email", "phone", "fax", "portal", "other")


class AlertNotFound(LookupError):
    pass


class InvalidTransition(ValueError):
    pass


def new_notification() -> dict:
    return {"status": "pending",          # pending | sent | partial | failed | rate_limited | no_channels
            "channels": {},               # name -> {ok, attempts, last_error, last_at}
            "cycles": 0, "counted": False, "last_attempt_at": None, "sent_at": None}


@dataclass
class Alert:
    id: str
    dedup_key: str
    status: str
    created_at: float                     # epoch seconds: when LogUnify noticed the incident = start of the 6-hour clock
    due_at: float                         # created_at + 6 h
    last_seen_at: float
    occurrences: int
    trigger: dict
    doc: dict                             # the full (unredacted) ECS record that triggered the alert: the evidence
    evidence: dict = field(default_factory=dict)          # record_sha256, event_id
    analyst: dict = field(default_factory=dict)           # details supplied by a human (see cert_in.ANALYST_FIELDS)
    ack: dict | None = None
    reported: dict | None = None
    closed: dict | None = None
    notification: dict = field(default_factory=new_notification)
    reminders_sent: list = field(default_factory=list)    # reminder thresholds (minutes before due) already sent
    overdue_last_at: float | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "Alert":
        return cls(**json.loads(text))
