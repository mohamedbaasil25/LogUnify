"""ECS schema validation for normalized documents.

What it checks: that every field LogUnify emits is under a known ECS root (or `logunify.*` / `labels.*`), that fields whose type
is known have a value of that type (ip is an IP, long is an integer, date parses, ...), that `event.kind/category/type/outcome` use
ECS's allowed values, and that the required fields (`@timestamp`, `ecs.version`, `event.kind`) are present.

What it does NOT do: it is not the full ECS 8.11 field list. `FIELD_TYPES` is a curated table of the ~230 fields that sources
commonly populate; a field that is under a valid ECS root but missing from the table is accepted untyped (never flagged), so the
validator has no false positives from the table's gaps. To check against the complete schema, load the official `ecs_flat.yml`
with `load_ecs_flat()` and pass the result as `types=`.

Modes (LOGUNIFY_TAXONOMY_MODE): `off`; `warn` (count violations by rule, never touch the log); `strict` (a document with a violation
is dead-lettered with its raw bytes, replayable once the parser is fixed). Tests run every shipped parser's fixtures in strict mode.
"""
import ipaddress
from datetime import datetime

from .taxonomy import CATEGORIES, KINDS, OUTCOMES, TYPES

ROOTS = {"@timestamp", "message", "tags", "labels", "agent", "as", "client", "cloud", "container", "data_stream", "destination", "device",
         "dll", "dns", "ecs", "email", "error", "event", "faas", "file", "group", "host", "http", "interface", "log", "network",
         "observer", "orchestrator", "organization", "os", "package", "pe", "process", "registry", "related", "risk", "rule", "server",
         "service", "source", "span", "threat", "tls", "trace", "transaction", "url", "user", "user_agent", "vlan", "volume",
         "vulnerability", "x509", "logunify"}

_T = """
@timestamp date | message text | tags keyword | ecs.version keyword | error.message text | error.code keyword | error.type keyword
event.kind keyword | event.category keyword | event.type keyword | event.outcome keyword | event.action keyword | event.id keyword
event.code keyword | event.dataset keyword | event.module keyword | event.provider keyword | event.reason keyword | event.original keyword
event.hash keyword | event.created date | event.ingested date | event.start date | event.end date | event.timezone keyword
event.severity long | event.risk_score float | event.duration long | event.sequence long | event.url keyword | event.reference keyword
log.level keyword | log.logger keyword | log.syslog.facility.code long | log.syslog.facility.name keyword | log.syslog.priority long
log.syslog.severity.code long | log.syslog.severity.name keyword | log.file.path keyword | log.origin.function keyword
host.name keyword | host.hostname keyword | host.id keyword | host.ip ip | host.mac keyword | host.os.name keyword | host.os.family keyword
host.os.version keyword | host.type keyword | host.domain keyword | host.architecture keyword
source.ip ip | source.port long | source.domain keyword | source.mac keyword | source.bytes long | source.packets long | source.address keyword
source.geo.country_iso_code keyword | source.geo.country_name keyword | source.geo.city_name keyword | source.geo.region_name keyword
destination.ip ip | destination.port long | destination.domain keyword | destination.mac keyword | destination.bytes long
destination.packets long | destination.address keyword | destination.geo.country_iso_code keyword | destination.geo.country_name keyword
client.ip ip | client.port long | client.domain keyword | server.ip ip | server.port long | server.domain keyword
network.transport keyword | network.protocol keyword | network.direction keyword | network.type keyword | network.bytes long
network.packets long | network.community_id keyword | network.application keyword
user.name keyword | user.id keyword | user.email keyword | user.domain keyword | user.full_name keyword | user.hash keyword
user.target.name keyword | user.target.id keyword | user.effective.name keyword | group.name keyword | group.id keyword
process.name keyword | process.pid long | process.ppid long | process.executable keyword | process.command_line keyword | process.args keyword
process.working_directory keyword | process.parent.name keyword | process.parent.pid long | process.start date | process.exit_code long
file.name keyword | file.path keyword | file.directory keyword | file.extension keyword | file.size long | file.type keyword
file.hash.md5 keyword | file.hash.sha1 keyword | file.hash.sha256 keyword | file.created date | file.mtime date
url.original wildcard | url.full wildcard | url.domain keyword | url.path wildcard | url.query keyword | url.scheme keyword | url.port long
url.fragment keyword | url.extension keyword
http.request.method keyword | http.request.referrer keyword | http.request.bytes long | http.request.body.bytes long
http.request.body.content wildcard | http.response.status_code long | http.response.bytes long | http.response.body.bytes long
http.version keyword
user_agent.original keyword | user_agent.name keyword | user_agent.version keyword | user_agent.device.name keyword
dns.question.name keyword | dns.question.type keyword | dns.response_code keyword | dns.type keyword | dns.id keyword
observer.vendor keyword | observer.product keyword | observer.version keyword | observer.type keyword | observer.name keyword
observer.hostname keyword | observer.ip ip | observer.serial_number keyword | observer.ingress.interface.name keyword
observer.egress.interface.name keyword
cloud.provider keyword | cloud.region keyword | cloud.account.id keyword | cloud.account.name keyword | cloud.availability_zone keyword
cloud.instance.id keyword | cloud.service.name keyword
service.name keyword | service.type keyword | service.version keyword | service.environment keyword
rule.id keyword | rule.name keyword | rule.category keyword | rule.description keyword | rule.ruleset keyword
threat.framework keyword | threat.technique.id keyword | threat.technique.name keyword | threat.technique.reference keyword
threat.tactic.id keyword | threat.tactic.name keyword | threat.tactic.reference keyword | threat.indicator.type keyword
threat.indicator.provider keyword | threat.indicator.confidence keyword | threat.indicator.ip ip | threat.indicator.description keyword
threat.indicator.reference keyword | threat.indicator.first_seen date | threat.indicator.last_seen date
registry.path keyword | registry.key keyword | registry.value keyword | email.from.address keyword | email.subject keyword
data_stream.type keyword | data_stream.dataset keyword | data_stream.namespace keyword
agent.name keyword | agent.id keyword | agent.type keyword | agent.version keyword
related.ip ip | related.user keyword | related.hosts keyword | related.hash keyword
logunify.anomaly.score float | logunify.anomaly.model_ready boolean | logunify.template.id long | logunify.template.text keyword
logunify.source_format keyword | logunify.transport keyword | logunify.source.id keyword | logunify.parser.name keyword
logunify.parser.version keyword | logunify.raw.redacted boolean | logunify.origin.kafka.offset long | logunify.origin.kafka.partition long
logunify.origin.kafka.topic keyword | logunify.origin.peer keyword
"""
FIELD_TYPES: dict[str, str] = {}
for _chunk in _T.replace("\n", "|").split("|"):
    _parts = _chunk.split()
    if len(_parts) == 2:
        FIELD_TYPES[_parts[0]] = _parts[1]

ARRAY_FIELDS = {"event.category", "event.type"}            # ECS: always arrays of keyword
REQUIRED = ("@timestamp", "ecs.version", "event.kind")
_ENUMS = {"event.kind": KINDS, "event.category": CATEGORIES, "event.type": TYPES, "event.outcome": OUTCOMES}
_INTS = {"long", "integer", "short", "byte"}


def load_ecs_flat(path: str) -> dict[str, str]:
    """Field -> type from the official ecs_flat.yml (https://github.com/elastic/ecs, generated/ecs/ecs_flat.yml)."""
    import yaml
    with open(path, encoding="utf-8") as f:
        flat = yaml.safe_load(f)
    return {k: v["type"] for k, v in flat.items() if isinstance(v, dict) and "type" in v}


def flatten(doc: dict, prefix: str = ""):
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from flatten(v, key + ".")
        else:
            yield key, v


def _scalar(v) -> bool:
    return isinstance(v, (str, int, float, bool))


def _check_type(t: str, v) -> str | None:
    if t in ("keyword", "text", "wildcard", "match_only_text", "constant_keyword"):
        return None if _scalar(v) else "expected a scalar string"
    if t == "ip":
        try:
            ipaddress.ip_address(str(v))
            return None
        except ValueError:
            return "not a valid IP address"
    if t in _INTS:
        return None if isinstance(v, int) and not isinstance(v, bool) else "expected an integer"
    if t in ("float", "scaled_float", "double", "half_float"):
        return None if isinstance(v, (int, float)) and not isinstance(v, bool) else "expected a number"
    if t == "date":
        try:
            datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return None
        except ValueError:
            return "not an ISO-8601 date"
    if t == "boolean":
        return None if isinstance(v, bool) else "expected true/false"
    return None


def validate(doc: dict, types: dict[str, str] | None = None) -> list[tuple[str, str, str]]:
    """-> [(rule, field, detail)]. Empty = valid."""
    types = types or FIELD_TYPES
    out: list[tuple[str, str, str]] = []
    present = set()
    for path, v in flatten(doc):
        present.add(path)
        root = path.split(".", 1)[0]
        if root not in ROOTS:
            out.append(("unknown_root", path, f"'{root}' is not an ECS field set (use labels.* or logunify.* for custom data)"))
            continue
        vals = v if isinstance(v, list) else [v]
        if path in ARRAY_FIELDS and not isinstance(v, list):
            out.append(("not_array", path, "ECS defines this field as an array"))
        t = types.get(path)
        if root == "labels" and not all(_scalar(x) for x in vals):
            out.append(("labels_scalar", path, "labels values must be scalars"))
        if t is not None:
            for x in vals:
                if (msg := _check_type(t, x)) is not None:
                    out.append(("type_mismatch", path, f"{t}: {msg} (got {type(x).__name__}: {str(x)[:40]})"))
                    break
        if path in _ENUMS:
            bad = [x for x in vals if x not in _ENUMS[path]]
            if bad:
                out.append(("bad_enum", path, f"{bad[0]!r} is not an allowed ECS value"))
    out += [("missing_required", f, "required ECS field is absent") for f in REQUIRED if f not in present]
    return out
